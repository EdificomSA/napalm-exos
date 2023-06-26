# Copyright Internet Association of Australia 2018. All rights reserved.
# Copyright Edificom SA. All rights reserved.

# TTP : name of template file within ``{NAPALM_install_dir}/utils/ttp_templates/{template}.txt`` folder

"""
Napalm driver for Extreme EXOS.

Read https://napalm.readthedocs.io for more information.
"""
import logging
import os
import uuid
import tempfile
import jinja2

import copy
import functools
import ipaddress
import os
import re
import socket
import tempfile
import uuid
from collections import defaultdict

from netmiko import FileTransfer, InLineTransfer

import napalm.base.constants as C
import napalm.base.helpers
from napalm.base.base import NetworkDriver
from napalm.base.exceptions import (
    ReplaceConfigException,
    MergeConfigException,
    ConnectionClosedException,
    CommandErrorException,
    CommitConfirmException,
)
from napalm.base.helpers import (
    canonical_interface_name,
    transform_lldp_capab,
    textfsm_extractor,
    ttp_parse,
    split_interface,
    abbreviated_interface_name,
    generate_regex_or,
    sanitize_configs,
)
from napalm.base.netmiko_helpers import netmiko_args


logging.basicConfig()


MINUTE_SECONDS = 60
HOUR_SECONDS = 60 * MINUTE_SECONDS
DAY_SECONDS = 24 * HOUR_SECONDS


class ExosDriver(NetworkDriver):
    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        if optional_args is None:
            optional_args = {}
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout

        self.transport = optional_args.get("transport", "ssh")

        # None will cause autodetection of dest_file_system
        self._dest_file_system = optional_args.get("dest_file_system", None)
        self.auto_rollback_on_error = optional_args.get("auto_rollback_on_error", True)

        self.netmiko_optional_args = netmiko_args(optional_args)

        # Set the default port if not set
        default_port = {"ssh": 22, "telnet": 23}
        self.netmiko_optional_args.setdefault("port", default_port[self.transport])

        self.device = None
        self.config_replace = False

        self.platform = "extreme_exos"
        self.profile = [self.platform]
        self.use_canonical_interface = optional_args.get("canonical_int", False)

    def open(self):
        """Open a connection to the device."""
        device_type = "extreme_exos"
        self.device = self._netmiko_open(
            device_type, netmiko_optional_args=self.netmiko_optional_args
        )

    def _discover_file_system(self):
        try:
            return self.device._autodetect_fs()
        except Exception:
            msg = (
                "Netmiko _autodetect_fs failed (to workaround specify "
                "dest_file_system in optional_args.)"
            )
            raise CommandErrorException(msg)

    def close(self):
        """ Close the connection to the device and do the necessary cleanup."""
        self._netmiko_close()


    def cli(self, commands):
        """ Will execute a list of commands and return the output in a dictionary format."""
        output = {}

        for cmd in commands:
            cmd_output = self.device.send_command(cmd)
            output[cmd] = cmd_output

        return output


    @staticmethod
    def parse_uptime(uptime_str):
        """
        Extract the uptime string from the given Extreme EXOS Device.
        Return the uptime in seconds as an integer
        """
        # Initialize to zero
        (days, hours, minutes) = (0, 0, 0, 0, 0)

        uptime_str = uptime_str.strip()
        time_list = uptime_str.split(",")
        for element in time_list:
            if re.search("days", element):
                days = int(element.split()[0])
            elif re.search("hours", element):
                hours = int(element.split()[0])
            elif re.search("minutes", element):
                minutes = int(element.split()[0])

        uptime_sec = (
            (days * DAY_SECONDS)
            + (hours * HOUR_SECONDS)
            + (minutes * MINUTE_SECONDS)
        )
        return uptime_sec


    def get_config(self, retrieve='all', full=False, sanitized=False):
        """
        Returns the startup or/and running configuration as dictionary.
        The keys of the dictionary represent the type of configuration
        (startup or running). The candidate is always empty string,
        since EXOS does not support candidate configuration.
        """
        configs = {
            'startup': '',
            'running': '',
            'candidate': '',
        }

        run_full = " detail" if full else ""
        command = f"show running-config{run_full}"

        if retrieve in ("running", "all"):
            configs['running'] = self.device.send_command(command).strip()

        if retrieve in ("startup", "all"):
            configs['startup'] = self.device.send_command("debug cfgmgr show configuration file primary").strip()

        if sanitized:
            return sanitize_configs(configs, C.CISCO_SANITIZE_FILTERS)

        return configs

    def get_optics(self, interface=None):
        structured = self._get_and_parse_output(
                        'show ports transceiver information detail'
                     )
        optics = {}

        for item in structured:
            if not item['channel'] or item['channel'] == '1':  # First / only channel
                optics[item['port_number']] = {}
                optics[item['port_number']]['physical_channels'] = {}
                optics[item['port_number']]['physical_channels']['channel'] = []

            channel = {
                "index": int(item['channel']) - 1 if item['channel'] else 0,
                "state": {
                    "input_power": {
                        "instant": float(item['rx_power_dbm'].strip('*').strip('-inf') or '0.0'),
                        "avg": 0.0,
                        "min": 0.0,
                        "max": 0.0
                    },
                    "output_power": {
                        "instant": float(item['tx_power_dbm'].strip('*').strip('-inf') or '0.0'),
                        "avg": 0.0,
                        "min": 0.0,
                        "max": 0.0
                    },
                    "laser_bias_current": {
                        "instant": float(item['tx_current_ma'].strip('*').strip('-inf') or '0.0'),
                        "avg": 0.0,
                        "min": 0.0,
                        "max": 0.0
                    }
                }
            }
            optics[item['port_number']]['physical_channels']['channel'].append(channel)

        return optics

    def get_arp_table(self):
        """
        Returns a list of dictionaries having the following set of keys:
            * interface (string)
            * mac (string)
            * ip (string)
            * age (float)
        """
        arp_table = self._get_and_parse_output(
            'show fdb')
        return arp_table

    def get_bgp_config(self, group=u'', neighbor=u''):
        pass

    def get_bgp_neighbors(self):
        pass

    def get_bgp_neighbors_detail(self, neighbor_address=u''):
        pass

    def get_environment(self):
        """
        Returns a dictionary where:
            * fans is a dictionary of dictionaries where the key is the location and the values:
                 * status (True/False) - True if it's ok, false if it's broken
            * temperature is a dict of dictionaries where the key is the location and the values:
                 * temperature (float) - Temperature in celsius the sensor is reporting.
                 * is_alert (True/False) - True if the temperature is above the alert threshold
                 * is_critical (True/False) - True if the temp is above the critical threshold
            * power is a dictionary of dictionaries where the key is the PSU id and the values:
                 * status (True/False) - True if it's ok, false if it's broken
                 * capacity (float) - Capacity in W that the power supply can support
                 * output (float) - Watts drawn by the system
            * cpu is a dictionary of dictionaries where the key is the ID and the values
                 * %usage
            * memory is a dictionary with:
                 * available_ram (int) - Total amount of RAM installed in the device
                 * used_ram (int) - RAM in use in the device
        """
        system = self._get_and_parse_output(
            'show system')

        power = self._get_and_parse_output(
            'show power detail')

        env = {}

        env.setdefault("fans", {})
        env.setdefault("temperature", {})
        env.setdefault("power", {})
        env.setdefault("cpu", {})
        for slot, denv in system.env.items() :
            env["temperature"][slot]["temperature"] = float(denv.temperature)
            env["temperature"][slot]["is_alert"] = denv.temperature_status != "Normal" and denv.temperature >= denv.temperature_alert
            env["temperature"][slot]["is_critical"] = denv.temperature_status != "Normal" and denv.temperature >= denv.temperature_critical
            env["power"][slot]["status"] = denv.psu_status == 'P'
            env["power"][slot]["capacity"] = float(denv)
            env["power"][slot]["ouput"] = float(denv.power_usage)
            env["cpu"][slot] = denv
            for fan, speed in denv[slot] :
                env["fans"][slot][fan] = bool(speed)

        memory = self._get_and_parse_output(
            'show memory')
        env.setdefault("memory", {})
        used_ram, available_ram = 0
        for slot, mem in memory.items() :
            used_ram += int(mem.used_system)
            used_ram += int(mem.used_user)
            available_ram += int(mem.free)
        env["memory"]["used_ram"] = used_ram
        env["memory"]["available_ram"] = available_ram

        return env

    def get_facts(self):
        """
        Returns a dictionary containing the following information:
         * uptime - Uptime of the device in seconds.
         * vendor - Manufacturer of the device.
         * model - Device model.
         * hostname - Hostname of the device
         * fqdn - Fqdn of the device
         * os_version - String with the OS version running on the device.
         * serial_number - Serial number of the device
         * interface_list - List of the interfaces of the device
        """
        system = self._get_and_parse_output(
            'show system')
        uptime = self.parse_uptime(system.uptime)
        return system

    def get_firewall_policies(self):
        pass

    def get_interfaces(self):
        pass

    def get_interfaces_counters(self):
        pass

    def get_interfaces_ip(self):
        pass

    def get_ipv6_neighbors_table(self):
        pass

    def get_lldp_neighbors(self):
        """
        Returns a dictionary where the keys are local ports and the value is a list of \
        dictionaries with the following information:
            * hostname
            * port
        """
        lldp_neighbors = self._get_and_parse_output(
            'show lldp neighbors')
        return lldp_neighbors

    def get_lldp_neighbors_detail(self, interface=u''):
        """
        Returns a detailed view of the LLDP neighbors as a dictionary
        containing lists of dictionaries for each interface.
        Empty entries are returned as an empty string (e.g. '') or list where applicable.
        Inner dictionaries contain fields:
            * parent_interface (string)
            * remote_port (string)
            * remote_port_description (string)
            * remote_chassis_id (string)
            * remote_system_name (string)
            * remote_system_description (string)
            * remote_system_capab (list) with any of these values
                * other
                * repeater
                * bridge
                * wlan-access-point
                * router
                * telephone
                * docsis-cable-device
                * station
            * remote_system_enabled_capab (list)
        """
        lldp_neighbors_detailed = self._get_and_parse_output(
            'show lldp neighbors')
        return lldp_neighbors_detailed

    def get_mac_address_table(self):
        """
        Returns a lists of dictionaries. Each dictionary represents an entry in the MAC Address
        Table, having the following keys:
            * mac (string)
            * interface (string)
            * vlan (int)
            * active (boolean)
            * static (boolean)
            * moves (int)
            * last_move (float)
        However, please note that not all vendors provide all these details.
        """
        mac_table = self._get_and_parse_output(
            'show fdb')
        return mac_table

    def get_network_instances(self, name=u''):
        pass

    def get_ntp_peers(self):
        pass

    def get_ntp_servers(self):
        pass

    def get_ntp_stats(self):
        pass

    def get_probes_config(self):
        pass

    def get_probes_results(self):
        pass

    def get_route_to(self, destination=u'', protocol=u''):
        pass

    def get_snmp_information(self):
        pass

    def get_users(self):
        pass

    # OSPF
    def get_ospf(self):
        ospf_config = self._get_and_parse_output(
            'show ospf')

        return self._key_textfsm_data(ospf_config, '', override_key='global')

    def get_ospf_interfaces(self):
        ospf_interfaces = self._get_and_parse_output(
            'show ospf interfaces detail')

        return self._key_textfsm_data(ospf_interfaces, 'vlan')

    def get_ospf_neighbors(self):
        ospf_neighbors = self._get_and_parse_output(
            'show ospf neighbor detail')

        return self._key_textfsm_data(ospf_neighbors, 'neighbor')

    # MPLS
    def get_mpls_interfaces(self):
        mpls_interfaces = self._get_and_parse_output(
            'show mpls interface detail')

        return self._key_textfsm_data(mpls_interfaces, 'vlan')

    # MPLS / LDP
    def get_mpls_ldp_peers(self):
        ldp_peers = self._get_and_parse_output(
            'show mpls ldp peer')

        return self._key_textfsm_data(ldp_peers, 'peer')

    # MPLS / RSVP
    def get_mpls_rsvp_neighbors(self):
        rsvp_neighbors = self._get_and_parse_output(
            'show mpls rsvp-te neighbor detail')

        return self._key_textfsm_data(rsvp_neighbors, 'neighbor_addr')

    def get_l2vpn(self, l2vpn_type=None):
        if l2vpn_type is None:
            l2vpn = self._get_and_parse_output('show l2vpn detail')
        elif l2vpn_type == "vpls":
            l2vpn = self._get_and_parse_output('show l2vpn vpls detail')
        elif l2vpn_type == "vpws":
            l2vpn = self._get_and_parse_output('show l2vpn vpws detail')

        return l2vpn

    def get_l2vpn_vpls(self):
        return self.get_l2vpn(l2vpn_type="vpls")

    def get_l2vpn_vpws(self):
        return self.get_l2vpn(l2vpn_type="vpws")

    def get_mpls_l2vpn_summary(self):
        pass

    def ping(self, destination, source=u'', ttl=255,
             timeout=2, size=100, count=5, vrf=u''):
        pass

    def traceroute(self, sdestination, source=u'', ttl=255, timeout=2,
                   vrf=u''):
        pass

    def _get_and_parse_output(self, command):
        output = self.device.send_command(command)
        # TODO: handle file not found, parse error, blank result?
        structured = ttp_parse(cls=self, template=command.replace(' ', '_'), raw_text=output)
        return structured

    def _key_textfsm_data(self, textfsm_data, key, override_key=""):
        data = {}

        for item in textfsm_data:
            new_key = ""
            if override_key:  # nasty hack for reasons
                new_key = override_key
            else:
                new_key = item[key]
                del item[key]
            data[new_key] = item
        return data

    def _create_temp_file(self, content, extension, name=None):
        # create a temp file with option name, defaults to random UUID
        # e.g. _create_temp_file(config, "pol", name="AS6500-POLICY-IN")

        tmp_dir = tempfile.gettempdir()

        if not name:
            rand_fname = str(uuid.uuid4()) + "." + extension
            filename = os.path.join(tmp_dir, rand_fname)
        else:
            filename = os.path.join(tmp_dir, name + "." + extension)

        with open(filename, 'wt') as fobj:
            fobj.write(content)
            fobj.close()

        return filename

    def _transfer_file_scp(self, source_file, destination_file):
        scp_conn = SCPConn(self.device)
        scp_conn.scp_transfer_file(source_file, destination_file)

    def load_merge_candidate(self, filename=None, config=None):
        # SCP config snippet to device.
        if filename and config:
            raise ValueError("Cannot simultaneously set file and config")

        temp_file = self._create_temp_file(config, "xsf")

        self._transfer_file_scp(filename, temp_file)

        output = self.cli(["run script " + temp_file])

        # TODO: Cleanup the random files on the device.

        return bool(output)

    def compare_config(self):
        diff = self.cli(['run script conf_diff'])
        return diff

    def commit_config(self):
        output = self.device.send_command("save\ry\r")
        return " successfully." in output

    def load_policy_template(self, policy_name, template_source, **template_vars):
        # for Extreme:
        # if template_path is None, then it loads to running config. Otherwise it assume an absolute filesystem location.
        # e.g. /usr/local/cfg

        if isinstance(template_source, py23_compat.string_types):
            # Load and render template to string.
            configuration = jinja2.Template(template_source).render(**template_vars)

            policy_file = self._create_temp_file(configuration, "pol", name=policy_name)

            # transfer to device.
            self._transfer_file_scp(policy_file, policy_name + ".pol")

            # Check the policy
            check_command = "check policy " + policy_name
            check_output = self.cli([check_command])

            if "successful" not in check_output[check_command]:
                raise ValueError
            else:
                return configuration
        else:
            raise NotImplementedError
