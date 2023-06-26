# napalm-exos

[![PyPI](https://img.shields.io/pypi/v/napalm-ruckus-fastiron.svg)](https://pypi.python.org/pypi/napalm-ruckus-fastiron)
[![PyPI](https://img.shields.io/pypi/dm/napalm-ruckus-fastiron.svg)](https://pypi.python.org/pypi/napalm-ruckus-fastiron)

NAPALM (Network Automation and Programmability Abstraction Layer with Multivendor support) is a Python library that implements a set of functions to interact with different router vendor devices using a unified API.

Current methods supported
=======

Configuration Support Matrix
-----------------------------------
- compare_config()
- rollback()

Getters Support Matrix
-----------------------------------
- get_arp_table()
- get_config()
- get_environment()
- get_facts()
- get_interfaces()
- get_interfaces_counters()
- get_interfaces_ip()
- get_lldp_neighbors()
- get_lldp_neighbors_detail()
- get_mac_address_table()
- get_network_instance()
- get_ntp_peers()
- get_ntp_servers()
- get_ntp_stats()
- get_users()
- IsAlive()

Currently Testing
=======
- load_template()
- get_optics()
- get_bgp_congfig()
- get_bgp_neighbors()
- get_bgp_neighbors_detail()
- get_route_to()
- get_snmp information()
- ping()
- tracerroute()

Not implemented
=======
- get_ipv6_neighbors_table

Requirements
=======
- Netmiko v4.1.2
- Extreme EXOS 31.7+

Netmiko methods
=======
- send_config()
- config_mode()
- check_config_mode()
- exit_config_mode()
- enable()
- exit_enable()
- clear_buffer()
- prompt()

Authors
=======
 * IAA-INC Internet Association of Australia [Tim Raphael, author_email="raphael.timothy@gmail.com"]
 * Peter Slopes
 * Edificom SA [Yannis Ansermoz]
