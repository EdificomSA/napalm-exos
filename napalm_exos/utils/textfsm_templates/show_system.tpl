Value Hostname (\S+)
Value Domain (\S+)
Value OS_Version (\S+)
Value Uptime (\S+)
Value CPU_Usage (\S+)
Value Memory_Usage (\S+)
Value Model (\S+)
Value Serial_Number (\S+)
Value MAC_Address (\S+)
Value Hardware_Revision (\S+)
Value System_Temperature (\S+)
Value IP_Address (\S+)
Value Subnet_Mask (\S+)
Value Default_Gateway (\S+)
Value DNS_Servers (\S+)

Start
  ^System Information -> System
  ^Hardware Information -> Hardware
  ^Network Information -> Network

System
  ^Hostname:\s+(?P<Hostname>\S+)\s+Domain:\s+(?P<Domain>\S+)
  ^OS Version:\s+(?P<OS_Version>\S+)\s+Uptime:\s+(?P<Uptime>\S+)
  ^CPU Usage:\s+(?P<CPU_Usage>\S+)\s+Memory Usage:\s+(?P<Memory_Usage>\S+)

Hardware
  ^Model:\s+(?P<Model>\S+)\s+Serial Number:\s+(?P<Serial_Number>\S+)
  ^MAC Address:\s+(?P<MAC_Address>\S+)\s+Hardware Revision:\s+(?P<Hardware_Revision>\S+)
  ^System Temperature:\s+(?P<System_Temperature>\S+)

Network
  ^IP Address:\s+(?P<IP_Address>\S+)\s+Subnet Mask:\s+(?P<Subnet_Mask>\S+)
  ^Default Gateway:\s+(?P<Default_Gateway>\S+)\s+DNS Servers:\s+(?P<DNS_Servers>\S+)