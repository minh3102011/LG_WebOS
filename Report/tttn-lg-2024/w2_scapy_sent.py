from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.inet6 import *

# MAC Address
SRC_MAC = "00:11:22:33:44:55"   #fill your MAC Address here
DST_MAC = "ff:ff:ff:ff:ff:ff" #fill the destination MAC

# VLAN
VLAN_ID = 0
dot1q = Dot1Q(vlan=VLAN_ID)

# IPv6
VALID_SRC_IPv6 = "abcd:1111::a123"
VALID_DST_IPv6 = "fd53:abcd:5678:5::15"

#IPv4
SRC_IPv4 = "20.10.23.23"
DST_IPv4 = "10.10.22.131"

# Ports
VALID_SPORT = 13400     
VALID_DPORT = 13400
pro_type = TCP

# Payload (bash)
payload ="echo 'hello world!'"

# PKT_IPv4_Send = Ether()/dot1q/IP(src=SRC_IPv4,
# dst=DST_IPv4)/pro_type(sport=VALID_SPORT, dport=VALID_DPORT)/payload_default
PKT_Default_Send = Ether()/dot1q/IPv6(dst=VALID_DST_IPv6,
src=VALID_SRC_IPv6)/pro_type(dport=VALID_DPORT, sport=VALID_SPORT)/payload

sendp(PKT_Default_Send)
# sendp(PKT_IPv4_Send)
