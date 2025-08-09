from scapy.all import *
from scapy.layers.l2 import Dot1Q
from scapy.layers.inet6 import *
from scapy.layers.inet import TCP


# Địa chỉ IPv6 và VLAN ID
SRC_MAC = "78:2B:46:4F:DD:AF"
# DST_MAC = "D8:3A:DD:A4:C3:8F"  # MAC WebOS
# DST_MAC = "30:13:8B:72:19:D0" # MAC Win Cuong
DST_MAC = "2C:58:B9:8B:51:F9" # MAC Win Manh
VALID_SRC_IPv6 = "fd53:10:10:5::23"
VALID_DST_IPv6 = "fd53:10:10:5::55"
VALID_SPORT = 13400
VALID_DPORT = 13400
payload_default = "Hello World"


# Tạo gói tin gửi
PKT_Default_Send = (
    Ether(src=SRC_MAC, dst=DST_MAC) /  # Địa chỉ MAC nguồn và đích
    IPv6(src=VALID_SRC_IPv6, dst=VALID_DST_IPv6) /  # Địa chỉ IPv6 nguồn và đích
    TCP(sport=VALID_SPORT, dport=VALID_DPORT) /  # Cổng nguồn và đích
    payload_default  # Payload
)


# Gửi gói tin
sendp(PKT_Default_Send)
