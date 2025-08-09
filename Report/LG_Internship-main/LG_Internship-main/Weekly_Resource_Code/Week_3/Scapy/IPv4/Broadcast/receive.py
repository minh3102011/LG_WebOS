from scapy.all import *
from scapy.layers.inet import UDP
from scapy.layers.inet6 import *
# Hàm xử lý gói tin UDP
def packet_handler(packet):
    if UDP in packet and packet[UDP].dport == 5555:  # Lọc gói UDP đến cổng 5555
        if Raw in packet:
            payload = packet[Raw].load.decode()
            print(f"Received payload from {packet[IP].src}:{packet[UDP].sport} -> {packet[IP].dst}:{packet[UDP].dport}")
            print(f"Payload: {payload}")


print("Listening for incoming UDP packets on port 5555...")
# Lắng nghe gói tin UDP
sniff(filter="udp", prn=packet_handler)
