from scapy.all import *
from scapy.layers.inet6 import IPv6, TCP


# Hàm xử lý gói tin TCP
def packet_handler(packet):
    if TCP in packet and packet[TCP].dport == 5555:  # Lọc các gói TCP đến cổng 5555
        if Raw in packet:
            payload = packet[Raw].load.decode()
            print(f"Received payload from {packet[IPv6].src}:{packet[TCP].sport} -> {packet[IPv6].dst}:{packet[TCP].dport}")
            print(f"Payload: {payload}")


# Lắng nghe các gói tin TCP
def listen_for_tcp():
    print(f"Listening for TCP packets on port 5555...")
    sniff(filter="tcp and dst port 5555", prn=packet_handler, store=0)


listen_for_tcp()