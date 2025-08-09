from scapy.all import *
from scapy.layers.inet6 import *
from scapy.layers.inet import TCP


# Hàm xử lý gói tin TCP
def packet_handler(packet):
    if TCP in packet and packet[TCP].dport == 5555:  # Lọc gói TCP đến cổng 5555
        if Raw in packet:
            payload = packet[Raw].load.decode()
            print(f"Received payload from {packet[IP].src}:{packet[TCP].sport} -> {packet[IP].dst}:{packet[TCP].dport}")
            print(f"Payload: {payload}")


print("Listening for incoming TCP packets on port 5555...")
# Lắng nghe gói tin TCP
sniff(filter="tcp", prn=packet_handler)
