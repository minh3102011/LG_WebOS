from scapy.all import *
from scapy.layers.inet import UDP
from scapy.layers.inet6 import *
# Cấu hình địa chỉ IP và cổng
source_ip = "10.10.22.107"        # IP nguồn
broadcast_ip = "10.10.22.255"     # Địa chỉ Broadcast của mạng
source_port = 12345               # Cổng nguồn
destination_port = 5555           # Cổng đích (5555)


print("Press Ctrl+C to stop sending packets.")
try:
    while True:
        # Nhập payload từ người dùng
        payload = input("Enter the payload to broadcast: ").encode()


        # Tạo gói tin UDP với địa chỉ Broadcast
        udp_packet = IP(src=source_ip, dst=broadcast_ip) / UDP(sport=source_port, dport=destination_port) / Raw(load=payload)


        # Gửi gói tin UDP
        send(udp_packet)
        print(f"Broadcast UDP packet sent to {broadcast_ip}:{destination_port} with payload: {payload.decode()}")
except KeyboardInterrupt:
    print("Stopped sending packets.")
