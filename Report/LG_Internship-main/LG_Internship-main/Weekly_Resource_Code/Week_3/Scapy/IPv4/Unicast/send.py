from scapy.all import *
from scapy.layers.l2 import Dot1Q
from scapy.layers.inet6 import *
from scapy.layers.inet import TCP


from scapy.all import *


# Cấu hình địa chỉ IP và cổng
source_ip = "10.10.22.131"       # IP nguồn
destination_ip = "10.10.22.107"  # IP đích (Unicast)
port = 5555        


print("Press Ctrl+C to stop sending packets.")
try:
    while True:
        # Nhập payload từ người dùng
        payload = input("Enter the payload to send: ").encode()


        # Tạo gói tin TCP với payload
        tcp_packet = IP(src=source_ip, dst=destination_ip) / TCP(sport=port, dport=port, flags="PA") / Raw(load=payload)


        # Gửi gói tin
        send(tcp_packet)
        print(f"Packet sent to {destination_ip}:{port} with payload: {payload.decode()}")
except KeyboardInterrupt:
    print("Stopped sending packets.")