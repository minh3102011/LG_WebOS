from scapy.all import *
from scapy.layers.inet6 import IPv6, TCP
import time


# Địa chỉ IPv6 và cổng
destination_ip = "fd53:10:10:5::13"  # Thay đổi thành địa chỉ IPv6 đích của bạn
source_ip = "fd53:10:10:5::23"  # Địa chỉ IPv6 nguồn của bạn
destination_port = 5555  # Cổng đích UDP


# Tạo vòng lặp để gửi payload liên tục
try:
    while True:
        # Nhập payload từ người dùng
        payload = input("Enter the payload to send (TCP data): ").encode()


        # Tạo gói tin TCP
        ip_packet = IPv6(src=source_ip, dst=destination_ip) / \
                    TCP(sport=12345, dport=destination_port) / \
                    Raw(load=payload)


        # Gửi gói tin TCP
        send(ip_packet)
        print(f"Sent TCP packet with payload: {payload.decode()}")


        # Tạm dừng trước khi gửi tiếp
        time.sleep(1)


except KeyboardInterrupt:
    print("Stopped sending packets.")
