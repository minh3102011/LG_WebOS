import socket


# Địa chỉ IPv6 và cổng
SERVER_ADDR = ('fe80::da3a:ddff:fea4:bfbe', 12345)  # Địa chỉ loopback IPv6 (localhost)
BUFFER_SIZE = 1024


# Tạo một socket IPv6
sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)


# Gửi thông điệp
message = 'Hello, Unicast IPv6!'
sock.sendto(message.encode(), SERVER_ADDR)


# Đóng socket
sock.close()