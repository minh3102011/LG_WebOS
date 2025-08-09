import socket


# Địa chỉ và cổng máy chủ
SERVER_ADDR = ('::', 12345)  # Nghe t?t c? các đ?a ch? IPv6
BUFFER_SIZE = 1024


# Tạo một socket IPv6
sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)


# Liên kết với địa chỉ và cổng
sock.bind(SERVER_ADDR)


# Nhận thông điệp
data, addr = sock.recvfrom(BUFFER_SIZE)
print(f"Received: {data.decode()} from {addr}")


# Đóng socket
sock.close()