import socket


# Cấu hình
HOST = '0.0.0.0'  # Lắng nghe trên tất cả các giao diện mạng
PORT = 12345       # Cổng giao tiếp


# Tạo socket
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    s.bind((HOST, PORT))  # Gắn socket vào địa chỉ và cổng
    print(f"Listening for broadcast messages on port {PORT}...")
   
    while True:
        data, addr = s.recvfrom(1024)  # Giới hạn kích thước gói tin
        print(f"Received: {data.decode()} from {addr}")