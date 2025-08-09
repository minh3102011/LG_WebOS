import socket


# Cấu hình
HOST = '10.10.22.131'  # Lắng nghe trên tất cả các giao diện mạng
PORT = 12345


# Tạo socket
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    s.bind((HOST, PORT))
    print("Listening for unicast messages...")
    while True:
        data, addr = s.recvfrom(1024)
        print(f"Received: {data.decode()} from {addr}")