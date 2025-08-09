import socket


# Cấu hình
BROADCAST_IP = '10.10.22.255'  # Địa chỉ broadcast của subnet
PORT = 12345                   # Cổng giao tiếp


# Tạo socket
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)  # Kích hoạt chế độ broadcast
   
    while True:
        message = input("Enter your broadcast message (or 'exit' to quit): ")
        if message.lower() == 'exit':
            print("Exiting...")
            break
       
        s.sendto(message.encode(), (BROADCAST_IP, PORT))
        print(f"Broadcasted: {message}")


