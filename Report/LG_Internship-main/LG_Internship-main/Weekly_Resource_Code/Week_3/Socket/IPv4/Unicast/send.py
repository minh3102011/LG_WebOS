import socket


# Cấu hình
HOST = '10.10.22.131'  # Địa chỉ IP của máy nhận
PORT = 12345          # Cổng giao tiếp


# Tạo socket
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    while True:
        # Nhập thông điệp từ người dùng
        message = input("Enter your message (or 'exit' to quit): ")


        # Kiểm tra nếu người dùng muốn thoát
        if message.lower() == 'exit':
            print("Exiting...")
            break


        # Gửi thông điệp
        s.sendto(message.encode(), (HOST, PORT))
        print(f"Sent: {message}")
