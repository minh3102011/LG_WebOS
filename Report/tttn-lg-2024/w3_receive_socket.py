import socket
print("Waiting for a message...")

while True:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
            s.bind(("::", 23232))            

            data, addr = s.recvfrom(1024)
            print(f"Received message: {data.decode()} from {addr}")