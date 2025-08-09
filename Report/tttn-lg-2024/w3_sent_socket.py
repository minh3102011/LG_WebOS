import socket

with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:     
        s.sendto(b"Anycast to abcd:1234::5", ("abcd:1234::5", 7843))


# import socket
# print("Waiting for a message...")

# while True:
#         with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
#             s.bind(("::", 23232))            

#             data, addr = s.recvfrom(1024)
#             print(f"Received message: {data.decode()} from {addr}")


# import socket
# import struct
# MCAST_GRP = 'ff02::12:1:1'
# MCAST_PORT = 23232

# sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
# sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

# sock.bind(('', MCAST_PORT))

# mreq = struct.pack("16sI", socket.inet_pton(socket.AF_INET6,MCAST_GRP), 0)
# sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)

# while True:
#         print(sock.recv(10240))
