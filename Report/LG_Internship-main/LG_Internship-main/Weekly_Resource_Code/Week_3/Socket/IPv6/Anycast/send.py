#device_1 send1.py
import socket
MCAST_GRP = 'ff02::1:1:1'
MCAST_PORT = 5007
MULTICAST_TTL = 2
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, MULTICAST_TTL)
sock.sendto("robot", (MCAST_GRP, MCAST_PORT))