from scapy.all import sniff, Ether, IPv6, Raw


# Địa chỉ MAC đích cần lọc
DST_MAC = "2c:58:b9:8b:51:f9"
VALID_SPORT = 13400
VALID_DPORT = 13400
# Hàm xử lý gói tin khi sniffed
def packet_handler(pkt):
    # Kiểm tra nếu gói tin có Ethernet và địa chỉ MAC đích trùng khớp
    if Ether in pkt and pkt[Ether].dst == DST_MAC:
        print(f"Packet captured for MAC address {DST_MAC}")
       
        # Kiểm tra nếu gói tin có IPv6
        if IPv6 in pkt:
            ipv6 = pkt[IPv6]
            print(f"Source IPv6: {ipv6.src}, Destination IPv6: {ipv6.dst}")
       
        # Kiểm tra nếu gói tin có Payload (dữ liệu thô)
        if Raw in pkt:
            print(f"Payload: {pkt[Raw].load.decode(errors='ignore')}")
        else:
            print("No Raw payload in this packet.")


# Lắng nghe và lọc các gói tin gửi tới địa chỉ MAC đích
sniff(prn=packet_handler, filter="ether dst " + DST_MAC + " and tcp port " + str(VALID_SPORT) + " and tcp port " + str(VALID_DPORT), store=0)
