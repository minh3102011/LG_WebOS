from scapy.all import * 

DST_MAC = "FF:FF:FF:FF:FF:FF" 

#IPv4 
SRC_IPv4 = "20.20.20.20" 
DST_IPv4 = "255.255.255.255" 

# Ports 
VALID_SPORT = 13400 
VALID_DPORT = 50021 

pro_type = UDP 

payload = "echo 'Broadcast to everyone!'" 

sendp(Ether(dst=DST_MAC)/IP(src=SRC_IPv4,dst=DST_IPv4)/pro_type(sport=VALID_SPORT, dport=VALID_DPORT)/payload) 