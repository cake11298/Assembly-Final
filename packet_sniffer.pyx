#packet_sniffer.pyx
from scapy.all import sniff, IP

def process_packet(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        print(f"Packet: {ip_src} -> {ip_dst}")
        print(packet.show())

sniff(filter="src host <your-ip-address>", prn=process_packet)