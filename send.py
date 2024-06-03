# send.py
import socket
from scapy.all import sniff, IP
import requests

target_ip = "140.115.220.161"
target_port = 5050

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def process_packet(packet):
    global ith
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        message = f"Packet: {ip_src} -> {ip_dst}\n{packet.show(dump=True)}"
        sock.sendto(message.encode(), (target_ip, target_port))
        print(f"{ith}'s packet has sent.")
        ith += 1

ith = 1
sniff(filter=f"src host <your-ip-address>", prn=process_packet)