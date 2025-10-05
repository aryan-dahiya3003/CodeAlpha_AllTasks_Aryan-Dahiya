# Basic Network Sniffer using Scapy
from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    print("="*60)
    if IP in packet:
        ip_layer = packet[IP]
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        print(f"Protocol: {ip_layer.proto}")
    if TCP in packet:
        print(f"Source Port: {packet[TCP].sport}")
        print(f"Destination Port: {packet[TCP].dport}")
        print("Protocol Type: TCP")
    elif UDP in packet:
        print(f"Source Port: {packet[UDP].sport}")
        print(f"Destination Port: {packet[UDP].dport}")
        print("Protocol Type: UDP")

print("[*] Starting Packet Capture... Press Ctrl+C to stop.")
sniff(prn=packet_callback, count=10)
