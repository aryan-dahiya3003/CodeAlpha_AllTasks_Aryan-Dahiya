
from scapy.all import sniff, IP, TCP

suspicious_ips = ["192.168.1.100", "10.0.0.5"]  # Example blacklist

def detect_attack(packet):
    if IP in packet:
        ip_layer = packet[IP]
        if ip_layer.src in suspicious_ips:
            print(f"[ALERT] Suspicious IP Detected: {ip_layer.src}")
        elif packet.haslayer(TCP) and packet[TCP].flags == 2:  # SYN scan
            print(f"[POSSIBLE SCAN] SYN packet from {ip_layer.src}")

print("[*] IDS Running... Monitoring network traffic")
sniff(prn=detect_attack, store=0)
