from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime

def packet_callback(packet):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"[{timestamp}]")
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        if protocol == 6:  # TCP
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print(f"TCP Packet - Src: {ip_src}:{src_port} -> Dst: {ip_dst}:{dst_port}")
        elif protocol == 17:  # UDP
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"UDP Packet - Src: {ip_src}:{src_port} -> Dst: {ip_dst}:{dst_port}")
        elif protocol == 1:  # ICMP
            print(f"ICMP Packet - Src: {ip_src} -> Dst: {ip_dst}")
        else:
            print(f"Unknown Protocol - Src: {ip_src} -> Dst: {ip_dst}")

        if packet.haslayer(Raw):
            payload = packet[Raw].load
            print(f"Payload: {payload.decode('utf-8', errors='ignore')}")

# Start sniffing on the default interface
sniff(prn=packet_callback, store=0)