from scapy.all import sniff, IP, TCP

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        if TCP in packet:
            tcp_sport = packet[TCP].sport
            tcp_dport = packet[TCP].dport
            print(f"IP {ip_src} -> {ip_dst} | TCP {tcp_sport} -> {tcp_dport}")

# Capture packets
sniff(prn=packet_callback, count=10)