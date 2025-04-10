import tkinter as tk
from scapy.all import sniff, IP, TCP, UDP, ICMP
import time
import threading

class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer")
        
        self.text = tk.Text(root)
        self.text.pack()

        self.start_button = tk.Button(root, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack()
        self.stop_button = tk.Button(root, text="Stop Sniffing", command=self.stop_sniffing)
        self.stop_button.pack()

        self.sniffing = False
        self.sniff_thread = None
        
    def packet_callback(self, packet):
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(packet.time))
            if TCP in packet:
                tcp_sport = packet[TCP].sport
                tcp_dport = packet[TCP].dport
                self.text.insert(tk.END, f"{timestamp} | IP {ip_src} -> {ip_dst} | TCP {tcp_sport} -> {tcp_dport}\n")
            elif UDP in packet:
                udp_sport = packet[UDP].sport
                udp_dport = packet[UDP].dport
                self.text.insert(tk.END, = f"{timestamp} | IP {ip_src} -> {ip_dst} | UDP {udp_sport} -> {udp_dport}\n")
            elif ICMP in packet:
                icmp_type = packet[ICMP].type
                icmp_code = packet[ICMP].code
                self.text.insert(tk.END, = f"{timestamp} | IP {ip_src} -> {ip_dst} | ICMP Type {icmp_type} Code {icmp_code}\n")
            self.text.see(tk.END)

    def sniff_packets(self):
        sniff(prn=self.packet_callback, stop_filter=lambda x: not self.sniffing)
            
    def start_sniffing(self):
        if not self.sniffing:
            self.sniffing = True
            self.sniff_thread = threading.Thread(target=self.sniff_packets, daemon=True)
            self.sniff_thread.start()
            self.text.insert(tk.END, "Sniffing started...\n")
            
    def stop_sniffing(self):
        if self.sniffing:
            self.sniffing = False
            self.text.insert(tk.END, "Sniffing stopped...(wait for next packet)\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()
