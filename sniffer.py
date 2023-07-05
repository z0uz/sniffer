from scapy.all import *
from scapy.layers.inet import TCP, IP


def packet_callback(packet):
    # Customize your intrusion detection logic here
    if packet[TCP].payload:
        print(f"TCP packet detected: {packet[IP].src} -> {packet[IP].dst}")

def packet_callback(packet):
    if packet.haslayer(IP):
        print(f"TCP packet detected: {packet[IP].src} -> {packet[IP].dst}")
    else:
        print("Packet does not have IP layer")

# Set the network interface you want to monitor
interface = "wlan0"

# Set the BPF filter to capture specific traffic (optional)
bpf_filter = "tcp"

# Start the packet sniffing process
sniff(iface=interface, filter=bpf_filter, prn=packet_callback)
