from scapy.all import *

# Define a callback function to process packets
def packet_callback(packet):
    if packet.haslayer(IP):
        # Extract source and destination IP addresses
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        print(f"Source IP: {src_ip} --> Destination IP: {dst_ip}")

# Start sniffing on the default interface
print("Starting packet capture...")
sniff(prn=packet_callback, store=0)
