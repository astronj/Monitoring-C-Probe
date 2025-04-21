from scapy.all import *
import socket

# Try to resolve IP to hostname
def resolve_ip(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return ip

# Analyze each captured packet
def packet_callback(packet):
    print("\n=== New Packet ===")

    # Ethernet Layer
    if packet.haslayer(Ether):
        eth = packet[Ether]
        print(f"MAC: {eth.src} -> {eth.dst}")

    # IP Layer
    if packet.haslayer(IP):
        ip = packet[IP]
        src_host = resolve_ip(ip.src)
        dst_host = resolve_ip(ip.dst)
        print(f"IP: {ip.src} ({src_host}) -> {ip.dst} ({dst_host}) | Protocol: {ip.proto}")

    # TCP Layer
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        print(f"TCP Port: {tcp.sport} -> {tcp.dport}")

    # UDP Layer
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        print(f"UDP Port: {udp.sport} -> {udp.dport}")

    # ICMP Layer
    if packet.haslayer(ICMP):
        print("ICMP packet detected")

    # DNS Queries
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        dns = packet[DNSQR]
        print(f"DNS Query: {dns.qname.decode(errors='ignore')}")

# Start sniffing packets
print("Starting detailed packet capture... Press Ctrl+C to stop.\n")
sniff(prn=packet_callback, store=0)
