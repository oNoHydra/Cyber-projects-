from scapy.all import sniff, wrpcap

def packet_callback(packet):
    print(f"Packet captured: {packet.summary()}")

# Capture 100 packets, filter for TCP, and save to file
packets = sniff(filter="tcp", prn=packet_callback, count=100)
wrpcap('tcp_packets.pcap', packets)
