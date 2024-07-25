from scapy.all import sniff, TCP

def packet_callback(packet):
    if packet.haslayer('IP'):
        ip_layer = packet.getlayer('IP')
        print(f"Source: {ip_layer.src} -> Destination: {ip_layer.dst}")
    if packet.haslayer('TCP'):
        tcp_layer = packet.getlayer('TCP')
        print(f"Source Port: {tcp_layer.sport} -> Destination Port: {tcp_layer.dport}")

# Start sniffing with a filter for IP packets
sniff(filter="ip", prn=packet_callback, count=20)
