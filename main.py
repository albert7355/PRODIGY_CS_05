from scapy.all import sniff, IP, TCP, UDP, ICMP

def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto

        proto_name = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(proto, "Other")

        print(f"[{proto_name}] {src_ip} -> {dst_ip}")

        if packet.haslayer(TCP) or packet.haslayer(UDP):
            payload = bytes(packet[proto_name].payload)
            print(f"Payload: {payload[:50]}...\n")  # Print first 50 bytes for readability

print("Starting packet capture... Press Ctrl+C to stop.")
sniff(filter="ip", prn=process_packet, store=0)
