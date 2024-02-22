import pyshark
from collections import Counter
pcap_file = f'VIT_Hackathon_Sample_Pcaps/challenge.pcapng'
# Initialize counters for protocols and IP addresses
protocol_counter = Counter()
ip_addresses = set()

for packet in pyshark.FileCapture(pcap_file):
    # Count protocols
    protocol_counter.update([packet.highest_layer])
    
    # Collect IP addresses
    if 'IP' in packet:
        ip_addresses.add(packet.ip.src)
        ip_addresses.add(packet.ip.dst)

print("Protocol counts:", protocol_counter)
print("Unique IP addresses:", ip_addresses)
