from scapy.all import PcapReader

# Specify the path to your large PCAP file
pcap_file = 'VIT_Hackathon_Sample_Pcaps/challenge.pcapng'

# Initialize a counter
packet_count = 0

# Use PcapReader to iterate through the packets efficiently
with PcapReader(pcap_file) as pcap_reader:
    for packet in pcap_reader:
        packet_count += 1

print(f"Total number of packets: {packet_count}")
