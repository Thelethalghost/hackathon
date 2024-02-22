from scapy.all import rdpcap
import json

# Specify the path to your PCAP file
pcap_file = 'VIT_Hackathon_Sample_Pcaps/4.pcap'

# Read the PCAP file
packets = rdpcap(pcap_file)

# Initialize a list to hold packet data
packets_data = []

# Iterate over each packet to extract information
for packet in packets:
    # Extracting only a few fields for demonstration purposes
    packet_info = {
        'src': packet.src,
        'dst': packet.dst,
        'len': len(packet),
        'payload': str(packet.payload)
    }
    packets_data.append(packet_info)

# Convert the list of packet data to JSON
packets_json = json.dumps(packets_data, indent=4)

# Optionally, save the JSON data to a file
with open('packets.json', 'w') as json_file:
    json_file.write(packets_json)

print("PCAP has been converted to JSON and saved as packets.json")
