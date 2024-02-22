import pyshark
import re

# Define regex patterns for username and password
username_pattern = re.compile(r'\buser(name)?\b[:=]\s*(\S+)', re.IGNORECASE)
password_pattern = re.compile(r'\bpass(word)?\b[:=]\s*(\S+)', re.IGNORECASE)

# Path to your PCAP file
pcap_file = 'VIT_Hackathon_Sample_Pcaps/challenge.pcapng'

def analyze_packet(packet):
    # Iterate through all layers of the packet
    for layer in packet.layers:
        # Attempt to access layer's fields if it has the attribute
        if hasattr(layer, '_all_fields'):
            for field_name, field_value in layer._all_fields.items():
                field_value_str = str(field_value)
                # Apply regex patterns to each field value
                username_match = username_pattern.search(field_value_str)
                password_match = password_pattern.search(field_value_str)

                if username_match:
                    print(f'Username detected: {username_match.group()} in layer {layer.layer_name}')
                if password_match:
                    print(f'Password detected: {password_match.group()} in layer {layer.layer_name}')

# Load the PCAP file and analyze each packet
capture = pyshark.FileCapture(pcap_file, keep_packets=True)

for packet in capture:
    analyze_packet(packet)

capture.close()
