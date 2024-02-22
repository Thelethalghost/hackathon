import pyshark

# Create a live capture instance
capture = pyshark.LiveCapture(interface='eno1')

# Capture packets in real-time and print basic details
for packet in capture.sniff_continuously(packet_count=10):
    print(f'Packet: {packet}')
