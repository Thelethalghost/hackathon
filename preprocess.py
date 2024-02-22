import pyshark
list_pcap=['1.pcap', '2.pcap', '3.pcap','4.pcap', '5.pcap', '6.pcap', '7.pcap']
# Path to your PCAP file
Name_pcap= input("Enter the name of the pcap file u want to analyze: ")
pcap_file = f'VIT_Hackathon_Sample_Pcaps/{Name_pcap}'

# Load the PCAP file
capture = pyshark.FileCapture(pcap_file)

# Preprocessing example: Filter by protocol and extract specific fields
for packet in capture:
    try:
        # Example: Extract HTTP request method and URI
        if 'HTTP' in packet:
            http_layer = packet['http']
            method = http_layer.get('request_method', None)
            uri = http_layer.get('request_uri', None)
            print(f'HTTP Method: {method}, URI: {uri}')
        
        # Example: Extract source and destination IP addresses for TCP packets
        if 'IP' in packet and 'TCP' in packet:
            ip_layer = packet['ip']
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            print(f'Source IP: {src_ip}, Destination IP: {dst_ip}')

    except AttributeError as e:
        # This error might occur if a packet does not have the expected layers or fields
        continue
