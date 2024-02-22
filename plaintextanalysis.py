import pyshark

# Path to your PCAP file
pcap_file = 'VIT_Hackathon_Sample_Pcaps/4.pcap'

# Load the PCAP file
capture = pyshark.FileCapture(pcap_file)

def check_http(packet):
    if 'HTTP' in packet:
        try:
            if 'authorization' in packet.http.field_names:
                print(f'Possible plaintext password found in HTTP Authorization header: {packet.http.authorization}')
            if packet.http.request_method == 'POST':
                print(f'Possible plaintext password found in HTTP POST: {packet}')
        except AttributeError:
            pass

def check_ftp(packet):
    if 'FTP' in packet:
        try:
            if packet.ftp.request_command in ['PASS', 'USER']:
                print(f'Possible plaintext password found in FTP command: {packet.ftp.request_arg}')
        except AttributeError:
            pass

for packet in capture:
    check_http(packet)
    check_ftp(packet)

capture.close()
