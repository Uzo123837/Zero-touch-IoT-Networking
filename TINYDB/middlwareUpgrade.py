from scapy.all import rdpcap, IP, IPv6, Ether, Dot15d4
from tinydb import TinyDB, Query
from scapy.all import conf
import os

# Set the protocol to SixLoWPAN
conf.dot15d4_protocol = 'sixlowpan'

# Initialize TinyDB
db = TinyDB('pcap_data.json')

# Function to create a table name based on the PCAP file name
def get_table_name(pcap_file):
    return os.path.splitext(os.path.basename(pcap_file))[0]

# Parse the PCAP file
pcap_file = '1Server5Attack.pcap'
packets = rdpcap(pcap_file)

# Create a new table for the PCAP file
table_name = get_table_name(pcap_file)
table = db.table(table_name)

# Iterate over each packet in the PCAP file
for packet in packets:
    # Initialize packet_data dictionary
    packet_data = {
        'time': float(packet.time),  # Timestamp
        'source': None,
        'destination': None,
        'protocol': None,
        'length': len(packet),  # Packet length
        'info': None
    }
    
    # Check for IPv6 layer
    if packet.haslayer(IPv6):
        packet_data['source'] = packet[IPv6].src  # Source IPv6 address
        packet_data['destination'] = packet[IPv6].dst  # Destination IPv6 address
        packet_data['protocol'] = packet[IPv6].name  # Protocol name
        packet_data['info'] = packet[IPv6].summary()  # Summary info

    # Check for IP layer (IPv4)
    elif packet.haslayer(IP):
        packet_data['source'] = packet[IP].src  # Source IP address
        packet_data['destination'] = packet[IP].dst  # Destination IP address
        packet_data['protocol'] = packet[IP].name  # Protocol name
        packet_data['info'] = packet[IP].summary()  # Summary info

    # Check for 802.15.4 layer (used in IoT networks)
    elif packet.haslayer(Dot15d4):
        packet_data['protocol'] = "IEEE 802.15.4"  # Protocol name
        packet_data['info'] = packet.summary()  # Summary info

    # Check for Ethernet layer
    elif packet.haslayer(Ether):
        packet_data['source'] = packet[Ether].src  # Source MAC address
        packet_data['destination'] = packet[Ether].dst  # Destination MAC address
        packet_data['protocol'] = "Ethernet"  # Protocol name
        packet_data['info'] = packet.summary()  # Summary info

    # Insert the packet data into the TinyDB table
    table.insert(packet_data)

# Optional: Query example
Packet = Query()
results = table.search(Packet.source == 'fe80::212:7401:1:101')
print(results)
