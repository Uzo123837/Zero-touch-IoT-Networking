from scapy.all import rdpcap, conf
import influxdb_client
from influxdb_client import InfluxDBClient, Point, WriteOptions, WritePrecision
import time

# Initialize InfluxDB client
token = "2v78eSanq2MmixEKBZSm9PnZTcKuhglpgrf-WCCtQ7UM9DK8tN4ONX6YUOeJmGGB8c0xKPCwe2FH_b7ZztluSg=="
org = "IotProject"
url = "http://localhost:8086"
bucket = "RadioLogs"
client = InfluxDBClient(url=url, token=token, org=org)
write_api = client.write_api(write_options=WriteOptions(batch_size=1, flush_interval=1000, jitter_interval=0, retry_interval=5000))

# Set the protocol to SixLoWPAN or ZigBee based on your needs
conf.dot15d4_protocol = "sixlowpan"

# Read the PCAP file
packets = rdpcap("radio_logs.pcap")

for packet in packets:
    try:
        # Extract relevant data from the packet
        timestamp = int(packet.time * 1e9)  # Convert to nanoseconds
        src_ip = packet.getlayer("IP").src if packet.haslayer("IP") else None
        dst_ip = packet.getlayer("IP").dst if packet.haslayer("IP") else None
        protocol = packet.getlayer("IP").proto if packet.haslayer("IP") else None
        packet_len = len(packet)

        # Create a data point
        point = (
            Point("network_traffic")
            .tag("src_ip", src_ip if src_ip else "N/A")
            .tag("dst_ip", dst_ip if dst_ip else "N/A")
            .field("protocol", protocol if protocol else "N/A")
            .field("packet_len", packet_len)
            .time(timestamp, WritePrecision.NS)  # Use nanosecond precision
        )
        
        # Write the data point to InfluxDB
        write_api.write(bucket=bucket, org=org, record=point)
    except Exception as e:
        print(f"Failed to process packet: {e}")

write_api.__del__()  # Ensure everything is flushed

print("PCAP file data has been imported to InfluxDB.")
