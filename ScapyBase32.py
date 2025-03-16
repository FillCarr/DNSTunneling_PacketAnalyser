import os
from scapy.config import conf
conf.use_ipv6 = False  # Disable IPv6 features for Scapy

from scapy.all import rdpcap
import base64

# Define the path to the PCAP file
pcap_file = r"C:\Users\StarHopper7\Documents\CIS 547\Project\dns-tunnel-iodine.pcap"

# Check if the file exists
if not os.path.exists(pcap_file):
    print(f"Error: The file '{pcap_file}' does not exist.")
    exit()

# Function to decode Base64 data
def decode_base64(data):
    try:
        return base64.b64decode(data).decode("utf-8", errors="ignore")
    except Exception as e:
        return None  # Return None if decoding fails

# Analyze DNS packets for Base64-encoded data
def analyze_dns_packets(packets):
    total_packets = 0
    dns_packets = 0
    suspicious_packets = 0
    successfully_decoded = 0
    decoded_results = []

    for pkt in packets:
        total_packets += 1
        if pkt.haslayer("DNS"):
            dns_packets += 1
            dns_layer = pkt["DNS"]
            
            # Check if it's a DNS query (qr == 0)
            if dns_layer.qr == 0:
                try:
                    query_name = dns_layer.qd.qname.decode("utf-8", errors="ignore")
                    query_parts = query_name.split(".")
                    
                    for part in query_parts:
                        if len(part) > 8:  # Filter for potentially Base64-encoded parts
                            decoded = decode_base64(part)
                            suspicious_packets += 1
                            if decoded:  # Successfully decoded
                                successfully_decoded += 1
                                decoded_results.append((query_name, part, decoded))
                except Exception as e:
                    print(f"Error processing DNS query: {e}")

    # Calculate success rate
    success_rate = (successfully_decoded / suspicious_packets * 100) if suspicious_packets > 0 else 0

    # Display analysis summary
    print("\n--- Analysis Summary ---")
    print(f"Total packets processed: {total_packets}")
    print(f"DNS packets identified: {dns_packets}")
    print(f"Suspicious packets identified: {suspicious_packets}")
    print(f"Successfully decoded packets: {successfully_decoded}")
    print(f"Decoding success rate: {success_rate:.2f}%")
    print("\nDecoded Results:")
    for result in decoded_results:
        print(f"Query: {result[0]} | Encoded: {result[1]} | Decoded: {result[2]}")

# Load the PCAP file and analyze packets
try:
    print(f"Loading PCAP file: {pcap_file}")
    packets = rdpcap(pcap_file)
    print("PCAP file loaded successfully. Starting analysis...\n")
    analyze_dns_packets(packets)
    print("\nAnalysis complete.")
except Exception as e:
    print(f"Error loading or analyzing PCAP file: {e}")
