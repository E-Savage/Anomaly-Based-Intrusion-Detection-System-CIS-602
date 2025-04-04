from scapy.all import sniff
import csv
from datetime import datetime

# Configuration
capture_duration = 600  # 10 minutes in seconds
interface = "enp5s0"  # Change this to your network interface (e.g., wlan0 for Wi-Fi)
output_file = "network_data_10min.csv"

# Fields for CSV output
fields = ["timestamp", "src_ip", "dst_ip", "protocol", "length"]

# Open CSV file and write header
with open(output_file, mode='w', newline='') as file:
    writer = csv.DictWriter(file, fieldnames=fields)
    writer.writeheader()

    def process_packet(pkt):
        if pkt.haslayer("IP"):
            row = {
                "timestamp": datetime.now().isoformat(),
                "src_ip": pkt["IP"].src,
                "dst_ip": pkt["IP"].dst,
                "protocol": pkt["IP"].proto,
                "length": len(pkt)
            }
            writer.writerow(row)
            file.flush()  # Write each row immediately

    print(f"[*] Capturing for {capture_duration} seconds on {interface}...")
    sniff(iface=interface, prn=process_packet, timeout=capture_duration, store=False)

print(f"[+] Capture complete. Data saved to {output_file}")

