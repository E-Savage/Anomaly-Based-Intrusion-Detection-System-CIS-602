from scapy.all import sniff, IP
import pandas as pd
import pickle
import ipaddress
from datetime import datetime

# === Load your trained model ===
with open('ids_isolation_forest.pkl', 'rb') as f:
    model = pickle.load(f)

# === IP to integer ===
def ip_to_int(ip_address):
    try:
        return int(ipaddress.ip_address(ip_address))
    except ValueError:
        return 0  # fallback

# === Detection Function ===
def process_packet(pkt):
    if IP in pkt:
        src_ip = ip_to_int(pkt[IP].src)
        dst_ip = ip_to_int(pkt[IP].dst)
        proto = pkt[IP].proto
        length = len(pkt)

        features = pd.DataFrame([{
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'protocol': proto,
            'length': length
        }])

        prediction = model.predict(features)[0]
        score = model.decision_function(features)[0]

        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        label = 'ATTACK DETECTED' if prediction == -1 else 'NORMAL'

        # Print alert
        if prediction == -1:
            print(f"{timestamp} | {label} | {pkt[IP].src} → {pkt[IP].dst} | proto={proto}, len={length} | score={score:.4f}")
        else:
            print(f"{timestamp} | NORMAL | {pkt[IP].src} → {pkt[IP].dst} | proto={proto}, len={length} | score={score:.4f}")

        # Optional logging of attacks
        with open("live_attack_log.csv", "a") as f:
            f.write(f"{timestamp},{pkt[IP].src},{pkt[IP].dst},{proto},{length},{score:.4f},{label}\n")

# === Sniff Interface ===
print("🛡️ Starting live attack detection... Press Ctrl+C to stop.")
sniff(iface="enp5s0", prn=process_packet, store=False)
