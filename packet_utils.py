from scapy.all import sniff, IP
import numpy as np
from datetime import datetime
import pandas as pd

def calculate_entropy(packet_sizes):
    _, counts = np.unique(packet_sizes, return_counts=True)
    probs = counts / counts.sum()
    return -np.sum(probs * np.log2(probs))

def start_capture(interface="Wi-Fi", timeout=30):
    """Captures packets and calculates metrics"""
    packets = []
    
    def handler(pkt):
        if IP in pkt:
            packets.append({
                "time": datetime.now().strftime("%H:%M:%S.%f"),
                "source": pkt[IP].src,
                "destination": pkt[IP].dst,
                "size": len(pkt),
                "protocol": pkt.sport if pkt.haslayer("TCP") else "Other"
            })
    
    sniff(iface=interface, prn=handler, store=0, timeout=timeout)
    df = pd.DataFrame(packets)
    
    # Anomaly detection
    df['is_anomaly'] = df['size'] > 1500  # Simple threshold
    return df