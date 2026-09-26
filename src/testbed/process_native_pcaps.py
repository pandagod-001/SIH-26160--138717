import glob
import os
import json
import pandas as pd
from scapy.all import rdpcap, IP, ESP
import numpy as np

def validate_pcap(pcap_path):
    if not os.path.exists(pcap_path) or os.path.getsize(pcap_path) < 100:
        return "INVALID", "File missing or empty"
    try:
        pkts = rdpcap(pcap_path)
        if len(pkts) == 0:
            return "INVALID", "Zero packets captured"
        esp_count = sum(1 for p in pkts if p.haslayer(ESP) or (p.haslayer(IP) and p[IP].proto == 50))
        if esp_count == 0:
            return "PARTIAL", "No ESP layer detected"
        return "VALID", f"{len(pkts)} pkts, {esp_count} ESP pkts"
    except Exception as e:
        return "INVALID", f"PCAP parse error: {str(e)}"

def extract_window_features(pcap_path, exp_id, sess_id, traffic_class, env_id, window_sec=2.0):
    try:
        pkts = rdpcap(pcap_path)
    except Exception:
        return []
    if not pkts:
        return []

    timestamps = [float(p.time) for p in pkts]
    min_t = min(timestamps)
    max_t = max(timestamps)
    total_duration = max_t - min_t
    if total_duration <= 0:
        return []

    windows = []
    num_windows = int(np.ceil(total_duration / window_sec))
    for w_idx in range(num_windows):
        w_start = min_t + w_idx * window_sec
        w_end = w_start + window_sec
        w_pkts = [p for p in pkts if w_start <= float(p.time) < w_end]
        if not w_pkts:
            continue
        w_times = [float(p.time) for p in w_pkts]
        w_sizes = [len(p) for p in w_pkts]
        duration = max(max(w_times) - min(w_times), 1e-6)
        pkt_count = len(w_pkts)
        byte_count = sum(w_sizes)
        pps = pkt_count / duration
        bps = byte_count / duration
        if pkt_count > 1:
            iats = np.diff(sorted(w_times))
            mean_iat = float(np.mean(iats))
            std_iat = float(np.std(iats))
        else:
            mean_iat = 0.0
            std_iat = 0.0
        windows.append({
            "sample_id": f"NAT_{exp_id}_{sess_id}_W{w_idx:03d}",
            "dataset_source": "DS1_NATIVE_IPSEC_LARGE",
            "provenance_tier": 1,
            "experiment_id": exp_id,
            "experiment_group": f"GRP_{exp_id}_{sess_id}",
            "session_id": sess_id,
            "window_id": w_idx,
            "traffic_class": traffic_class,
            "environment_id": env_id,
            "flow_duration_sec": round(duration, 6),
            "packets_per_sec": round(pps, 4),
            "bytes_per_sec": round(bps, 4),
            "mean_iat_sec": round(mean_iat, 6),
            "std_iat_sec": round(std_iat, 6),
            "mean_packet_size_bytes": round(float(np.mean(w_sizes)), 2),
            "std_packet_size_bytes": round(float(np.std(w_sizes)), 2),
            "min_packet_size_bytes": float(np.min(w_sizes)),
            "max_packet_size_bytes": float(np.max(w_sizes)),
            "pcap_source": os.path.basename(pcap_path)
        })
    return windows

def main():
    pcaps = sorted(glob.glob("data/raw_native_ipsec/pcaps/*.pcap"))
    print(f"Found {len(pcaps)} raw native IPsec pcaps on disk.")
    all_windows = []
    val_counts = {"VALID": 0, "INVALID": 0, "PARTIAL": 0}

    for p in pcaps:
        base = os.path.basename(p).replace(".pcap", "")
        parts = base.split("_")
        t_cls = parts[1]
        env_id = parts[2] + "_" + parts[3]
        sess_id = parts[4] + "_" + parts[5]
        exp_id = f"EXP_{t_cls}_{env_id}"
        
        status, msg = validate_pcap(p)
        val_counts[status] = val_counts.get(status, 0) + 1
        if status == "VALID":
            w = extract_window_features(p, exp_id, sess_id, t_cls, env_id, window_sec=2.0)
            all_windows.extend(w)

    df = pd.DataFrame(all_windows)
    print(f"Validation summary: {val_counts}")
    print(f"Total extracted native IPsec window samples: {len(df)}")
    if len(df) > 0:
        print(df['traffic_class'].value_counts())
        print(f"Unique session groups: {df['experiment_group'].nunique()}")
        os.makedirs("data/processed", exist_ok=True)
        df.to_csv("data/processed/native_ipsec_large_dataset.csv", index=False)
        print("Saved to data/processed/native_ipsec_large_dataset.csv")

if __name__ == "__main__":
    main()
