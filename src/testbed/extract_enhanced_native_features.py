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

def extract_advanced_features(pcap_path, exp_id, sess_id, traffic_class, env_id, window_sec=3.0, stride_sec=0.5):
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

    windows = []
    w_idx = 0
    cur_start = min_t
    
    # If duration is shorter than window, process as one full window
    if total_duration < window_sec:
        window_sec_eff = max(total_duration, 1e-4)
    else:
        window_sec_eff = window_sec

    while cur_start + window_sec_eff <= max_t + 1e-4 or (w_idx == 0 and len(windows) == 0):
        cur_end = cur_start + window_sec_eff
        w_pkts = [p for p in pkts if cur_start <= float(p.time) <= cur_end]
        if w_pkts:
            w_times = [float(p.time) for p in w_pkts]
            w_sizes = [len(p) for p in w_pkts]
            duration = max(max(w_times) - min(w_times), 1e-6)
            pkt_count = len(w_pkts)
            byte_count = sum(w_sizes)
            pps = pkt_count / duration
            bps = byte_count / duration
            
            # Directional analysis (by source IP inside IP layer)
            src_ips = [p[IP].src if p.haslayer(IP) else "unknown" for p in w_pkts]
            unique_ips = list(set(src_ips))
            if len(unique_ips) >= 2:
                client_ip = unique_ips[0]
                fwd_pkts = [s for s, ip in zip(w_sizes, src_ips) if ip == client_ip]
                bwd_pkts = [s for s, ip in zip(w_sizes, src_ips) if ip != client_ip]
                fwd_bytes = sum(fwd_pkts)
                bwd_bytes = sum(bwd_pkts)
                dir_ratio = fwd_bytes / max(bwd_bytes, 1.0)
            else:
                dir_ratio = 1.0
                fwd_bytes = byte_count
                bwd_bytes = 0

            # Quantiles of packet length
            p25 = float(np.percentile(w_sizes, 25))
            p50 = float(np.percentile(w_sizes, 50))
            p75 = float(np.percentile(w_sizes, 75))
            p90 = float(np.percentile(w_sizes, 90))

            if pkt_count > 1:
                iats = np.diff(sorted(w_times))
                mean_iat = float(np.mean(iats))
                std_iat = float(np.std(iats))
            else:
                mean_iat = 0.0
                std_iat = 0.0

            windows.append({
                "sample_id": f"NAT_ENH_{exp_id}_{sess_id}_W{w_idx:04d}",
                "dataset_source": "DS1_NATIVE_IPSEC_ENHANCED",
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
                "pkt_len_p25": p25,
                "pkt_len_p50": p50,
                "pkt_len_p75": p75,
                "pkt_len_p90": p90,
                "directional_byte_ratio": round(dir_ratio, 4),
                "pcap_source": os.path.basename(pcap_path)
            })
            w_idx += 1
        cur_start += stride_sec
        if total_duration < window_sec:
            break

    return windows

def main():
    pcaps = sorted(glob.glob("data/raw_native_ipsec/pcaps/*.pcap"))
    print(f"Extracting advanced engineered features from {len(pcaps)} raw PCAPs...")
    all_windows = []

    for p in pcaps:
        base = os.path.basename(p).replace(".pcap", "")
        parts = base.split("_")
        t_cls = parts[1]
        env_id = parts[2] + "_" + parts[3]
        sess_id = parts[4] + "_" + parts[5]
        exp_id = f"EXP_{t_cls}_{env_id}"
        
        status, msg = validate_pcap(p)
        if status == "VALID":
            w = extract_advanced_features(p, exp_id, sess_id, t_cls, env_id, window_sec=3.0, stride_sec=0.5)
            all_windows.extend(w)

    df = pd.DataFrame(all_windows)
    print(f"Total Enhanced Native IPsec Samples Extracted: {len(df)}")
    print("Class Distribution:")
    print(df['traffic_class'].value_counts())
    
    out_csv = "data/processed/native_ipsec_enhanced_dataset.csv"
    df.to_csv(out_csv, index=False)
    print(f"Saved enhanced feature dataset to: {out_csv}")

if __name__ == "__main__":
    main()
