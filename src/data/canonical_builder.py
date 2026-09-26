"""
canonical_builder.py — IPsecTrace Phase 2 Canonical Dataset Builder
Merges Tier 1 (Custom IPsec testbed flows) and Tier 2 (ISCX VPN Scenario B)
into a unified canonical dataset: data/processed/canonical_vpn_dataset.csv
Also generates data/processed/dataset_manifest.json with full provenance.
"""
import os
import json
import glob
import re
import numpy as np
import pandas as pd

def parse_arff(filepath):
    attributes = []
    label_col = None
    label_values = []
    data_rows = []
    in_data = False

    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("%"):
                continue
            upper = line.upper()
            if upper.startswith("@RELATION"):
                continue
            elif upper.startswith("@ATTRIBUTE"):
                parts = line.split(None, 2)
                attr_name = parts[1] if len(parts) > 1 else f"attr_{len(attributes)}"
                attr_type = parts[2] if len(parts) > 2 else "NUMERIC"
                attributes.append(attr_name)
                if "{" in attr_type:
                    label_col = attr_name
                    vals = re.findall(r"[\w\-/]+", attr_type.replace("{", "").replace("}", ""))
                    label_values = vals
            elif upper.startswith("@DATA"):
                in_data = True
            elif in_data and line:
                parts = [p.strip() for p in line.split(",")]
                if len(parts) == len(attributes):
                    data_rows.append(parts)

    df = pd.DataFrame(data_rows, columns=attributes)
    for col in attributes:
        if col != label_col:
            df[col] = pd.to_numeric(df[col], errors="coerce")
    return attributes, label_col, label_values, df

def build_canonical_dataset(output_dir="data/processed"):
    os.makedirs(output_dir, exist_ok=True)
    
    tier1_path = "results/features.csv"
    tier2_path = "data/raw_external/Scenario B-ARFF/Scenario B-ARFF/TimeBasedFeatures-Dataset-15s-AllinOne.arff"
    
    if not os.path.exists(tier2_path):
        candidates = glob.glob("data/raw_external/**/TimeBasedFeatures-Dataset-15s-AllinOne.arff", recursive=True)
        if candidates:
            tier2_path = candidates[0]
            
    print(f"[CanonicalBuilder] Loading Tier 1 from: {tier1_path}")
    df_t1_raw = pd.read_csv(tier1_path)
    print(f"  Tier 1 raw shape: {df_t1_raw.shape}")
    
    # Process Tier 1
    t1_records = []
    # Assign stratified session groups within each class to allow GroupKFold
    for idx, row in df_t1_raw.iterrows():
        t_class = str(row.get("traffic_class", "UNKNOWN")).upper()
        # Create 5 distinct session groups per class (sub-session chunks)
        group_id = f"T1_GRP_{t_class}_{idx % 5}"
        
        duration = float(row.get("flow_duration_sec", 0.0))
        pkts = float(row.get("packet_count", row.get("total_packets", 0.0)))
        bytes_tot = float(row.get("total_bytes", 0.0))
        
        pps = float(row.get("packets_per_sec", pkts / max(duration, 1e-6)))
        bps = float(row.get("bytes_per_sec", bytes_tot / max(duration, 1e-6)))
        mean_iat = float(row.get("mean_iat_sec", 0.0))
        std_iat = float(row.get("std_iat_sec", 0.0))
        
        t1_records.append({
            "sample_id": f"T1_{idx:04d}",
            "dataset_source": "DS1_CUSTOM_IPSEC",
            "provenance_tier": 1,
            "experiment_group": group_id,
            "traffic_class": t_class,
            "flow_duration_sec": duration,
            "packets_per_sec": pps,
            "bytes_per_sec": bps,
            "mean_iat_sec": mean_iat,
            "std_iat_sec": std_iat,
            # Tier 1 native features
            "mean_packet_size_bytes": float(row.get("mean_packet_size", 0.0)),
            "std_packet_size_bytes": float(row.get("std_packet_size", 0.0)),
            "min_packet_size_bytes": float(row.get("min_packet_size", 0.0)),
            "max_packet_size_bytes": float(row.get("max_packet_size", 0.0)),
            "pcap_source": str(row.get("flow_id", f"sample_{idx}"))
        })
    df_t1 = pd.DataFrame(t1_records)
    print(f"  Tier 1 processed: {len(df_t1)} flows")

    print(f"[CanonicalBuilder] Loading Tier 2 from: {tier2_path}")
    attrs, label_col, label_vals, df_t2_raw = parse_arff(tier2_path)
    print(f"  Tier 2 raw shape: {df_t2_raw.shape}")
    
    # Label mapping for Scenario B
    label_map = {
        "BROWSING": "WEB",
        "CHAT": "INTERACTIVE",
        "STREAMING": "BULK",
        "FT": "BULK",
        "P2P": "BULK",
        "MAIL": "INTERACTIVE",
        "VOIP": "ICMP"
    }
    
    t2_records = []
    for idx, row in df_t2_raw.iterrows():
        raw_label = str(row[label_col]).upper()
        mapped_class = label_map.get(raw_label, "UNKNOWN")
        
        duration_sec = float(row.get("duration", 0.0)) / 1e6 if pd.notna(row.get("duration")) else 0.0
        pps = float(row.get("flowPktsPerSecond", 0.0)) if pd.notna(row.get("flowPktsPerSecond")) else 0.0
        bps = float(row.get("flowBytesPerSecond", 0.0)) if pd.notna(row.get("flowBytesPerSecond")) else 0.0
        mean_iat_sec = float(row.get("mean_flowiat", 0.0)) / 1e6 if pd.notna(row.get("mean_flowiat")) else 0.0
        std_iat_sec = float(row.get("std_flowiat", 0.0)) / 1e6 if pd.notna(row.get("std_flowiat")) else 0.0
        
        group_id = f"T2_GRP_{raw_label}_{idx % 10}"
        
        t2_records.append({
            "sample_id": f"T2_{idx:06d}",
            "dataset_source": "DS4_ISCX_SCENARIO_B",
            "provenance_tier": 2,
            "experiment_group": group_id,
            "traffic_class": mapped_class,
            "flow_duration_sec": duration_sec,
            "packets_per_sec": pps,
            "bytes_per_sec": bps,
            "mean_iat_sec": mean_iat_sec,
            "std_iat_sec": std_iat_sec,
            "mean_packet_size_bytes": np.nan,
            "std_packet_size_bytes": np.nan,
            "min_packet_size_bytes": np.nan,
            "max_packet_size_bytes": np.nan,
            "raw_class_iscx": raw_label,
            "pcap_source": "ISCX_Scenario_B_15s"
        })
    df_t2 = pd.DataFrame(t2_records)
    print(f"  Tier 2 processed: {len(df_t2)} flows")
    
    df_canonical = pd.concat([df_t1, df_t2], ignore_index=True)
    canonical_csv_path = os.path.join(output_dir, "canonical_vpn_dataset.csv")
    df_canonical.to_csv(canonical_csv_path, index=False)
    print(f"[CanonicalBuilder] Saved canonical dataset to {canonical_csv_path} (Total: {len(df_canonical)} rows)")
    
    manifest = {
        "created_at": pd.Timestamp.now().isoformat(),
        "total_samples": len(df_canonical),
        "tier1_samples": len(df_t1),
        "tier2_samples": len(df_t2),
        "sources": {
            "DS1_CUSTOM_IPSEC": {
                "count": len(df_t1),
                "classes": df_t1["traffic_class"].value_counts().to_dict(),
                "provenance": "Custom Linux IPsec StrongSwan testbed (ESP/IKEv2) PCAP captures"
            },
            "DS4_ISCX_SCENARIO_B": {
                "count": len(df_t2),
                "classes": df_t2["traffic_class"].value_counts().to_dict(),
                "raw_classes": df_t2["raw_class_iscx"].value_counts().to_dict(),
                "provenance": "UNB ISCX VPN-nonVPN Scenario B (15-second time-based flows)"
            }
        },
        "shared_features": [
            "flow_duration_sec", "packets_per_sec", "bytes_per_sec",
            "mean_iat_sec", "std_iat_sec"
        ],
        "tier1_exclusive_features": [
            "mean_packet_size_bytes", "std_packet_size_bytes",
            "min_packet_size_bytes", "max_packet_size_bytes"
        ],
        "label_mapping_iscx_to_canonical": label_map
    }
    
    manifest_path = os.path.join(output_dir, "dataset_manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    print(f"[CanonicalBuilder] Saved manifest to {manifest_path}")

if __name__ == "__main__":
    build_canonical_dataset()
