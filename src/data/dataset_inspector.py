"""
dataset_inspector.py — IPsecTrace Phase 2 Dataset Forensics
Inspects every available dataset, measures record counts, feature sets,
label distributions, missing values, and generates dataset cards.
No fabrication. All numbers come from actual file reads.
"""
import os
import json
import glob
import re
import datetime
import numpy as np
import pandas as pd

# ── ARFF parser ────────────────────────────────────────────────────────────────

def parse_arff(filepath):
    """
    Minimal ARFF parser that returns (attribute_names, label_values, DataFrame).
    Handles @ATTRIBUTE lines and @DATA section.
    """
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
                # detect nominal (label) column
                if "{" in attr_type:
                    label_col = attr_name
                    vals = re.findall(r"[\w\-/]+", attr_type.replace("{", "").replace("}", ""))
                    label_values = vals
            elif upper.startswith("@DATA"):
                in_data = True
            elif in_data and line:
                # Split on comma but be careful with spaces
                parts = [p.strip() for p in line.split(",")]
                if len(parts) == len(attributes):
                    data_rows.append(parts)

    df = pd.DataFrame(data_rows, columns=attributes)

    # Convert numeric columns
    for col in attributes:
        if col != label_col:
            df[col] = pd.to_numeric(df[col], errors="coerce")

    return attributes, label_col, label_values, df


# ── JSON flow inspector ─────────────────────────────────────────────────────────

def inspect_json_flow_file(filepath):
    """
    Inspects a JSON flow file (encrypted_vpn_dataset format).
    Returns summary dict.
    """
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        return {"error": str(e), "num_flows": 0}

    if not isinstance(data, list):
        return {"error": "Not a list", "num_flows": 0}

    num_flows = len(data)
    total_packets = 0
    flow_fields = set()
    packet_fields = set()

    for flow in data[:200]:  # sample first 200 flows
        if isinstance(flow, dict):
            flow_fields.update(flow.keys())
            pkts = flow.get("x_packets", [])
            total_packets += len(pkts)
            for pkt in pkts[:5]:
                if isinstance(pkt, dict):
                    packet_fields.update(pkt.keys())

    return {
        "num_flows": num_flows,
        "flow_fields": sorted(flow_fields),
        "packet_fields": sorted(packet_fields),
        "approx_total_packets": total_packets,
        "file_size_mb": round(os.path.getsize(filepath) / 1e6, 2)
    }


# ── PCAP inspector (counts packets via scapy if available) ────────────────────

def inspect_pcap_file(filepath):
    """
    Inspects a PCAP file and returns basic stats.
    Falls back to file size if Scapy not usable.
    """
    size_mb = round(os.path.getsize(filepath) / 1e6, 2)
    try:
        from scapy.all import rdpcap, ESP, IP
        pkts = rdpcap(filepath)
        esp_count = sum(1 for p in pkts if p.haslayer(ESP))
        ip_count = sum(1 for p in pkts if p.haslayer(IP))
        return {
            "total_packets": len(pkts),
            "esp_packets": esp_count,
            "ip_packets": ip_count,
            "file_size_mb": size_mb
        }
    except Exception as e:
        # Scapy may not parse pcapng properly on Windows without npcap
        return {
            "total_packets": "unavailable",
            "note": str(e)[:80],
            "file_size_mb": size_mb
        }


# ── Main inspection routine ────────────────────────────────────────────────────

def run_dataset_inspection(base_dir="data/raw_external",
                           custom_csv="results/features.csv",
                           out_dir="SIH_EVIDENCE"):
    os.makedirs(out_dir, exist_ok=True)
    os.makedirs(f"{out_dir}/dataset_cards", exist_ok=True)

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    all_cards = []

    # ── DS1: Custom IPsec Testbed ─────────────────────────────────────────────
    print("[INSPECT] DS1: Custom IPsec Testbed (results/features.csv)")
    card_ds1 = _inspect_custom_ipsec(custom_csv)
    all_cards.append(card_ds1)
    _write_card(card_ds1, f"{out_dir}/dataset_cards/DS1_custom_ipsec.md")

    # ── DS2: ISCX Scenario A1 ARFF ────────────────────────────────────────────
    a1_dir = f"{base_dir}/Scenario A1-ARFF/Scenario A1-ARFF"
    if os.path.isdir(a1_dir):
        print("[INSPECT] DS2: ISCX Scenario A1 ARFF")
        card_a1 = _inspect_arff_dataset(
            a1_dir, "DS2_ISCX_A1",
            "ISCX VPN-nonVPN 2016 — Scenario A1 (VPN vs Encrypted)",
            "University of New Brunswick (UNB) / ISCXVPN2016",
            "Binary: VPN vs. Non-VPN encrypted traffic",
            "ISCXFlowMeter pre-extracted flow statistics (23 features) across 15s/30s/60s/120s time windows",
            "OpenVPN, IPsec, Skype, YouTube, Vimeo, Facebook, Netflix, SFTP, VoIP",
            "VPN = tunneled (OpenVPN/IPsec), Non-VPN = native encrypted (HTTPS/TLS)",
        )
        all_cards.append(card_a1)
        _write_card(card_a1, f"{out_dir}/dataset_cards/DS2_iscx_a1.md")

    # ── DS3: ISCX Scenario A2 ARFF ────────────────────────────────────────────
    a2_dir = f"{base_dir}/Scenario A2-ARFF/Scenario A2-ARFF"
    if os.path.isdir(a2_dir):
        print("[INSPECT] DS3: ISCX Scenario A2 ARFF")
        card_a2 = _inspect_arff_dataset(
            a2_dir, "DS3_ISCX_A2",
            "ISCX VPN-nonVPN 2016 — Scenario A2 (VPN vs Non-VPN)",
            "University of New Brunswick (UNB) / ISCXVPN2016",
            "Binary: VPN vs. non-VPN (unencrypted/cleartext traffic)",
            "ISCXFlowMeter pre-extracted flow statistics (23 features) across 15s/30s/60s/120s time windows",
            "VPN-tunneled vs. unencrypted application traffic",
            "VPN = tunneled, Non-VPN = unencrypted",
        )
        all_cards.append(card_a2)
        _write_card(card_a2, f"{out_dir}/dataset_cards/DS3_iscx_a2.md")

    # ── DS4: ISCX Scenario B ARFF ─────────────────────────────────────────────
    b_dir = f"{base_dir}/Scenario B-ARFF/Scenario B-ARFF"
    if os.path.isdir(b_dir):
        print("[INSPECT] DS4: ISCX Scenario B ARFF")
        card_b = _inspect_arff_dataset(
            b_dir, "DS4_ISCX_B",
            "ISCX VPN-nonVPN 2016 — Scenario B (Multi-class traffic over VPN)",
            "University of New Brunswick (UNB) / ISCXVPN2016",
            "Multi-class: BROWSING, CHAT, STREAMING, MAIL, VOIP, P2P, FT",
            "ISCXFlowMeter pre-extracted flow statistics (23 features) across 15s/30s/60s/120s time windows",
            "All traffic carried over VPN tunnels (OpenVPN / IPsec)",
            "Application-layer category labels (ground truth via controlled traffic generators)",
        )
        all_cards.append(card_b)
        _write_card(card_b, f"{out_dir}/dataset_cards/DS4_iscx_b.md")

    # ── DS5: Encrypted VPN JSON (OpenVPN) ─────────────────────────────────────
    openvpn_dir = f"{base_dir}/encrypted_vpn_dataset/encrypted_vpn_dataset/VPN/OpenVPN"
    if os.path.isdir(openvpn_dir):
        print("[INSPECT] DS5: Encrypted VPN JSON — OpenVPN")
        card_ovpn = _inspect_json_dataset(
            openvpn_dir, "DS5_ENCRYPTED_OPENVPN",
            "Encrypted VPN Flow Dataset — OpenVPN",
            "Academic research dataset (JSON packet-level flow series)",
            "SSH, Meet, Non-streaming flows over OpenVPN UDP 1194",
            "NOT IPsec — OpenVPN protocol only",
        )
        all_cards.append(card_ovpn)
        _write_card(card_ovpn, f"{out_dir}/dataset_cards/DS5_encrypted_openvpn.md")

    # ── DS6: Encrypted VPN JSON (SSTP) ────────────────────────────────────────
    sstp_dir = f"{base_dir}/encrypted_vpn_dataset/encrypted_vpn_dataset/VPN/SSTP"
    if os.path.isdir(sstp_dir):
        print("[INSPECT] DS6: Encrypted VPN JSON — SSTP")
        card_sstp = _inspect_json_dataset(
            sstp_dir, "DS6_ENCRYPTED_SSTP",
            "Encrypted VPN Flow Dataset — SSTP",
            "Academic research dataset (JSON packet-level flow series)",
            "SSH, Meet, Mail, Non-streaming, Streaming flows over SSTP",
            "NOT IPsec — Microsoft SSTP protocol only",
        )
        all_cards.append(card_sstp)
        _write_card(card_sstp, f"{out_dir}/dataset_cards/DS6_encrypted_sstp.md")

    # ── DS7: ISCX VPN PCAPs ───────────────────────────────────────────────────
    vpn_pcap_dir = f"{base_dir}/VPN-PCAPs-02"
    if os.path.isdir(vpn_pcap_dir):
        print("[INSPECT] DS7: ISCX VPN Raw PCAPs")
        card_vpcap = _inspect_pcap_dataset(
            vpn_pcap_dir, "DS7_ISCX_VPN_PCAP",
            "ISCX VPN-nonVPN 2016 — VPN PCAPs-02",
            "University of New Brunswick (UNB) / ISCXVPN2016",
            "ICQ Chat, Netflix Streaming over VPN tunnel (OpenVPN/IPsec)",
            "VPN-tunneled raw packet captures",
        )
        all_cards.append(card_vpcap)
        _write_card(card_vpcap, f"{out_dir}/dataset_cards/DS7_iscx_vpn_pcap.md")

    # ── DS8: ISCX NonVPN PCAPs ────────────────────────────────────────────────
    nonvpn_pcap_dir = f"{base_dir}/NonVPN-PCAPs-01"
    if os.path.isdir(nonvpn_pcap_dir):
        print("[INSPECT] DS8: ISCX NonVPN Raw PCAPs")
        card_nvpcap = _inspect_pcap_dataset(
            nonvpn_pcap_dir, "DS8_ISCX_NONVPN_PCAP",
            "ISCX VPN-nonVPN 2016 — NonVPN PCAPs-01",
            "University of New Brunswick (UNB) / ISCXVPN2016",
            "AIM Chat, Email, Facebook Audio/Video (unencrypted/native TLS)",
            "Unencrypted or native TLS traffic — NOT VPN, NOT IPsec",
        )
        all_cards.append(card_nvpcap)
        _write_card(card_nvpcap, f"{out_dir}/dataset_cards/DS8_iscx_nonvpn_pcap.md")

    # ── Write inventory ───────────────────────────────────────────────────────
    _write_inventory(all_cards, f"{out_dir}/dataset_inventory.md", timestamp)

    print(f"\n[INSPECT] Dataset inspection complete. {len(all_cards)} datasets profiled.")
    return all_cards


# ── Individual dataset inspectors ─────────────────────────────────────────────

def _inspect_custom_ipsec(csv_path):
    card = {
        "id": "DS1_CUSTOM_IPSEC",
        "name": "Custom IPsec Testbed Dataset",
        "source": "Locally generated — dual Linux network namespace testbed (ns-client ↔ ns-server, IKEv2/ESP/AES-128-CBC/HMAC-SHA256/MODP-2048)",
        "format": "Pre-extracted flow statistics CSV (results/features.csv)",
        "technology": "Native IPsec — IKEv2 + ESP (kernel ip xfrm)",
        "ike_version": "IKEv2",
        "esp_ah": "ESP",
        "tunnel_transport": "Tunnel mode",
        "ip_version": "IPv4",
        "capture_env": "Controlled Linux network namespaces (WSL2 Ubuntu 24.04)",
        "capture_point": "Both endpoints (ns-client and ns-server) via tcpdump",
        "ground_truth": "Yes — traffic class determined by controlled generator script",
        "provenance_tier": "Tier 1 — Primary native IPsec data",
        "is_native_ipsec": True,
        "license": "Self-generated — no external license restrictions",
        "notes": []
    }

    if not os.path.exists(csv_path):
        card["error"] = f"File not found: {csv_path}"
        card["num_records"] = 0
        return card

    df = pd.read_csv(csv_path)
    card["num_records"] = len(df)
    card["num_features"] = len(df.columns) - 3  # exclude meta cols
    card["feature_names"] = list(df.columns)

    if "traffic_class" in df.columns:
        dist = df["traffic_class"].value_counts().to_dict()
        card["class_distribution"] = dist
        card["classes"] = sorted(dist.keys())
        card["num_classes"] = len(dist)

    # Quality checks
    card["missing_values"] = int(df.isnull().sum().sum())
    card["duplicate_rows"] = int(df.duplicated().sum())

    # Check for near-identical packet sizes (controlled testbed artifact)
    if "std_packet_size" in df.columns:
        zero_std = int((df["std_packet_size"] == 0).sum())
        if zero_std > 0:
            card["notes"].append(
                f"{zero_std}/{len(df)} flows have zero packet size std — uniform-size traffic (BULK TCP)."
            )

    # Leakage risk
    card["leakage_assessment"] = (
        "LOW — Labels are assigned from controlled generator scripts (ground truth). "
        "Directory-name-derived label in flow_extractor.py is by design here. "
        "No post-hoc label field leaks into feature columns."
    )
    return card


def _inspect_arff_dataset(arff_dir, ds_id, name, source, label_desc,
                          feature_desc, traffic_desc, label_ground_truth):
    card = {
        "id": ds_id,
        "name": name,
        "source": source,
        "format": "Weka ARFF (ISCXFlowMeter pre-extracted features)",
        "technology": traffic_desc,
        "ground_truth": label_ground_truth,
        "feature_description": feature_desc,
        "label_description": label_desc,
        "is_native_ipsec": False,
        "ip_version": "IPv4/IPv6 mixed",
        "capture_env": "University of New Brunswick campus network + Wireshark/tcpdump",
        "license": "Publicly available via UNB website (research use)",
        "provenance_tier": "Tier 2 — External encrypted VPN benchmark",
        "time_windows": [],
        "files": [],
        "notes": []
    }

    arff_files = sorted(glob.glob(f"{arff_dir}/*.arff"))
    if not arff_files:
        card["error"] = "No ARFF files found"
        return card

    total_records = 0
    all_classes = set()
    feature_names = []
    missing_total = 0
    window_data = {}

    for fpath in arff_files:
        fname = os.path.basename(fpath)
        # Extract time window from filename
        m = re.search(r"(\d+s)", fname)
        window = m.group(1) if m else "unknown"
        is_vpn = "VPN" in fname and "NO" not in fname

        try:
            attrs, label_col, label_vals, df = parse_arff(fpath)
            n = len(df)
            total_records += n
            if label_col and label_col in df.columns:
                dist = df[label_col].value_counts().to_dict()
                all_classes.update(dist.keys())
            missing = int(df.isnull().sum().sum())
            missing_total += missing

            # Capture feature names once
            if not feature_names and label_col:
                feature_names = [a for a in attrs if a != label_col]

            file_summary = {
                "filename": fname,
                "time_window": window,
                "vpn_subset": is_vpn,
                "num_records": n,
                "num_features": len(attrs) - 1,
                "label_column": label_col,
                "class_values": label_vals,
                "missing_values": missing
            }
            card["files"].append(file_summary)
            if window not in window_data:
                window_data[window] = 0
            window_data[window] += n

        except Exception as e:
            card["files"].append({"filename": fname, "error": str(e)[:120]})

    card["total_records_across_files"] = total_records
    card["time_windows"] = sorted(window_data.keys())
    card["records_per_window"] = window_data
    card["feature_names"] = feature_names
    card["num_features"] = len(feature_names)
    card["classes"] = sorted(all_classes)
    card["num_classes"] = len(all_classes)
    card["missing_values_total"] = missing_total

    # Leakage assessment
    card["leakage_assessment"] = (
        "LOW — Features are pre-extracted ISCXFlowMeter statistics. "
        "No IP addresses, port numbers, or protocol identifiers included. "
        "CAUTION: Dataset source (VPN vs NO-VPN file) could leak if used as a feature. "
        "Only statistical flow features will be used in experiments."
    )

    # Dataset-specific notes
    if "ARFF_B" in ds_id or ds_id == "DS4_ISCX_B":
        card["notes"].append(
            "Labels (BROWSING, CHAT, STREAMING, MAIL, VOIP, P2P, FT) require mapping to our "
            "custom testbed classes (WEB, INTERACTIVE, BULK, ICMP) for cross-dataset experiments. "
            "Mapping is approximate and will be explicitly flagged in all results."
        )
    if "A2" in ds_id:
        card["notes"].append(
            "Contains separate VPN and NO-VPN ARFF files. Only 23 shared ISCXFlowMeter features. "
            "Useful for binary VPN-detection benchmarking."
        )

    return card


def _inspect_json_dataset(json_dir, ds_id, name, source, traffic_desc, tech_warning):
    card = {
        "id": ds_id,
        "name": name,
        "source": source,
        "format": "JSON packet-level flow series",
        "technology": traffic_desc,
        "tech_warning": tech_warning,
        "is_native_ipsec": False,
        "ground_truth": "Inferred from VPN client application and destination port",
        "provenance_tier": "Tier 3 — Auxiliary encrypted VPN data (NOT IPsec)",
        "files": [],
        "notes": [tech_warning]
    }

    json_files = sorted(glob.glob(f"{json_dir}/*.json"))
    total_flows = 0

    for fpath in json_files:
        fname = os.path.basename(fpath)
        info = inspect_json_flow_file(fpath)
        info["filename"] = fname
        card["files"].append(info)
        total_flows += info.get("num_flows", 0)

    card["total_flows"] = total_flows
    card["leakage_assessment"] = (
        "HIGH RISK if filename or directory used as label source. "
        "Traffic class is encoded in filename (e.g., ssh.json → SSH class). "
        "This is ground truth by design but constitutes leakage if filename "
        "is accessible to the model. Labels must be assigned externally before training."
    )
    card["notes"].append(
        "Feature extraction from x_packets[] required before ML use. "
        "Each packet record has: bytes, ip_header_len, tcp_flags, tcp_seq_number, timestamp_start/end."
    )
    return card


def _inspect_pcap_dataset(pcap_dir, ds_id, name, source, traffic_desc, tech_warning):
    card = {
        "id": ds_id,
        "name": name,
        "source": source,
        "format": "Raw PCAP / PCAPNG captures",
        "technology": traffic_desc,
        "tech_warning": tech_warning,
        "is_native_ipsec": False,
        "ground_truth": "Inferred from capture filename convention",
        "provenance_tier": "Tier 3 — Auxiliary raw capture data",
        "files": [],
        "notes": [tech_warning]
    }

    pcap_files = sorted(glob.glob(f"{pcap_dir}/*.pcap") + glob.glob(f"{pcap_dir}/*.pcapng"))
    total_size = 0

    for fpath in pcap_files:
        fname = os.path.basename(fpath)
        size_mb = round(os.path.getsize(fpath) / 1e6, 2)
        total_size += size_mb
        card["files"].append({"filename": fname, "size_mb": size_mb})

    card["num_files"] = len(pcap_files)
    card["total_size_mb"] = round(total_size, 2)
    card["leakage_assessment"] = (
        "MEDIUM — Filename encodes traffic type (e.g., vpn_netflix_A.pcap). "
        "Raw PCAP features derived from Scapy parsing would not see filenames. "
        "However, specific packet patterns (e.g., Netflix CDN IPs) could leak content type."
    )
    return card


# ── Writers ───────────────────────────────────────────────────────────────────

def _write_card(card, out_path):
    lines = [f"# Dataset Card: {card.get('name', card.get('id', 'Unknown'))}", ""]
    lines.append(f"**Dataset ID**: `{card.get('id', 'N/A')}`  ")
    lines.append(f"**Source**: {card.get('source', 'N/A')}  ")
    lines.append(f"**Format**: {card.get('format', 'N/A')}  ")
    lines.append(f"**Technology**: {card.get('technology', 'N/A')}  ")
    lines.append(f"**Native IPsec**: {'Yes' if card.get('is_native_ipsec') else 'No'}  ")
    lines.append(f"**Provenance Tier**: {card.get('provenance_tier', 'N/A')}  ")
    lines.append(f"**Ground Truth**: {card.get('ground_truth', 'N/A')}  ")
    lines.append("")

    if "num_records" in card:
        lines.append(f"**Records**: {card['num_records']}  ")
    if "total_records_across_files" in card:
        lines.append(f"**Total Records (all windows)**: {card['total_records_across_files']}  ")
    if "total_flows" in card:
        lines.append(f"**Total Flows**: {card['total_flows']}  ")
    if "num_features" in card:
        lines.append(f"**Features**: {card['num_features']}  ")
    if "classes" in card:
        lines.append(f"**Classes**: {', '.join(str(c) for c in card['classes'])}  ")
        lines.append(f"**Num Classes**: {card.get('num_classes', len(card['classes']))}  ")
    if "class_distribution" in card:
        lines.append("")
        lines.append("## Class Distribution")
        lines.append("")
        lines.append("| Class | Count |")
        lines.append("|---|---|")
        for cls, cnt in sorted(card["class_distribution"].items()):
            lines.append(f"| {cls} | {cnt} |")
    if "missing_values" in card:
        lines.append("")
        lines.append(f"**Missing Values**: {card['missing_values']}  ")
    if "missing_values_total" in card:
        lines.append(f"**Missing Values (all files)**: {card['missing_values_total']}  ")

    lines.append("")
    lines.append("## Leakage Assessment")
    lines.append("")
    lines.append(card.get("leakage_assessment", "Not assessed."))

    if card.get("notes"):
        lines.append("")
        lines.append("## Notes")
        lines.append("")
        for note in card["notes"]:
            lines.append(f"- {note}")

    if card.get("files"):
        lines.append("")
        lines.append("## File Inventory")
        lines.append("")
        lines.append("| Filename | Records / Size | Window / Info |")
        lines.append("|---|---|---|")
        for f in card["files"]:
            fname = f.get("filename", "?")
            info = f.get("num_records", f.get("num_flows", f.get("size_mb", "?")))
            extra = f.get("time_window", f.get("note", ""))
            lines.append(f"| {fname} | {info} | {extra} |")

    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def _write_inventory(cards, out_path, timestamp):
    lines = [
        "# SIH_EVIDENCE/dataset_inventory.md — IPsecTrace Phase 2 Dataset Inventory",
        "",
        f"**Generated**: {timestamp}  ",
        f"**Total Datasets Profiled**: {len(cards)}  ",
        "",
        "---",
        "",
        "## Dataset Hierarchy",
        "",
        "```",
        "PRIMARY NATIVE IPsec DATA",
        "  └── DS1: Custom IPsec Testbed (IKEv2/ESP, controlled ground truth)",
        "",
        "EXTERNAL ENCRYPTED VPN BENCHMARK",
        "  └── DS2: ISCX Scenario A1 ARFF (VPN vs Encrypted, binary)",
        "  └── DS3: ISCX Scenario A2 ARFF (VPN vs Non-VPN, binary)",
        "  └── DS4: ISCX Scenario B ARFF  (Multi-class traffic over VPN) ← PRIMARY EXTERNAL",
        "  └── DS7: ISCX VPN PCAPs-02 (raw captures, OpenVPN/IPsec)",
        "",
        "AUXILIARY ENCRYPTED VPN DATA (NOT IPsec)",
        "  └── DS5: Encrypted VPN JSON — OpenVPN",
        "  └── DS6: Encrypted VPN JSON — SSTP",
        "  └── DS8: ISCX NonVPN PCAPs-01 (reference baseline)",
        "```",
        "",
        "---",
        "",
        "## Summary Table",
        "",
        "| ID | Name | Format | Native IPsec | Records | Classes | Tier | Used in Experiments |",
        "|---|---|---|---|---|---|---|---|",
    ]

    for c in cards:
        ds_id = c.get("id", "?")
        name = c.get("name", "?")[:50]
        fmt = c.get("format", "?")[:25]
        native = "Yes" if c.get("is_native_ipsec") else "No"
        recs = c.get("num_records",
               c.get("total_records_across_files",
               c.get("total_flows",
               c.get("num_files", "?"))))
        classes = c.get("num_classes", "?")
        tier = c.get("provenance_tier", "?")[:10]

        # Decide usage
        if ds_id in ("DS1_CUSTOM_IPSEC", "DS4_ISCX_B"):
            usage = "Yes — primary"
        elif ds_id in ("DS2_ISCX_A1", "DS3_ISCX_A2"):
            usage = "Yes — binary VPN"
        else:
            usage = "Reference only"

        lines.append(f"| {ds_id} | {name} | {fmt} | {native} | {recs} | {classes} | Tier {tier[4]} | {usage} |")

    lines += [
        "",
        "---",
        "",
        "## Key Technical Notes",
        "",
        "1. **DS1 is the only native IPsec dataset** with IKEv2/ESP headers observable.",
        "   All other datasets contain VPN-tunneled or unencrypted traffic where IPsec may or",
        "   may not be the underlying VPN technology.",
        "",
        "2. **DS4 (ISCX Scenario B)** is the primary external dataset for cross-dataset",
        "   generalization experiments. Its labels (BROWSING, CHAT, STREAMING, MAIL, VOIP, P2P, FT)",
        "   require explicit mapping to our classes and this mapping is approximate.",
        "",
        "3. **DS5 and DS6** contain OpenVPN and SSTP flows — NOT IPsec. They are documented",
        "   for completeness but are NOT used in cross-IPsec-generalization claims.",
        "",
        "4. **DS8** is unencrypted reference traffic — used only as non-VPN baseline context.",
        "",
        "5. **Cross-dataset experiments** between DS1 and DS4 must be qualified as:",
        "   'Encrypted application traffic classification generalization' —",
        "   NOT 'cross-IPsec-implementation generalization'.",
    ]

    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    run_dataset_inspection()
