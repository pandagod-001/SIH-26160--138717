import os
import json
import shutil

WORKSPACE = "/mnt/c/Users/Abhijay/ipsec"
MASTER_DIR = os.path.join(WORKSPACE, "IPsecTrace_FINAL_MASTER")

FILES = {
    # 1. DATASETS
    "datasets/dataset_cards/DS1_NATIVE_IPSEC_CARD.md": """# Dataset Card: DS1_NATIVE_IPSEC_LARGE & DS1_NATIVE_IPSEC_ENHANCED

**Dataset ID**: DS1_NATIVE_IPSEC  
**Provenance Tier**: Tier 1 (Authentic Ground Truth)  
**Capture Environment**: Linux Kernel XFRM / Network Namespaces (`ns-client` <-> `ns-server`)  
**Encapsulation**: ESP Protocol 50 over IPv4  
**Cryptographic Suite**: AES-128-CBC Encryption + HMAC-SHA256 Integrity  
**Raw Assets**: 294 Verified `.pcap` files across 157 session groups  
**Canonical Flow Windows**: 5,482 (1.0s window baseline) / 1,829 (3.0s window enhanced)  
**Workload Classes**:
- `WEB`: HTTP request/response patterns via curl (1,866 samples)
- `ICMP`: Ping probes with varying payload sizes 56B–1200B (1,518 samples)
- `INTERACTIVE`: Bursty bidirectional transactions (1,424 samples)
- `BULK`: Sustained high-volume file transfers (674 samples)
**Network Emulation Profiles (`tc netem`)**:
- `ENV_CLEAN`: 0ms latency, 0% loss, 0ms jitter
- `ENV_LOW`: 10ms latency, 2ms jitter, 0% loss
- `ENV_HIGH`: 45ms latency, 5ms jitter, 0.5% loss
- `ENV_LOSSY`: 20ms latency, 3ms jitter, 1.5% loss
""",

    "datasets/dataset_cards/DS4_ISCX_SCENARIO_B_CARD.md": """# Dataset Card: DS4_ISCX_SCENARIO_B (Auxiliary Encrypted VPN)

**Dataset ID**: DS4_ISCX_SCENARIO_B  
**Provenance Tier**: Tier 2 (Auxiliary External Benchmark)  
**Source Organization**: University of New Brunswick (UNB ISCX VPN-nonVPN 2016)  
**Encapsulation**: OpenVPN / SSL VPN over UDP/TCP  
**Sample Count**: 13,655 flow records in Scenario B ARFF (18,758 total with Scenario A)  
**Role in IPsecTrace**: Used strictly for large-scale external validation of machine learning feature extractors on public cybersecurity benchmarks.  
**Critical Constraint**: Must NOT be mislabelled as Native IPsec ESP ground truth.
""",

    "datasets/provenance/DATASET_PROVENANCE_MATRIX.md": """# Master Dataset Provenance Matrix

| Dataset Identifier | Canonical Samples | Raw Source File / Generator | Capture Technology | Tier Label |
| :--- | :--- | :--- | :--- | :--- |
| **`DS1_NATIVE_IPSEC_LARGE`** | **5,482** | 294 Raw PCAPs in `data/raw_native_ipsec/` | Linux XFRM ESP (AES-128-CBC) | **Tier 1 Ground Truth** |
| **`DS1_NATIVE_ENHANCED`** | **1,829** | 294 Raw PCAPs (3.0s sliding windows) | Linux XFRM ESP (AES-128-CBC) | **Tier 1 Ground Truth** |
| **`DS4_ISCX_SCENARIO_B`** | **13,655** | `Scenario B-ARFF.zip` (UNB ISCX 2016) | OpenVPN / SSL over UDP/TCP | **Tier 2 Auxiliary VPN** |
| **`DS_ENCRYPTED_VPN_JSON`** | **5,103** | `encrypted_vpn_dataset.zip` | Multi-VPN JSON Flow Records | **Tier 2 Auxiliary VPN** |
| **`DS_CUSTOM_IPSEC`** | **84** | Initial Controlled Testbed PCAPs | Linux IPsec PoC | **Tier 1 Pilot Lab** |
| **TOTAL CANONICAL RECONCILED**| **18,842** | Master Reconciliation Metric | Multi-Dataset Pipeline | **Authoritative Benchmark** |
""",

    "datasets/schemas/FEATURE_SCHEMA.json": json.dumps({
        "schema_version": "2.1.0",
        "description": "Standardized non-payload feature extraction schema for encrypted IPsec ESP flows",
        "features": {
            "flow_duration_sec": {"type": "float", "unit": "seconds", "description": "Total duration of the time window"},
            "packets_per_sec": {"type": "float", "unit": "pkts/sec", "description": "Packet rate observed in window"},
            "bytes_per_sec": {"type": "float", "unit": "bytes/sec", "description": "Byte throughput in window"},
            "mean_iat_sec": {"type": "float", "unit": "seconds", "description": "Mean packet inter-arrival time"},
            "std_iat_sec": {"type": "float", "unit": "seconds", "description": "Standard deviation of inter-arrival time"},
            "mean_packet_size_bytes": {"type": "float", "unit": "bytes", "description": "Mean length of encapsulated ESP frames"},
            "std_packet_size_bytes": {"type": "float", "unit": "bytes", "description": "Standard deviation of packet length"},
            "min_packet_size_bytes": {"type": "float", "unit": "bytes", "description": "Minimum packet size observed"},
            "max_packet_size_bytes": {"type": "float", "unit": "bytes", "description": "Maximum packet size observed"},
            "pkt_len_p25": {"type": "float", "unit": "bytes", "description": "25th percentile of packet length"},
            "pkt_len_p50": {"type": "float", "unit": "bytes", "description": "Median packet length"},
            "pkt_len_p75": {"type": "float", "unit": "bytes", "description": "75th percentile of packet length"},
            "pkt_len_p90": {"type": "float", "unit": "bytes", "description": "90th percentile of packet length"},
            "directional_byte_ratio": {"type": "float", "unit": "ratio", "description": "Forward bytes / Backward bytes"}
        }
    }, indent=2),

    # 2. RESEARCH NOTES
    "research/RFCs/RFC_IPSEC_SUMMARY.md": """# Summary of Foundational IPsec Standards

- **RFC 7296 (IKEv2)**: Replaces RFC 5996 / 4306. Specifies the IKEv2 protocol for performing mutual authentication and establishing Security Associations (SAs). Defines exchange types: `IKE_SA_INIT`, `IKE_AUTH`, `CREATE_CHILD_SA`, and `INFORMATIONAL`.
- **RFC 4303 (ESP)**: Specifies the Encapsulating Security Payload header. Key fields: `SPI` (32-bit), `Sequence Number` (32-bit), `Payload Data`, `Padding`, `Pad Length`, `Next Header`, and optional `ICV` (Integrity Check Value). Defines anti-replay sliding window mechanisms.
- **RFC 4302 (AH)**: Specifies the Authentication Header, providing connectionless data integrity and data origin authentication for IP datagrams.
- **RFC 4301 (Security Architecture)**: Defines Security Policy Database (SPD), Security Association Database (SAD), and Peer Authorization Database (PAD).
""",

    "research/NIST/NIST_GUIDELINES_SUMMARY.md": """# Summary of NIST Cryptographic & IPsec Guidelines

- **NIST SP 800-77 Rev. 1 (Guide to IPsec VPNs)**:
  - Recommends AES-GCM (128 or 256 bits) as primary authenticated encryption cipher.
  - For AES-CBC, requires mandatory HMAC-SHA-256 (or stronger) integrity protection.
  - Prohibits legacy DES, 3DES, and RC4.
  - Recommends Diffie-Hellman Group 14 (MODP 2048-bit) or higher (ECDH Group 19/20).
- **NIST SP 800-131A Rev. 2 (Transitioning Cryptographic Algorithms)**:
  - Formally disallows 2-key 3DES, MD5, and SHA-1 for digital signatures and integrity protection.
  - Sets security strength requirement to >= 112 bits (moving to >= 128 bits).
""",

    "research/research_notes/ENCRYPTED_TRAFFIC_ML_NOTES.md": """# Research Notes: Machine Learning on Encrypted Traffic

1. **The Core Physical Boundary**:
   Encryption creates pseudorandom ciphertexts with high byte entropy (approaching 8.0 bits/byte). Deep Packet Inspection cannot examine payload text.
2. **Observable Side-Channels**:
   Traffic behavior leaks through:
   - Encapsulated frame sizes (dictated by MTU, application buffer sizes, and padding).
   - Directional burstiness (upload-heavy vs. download-heavy asymmetry).
   - Temporal pacing (inter-arrival distributions and interactive idle pauses).
3. **The Autocorrelation Leakage Trap**:
   Packets belonging to the same TCP/IP flow share nearly identical size distributions. A random train/test split leaks flow-specific patterns, generating artificially inflated 100% accuracy. Session-isolated GroupKFold cross-validation is mandatory for scientific validity.
""",

    # 3. REPRODUCIBILITY
    "reproducibility/ENVIRONMENT_SPEC.md": """# Complete Environment & Dependency Specification

- **Host OS**: Microsoft Windows 11 (WSL2 Ubuntu 24.04 LTS)
- **Linux Kernel**: 5.15.x / 6.x x86_64 with `XFRM`, `iproute2`, and `tc netem` enabled
- **Python Version**: Python 3.12.3 / 3.10+
- **Core Python Dependencies**:
  - `scapy == 2.5.0 / 2.7.0` (Packet parsing and testbed generation)
  - `scikit-learn == 1.4.2` (GroupKFold, Random Forest, Logistic Regression, metrics)
  - `xgboost == 2.0.3` (Gradient Boosted Decision Trees)
  - `numpy == 1.26.4`
  - `pandas == 2.2.2`
  - `matplotlib == 3.8.4`
""",

    "reproducibility/REPRODUCE_ALL.sh": """#!/bin/bash
# Master Reproduction Script for IPsecTrace
set -e
echo "======================================================="
echo "   IPsecTrace REPRODUCIBILITY EXECUTION SUITE       "
echo "======================================================="

export PYTHONPATH=.

echo "[1/4] Running Master Forensic Hardening & Metric Recalculation..."
python3 src/audit/run_final_hardening_pass.py

echo "[2/4] Running Native IPsec Large Benchmark..."
python3 src/ml/run_native_ipsec_ml_benchmark.py

echo "[3/4] Running Enhanced Feature Pipeline Evaluation..."
python3 src/ml/evaluate_enhanced_native_ipsec.py

echo "[4/4] Plotting All Master Figures..."
python3 src/visualizer/plot_charts.py
python3 src/visualizer/plot_native_ipsec_benchmarks.py

echo "======================================================="
echo "   ALL EXPERIMENTS REPRODUCED SUCCESSFULLY!           "
echo "======================================================="
"""
}

def populate_all():
    for rel_path, content in FILES.items():
        full_path = os.path.join(MASTER_DIR, rel_path)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, "w", encoding="utf-8") as fp:
            fp.write(content.strip() + "\n")
        print(f"Created: {rel_path}")

if __name__ == "__main__":
    populate_all()
