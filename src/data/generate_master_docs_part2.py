import os
import json

WORKSPACE = "/mnt/c/Users/Abhijay/ipsec"
MASTER_DIR = os.path.join(WORKSPACE, "IPsecTrace_FINAL_MASTER")

DOCS_PART2 = {
    "03_PROBLEM_STATEMENT.md": """# 03 — Technical Problem Statement & Observability Boundary

## 1. Problem Context (SIH 2026 / NTRO 26160)
IPsec VPNs operate at Layer 3 to provide confidentiality, integrity, and authentication for network communications using IKE (Internet Key Exchange) and ESP (Encapsulating Security Payload) / AH (Authentication Header). 

While encryption provides essential security, it establishes a strict **observability boundary** for network defense analysts:
- **Directly Observable**: IKE negotiation parameters (RFC 7296), ESP headers, Security Parameter Indexes (SPIs), sequence numbers (RFC 4303), packet lengths, timestamps, direction, and flow dynamics.
- **Protected / Encrypted**: Inner IP headers, TCP/UDP port numbers, and application payloads.

## 2. Why Conventional DPI Fails
Deep Packet Inspection (DPI) relies on plaintext regex matching and application protocol signatures (e.g. HTTP GET, TLS SNI). Inside an IPsec ESP tunnel using standard ciphers (AES-128-CBC, AES-256-GCM), all inner bytes are cryptographically indistinguishable from random noise.

## 3. The IPsecTrace Solution
IPsecTrace formulates a **Layered Evidence Model**:
1. **Verify** what is directly observable in the protocol headers (IKE proposals, ESP SPIs).
2. **Reconstruct** stateful relationships (IKE Session -> Child SA -> ESP Flow).
3. **Infer** broad traffic behavioral classes using machine learning on statistical features.
4. **Evaluate** security policies deterministically.
5. **Report** confidence and explicit uncertainty (`UNKNOWN`, `NOT OBSERVABLE`, `CONFLICT`).
""",

    "04_RESEARCH_BACKGROUND.md": """# 04 — Research Background & Foundational Literature

## 1. Core IPsec & Cryptographic Standards
- **RFC 7296 (IKEv2)**: Defines IKEv2 negotiation, SA_INIT, IKE_AUTH, and Child SA exchange mechanics.
- **RFC 4303 (ESP)**: Defines Encapsulating Security Payload format, anti-replay sequence number mechanics, and IV/padding geometry.
- **RFC 4302 (AH)**: Defines Authentication Header specification.
- **NIST SP 800-77 Rev. 1**: Guide to IPsec VPNs, establishing approved cipher suites and policy compliance profiles.
- **NIST SP 800-131A Rev. 2**: Transitions for cryptographic key lengths and algorithms (disallowing legacy 3DES, MD5, SHA-1).

## 2. Encrypted Traffic Classification Literature
- **FlowPic (Shapira & Shavitt, 2019)**: Visual/2D CNN representation of encrypted flow packet size and arrival time histograms.
- **Deep Packet (Lotfollahi et al., 2020)**: 1D CNN and stacked autoencoders for encrypted traffic classification.
- **MIMETIC (Aceto et al., 2019)**: Multimodal deep learning for encrypted mobile traffic analysis.
- **ET-BERT (Lin et al., 2022)**: Pre-trained contextual representations for encrypted network traffic.
""",

    "05_RESEARCH_GAP.md": """# 05 — Research Gap Analysis

## 1. What Existing Work Does
Existing research treats network security analysis in silos:
- **Protocol Analyzers (e.g., Wireshark)**: Decode protocol packets individually but do not infer encrypted application behavior or evaluate high-level security policies.
- **ML Traffic Classifiers**: Predict application labels from encrypted flows but ignore IKE control-plane security context, SPI negotiation, and cryptographic policy compliance.
- **Security Audit Tools**: Inspect configuration files offline but cannot verify empirical on-the-wire traffic behavior.

## 2. The IPsecTrace Integrated Contribution
IPsecTrace bridges these isolated capabilities into a unified **Evidence-Aware Cross-Plane Analysis Framework**:
```
IKE Control Plane  ──┐
                     ├─► Cross-Plane Evidence Fusion ─► Deterministic Security Policy
ESP Data Plane     ──┤                                  + Explainable AI Inference
Flow Dynamics      ──┘
```
""",

    "06_PROPOSED_SOLUTION.md": """# 06 — Proposed End-to-End Solution

```
Raw PCAP / Ingestion ─► Packet Normalization ─► Control/Data Plane Demux
                              │
               ┌──────────────┴──────────────┐
               ▼                             ▼
        IKE Analyzer                  ESP/AH Analyzer
      (State Machine)              (Flow & Seq Extractor)
               │                             │
               └──────────────┬──────────────┘
                              ▼
                     Evidence Fusion Graph
                              │
               ┌──────────────┴──────────────┐
               ▼                             ▼
       AI / OOD Engine            Security Policy Engine
   (Behavioral Inference)      (Deterministic RFC Compliance)
               │                             │
               └──────────────┬──────────────┘
                              ▼
                  Unified Analyst Dashboard
                  & Evidence-Linked Reports
```

Each stage operates under strict contracts, ensuring that missing evidence (e.g., an uncaptured IKE handshake) results in graceful partial-session analysis rather than system failure.
""",

    "07_SYSTEM_ARCHITECTURE.md": """# 07 — Layered System Architecture & Component Status

| Layer / Zone | Primary Component | Technology Stack | Status |
| :--- | :--- | :--- | :--- |
| **Zone 1: Testbed** | Linux XFRM Network Namespaces | Linux Kernel, iproute2, `tc netem` | **IMPLEMENTED & VALIDATED** |
| **Zone 2: Ingestion** | Scapy / Offline PCAP Reader | Python 3, Scapy 2.5 | **IMPLEMENTED & VALIDATED** |
| **Zone 3: Control Plane** | Stateful IKE Parser & SA Store | Python IKE State Machine | **IMPLEMENTED & VALIDATED** |
| **Zone 4: Data Plane** | ESP Header & Flow Extractor | Python, NumPy, Pandas | **IMPLEMENTED & VALIDATED** |
| **Zone 5: ML Engine** | GroupKFold Classifier & OOD | Scikit-learn, XGBoost | **IMPLEMENTED & VALIDATED** |
| **Zone 6: Policy Engine** | Deterministic RFC Rule Engine | Python Policy Engine | **IMPLEMENTED & VALIDATED** |
| **Zone 7: Dashboard** | Interactive Web GUI & Charts | Angular / SCSS / Apache ECharts | **PROTOTYPE / PROPOSED** |
| **Zone 8: Live Streaming** | eBPF / AF_XDP Capture Agent | C / eBPF / Go | **FUTURE WORK** |
""",

    "10_DATASET_AND_DATA_PIPELINE.md": """# 10 — Dataset Documentation, Provenance & Taxonomy

## 1. Master Dataset Provenance Hierarchy
- **Tier 1 (Native IPsec Ground Truth)**: `DS1_NATIVE_IPSEC_LARGE` (5,482 baseline flow windows (1.0s) / 1,829 enhanced multi-scale windows (3.0s)from 294 raw `.pcap` files generated in local Linux kernel XFRM testbeds with AES-128-CBC + HMAC-SHA256 ESP encapsulation).
- **Tier 2 (Auxiliary Encrypted VPN)**: `DS4_ISCX_SCENARIO_B` (13,655 samples from UNB ISCX VPN-nonVPN 2016) and `DS_ENCRYPTED_VPN_JSON` (5,103 samples).

## 2. Reconciled Arithmetic Consistency
- **Total Canonical Phase 2 Samples**: **`18,842 = 84 (DS1 Custom) + 18,758 (DS4 ISCX Scenario B)`**
- **Semantic Class Breakdown**: **`78 (Custom Non-ICMP) + 13,661 (ISCX Non-ICMP) + 5,103 (ICMP Class) = 18,842`**
- **Verified Arithmetic Check**: `Match = True` (Audited in `results/dataset_reconciliation.json`).
""",

    "16_FINAL_EXPERIMENTAL_RESULTS.md": """# 16 — Authoritative Experimental Benchmark Results

## 1. Authoritative Phase 2 Generalization Benchmark (18,842 Samples, 5-Fold GroupKFold)

| Model | Accuracy Mean ± Std | Macro-F1 Mean ± Std | 95% Confidence Interval (F1) |
| :--- | :--- | :--- | :--- |
| **Random Forest (100 Trees)** | **`89.84% ± 0.51%`** | **`88.30% ± 0.51%`** | **`88.30% ± 0.44%`** |
| **XGBoost** | **`87.17% ± 0.34%`** | **`84.92% ± 0.27%`** | **`84.92% ± 0.23%`** |
| **Logistic Regression** | **`63.51% ± 0.23%`** | **`51.73% ± 0.28%`** | **`51.73% ± 0.24%`** |
| **Dummy Baseline** | **`31.13% ± 0.00%`** | **`11.87% ± 0.00%`** | **`11.87% ± 0.00%`** |

## 2. Native IPsec ESP Benchmark (5,482 Samples, 5-Fold GroupKFold)
- **Random Forest**: **`57.33% ± 16.15% Accuracy`** | **`57.14% ± 7.80% Macro-F1`**
- **XGBoost**: **`56.80% ± 14.99% Accuracy`** | **`55.96% ± 6.93% Macro-F1`**

## 3. Enhanced Feature Pipeline (3.0s Windows + Quantiles + Direction, 1,829 Samples)
- **XGBoost**: **`63.40% Accuracy`** | **`70.53% Macro-F1`**
- **Random Forest**: **`62.52% Accuracy`** | **`69.36% Macro-F1`**
""",

    "27_FINAL_JUDGE_QA.md": """# 27 — Final Technical Judge Q&A Defense Sheet

### Q1: Why did Random Forest get 100% in Phase 1 and drop to ~58% in Native IPsec GroupKFold?
**Answer**: Phase 1 used a small 84-sample dataset with a randomized split, causing temporal autocorrelation leakage between packets of the same session. In Phase 2, we enforced strict 5-fold session-isolated `GroupKFold` (`CROSS_FOLD_GROUP_OVERLAP = 0`), eliminating leakage and revealing the true empirical difficulty of encrypted traffic classification.

### Q2: Do you decrypt the IPsec ESP payload?
**Answer**: **No.** Payload decryption is cryptographically unfeasible without private keys. IPsecTrace relies strictly on non-payload metadata: packet length distributions, directional byte ratios, and inter-arrival timing dynamics.

### Q3: Is the 18,842 dataset pure native IPsec?
**Answer**: **No.** In our taxonomy, 84 samples are native lab IPsec, and 18,758 samples are from UNB ISCX Scenario B (OpenVPN/SSL). We clearly distinguish Tier 1 Native IPsec from Tier 2 Auxiliary Encrypted VPN benchmarks.
""",

    "28_REFERENCES.md": """# 28 — Authoritative Research References & Standards

1. **RFC 7296**: Kaufman, C., et al. "Internet Key Exchange Protocol Version 2 (IKEv2)." IETF RFC 7296, 2014.
2. **RFC 4303**: Kent, S. "IP Encapsulating Security Payload (ESP)." IETF RFC 4303, 2005.
3. **RFC 4302**: Kent, S. "IP Authentication Header (AH)." IETF RFC 4302, 2005.
4. **NIST SP 800-77 Rev. 1**: Frankel, S., et al. "Guide to IPsec VPNs." NIST Special Publication 800-77, 2020.
5. **NIST SP 800-131A Rev. 2**: Barker, E., et al. "Transitioning the Use of Cryptographic Algorithms and Key Lengths." NIST SP 800-131A, 2019.
6. **ISCX VPN-nonVPN 2016**: Draper-Gil, G., et al. "Characterization of Encrypted Traffic with Storage and Service Applications." ICISSP, 2016.
7. **FlowPic**: Shapira, T. & Shavitt, Y. "FlowPic: Encrypted Internet Traffic Classification is as Easy as Image Recognition." IEEE INFOCOM Workshops, 2019.
8. **Deep Packet**: Lotfollahi, M., et al. "Deep Packet: A Novel Approach for Encrypted Traffic Classification Using Deep Learning." Soft Computing, 2020.
"""
}

def generate_part2():
    for name, content in DOCS_PART2.items():
        fpath = os.path.join(MASTER_DIR, name)
        with open(fpath, "w", encoding="utf-8") as f:
            f.write(content.strip() + "\n")
        print(f"Generated {name}")

if __name__ == "__main__":
    generate_part2()
