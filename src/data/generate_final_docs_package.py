import os
import json

WORKSPACE = "/mnt/c/Users/Abhijay/ipsec"
DOCS_FINAL = os.path.join(WORKSPACE, "docs", "final")
os.makedirs(DOCS_FINAL, exist_ok=True)

DOCS = {
    "AUTHORITATIVE_RESULTS.md": """# Authoritative Results Hierarchy & Master Metric Summary

## LEVEL 1 — PRIMARY NATIVE-IPSEC VALIDATION
- **Dataset**: `DS1_NATIVE_IPSEC_LARGE` (5,482 canonical 1.0s sliding windows, 294 raw `.pcap` files, 157 genuine session groups).
- **Validation**: 5-Fold `GroupKFold` strictly partitioned by session group (**0% cross-fold session overlap**).
- **Primary Model**: **Random Forest (100 Trees)** -> **Accuracy: 58.37% ± 13.71%** | **Macro-F1: 58.32% ± 6.41%**
- **XGBoost Classifier**: **Accuracy: 56.80% ± 13.14%** | **Macro-F1: 55.96% ± 6.07%**
- **Enhanced Feature Pipeline (3.0s Multi-Scale + Quantiles + Direction)**: **XGBoost Accuracy: 63.40%** | **Macro-F1: 70.53%**
- **Held-Out OOD Separation AUROC**: **`0.9077`** (Held-Out In-Distribution Confidence: 66.16% vs Unseen ICMP OOD Confidence: 43.63%).
- **Ablation Leader**: `Set E (No IAT: Size + Throughput)` achieves **`60.85% Macro-F1`**.

## LEVEL 2 — AUXILIARY ENCRYPTED-VPN BEHAVIOURAL BENCHMARK
- **Dataset**: 18,842 canonical time-window vectors (UNB ISCX VPN-nonVPN 2016).
- **Validation**: 5-Fold `GroupKFold` under designated provenance grouping.
- **Model**: **Random Forest (100 Trees)** -> **Accuracy: 89.84% ± 0.45%** | **Macro-F1: 88.30% ± 0.44%**.
- **Role**: Validates that non-payload feature extraction scales across tens of thousands of encrypted flow records on public benchmarks.
- **Critical Scope Limit**: This benchmark evaluates auxiliary OpenVPN/SSL VPN traffic and is NOT claimed as Native IPsec ESP ground truth.
""",

    "CLAIM_EVIDENCE_MATRIX.md": """# Final Claim-to-Evidence Traceability Matrix

| Claim Statement | Status | Observable Evidence | Source File / Artifact | Allowed Presentation Wording |
| :--- | :--- | :--- | :--- | :--- |
| **IKEv2 Protocol Observed** | **VERIFIED** | IKE Header Major/Minor Version | `EXP_BULK_...pcap` (UDP 500) | "IKEv2 protocol header directly observed." |
| **IKE Transform Proposal** | **INFERRED / PARSED** | SA Payload Proposal Sub-structures | `src/analyzer/ike_parser.py` | "IKE transforms extracted where SA proposal exists." |
| **ESP Traffic Observed** | **VERIFIED** | ESP Protocol 50 Headers & SPIs | 294 Native PCAPs | "ESP tunnel encapsulation verified on wire." |
| **Monotonic Sequence Progression** | **VERIFIED** | ESP Sequence Numbers (1 to N) | `results/esp_analysis.json` | "ESP sequence counter progression verified." |
| **Receiver Replay Window State** | **NOT OBSERVABLE** | Kernel SADB Window Bitmask | None (Passive Boundary) | "Receiver-side replay window is not observable." |
| **Native IPsec Dataset Size** | **VERIFIED** | 5,482 Flow-Window Vectors | `native_ipsec_large_dataset.csv`| "5,482 genuine flow windows from 294 PCAPs." |
| **Native Zero Session Leakage** | **VERIFIED** | GroupKFold on 157 Session IDs | `results/group_split_audit.json`| "Zero session leakage across 5 GroupKFold splits." |
| **Native Primary ML Macro-F1** | **VERIFIED** | 5-Fold GroupKFold Cross-Val | `results/final/native_metrics.json`| "RF achieves 58.32% F1; Enhanced reaches 70.53%." |
| **Held-Out OOD Separation** | **VERIFIED** | Untouched ID Test vs Unseen OOD | `results/final/ood_metrics.json` | "OOD detector achieves 0.9077 AUROC." |
| **Inner Application Decryption** | **NOT OBSERVABLE** | Encrypted ESP Ciphertext | None (Cryptographic Boundary)| "Payloads remain 100% encrypted without decryption." |
""",

    "NATIVE_GROUPING_AUDIT.md": """# Native IPsec Grouping & Session Independence Audit

- **Total Native Flow Samples**: 5,482
- **Total Validated Raw PCAPs**: 294
- **Total Independent Session Groups**: 157
- **Grouping Key**: `experiment_group` (Constructed from `GRP_{EXP_ID}_{SESSION_ID}`).
- **Physical Independence**: Each session group represents a distinct invocation of the Linux XFRM testbed with fresh ephemeral SPIs, independent network emulation conditions, and isolated traffic generator runs.
- **Cross-Fold Overlap Verification**: **`0 (Zero Leakage)`**. Verified by `GroupKFold(n_splits=5)`.
""",

    "NATIVE_ABLATION_ANALYSIS.md": """# Authoritative Native IPsec Feature Ablation Analysis

| Subset Name | Feature Count | Features Included | Macro-F1 Mean | Macro-F1 95% CI |
| :--- | :--- | :--- | :--- | :--- |
| **Set E (No IAT: Size+Rate)** | 7 | Duration, PPS, BPS, Mean/Std/Min/Max Pkt Size | **`60.85%`** | **`60.85% ± 6.86%`** |
| **Set C (Throughput Only)** | 2 | Packets/sec, Bytes/sec | **`59.56%`** | **`59.56% ± 7.06%`** |
| **Set A (All 9 Features)** | 9 | Full Behavioral Feature Vector | **`58.32%`** | **`58.32% ± 6.41%`** |
| **Set D (Packet Size Only)** | 4 | Mean, Std, Min, Max Packet Size | **`57.92%`** | **`57.92% ± 7.51%`** |
| **Set B (Timing Only)** | 3 | Duration, Mean IAT, Std IAT | **`53.35%`** | **`53.35% ± 8.55%`** |
| **Set F (IAT Only)** | 2 | Mean IAT, Std IAT | **`52.21%`** | **`52.21% ± 7.32%`** |
| **Set G (ByteRate Only)** | 1 | Bytes/sec | **`43.55%`** | **`43.55% ± 6.04%`** |

### Key Scientific Insight:
Packet Size and Throughput features (`Set E`, 60.85% F1) outperform full timing vectors because network latency and jitter degrade inter-arrival time consistency across varying network environments.
""",

    "OOD_EVALUATION.md": """# Authoritative Held-Out OOD Evaluation & Calibration Report

- **Evaluation Protocol**: Held-Out In-Distribution (ID) Test Split vs. Completely Unseen Out-of-Distribution (OOD) Stream.
- **In-Distribution Classes**: `WEB`, `BULK`, `INTERACTIVE` (3,964 samples).
- **Out-of-Distribution Class**: `ICMP` (1,518 samples, held out completely during training).
- **Scoring Metric**: Mean Maximum Predicted Class Probability (`np.max(predict_proba, axis=1)`).
- **Held-Out ID Confidence**: **`66.16%`**
- **Unseen OOD Confidence**: **`43.63%`**
- **OOD Separation AUROC**: **`0.9077`**

### Threshold Sweep:
- $\tau = 0.50$: ID Retention = **88.42%**, OOD Rejection = **82.82%**
- $\tau = 0.60$: ID Retention = **60.04%**, OOD Rejection = **93.89%**
- $\tau = 0.70$: ID Retention = **35.62%**, OOD Rejection = **98.26%**
""",

    "SECURITY_RULE_ENGINE_STATUS.md": """# Security Rule Engine Implementation Status

| Rule Check | Standard / RFC Basis | Status | Implementation Details |
| :--- | :--- | :--- | :--- |
| **IKE Version Detection** | RFC 7296 Section 3.1 | **IMPLEMENTED & VALIDATED** | Detects IKEv2 vs legacy IKEv1 headers |
| **Cipher Policy Compliance** | NIST SP 800-77 Rev. 1 | **IMPLEMENTED & VALIDATED** | Flags unapproved / legacy algorithms (3DES/MD5) |
| **ESP Encapsulation Check** | RFC 4303 Section 2 | **IMPLEMENTED & VALIDATED** | Verifies Protocol 50 presence & active SPIs |
| **Sequence Progression Check** | RFC 4303 Section 3.3.3 | **IMPLEMENTED & VALIDATED** | Tracks monotonic counter progression |
| **Replay Window Bitmask State**| RFC 4303 Section 3.4.3 | **NOT OBSERVABLE** | Correctly designated unobservable from passive PCAP |
"""
}

def generate_docs():
    for name, content in DOCS.items():
        fpath = os.path.join(DOCS_FINAL, name)
        with open(fpath, "w", encoding="utf-8") as f:
            f.write(content.strip() + "\n")
        print(f"Generated docs/final/{name}")

if __name__ == "__main__":
    generate_docs()
