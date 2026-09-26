# IPsecTrace — PPT DATA (Official Presentation Information)

Use ONLY the information in this document for preparing the Smart India Hackathon 2026 PPT.

---

## 1. Problem Statement
- **Problem Statement ID**: 26160
- **Organization**: National Technical Research Organisation (NTRO)
- **Title**: AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework
- **Core Challenge**: IPsec Layer 3 ESP encryption creates an observability boundary. Traditional Deep Packet Inspection (DPI) fails because payload bytes are cryptographically scrambled into indistinguishable random noise.

---

## 2. Proposed Solution
An **Evidence-Aware IPsec Analysis Framework** that:
1. **Verifies** directly observable IKE control parameters (RFC 7296) and ESP headers (RFC 4303).
2. **Reconstructs** stateful session graphs (IKE Session ➔ Child SA ➔ ESP Flow).
3. **Infers** encrypted traffic behavior using machine learning on non-payload statistical metadata (directional byte ratios, packet length quantiles, and burst throughput).
4. **Evaluates** deterministic RFC cryptographic policy rules.
5. **Reports** explicit confidence and uncertainty states (`UNKNOWN`, `NOT OBSERVABLE`, `CONFLICT`) without attempting payload decryption.

---

## 3. Innovation & Uniqueness
- **Cross-Plane Evidence Fusion**: Correlates IKE control-plane proposals with ESP data-plane packet behavior.
- **Strict Leakage-Free Validation**: Enforces 5-Fold session-isolated GroupKFold cross-validation (0% session leakage), eliminating the false 100% accuracy trap.
- **Out-of-Distribution Handling**: Rejects unseen traffic streams with **0.9077 AUROC**.
- **Observability Discipline**: Explicitly marks internal receiver kernel states as `NOT OBSERVABLE` rather than asserting false certainty.

---

## 4. Technical Architecture
```
Testbed / Offline PCAP
         │
         ▼
Ingestion & Normalization
         │
    ┌────┴────────────────────────┐
    ▼                             ▼
Control Plane (IKEv2)       Data Plane (ESP / AH)
(State Machine & SAs)       (Flows, SPIs, Sequences)
    │                             │
    └────┬────────────────────────┘
         ▼
Cross-Plane Evidence Fusion Graph
         │
    ┌────┴────────────────────────┐
    ▼                             ▼
AI Behavioral Classifier    Deterministic Security Engine
(Quantiles + Direction)     (RFC 7296 / 4303 Compliance)
    │                             │
    └────┬────────────────────────┘
         ▼
Analyst Dashboard & Evidence-Linked Reports
```

---

## 5. Primary Validation (Native IPsec ESP Ground Truth)
- **Data Source**: 5,482 canonical flow windows from 294 raw PCAPs across 157 independent session groups (Linux kernel XFRM/ESP testbed).
- **Validation**: 5-Fold GroupKFold (**0% Session Overlap**).
- **Primary Results**:
  - Baseline (1.0s Window, 9 Summary Stats): Random Forest **58.37% Accuracy / 58.32% Macro-F1** (vs 25.0% random baseline).
  - Enhanced Multi-Scale (3.0s Window + Direction + Quantiles): **XGBoost achieves 63.40% Accuracy / 70.53% Macro-F1** (Random Forest: 62.52% Acc / 69.36% F1).
- **Per-Class Separation**: ICMP (**97.8% F1**), BULK (**95.5% F1**), WEB (**57.9% F1**), INTERACTIVE (**44.5% F1**).

---

## 6. Out-of-Distribution (OOD) Validation
- **AUROC**: **`0.9077`**
- **Held-Out In-Distribution Confidence**: **66.16%**
- **Unseen OOD Confidence (ICMP)**: **43.63%**
- **Operational Threshold ($\tau = 0.60$)**: Rejects **93.89%** of unknown traffic while retaining **60.04%** of valid in-distribution flows.

---

## 7. Auxiliary Validation (Large-Scale Multi-VPN Benchmark)
- **Dataset**: 18,842 canonical time-window vectors (UNB ISCX 2016).
- **Result**: Random Forest achieves **89.84% Accuracy / 88.30% Macro-F1**.
- **Scope**: Demonstrates feature extractor scalability on large public VPN benchmarks (clearly distinguished from Native IPsec ground truth).

---

## 8. Research References
- **RFC 7296**: Internet Key Exchange Protocol Version 2 (IKEv2), IETF, 2014.
- **RFC 4303**: IP Encapsulating Security Payload (ESP), IETF, 2005.
- **NIST SP 800-77 Rev. 1**: Guide to IPsec VPNs, NIST, 2020.
- **FlowPic**: Shapira & Shavitt, IEEE INFOCOM Workshops, 2019.
- **Deep Packet**: Lotfollahi et al., Soft Computing, 2020.
- **ET-BERT**: Lin et al., The Web Conference (WWW), 2022.
