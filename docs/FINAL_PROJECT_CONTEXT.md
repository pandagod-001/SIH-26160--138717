# IPsecTrace — Final Project Context (Single Source of Truth)

**Project Name**: IPsecTrace  
**Title**: AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework  
**Hackathon**: Smart India Hackathon 2026 — Problem Statement 26160  
**Organization**: National Technical Research Organisation (NTRO)  
**Domain**: Cybersecurity / Cryptographic Protocol Analysis / Network Telemetry / AI-Assisted Security  
**Research & Benchmark Repository**: [https://github.com/pandagod-001/SIH-26160--138717](https://github.com/pandagod-001/SIH-26160--138717)  
**Prototype Implementation Repository**: [https://github.com/pandagod-001/IPsecTrace](https://github.com/pandagod-001/IPsecTrace)  

---

## 1. Core Idea & Philosophy
IPsecTrace is an evidence-aware IPsec analysis framework that combines deterministic protocol telemetry with non-payload encrypted-flow behavioral analysis, cross-plane correlation, and security-policy assessment without decrypting protected payloads.

- **Directly Observable**: IKE negotiation parameters (RFC 7296), ESP Protocol 50 headers, Security Parameter Indexes (SPIs), sequence progression, packet lengths, directional byte ratios, and timing dynamics.
- **Protected / Encrypted**: Inner IP headers and application payloads (protected by AES-128-CBC / AES-256-GCM).
- **Core Principle**: Do not guess what can be verified. Do not hide what cannot be known. Deterministic RFC checks always take precedence over AI predictions.

---

## 2. Primary Evidence Track: Native IPsec ESP Testbed Validation
This is the primary ground-truth evaluation of the IPsecTrace project.

- **Data Source**: Linux Kernel XFRM / Network Namespaces (`ns-client` <-> `ns-server`) with AES-128-CBC + HMAC-SHA256 ESP encapsulation.
- **Sample Count**: **5,482 genuine canonical flow windows**
- **Raw PCAP Captures**: **294 verified `.pcap` files**
- **Session Groups**: **157 genuine independent session groups** (Fresh ephemeral SPIs and isolated traffic generator runs).
- **Validation Scheme**: Strict 5-Fold `GroupKFold` cross-validation (**0% Cross-Fold Session Overlap**).

### Primary Native Machine Learning Results:
- **Baseline Short-Window (1.0s Window, 9 Summary Features)**:
  - Random Forest: **`58.37% Accuracy`** | **`58.32% Macro-F1`** (vs 25.0% Random Baseline)
  - XGBoost: **`56.80% Accuracy`** | **`55.96% Macro-F1`**
- **Enhanced Multi-Scale Pipeline (3.0s Window + Directional Ratios + Length Quantiles)**:
  - **XGBoost Classifier**: **`63.40% Accuracy`** | **`70.53% Macro-F1`**
  - **Random Forest**: **`62.52% Accuracy`** | **`69.36% Macro-F1`**
- **Per-Class Encrypted Separation (Enhanced)**:
  - `ICMP`: **97.8% F1** (Deterministic packet sizes 56B–1200B and periodic IAT)
  - `BULK`: **95.5% F1** (Sustained high-throughput MTU fill rate)
  - `WEB`: **57.9% F1** (Bursty HTTP request/response patterns)
  - `INTERACTIVE`: **44.5% F1** (Overlaps with small Web request packets)

---

## 3. Out-of-Distribution (OOD) Validation
- **Evaluation Scheme**: Model trained strictly on in-distribution application workloads (`WEB`, `BULK`, `INTERACTIVE`), tested against untouched ID test splits and completely unseen `ICMP` traffic as unknown OOD streams.
- **Scoring Method**: Mean Maximum Predicted Class Probability (`np.max(predict_proba, axis=1)`).
- **Held-Out ID Confidence**: **`66.16%`**
- **Unseen OOD Confidence**: **`43.63%`**
- **OOD Separation AUROC**: **`0.9077`**
- **Threshold Operational Point ($\tau = 0.60$)**: Retains **60.04%** of valid ID traffic while rejecting **93.89%** of unseen OOD streams.

---

## 4. Feature Ablation Insights
Evaluated across all 5,482 baseline flow windows (1.0s) / 1,829 enhanced multi-scale windows (3.0s)using 5-Fold GroupKFold:
- **`Set E (No IAT: Size + Throughput)`**: **`60.85% Macro-F1`** (Top standalone subset).
- **`Set C (Throughput Only)`**: **`59.56% Macro-F1`**.
- **`Set A (All 9 Features)`**: **`58.32% Macro-F1`**.
- **`Set D (Packet Size Only)`**: **`57.92% Macro-F1`**.
- **`Set B (Timing Only)`**: **`53.35% Macro-F1`**.
- **`Set G (ByteRate Only)`**: **`43.55% Macro-F1`**.

*Insight*: Encapsulated packet lengths and throughput dominate classification because simulated network latency (10ms–45ms) and jitter (2ms–5ms) degrade timing features.

---

## 5. Auxiliary Evidence Track: Large-Scale Encrypted VPN Benchmark
- **Dataset**: 18,842 canonical time-window vectors from UNB ISCX VPN-nonVPN 2016.
- **Model**: Random Forest achieves **89.84% Accuracy / 88.30% Macro-F1** under designated provenance grouping.
- **Scope**: Used strictly for large-scale external validation of feature extractors on public benchmarks. It is **NOT** claimed as Native IPsec ESP ground truth.

---

## 6. Deterministic Security Rules vs AI Independence
1. **IKE Protocol Analysis**: Parses RFC 7296 header fields, exchange types (`IKE_SA_INIT`, `IKE_AUTH`), and SA proposal transforms directly from packet bytes.
2. **Anti-Replay Progression**: Verifies monotonic ESP sequence numbering; explicitly designates internal receiver-side SADB window bitmask enforcement as `NOT OBSERVABLE` from passive PCAPs.
3. **Decoupled Architecture**: Security rule evaluations are 100% deterministic and strictly isolated from statistical ML predictions.
