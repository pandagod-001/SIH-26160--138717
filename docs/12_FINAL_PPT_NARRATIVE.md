# 12. IPsecTrace — Final Presentation (PPT) Narrative

**Presentation Title**: IPsecTrace: Protocol-Aware Multi-View AI for Native IPsec Security Analysis & Encrypted Traffic Classification  
**Target Length**: 12–14 Slides  
**Audience**: Technical Evaluators, Defense Panels, Security Researchers

---

### Slide 1: Title & Core Problem
- **Headline**: IPsecTrace — Protocol-Aware Multi-View Security Analysis for Encrypted IPsec Tunnels
- **The Core Problem**: Layer 4 headers and application payloads are encrypted inside ESP (proto 50). Deep Packet Inspection (DPI) fails completely without breaking cryptographic keys.
- **Visual**: Raw ESP ciphertext packet diagram showing encrypted TCP/UDP headers.

---

### Slide 2: Research Motivation & Gap
- **Limitations of Prior Art**:
  - Aggregate tabular ML models discard temporal packet order, burst dynamics, and inter-arrival timing.
  - Blind ML models act as black boxes and risk hallucinating cryptographic facts or overfitting.
  - No existing system combines deterministic IKE control-plane evidence with encrypted-side temporal representations.
- **Core Research Question**: Can protocol-aware multi-view AI classify encrypted traffic and assess risk without decrypting ESP payloads?

---

### Slide 3: Proposed Architecture Overview
- **Three-Pillar Architecture**:
  1. **Deterministic Parser**: Authoritative for IKE ciphers, DH groups, SPIs, and replay protection.
  2. **Multi-View Neural Model**: Tabular flow properties (View A) + Transformer sequence dynamics (View B).
  3. **Evidence Fusion & Explanation**: Strict attribution markers (`DETERMINISTIC`, `ML`, `OOD`).
- **Visual**: `results/final/architecture/system_architecture_diagram.png`

---

### Slide 4: Dataset & Zero-Leakage Evaluation Protocol
- **Dataset**: `DS1_NATIVE_IPSEC_ENHANCED` (1,829 flow windows across 294 real physical PCAPs and 157 experiment groups).
- **Zero-Leakage Guarantee**: 5-Fold `GroupKFold` on `experiment_group`.
- **Key Metric**: Train PCAP ∩ Test PCAP = ∅ (**0% PCAP and 0% Group leakage**).
- **Visual**: `results/final/figures/dataset_class_distribution.png`

---

### Slide 5: Authoritative Multi-Model Benchmark
- **The Comparison**:
  - Model A (XGBoost Baseline): **66.91%** Acc | **73.91%** Macro-F1
  - Model B1 (Sequence Transformer): **69.96%** Acc | **77.66%** Macro-F1
  - Model B3 (SSL Pretrained Sequence): **72.25%** Acc | **76.18%** Macro-F1
  - **Model C (Hybrid Tabular + Sequence)**: **80.25%** Acc | **81.89%** Macro-F1 (**+13.35% improvement**)
- **Visual**: `results/final/figures/model_accuracy_comparison.png`

---

### Slide 6: The Key Finding — Solving the Interactive vs Web Bottleneck
- **Why XGBoost Failed**: Misclassified 298/484 INTERACTIVE windows as WEB (INTERACTIVE F1 = **38.46%**).
- **How Hybrid Solved It**: Combining global statistical distributions with temporal burst dynamics raised INTERACTIVE F1 to **63.46%** (+25.00 percentage points).
- **Visual**: `results/final/figures/per_class_f1_comparison.png`

---

### Slide 7: Self-Supervised Learning (SSL) Pretraining
- **Objective**: Masked Packet Feature Reconstruction (unsupervised pretraining on train fold sequences).
- **Result**: Model B3 achieved **72.25% accuracy** (+5.35% over XGBoost and +2.29% over un-pretrained Sequence Transformer).
- **Key Insight**: SSL regularizes representations on difficult high-burst captures without requiring labeled data.

---

### Slide 8: Scientific Transparency — The Negative Multi-View Result
- **The Experiment**: Adding static Layer 3/4 context markers (`is_esp`, `direction_confidence`) in Model D dropped accuracy to **61.33%**.
- **The Scientific Reason**: In a pure native-IPsec testbed, `is_esp=1.0` in 100% of samples (zero entropy). Adding redundant projection layers diluted gradient flow.
- **Value**: Demonstrates rigorous empirical integrity rather than claiming "more features always win".

---

### Slide 9: Open-Set & Out-of-Distribution (OOD) Novelty Detection
- **Method**: Latent embedding distance to training centroids.
- **Result**: **AUROC = 0.9962** (In-distribution mean distance: 6.10 vs OOD mean distance: 22.57).
- **Unknown Detection Rate**: **98.2%** at 95th-percentile train threshold.
- **Visual**: `results/final/figures/ood_distance_distribution.png`

---

### Slide 10: Deterministic Cryptographic Authority & Real-PCAP Demo
- **Authoritative Rule**: Ciphers, keys, SPIs, and replay counters are parsed 100% deterministically. ML never hallucinates cryptographic facts.
- **Real-PCAP Verification**:
  - WEB Capture: 516 pkts, Top-1 Prob = **96.84%**, Margin = **94.12%** (HIGH Separation)
  - ICMP Capture: 83 pkts, Top-1 Prob = **99.97%**, Margin = **99.95%** (HIGH Separation)
  - BULK Capture: 306 pkts, Top-1 Prob = **99.81%**, Margin = **99.69%** (HIGH Separation)
- **Visual**: `results/final/pcap_demos/real_pcap_demonstration_summary.png`

---

### Slide 11: Production Backend & System Verification
- **Backend Architecture**: FastAPI asynchronous REST API + SQLite repository + non-blocking ML inference engine.
- **Testing Verification**: **30/30 test cases passing** (`backend/tests/test_prototype.py`).
- **Safety Rule**: Research failures remain isolated; deterministic security assessment is non-blocking.

---

### Slide 12: Limitations & Conclusion
- **Limitations**: Controlled testbed dataset (1,829 windows), pure native-IPsec scope, and OOD embedding distance remains experimental.
- **Conclusion**: IPsecTrace establishes that protocol-grounded hybrid AI achieves **80.25% accuracy** on encrypted ESP traffic while preserving 100% deterministic cryptographic authority.
