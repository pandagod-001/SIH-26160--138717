# IPsecTrace — AI-Powered IPsec VPN Protocol Analyzer & Security Framework

**Smart India Hackathon 2026** | **Problem Statement**: 26160 | **Organization**: National Technical Research Organisation (NTRO)  
**Domain**: Cybersecurity / Network Security / Cryptographic Protocol Telemetry / Machine Learning  
**Research & Benchmark Repository**: [https://github.com/pandagod-001/SIH-26160--138717](https://github.com/pandagod-001/SIH-26160--138717)  
**Prototype Implementation Repository**: [https://github.com/pandagod-001/IPsecTrace](https://github.com/pandagod-001/IPsecTrace)  
**Final Status**: **`GREEN (100% Empirically Validated, Frozen, & Presentation-Ready)`**  

---

## 📌 Single Source of Truth for Presentation & PPT
For preparing the final SIH presentation, please refer **ONLY** to the documents in [`docs/`](file:///c:/Users/Abhijay/ipsec/docs):

1. 📄 **[`docs/PPT_DATA.md`](file:///c:/Users/Abhijay/ipsec/docs/PPT_DATA.md)** — Complete, clean data blocks ready for direct slide preparation.
2. 📄 **[`docs/FINAL_PROJECT_CONTEXT.md`](file:///c:/Users/Abhijay/ipsec/docs/FINAL_PROJECT_CONTEXT.md)** — Comprehensive technical single source of truth.
3. ⚠️ **[`docs/DO_NOT_USE_STALE_RESULTS.md`](file:///c:/Users/Abhijay/ipsec/docs/DO_NOT_USE_STALE_RESULTS.md)** — List of superseded/historical numbers to avoid.

> **CRITICAL NOTICE**: Do **NOT** use archived/superseded experiment reports in `archive/` for final metrics.

---

## 🚀 Key Authoritative Results Summary

- **Primary Native IPsec Evaluation (Linux XFRM ESP Testbed, 5,482 Samples, 294 PCAPs, 157 Groups, 0% Leakage)**:
  - **Baseline (1.0s Window, 9 Summary Features)**: Random Forest **58.37% Accuracy / 58.32% Macro-F1**
  - **Enhanced Pipeline (3.0s Window + Direction & Quantiles)**: **XGBoost achieves 63.40% Accuracy / 70.53% Macro-F1**
  - **Out-of-Distribution (OOD) Separation**: **0.9077 AUROC** (Held-out ID Conf: 66.16% vs Unseen OOD Conf: 43.63%)
  - **Top Feature Subset (Ablation)**: `Set E (No IAT: Size + Throughput)` achieves **60.85% Macro-F1**
- **Auxiliary Large-Scale VPN Benchmark (18,842 Samples, UNB ISCX)**:
  - Random Forest achieves **89.84% Accuracy / 88.30% Macro-F1** (clearly separated as auxiliary validation).

---

## 🛠️ Reproducing All Results

```bash
# In WSL2 / Linux Environment with Python 3.10+
cd /mnt/c/Users/Abhijay/ipsec
PYTHONPATH=. python3 src/audit/run_final_hardening_pass.py
python3 src/ml/run_final_native_model_comparison.py
python3 src/ml/run_real_ablation.py
python3 src/ml/run_heldout_ood.py
```

---

## 🧪 Research Branch: Sequence Learning on Encrypted ESP Streams

An experimental sequence-learning research branch operates in parallel to the production baseline:
- **Hypothesis**: Observable packet-level sequence representations (length, log-scaled IAT, direction, position) retain temporal dynamics discarded by 14 tabular aggregate features.
- **Leakage Control**: 5-Fold GroupKFold strictly isolated on `experiment_group` and physical PCAP boundaries (0% capture leakage).
- **Benchmark Results (`DS1_NATIVE_IPSEC_ENHANCED`, N=1,829)**:
  - **Baseline XGBoost**: Accuracy 66.91% ± 18.66%, Macro-F1 73.91% ± 4.84%
  - **Sequence Transformer**: Accuracy 71.33% ± 22.56%, Macro-F1 76.07% ± 11.09%
  - **Hybrid Classifier**: Accuracy 70.89% ± 23.55%, Macro-F1 71.43% ± 9.87%
- **Backend API Integration**: Non-blocking parallel inference via `/api/v1/analyses/{id}/prediction` and `/api/v1/analyses/{id}/research`.
- **Integrity Notice**: Deterministic protocol parsing (IKE ciphers, SA, replay state) remains strictly authoritative. The sequence model does not alter cryptographic facts. Full details in [`research_sequence_experiment.md`](file:///c:/Users/Abhijay/ipsec/research_sequence_experiment.md).

---

## 📁 Repository Directory Structure

```
IPsecTrace/
├── docs/                                  <- Presentation-Ready Documents
│   ├── FINAL_PROJECT_CONTEXT.md           <- Single Source of Truth
│   ├── PPT_DATA.md                        <- Structured Slide Content
│   ├── DO_NOT_USE_STALE_RESULTS.md        <- Warning List of Superseded Claims
│   └── final/                             <- Authoritative Metrics & Grouping Audits
│
├── src/                                   <- Clean Modular Source Code
│   ├── analyzer/                          <- RFC 7296 IKE & RFC 4303 ESP Parsers
│   ├── security/                          <- Deterministic Security Policy Engine
│   ├── testbed/                           <- Linux XFRM Capture & Feature Extraction
│   ├── ml/                                <- GroupKFold Benchmarks, Ablation, OOD, Sequence Models
│   ├── audit/                             <- Forensic Hardening & Manifest Generators
│   └── visualizer/                        <- 300 DPI Publication Figure Plotters
│
├── data/                                  <- Processed Canonical Datasets
│   └── processed/
│       ├── native_ipsec_large_dataset.csv     <- 5,482 Baseline Flow Windows
│       └── native_ipsec_enhanced_dataset.csv  <- 1,829 Enhanced Flow Windows
│
├── results/                               <- Authoritative Benchmark Outputs & Figures
│   ├── final/                             <- Active Serialized Metrics & Reports
│   └── figures/                           <- High-Resolution Presentation Charts

```
