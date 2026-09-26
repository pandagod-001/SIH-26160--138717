# IPsecTrace — Final Repository Forensic Audit & Package Verification

**Audit Date**: September 24, 2026  
**Repository State**: Clean Final Research Package  
**Test Suite Status**: 30/30 Passing (`backend/tests/test_prototype.py`)

---

## 1. Quantitative Inventory Comparison

| Metric | Before Audit | After Audit & Cleanup | Delta |
| :--- | :---: | :---: | :---: |
| **Total Non-Ignored Files** | 1,125 | **865** | -260 files |
| **Markdown Documents** | 143 | **18** | -125 obsolete/duplicated files consolidated |
| **Images & Figures** | 79 | **34** | -45 obsolete charts removed, 15 regenerated |
| **Model Artifacts** | 5 | **5** | Authoritative models preserved |
| **Datasets & PCAP Files** | 370 | **344** | Intermediate duplicates cleaned, 294 source PCAPs preserved |

---

## 2. Directory & Artifact Cleanup Details

### Deleted Obsolete / Redundant Artifacts:
1. `IPsecTrace_FINAL_MASTER/` (210 files) — Obsolete unaligned development tree (fully preserved in `IPsecTrace_FINAL_MASTER_ARCHIVE.zip`).
2. `SIH_EVIDENCE/` (63 files) — Deprecated competition scratch notes (fully preserved in `SIH_EVIDENCE.zip`).
3. `archive/` (7 files) — Historical superseded scratch files.
4. `results/figures/` (19 files) — Outdated single-fold charts with obsolete metrics.

### Regenerated High-Resolution Figures in `results/final/`:
- `results/final/figures/model_accuracy_comparison.png`
- `results/final/figures/model_macro_f1_comparison.png`
- `results/final/figures/model_weighted_f1_comparison.png`
- `results/final/figures/fold_accuracy_variance.png`
- `results/final/figures/per_class_f1_comparison.png`
- `results/final/figures/dataset_class_distribution.png`
- `results/final/figures/ood_distance_distribution.png`
- `results/final/confusion_matrices/a_xgboost_confusion_matrix.png`
- `results/final/confusion_matrices/b1_transformer_confusion_matrix.png`
- `results/final/confusion_matrices/b2_protocol_aware_confusion_matrix.png`
- `results/final/confusion_matrices/b3_ssl_pretrained_confusion_matrix.png`
- `results/final/confusion_matrices/c_hybrid_tabular_confusion_matrix.png`
- `results/final/confusion_matrices/d_multiview_ipsec_confusion_matrix.png`
- `results/final/architecture/system_architecture_diagram.png`
- `results/final/pcap_demos/real_pcap_demonstration_summary.png`

---

## 3. Authoritative Multi-Model Benchmark (5-Fold GroupKFold)

| Model | Accuracy (Mean ± Std) | Macro-F1 (Mean ± Std) | Weighted-F1 (Mean ± Std) | Delta Acc vs Baseline |
| :--- | :---: | :---: | :---: | :---: |
| **Model A: Canonical XGBoost Baseline** | 66.91% ± 18.66% | 73.91% ± 4.84% | 68.22% ± 18.65% | +0.00% |
| **Model B1: Sequence Transformer** | 69.96% ± 26.40% | 77.66% ± 14.59% | 68.29% ± 30.87% | +3.05% |
| **Model B2: Protocol-Aware Sequence** | 67.23% ± 22.06% | 70.95% ± 10.62% | 64.75% ± 26.99% | +0.32% |
| **Model B3: SSL Pretrained Sequence** | 72.25% ± 25.73% | 76.18% ± 13.33% | 68.51% ± 30.06% | +5.35% |
| **Model C: Hybrid Tabular + Sequence** | **80.25% ± 13.77%** | **81.89% ± 9.15%** | **81.56% ± 12.48%** | **+13.35%** |
| **Model D: Multi-View IPsec** | 61.33% ± 25.07% | 70.28% ± 9.54% | 58.13% ± 30.02% | -5.58% |

---

## 4. Zero-Leakage Protocol Audit

- **Partition Boundaries**: 5-Fold `GroupKFold` on `experiment_group`. Train PCAPs ∩ Test PCAPs = ∅ across all 5 folds (**0% PCAP and 0% Group leakage**).
- **Preprocessing Isolation**: Feature standardizations (`log1p` + `StandardScaler`), sequence padding, and embedding centroids were fit strictly on the training partition of each fold.
- **SSL Isolation**: The self-supervised masked sequence reconstruction objective (Model B3) was trained strictly on `train_seq[train_idx]`.

---

## 5. Real-PCAP Dynamic Inference Verification

- **WEB Traffic Capture**: 516 pkts, 343 ESP pkts, Top-1 Probability = **96.84%**, Confidence Margin = **94.12%** (HIGH Separation).
- **ICMP Traffic Capture**: 83 pkts, 48 ESP pkts, Top-1 Probability = **99.97%**, Confidence Margin = **99.95%** (HIGH Separation).
- **BULK Traffic Capture**: 306 pkts, 183 ESP pkts, Top-1 Probability = **99.81%**, Confidence Margin = **99.69%** (HIGH Separation).

---

## 6. Authoritative Documentation Index (`docs/`)

```
docs/
├── 00_README.md
├── 01_RESEARCH_OVERVIEW.md
├── 02_PROBLEM_STATEMENT.md
├── 03_SYSTEM_ARCHITECTURE.md
├── 04_DATASET_AND_METHODOLOGY.md
├── 05_DETERMINISTIC_PROTOCOL_FORENSICS.md
├── 06_ML_AND_REPRESENTATION_LEARNING.md
├── 07_RESULTS_AND_ABLATION.md
├── 08_OOD_AND_NOVELTY.md
├── 09_REAL_PCAP_DEMONSTRATIONS.md
├── 10_SECURITY_ASSESSMENT.md
├── 11_LIMITATIONS_AND_FUTURE_WORK.md
└── 12_FINAL_PAPER_STRUCTURE.md
```

---

## 7. Backend Testing Verification

```
cd backend
python -m pytest tests/test_prototype.py
======================= 30 passed, 5 warnings in 14.00s =======================
```
All 30 backend tests pass, verifying non-blocking research inference, backward-compatible API schemas, and strict deterministic protocol authority.
