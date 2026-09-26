# DO NOT USE — Stale / Superseded Claims & Numbers

This document lists historical, preliminary, or superseded numbers that must **NOT** be used in the final SIH 2026 presentation or technical reports.

---

| Superseded Claim / Number | Context & Reason for Disqualification | Correct Authoritative Replacement |
| :--- | :--- | :--- |
| ❌ **100% Random Forest Accuracy** | From Phase 1 pilot on 5,482 baseline samples (1,829 enhanced samples) with randomized 70/30 split. Caused by temporal autocorrelation leakage between packets of the same session. | **58.32% Macro-F1 (baseline)** / **70.53% Macro-F1 (enhanced)** on 5,482 baseline flow windows (1.0s) / 1,829 enhanced multi-scale windows (3.0s)under 5-Fold GroupKFold. |
| ❌ **Old OOD Confidence (0.6616 (Held-out ID) / 0.4363 (Unseen OOD))** | Measured on seen training distributions rather than untouched held-out test splits. | **Held-Out ID: 66.16%** / **Unseen OOD: 43.63%** (**AUROC = 0.9077**). |
| ❌ **"Mean Maximum Predicted Probability" for RF** | Random Forest outputs empirical decision tree vote proportions, not softmax probabilities. | **Mean Maximum Predicted Class Probability**. |
| ❌ **"Set E recovers >99% of performance"** | Inaccurate historical arithmetic (0.8542 / 0.8830 = 96.7%). | In recomputed native ablation, **Set E achieves 60.85% Macro-F1** (optimal standalone subset). |
| ❌ **"Replay Protection = PASS"** | Passive PCAPs cannot observe internal receiver-side kernel SADB replay window bitmasks. | **Observed Sequence Progression = VERIFIED**; **Receiver Window State = NOT OBSERVABLE**. |
| ❌ **"88.30% Macro-F1 on IPsec"** | The 18,842 dataset is from UNB ISCX (OpenVPN/SSL), which is an auxiliary VPN benchmark, not Native IPsec ESP. | **Primary Native IPsec: 70.53% Macro-F1 (XGBoost)**; Auxiliary VPN Benchmark: 88.30% Macro-F1 (RF). |
| ❌ **"Synthetic Group Counts (38 / 90 groups)"**| Derived from artificial index modulo partitioning on auxiliary data. | Native IPsec evaluations use **157 genuine session groups** (0% cross-fold leakage). |
| ❌ **"IPsecTrace decrypts IPsec payloads"** | Violates fundamental cryptography (AES-128-CBC / AES-256-GCM). | **Non-payload encrypted traffic behavioral modeling** (lengths, direction, throughput, timing). |
