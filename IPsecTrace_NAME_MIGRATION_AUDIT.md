# IPsecTrace — PROJECT NAME MIGRATION & ZERO-OLD-NAME AUDIT REPORT

**Canonical Project Identity**: `IPsecTrace`  
**Public-Facing Focus**: Protocol-Aware Encrypted IPsec Traffic Analysis & Security Assessment  
**Audit Date**: September 26, 2026  
**Status**: **100% COMPLETE & VALIDATED**

---

## 1. Migration Overview & Scope

A comprehensive, dependency-aware migration was performed across the entire repository to standardize the canonical project identity to **IPsecTrace**.

### Previous Identities Detected & Migrated:
- `SENTRY-IPSEC` / `SENTRY_IPSEC` / `Sentry-IPsec` / `Sentry IPsec` / `sentry_ipsec`
- `ENTRY-IPSEC` / `ENTRY IPSEC`
- `IP TRACE` / `IP Trace` / `ip_trace`

---

## 2. Updated Deliverables & Subsystems

### A. Google Drive Research Documentation Package
- Renamed directory: `IPsecTrace_GOOGLE_DRIVE_RESEARCH_PACKAGE/`
- All 7 authoritative DOCX files regenerated with custom Calibri/Navy styling:
  1. [`00_IPsecTrace_RESEARCH_INDEX.docx`](file:///c:/Users/Abhijay/ipsec/IPsecTrace_GOOGLE_DRIVE_RESEARCH_PACKAGE/00_IPsecTrace_RESEARCH_INDEX.docx)
  2. [`01_IPsecTrace_Executive_White_Paper.docx`](file:///c:/Users/Abhijay/ipsec/IPsecTrace_GOOGLE_DRIVE_RESEARCH_PACKAGE/01_IPsecTrace_Executive_White_Paper.docx)
  3. [`02_IPsecTrace_System_Architecture.docx`](file:///c:/Users/Abhijay/ipsec/IPsecTrace_GOOGLE_DRIVE_RESEARCH_PACKAGE/02_IPsecTrace_System_Architecture.docx)
  4. [`03_IPsecTrace_Dataset_Methodology.docx`](file:///c:/Users/Abhijay/ipsec/IPsecTrace_GOOGLE_DRIVE_RESEARCH_PACKAGE/03_IPsecTrace_Dataset_Methodology.docx)
  5. [`04_IPsecTrace_ML_Experiments_Results.docx`](file:///c:/Users/Abhijay/ipsec/IPsecTrace_GOOGLE_DRIVE_RESEARCH_PACKAGE/04_IPsecTrace_ML_Experiments_Results.docx)
  6. [`05_IPsecTrace_Security_Real_PCAP_Evidence.docx`](file:///c:/Users/Abhijay/ipsec/IPsecTrace_GOOGLE_DRIVE_RESEARCH_PACKAGE/05_IPsecTrace_Security_Real_PCAP_Evidence.docx)
  7. [`06_IPsecTrace_Reproducibility_Limitations_Future_Work.docx`](file:///c:/Users/Abhijay/ipsec/IPsecTrace_GOOGLE_DRIVE_RESEARCH_PACKAGE/06_IPsecTrace_Reproducibility_Limitations_Future_Work.docx)
  - Traceability manifest: [`source_manifest.md`](file:///c:/Users/Abhijay/ipsec/IPsecTrace_GOOGLE_DRIVE_RESEARCH_PACKAGE/source_manifest.md)
  - Package overview: [`README.md`](file:///c:/Users/Abhijay/ipsec/IPsecTrace_GOOGLE_DRIVE_RESEARCH_PACKAGE/README.md)

### B. High-Performance Master Video Generation
- Optimized engine created in [`demo/create_final_video.py`](file:///c:/Users/Abhijay/ipsec/demo/create_final_video.py) executing in **42.5 seconds** (previously hanging at 30+ minutes due to pyttsx3 COM loop contention).
- **Master Video Output**: [`demo/output/IPsecTrace_RESEARCH_DEMO.mp4`](file:///c:/Users/Abhijay/ipsec/demo/output/IPsecTrace_RESEARCH_DEMO.mp4)
  - Duration: **2.01 minutes (120.39s)**
  - Resolution: **1920x1080 (16:9 Full HD)** @ 30 FPS
  - File Size: **9.75 MB**
  - Audio: Win32 COM SAPI natural voiceover synchronized with 10 research cards
  - Subtitles: [`demo/output/IPsecTrace_FINAL_SUBTITLES.srt`](file:///c:/Users/Abhijay/ipsec/demo/output/IPsecTrace_FINAL_SUBTITLES.srt)
  - Silent Version: [`demo/output/IPsecTrace_RESEARCH_DEMO_WITHOUT_AUDIO.mp4`](file:///c:/Users/Abhijay/ipsec/demo/output/IPsecTrace_RESEARCH_DEMO_WITHOUT_AUDIO.mp4)

### C. Live Terminal Demonstration & Scripts
- Updated runner: [`demo/run_demo.py`](file:///c:/Users/Abhijay/ipsec/demo/run_demo.py)
- Updated shell orchestrators: [`demo/start_demo.sh`](file:///c:/Users/Abhijay/ipsec/demo/start_demo.sh), [`demo/record_demo.sh`](file:///c:/Users/Abhijay/ipsec/demo/record_demo.sh), and [`demo/aws/`](file:///c:/Users/Abhijay/ipsec/demo/aws/)
- Updated narration guides: [`demo/VOICEOVER_SCRIPT.md`](file:///c:/Users/Abhijay/ipsec/demo/VOICEOVER_SCRIPT.md), [`demo/DEMO_SCRIPT.md`](file:///c:/Users/Abhijay/ipsec/demo/DEMO_SCRIPT.md), [`demo/DEMO_VALIDATION.md`](file:///c:/Users/Abhijay/ipsec/demo/DEMO_VALIDATION.md)

---

## 3. Authoritative Scientific Results (Preserved Without Mutation)

- **Dataset**: `DS1_NATIVE_IPSEC_ENHANCED` (1,829 flow windows, 294 PCAPs, 157 experiment groups)
- **Validation**: Strict 5-Fold GroupKFold with 0% PCAP and 0% group leakage
- **Model A (XGBoost Baseline)**: 66.91% ± 18.66% Accuracy | 73.91% ± 4.84% Macro-F1
- **Model B1 (Sequence Transformer)**: 69.96% ± 26.40% Accuracy | 77.66% ± 14.59% Macro-F1
- **Model B2 (Protocol-Aware Sequence)**: 67.23% ± 22.06% Accuracy | 70.95% ± 10.62% Macro-F1
- **Model B3 (SSL Pretrained Sequence)**: 72.25% ± 25.73% Accuracy | 76.18% ± 13.33% Macro-F1
- **Model C (Winning Hybrid Model)**: **80.25% ± 13.77% Accuracy | 81.89% ± 9.15% Macro-F1 (+13.35% gain)**
- **Model D (Multi-View Negative Finding)**: 61.33% ± 25.07% Accuracy | 70.28% ± 9.54% Macro-F1
- **OOD Novelty Indicator**: AUROC = **0.9962** (In-Distribution Mean = 6.103 vs OOD Mean = 22.569)
- **Backend Test Suite**: **30 passed / 30 total tests (100% passing)**

---

## 4. Final Zero-Trace Audit Summary

- **Active User-Facing Occurrences of Old Branding**: **0**
- **Internal Database Identifier Preserved**: `sentry_ipsec.db` (Preserved locally to maintain backward compatibility with existing SQLite tables without breaking ORM connection strings).
- **Backend Test Status**: 30/30 unit & integration tests passing.
