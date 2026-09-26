# IPsecTrace — Repository Migration & Restructuring Report

## Executive Summary
This report documents the architectural restructuring of the **IPsecTrace** project into two clean, self-contained repositories:
1. **IPsecTrace (Research & Evidence Repository)**: Retains the complete historical and scientific evidence, full 294-PCAP dataset, raw benchmarks, confusion matrices, figures, generated 2-minute master video, 6 Google Drive whitepapers, and complete experimental methodology.
2. **IPsecTrace_PROTOTYPE (Standalone Prototype Code Repository)**: A lean, isolated, runnable implementation of the current working prototype containing only what is strictly necessary to install, inspect, test, and run the pipeline.

---

## 1. Repository Structure Breakdown

### A. Existing Research Repository (`IPsecTrace/`)
- **Location**: `c:\Users\Abhijay\ipsec`
- **Scope**: Full research, forensic datasets, model benchmarks, evaluation scripts, and multi-format evidence.
- **Key Artifacts Retained**:
  - `data/` (294 raw PCAP captures across all traffic classes: Bulk, Web, Interactive, ICMP)
  - `research/` & `scripts/` (evaluation scripts, 5-fold GroupKFold validation pipelines, confusion matrix generators)
  - `docs/` & `IPsecTrace_GOOGLE_DRIVE_RESEARCH_PACKAGE/` (7 structured DOCX whitepapers, markdown architectural docs, high-res figures)
  - `demo/output/` (Master 120.33s / 2.01 min demo video `IPsecTrace_RESEARCH_DEMO.mp4`, subtitle track `.srt`, build reports)
  - `models/` (Baseline XGBoost models, PyTorch sequence transformers, metadata)

### B. New Prototype Repository (`IPsecTrace_PROTOTYPE/`)
- **Location**: `c:\Users\Abhijay\ipsec\IPsecTrace_PROTOTYPE`
- **Total Files**: 38 files
- **Total Size**: ~8.5 MB (excluding git metadata / virtual environments)
- **Structure**:
```text
IPsecTrace_PROTOTYPE/
├── README.md                  # Comprehensive prototype overview, capabilities, setup & demo
├── LICENSE                    # Standard MIT License
├── requirements.txt           # Minimal runtime dependencies (FastAPI, Scapy, Torch, XGBoost)
├── pyproject.toml             # Python packaging & pytest path configuration
├── .env.example               # Example configuration without secrets
├── .gitignore                 # Standard clean ignore list
│
├── app/                       # Core FastAPI & Ingestion Engine
│   ├── api/                   # REST API endpoints (/upload, /audit, /health)
│   ├── database/              # SQLite ORM session and schema models
│   ├── evidence/              # Evidence fusion and SOC attribution generator
│   ├── features/              # Direction-aware flow builder & temporal windowing
│   ├── ingestion/             # DPKT/Scapy PCAP reader and packet parser
│   ├── ml/                    # Hybrid Model C loader, XGBoost inference, OOD scorer
│   ├── protocols/             # Deterministic IKE & ESP protocol dissectors
│   ├── security/              # NIST SP 800-77 Rev. 1 deterministic compliance rules
│   ├── sessions/              # SPI tracker and SA state reconstructor
│   └── main.py                # Backend FastAPI application entrypoint
│
├── src/                       # Packaged Python library components
│   ├── ipsectrace/            # Sequence tensor extractors & window builders
│   └── ml/                    # MultiViewSequenceClassifier PyTorch model architecture
│
├── models/                    # Verified model checkpoints & authoritative metadata
│   ├── model_metadata.json    # XGBoost authoritative class ordering & features
│   ├── xgb_native_ipsec.json  # Native XGBoost tabular model
│   └── research/              # PyTorch Sequence Transformer (Model C)
│       ├── multiview_sequence_classifier.pt
│       └── research_model_metadata.json
│
├── sample_data/               # Minimal representative evaluation PCAPs (1 per class)
│   ├── sample_bulk.pcap       # Bulk transfer capture
│   ├── sample_web.pcap        # Web browsing capture
│   ├── sample_interactive.pcap# Interactive / SSH capture
│   └── sample_icmp.pcap       # ICMP tunneling capture
│
├── tests/                     # 30 passing pytest test fixtures
│   └── test_prototype.py      # Full unit, integration, and security rule test suite
│
├── demo/                      # Standalone demo runners
│   ├── run_demo.py            # One-command CLI demonstration harness
│   └── start_demo.sh          # Linux/Bash shell runner wrapper
│
└── docs/                      # Essential technical documentation
    ├── ARCHITECTURE.md        # Technical pipeline and multi-modal architecture
    ├── SETUP.md               # Step-by-step installation and environment guide
    ├── PROTOTYPE_STATUS.md    # Implemented vs Experimental vs Future Work matrix
    └── REPRODUCIBILITY.md     # Authoritative benchmark figures & verification steps
```

---

## 2. Inventory & Audit Summary

| Category | Research Repo (`IPsecTrace`) | Prototype Repo (`IPsecTrace_PROTOTYPE`) | Rationale / Status |
| :--- | :--- | :--- | :--- |
| **PCAPs** | 294 files (full corpus) | 4 files (`sample_data/`) | One minimal sample per traffic class for zero-overhead validation. |
| **Models** | All checkpoints & backups | 2 active models (XGBoost + Model C) | Only production inference models are included. |
| **Source Code** | Complete backend + research | Modular `app/`, `src/`, `demo/` | Clean runtime without legacy experiment scripts. |
| **Tests** | 30 tests | 30 tests (`pytest tests/ -v`) | 100% test pass rate in isolated environment. |
| **Documentation** | Full papers, DOCX, reports | 5 core technical docs | Focused on setup, architecture, and prototype capabilities. |
| **Media** | MP4 video, raw clips, WAVs | Excluded | Video and rendering assets retained in research archive. |

---

## 3. Active Branding Migration

- **Canonical Brand**: `IPsecTrace`
- **Obsolete Brands Eliminated from Active Use**: `SENTRY-IPSEC`, `SENTRY IPSEC`, `ENTRY-IPSEC`, `IP TRACE`, `IP Trace`.
- **Files Updated Across Workspaces**: Over 114 markdown files, Python modules, FastAPI documentation, test suites, CLI runners, and build scripts.
- **Intentionally Preserved Technical Identifiers**:
  - `sentry_ipsec.db` (local SQLite connection string to avoid breaking active database schema state)
  - Historical commit logs (Git history preserved intact without rewriting)

---

## 4. Scientific Rigor & Benchmark Integrity
No scientific numbers, benchmark metrics, or experimental methodologies were altered:
- **Hybrid Model C Performance**:
  - **80.25% Mean Accuracy** (evaluated under 5-fold GroupKFold capture/group-disjoint separation)
  - **81.89% Macro-F1**
  - **81.56% Weighted-F1**
- **OOD Novelty Component**: Formally documented as an **experimental novelty indicator** (Mahalanobis distance AUROC = 0.9962), not a guaranteed unknown traffic detector.
- **Zero Decryption**: Strictly labeled as **Protocol-Aware Encrypted IPsec Traffic Analysis without payload decryption**. Payload contents remain `NOT_OBSERVABLE`.

---

## 5. Verification & Test Execution

### Prototype Test Suite
```bash
cd IPsecTrace_PROTOTYPE
pytest tests/ -v
# Result: 30 passed, 5 warnings in 13.94s
```

### Prototype Demo Execution
```bash
cd IPsecTrace_PROTOTYPE
python demo/run_demo.py --pcap sample_data/sample_bulk.pcap
# Result: SUCCESS (2.66s pipeline execution, dynamic dissection, 97.46% BULK classification, NIST audit)
```
