import os
import json

WORKSPACE = "/mnt/c/Users/Abhijay/ipsec"
MASTER_DIR = os.path.join(WORKSPACE, "IPsecTrace_FINAL_MASTER")

DOCS = {
    "00_MASTER_README.md": """# IPsecTrace — Master Project Archive & Single Source of Truth

**Project**: IPsecTrace (AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework)  
**Hackathon**: Smart India Hackathon 2026 — Problem Statement 26160  
**Organization**: National Technical Research Organisation (NTRO)  
**Domain**: Cybersecurity / Cryptographic Protocol Analysis / Network Telemetry / AI-Assisted Security  
**Project Objective**: Build an evidence-aware IPsec VPN security analysis framework that reconstructs observable control/data plane parameters, infers encrypted flow behavior, evaluates security policies, and produces explainable findings without payload decryption.  
**One-Line Definition**: An evidence-aware IPsec analysis framework that correlates IKE control telemetry with ESP encrypted data-plane behavior, infers traffic classes using AI, evaluates deterministic security policy, and reports confidence and uncertainty without decrypting payloads.  
**Current Status**: Prototype & Comprehensive Empirical Validation Complete (Phase 1, Phase 2, Forensic Audit, and Enhanced Feature Study).  

---

## 1. Authoritative Experimental Results

### A. Authoritative Phase 2 Generalization Benchmark (18,842 Encrypted VPN Samples)
- **Primary Model**: Random Forest (100 Trees)
- **Authoritative Accuracy**: **`89.84% ± 0.45%`** (95% CI: 89.39% – 90.29%)
- **Authoritative Macro-F1**: **`88.30% ± 0.44%`** (95% CI: 87.86% – 88.74%)
- **Validation Scheme**: 5-Fold `GroupKFold` across 38 session groups (**0% Cross-Fold Session Overlap**)
- **Dataset**: 18,842 canonical time-window feature vectors (84 Native IPsec + 18,758 ISCX Scenario B)

### B. Pure Native IPsec ESP Testbed Benchmark (5,482 Genuine Samples)
- **Random Forest**: **`57.33% ± 16.15% Accuracy`** | **`57.14% ± 7.80% Macro-F1`**
- **XGBoost**: **`56.80% ± 14.99% Accuracy`** | **`55.96% ± 6.93% Macro-F1`**
- **Data Source**: 294 raw `.pcap` captures over Linux kernel XFRM/ESP network namespaces (157 session groups)

### C. Enhanced Multi-Scale & Directional Feature Study (1,829 Samples)
- **XGBoost (Enhanced 3.0s Windows + Quantiles + Direction)**: **`63.40% Accuracy`** | **`70.53% Macro-F1`**
- **Random Forest**: **`62.52% Accuracy`** | **`69.36% Macro-F1`**

---

## 2. Master Repository Structure

```
IPsecTrace_FINAL_MASTER/
├── 00_MASTER_README.md                    <- Main Entry Point
├── 01_EXECUTIVE_OVERVIEW.md               <- High-Level Executive Summary
├── 02_PROJECT_EVOLUTION.md                <- Chronological Evolution (Idea -> Audit)
├── 03_PROBLEM_STATEMENT.md                <- Technical Problem Statement & Observability Boundary
├── 04_RESEARCH_BACKGROUND.md              <- Literature Review & Standards
├── 05_RESEARCH_GAP.md                     <- Clear Research Gap Analysis
├── 06_PROPOSED_SOLUTION.md                <- Complete Architectural Solution
├── 07_SYSTEM_ARCHITECTURE.md              <- Layered System Architecture & Component States
├── 08_TECHNICAL_METHODOLOGY.md            <- Mathematical & Experimental Methodology
├── 09_IPSEC_PROTOCOL_ANALYSIS.md          <- IKEv2 & ESP/AH Protocol Analysis Logic
├── 10_DATASET_AND_DATA_PIPELINE.md        <- Dataset Cards, Provenance, & Taxonomy
├── 11_MACHINE_LEARNING_PIPELINE.md        <- Feature Extraction, Training, & Evaluation Logic
├── 12_PHASE1_EXPERIMENT.md                <- Phase 1 Baseline & Randomized Split Findings
├── 13_PHASE1_LIMITATIONS.md               <- Discovery of Leakage & Methodological Flaws
├── 14_PHASE2_EXPERIMENT.md                <- Phase 2 Scale & Session-Isolated GroupKFold Setup
├── 15_FORENSIC_AUDIT.md                   <- Full Forensic Audit & 18,842 Arithmetic Verification
├── 16_FINAL_EXPERIMENTAL_RESULTS.md       <- Authoritative Benchmarks & Metric Tables
├── 17_GENERALIZATION_AND_OOD.md           <- Cross-Dataset & Out-of-Distribution Calibration
├── 18_ABLATION_AND_ERROR_ANALYSIS.md      <- 7-Feature Subset Ablation & Confusion Forensics
├── 19_SECURITY_ASSESSMENT.md              <- Rule Engine, Anti-Replay, & Policy Matrix
├── 20_EVIDENCE_AND_CLAIMS.md              <- Claim Discipline & Wording Constraints
├── 21_THREATS_TO_VALIDITY.md              <- Internal, External, & Construct Validity Threats
├── 22_LIMITATIONS.md                      <- Explicit Honest Limitations
├── 23_REPRODUCIBILITY.md                  <- Step-by-Step Reproduction Guide & Hashes
├── 24_RESEARCH_CONTRIBUTION.md            <- Summary of 11 Core Technical Contributions
├── 25_CURRENT_PROJECT_STATUS.md           <- Implemented vs Proposed vs Future Matrix
├── 26_FUTURE_WORK.md                      <- Roadmap for Hardware, PQC, & Live Streaming
├── 27_FINAL_JUDGE_QA.md                   <- 20 Socratic Judge Defense Q&As
├── 28_REFERENCES.md                       <- RFCs, NIST Guidelines, & Academic Papers
├── IPsecTrace_FINAL_TECHNICAL_REPORT.md <- 40-Section Complete Master Research Report
├── AI_PROJECT_CONTEXT.md                  <- Compact Context for Future AI Assistants
├── PROJECT_TIMELINE.md                    <- Milestone-by-Milestone Chronology
│
├── figures/                               <- All Visual Plots & Architectural Diagrams
├── results/                               <- All Authoritative CSVs & Serialized JSON Metrics
├── datasets/                              <- Schemas, Cards, and Provenance Logs
├── source_code/                           <- Clean Modular Python Pipeline Code
├── sih_evidence/                          <- All 21 Individual SIH Audit Files
└── reproducibility/                       <- Hashes, Manifests, and Environment Reports
```

---

## 3. How to Reproduce All Results

```bash
# In WSL2 / Linux Environment with Python 3.10+
cd /mnt/c/Users/Abhijay/ipsec
PYTHONPATH=. python3 src/audit/run_final_hardening_pass.py
```
""",

    "01_EXECUTIVE_OVERVIEW.md": """# 01 — Executive Overview

## 1. Project Background
IPsecTrace was created for Smart India Hackathon 2026 under Problem Statement 26160 by the National Technical Research Organisation (NTRO). The core challenge is assessing the security and traffic behavior of IPsec VPN deployments without violating cryptographic boundaries.

## 2. Core Technical Philosophy
1. **Never Decrypt Payloads**: Rely on observable network layer metadata (IKE control parameters, ESP SPIs, sequence numbers, and statistical packet dynamics).
2. **Evidence Before Inference**: Deterministic protocol checks always take precedence over machine learning guesses.
3. **Explicit Uncertainty**: Use `UNKNOWN`, `NOT OBSERVABLE`, and `CONFLICT` states rather than forcing false certainty.

## 3. Two-Tier Empirical Validation
- **Tier 1 (Native IPsec ESP Ground Truth)**: 5,482 genuine flow windows extracted from 294 raw PCAPs in a Linux kernel XFRM testbed. Evaluated under strict 5-fold session-isolated `GroupKFold` cross-validation (Macro-F1: **57.14% baseline**, **70.53% enhanced**).
- **Tier 2 (Large-Scale Multi-VPN Benchmark)**: 18,842 canonical time-window feature vectors across public cybersecurity benchmarks. Evaluated with 0% session leakage (Random Forest Accuracy: **89.84%**, Macro-F1: **88.30%**).
""",

    "02_PROJECT_EVOLUTION.md": """# 02 — Project Evolution (Chronological History)

```
STAGE 1: Problem Conception & NTRO 26160 Scope
   │
   ▼
STAGE 2: Literature Review (RFC 7296, RFC 4303, NIST SP 800-77)
   │
   ▼
STAGE 3: Initial Architecture & Layered Evidence Model Design
   │
   ▼
STAGE 4: Native IPsec Linux XFRM / Network Namespace Testbed Build
   │
   ▼
STAGE 5: Phase 1 Prototype (84 Flow Samples from Controlled Sessions)
   │
   ▼
STAGE 6: Phase 1 Evaluation -> Discovery of Suspicious 100% RF Accuracy
   │
   ▼
STAGE 7: Forensic Discovery of Randomized Cross-Validation Leakage
   │
   ▼
STAGE 8: Phase 2 Architecture & Large Dataset Expansion (18,842 Samples)
   │
   ▼
STAGE 9: Enforcement of 5-Fold Session-Isolated GroupKFold (0% Leakage)
   │
   ▼
STAGE 10: Authoritative Metric Benchmark (RF: 89.84% Acc / 88.30% F1)
   │
   ▼
STAGE 11: Comprehensive Ablation, OOD Calibration, & Error Forensics
   │
   ▼
STAGE 12: Expansion to 5,482 Pure Native IPsec ESP Captures (57.14% F1)
   │
   ▼
STAGE 13: Enhanced Directional & Multi-Scale Feature Pipeline (70.53% F1)
   │
   ▼
STAGE 14: Final Master Forensic Audit & Frozen Master Archive Release
```

### Key Lesson Learned:
Randomized train/test splits create an illusion of perfect 100% accuracy due to temporal autocorrelation among packets in the same session. Enforcing strict session grouping eliminates leakage and produces honest, scientifically defensible metrics.
""",

    "AI_PROJECT_CONTEXT.md": """# AI_PROJECT_CONTEXT.md — Fast Context for Future AI Assistants

**PROJECT**: IPsecTrace  
**PROBLEM STATEMENT**: SIH 2026 / NTRO Problem Statement 26160  
**GOAL**: Evidence-aware IPsec VPN security analysis and encrypted traffic classification without payload decryption.  

---

## 1. Core Facts & Numbers (Zero Fabrication)

- **Authoritative Phase 2 Benchmark (18,842 samples, 38 groups, 5-Fold GroupKFold, 0% Leakage)**:
  - **Random Forest**: **`89.84% ± 0.45% Accuracy`** | **`88.30% ± 0.44% Macro-F1`**
  - **XGBoost**: **`87.17% ± 0.30% Accuracy`** | **`84.92% ± 0.23% Macro-F1`**
  - **Logistic Regression**: **`63.51% ± 0.20% Accuracy`** | **`51.73% ± 0.24% Macro-F1`**
  - **Dummy Baseline**: **`31.13% Accuracy`** | **`11.87% Macro-F1`**

- **Dataset Provenance & Arithmetic**:
  - Total: **`18,842 = 84 (DS1 Custom IPsec) + 18,758 (DS4 ISCX Scenario B)`**
  - Semantic Split: **`78 (Custom Non-ICMP) + 13,661 (ISCX Non-ICMP) + 5,103 (ICMP Class) = 18,842`**

- **Pure Native IPsec ESP Benchmark (5,482 genuine samples, 294 PCAPs, 157 groups)**:
  - **Random Forest**: **`57.33% Accuracy`** | **`57.14% Macro-F1`**
  - **Enhanced Feature Pipeline (3.0s window + quantiles + direction, 1,829 samples)**: **`63.40% Accuracy`** | **`70.53% Macro-F1`**

---

## 2. Key Architectural Rules
1. Never claim encrypted payloads were decrypted.
2. Never claim passive PCAP observation proves internal anti-replay window configuration.
3. Keep deterministic protocol verification strictly decoupled from statistical AI predictions.
4. Always use 5-Fold GroupKFold grouped by session ID (`experiment_group`) to guarantee 0% cross-fold leakage.
""",

    "PROJECT_TIMELINE.md": """# PROJECT_TIMELINE.md — IPsecTrace Chronological Milestone Log

| Stage / Phase | Milestone Event | Technical Implementation | Empirical Output / Finding |
| :--- | :--- | :--- | :--- |
| **Phase 0** | Problem Definition | NTRO Problem Statement 26160 review | Master Blueprint & Layered Evidence Model |
| **Phase 1** | PoC Testbed Build | Linux XFRM network namespaces (`ns-client` <-> `ns-server`) | 84 flow samples from controlled AES-128-CBC ESP sessions |
| **Phase 1 Eval** | Baseline ML Evaluation | Scikit-learn Random Forest on randomized 70/30 split | 100% Accuracy observed; flagged as suspicious leakage |
| **Phase 2** | Scale & Leakage Fix | Ingested 18,842 samples; implemented 5-Fold GroupKFold | RF: 89.84% Acc / 88.30% F1; 0% session overlap verified |
| **Forensic Audit** | Arithmetic Hardening | Reconciliation of 18,842 dataset sources | 84 Custom + 18,758 ISCX = 18,842 (Match = True) |
| **Native Scale** | Native Testbed Scale | Automated generation of 294 raw PCAPs across 4 envs | 5,482 genuine ESP flow windows extracted |
| **Enhanced Study** | Feature Engineering | Directional byte ratios + packet length quantiles (3.0s) | XGBoost achieves 70.53% Macro-F1 on native IPsec |
| **Master Freeze** | Archive Consolidation | Full report compilation and SHA-256 manifest creation | Frozen `IPsecTrace_FINAL_MASTER` package created |
"""
}

def generate_docs():
    for name, content in DOCS.items():
        fpath = os.path.join(MASTER_DIR, name)
        with open(fpath, "w", encoding="utf-8") as f:
            f.write(content.strip() + "\n")
        print(f"Generated {name}")

if __name__ == "__main__":
    generate_docs()
