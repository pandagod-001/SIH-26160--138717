# IPsecTrace Canonical Research Documentation

Welcome to the authoritative research package for **IPsecTrace**: *Protocol-Aware Multi-View AI Architecture for Native IPsec Security Analysis & Encrypted Traffic Classification*.

---

## 📚 Documentation Index

1. [**01. Executive Research Overview**](01_RESEARCH_OVERVIEW.md) — Complete end-to-end explanation of the problem, proposed system, multi-view architecture, empirical findings, and limitations.
2. [**02. Problem Statement & Research Gap**](02_PROBLEM_STATEMENT.md) — Deep packet inspection failure under ESP encryption, overconfidence on uncalibrated models, and lack of protocol-grounded attribution.
3. [**03. System Architecture**](03_SYSTEM_ARCHITECTURE.md) — Scapy deterministic protocol parser, 14-feature tabular branch, Transformer sequence branch, multi-view fusion, and explanation layer.
4. [**04. Dataset & Capture Methodology**](04_DATASET_AND_METHODOLOGY.md) — 1,829 flow windows, 294 real physical PCAPs, 157 experiment groups, 0% leakage GroupKFold partitioning.
5. [**05. Deterministic Protocol Forensics**](05_DETERMINISTIC_PROTOCOL_FORENSICS.md) — Authoritative extraction of IKE transforms, DH groups, SPIs, SADB replay state, and direction inference.
6. [**06. Machine Learning & Multi-View Representation**](06_ML_AND_REPRESENTATION_LEARNING.md) — Canonical XGBoost (Model A), Sequence Transformer (Model B1), SSL Pretrained Encoder (Model B3), Hybrid Tabular + Sequence (Model C), and Multi-View (Model D).
7. [**07. Experimental Results & Ablation Analysis**](07_RESULTS_AND_ABLATION.md) — Controlled 5-fold benchmark, per-class metrics, confusion matrices, and the +13.35% hybrid improvement analysis.
8. [**08. Open-Set & Out-of-Distribution Novelty**](08_OOD_AND_NOVELTY.md) — Latent embedding distance evaluation (AUROC = 0.9962) and strict experimental boundaries.
9. [**09. Real-PCAP Demonstration**](09_REAL_PCAP_DEMONSTRATIONS.md) — Verified dynamic pipeline analysis on WEB, ICMP, and BULK IPsec traffic captures.
10. [**10. Security Assessment & Evidence Fusion**](10_SECURITY_ASSESSMENT.md) — Separation of deterministic cryptographic facts from probabilistic behavioral inferences.
11. [**11. Limitations & Future Work**](11_LIMITATIONS_AND_FUTURE_WORK.md) — Homogeneous testbed constraints, WEB/INTERACTIVE boundary, and next research steps.
12. [**12. Presentation & PPT Narrative**](12_FINAL_PPT_NARRATIVE.md) — 12-slide authoritative presentation structure for evaluators and defense.
13. [**13. Paper Structure & Latex Blueprint**](13_FINAL_PAPER_STRUCTURE.md) — IEEE/ACM conference-ready publication structure.
