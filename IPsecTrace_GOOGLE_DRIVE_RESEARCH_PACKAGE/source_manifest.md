# IPsecTrace RESEARCH PACKAGE — SOURCE & ARTIFACT MANIFEST

This manifest provides complete end-to-end traceability for every document, metric, figure, dataset, and source file in the IPsecTrace Google Drive Research Documentation Package.

## 1. Document to Source Code & Artifact Traceability

| Document Filename | Primary Source Files | Primary Dataset & Split | Primary Experiment Artifacts | Embedded Figures |
| :--- | :--- | :--- | :--- | :--- |
| **00_IPsecTrace_RESEARCH_INDEX.docx** | `README.md`, `backend/app/main.py` | `DS1_NATIVE_IPSEC_ENHANCED` (1,829 windows) | `results/final/metrics/authoritative_benchmark_metrics.json` | None (Master Guide) |
| **01_IPsecTrace_Executive_White_Paper.docx** | `backend/app/services/pipeline_service.py`, `backend/app/ml/research_service.py` | `DS1_NATIVE_IPSEC_ENHANCED` (157 groups, 294 PCAPs) | `results/final/metrics/authoritative_benchmark_metrics.json` | `architecture.png` |
| **02_IPsecTrace_System_Architecture.docx** | `backend/app/parsers/packet_parser.py`, `backend/app/analyzers/esp_analyzer.py`, `backend/app/flow/window_builder.py` | Native PCAP stream & 3.0s window builder | `backend/tests/test_prototype.py` | `detailed_architecture.png`, `workflow.png` |
| **03_IPsecTrace_Dataset_Methodology.docx** | `src/ml/check_splits_fast.py`, `backend/app/flow/window_builder.py` | `data/flow_windows_dataset.csv` (1,829 rows, 14 baseline features) | `results/final/native_fold_results.csv` | `dataset_distribution.png` |
| **04_IPsecTrace_ML_Experiments_Results.docx** | `src/ml/run_native_experiments.py`, `src/ml/models/sequence_transformer.py` | 5-Fold GroupKFold (zero PCAP / group overlap) | `results/final/metrics/authoritative_benchmark_metrics.json`, `results/final/metrics/per_class_metrics.json` | `model_comparison.png`, `confusion_matrix.png` |
| **05_IPsecTrace_Security_Real_PCAP_Evidence.docx** | `backend/app/security/rules.py`, `backend/app/security/evidence_fusion.py` | Real-PCAP Dynamic Demonstrations (WEB, ICMP, BULK) | `results/final/ood_metrics.json`, `results/final/pcap_demos/` | `evidence_architecture.png`, `ood.png`, `real_pcap_demo.png` |
| **06_IPsecTrace_Reproducibility_Limitations_Future_Work.docx** | `backend/tests/test_prototype.py`, `src/ml/regenerate_final_figures.py` | Full Reproducibility Testbed | 30/30 Passing Backend Tests | None (Execution Scripts & Tables) |
