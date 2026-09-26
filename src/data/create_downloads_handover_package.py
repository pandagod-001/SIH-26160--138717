1800 records are native ipsec right ?import os
import shutil
import zipfile
import glob

USER_DOWNLOADS = "/mnt/c/Users/Abhijay/Downloads"
PACKAGE_DIR = os.path.join(USER_DOWNLOADS, "IPsecTrace_SIH2026_PRESENTATION_PACKAGE")
ZIP_OUT = os.path.join(USER_DOWNLOADS, "IPsecTrace_SIH2026_PRESENTATION_PACKAGE.zip")
WORKSPACE = "/mnt/c/Users/Abhijay/ipsec"

def build_download_package():
    os.makedirs(PACKAGE_DIR, exist_ok=True)
    os.makedirs(os.path.join(PACKAGE_DIR, "presentation_docs"), exist_ok=True)
    os.makedirs(os.path.join(PACKAGE_DIR, "presentation_figures"), exist_ok=True)
    os.makedirs(os.path.join(PACKAGE_DIR, "authoritative_metrics"), exist_ok=True)
    os.makedirs(os.path.join(PACKAGE_DIR, "datasets"), exist_ok=True)

    # 1. Copy Key Presentation Docs
    doc_files = [
        "docs/PPT_DATA.md",
        "docs/FINAL_PROJECT_CONTEXT.md",
        "docs/DO_NOT_USE_STALE_RESULTS.md",
        "docs/final/AUTHORITATIVE_RESULTS.md",
        "docs/final/CLAIM_EVIDENCE_MATRIX.md",
        "docs/final/SIH_SAFE_CLAIMS.md",
        "docs/final/NATIVE_GROUPING_AUDIT.md",
        "docs/final/NATIVE_ABLATION_ANALYSIS.md",
        "docs/final/OOD_EVALUATION.md",
        "docs/final/SECURITY_RULE_ENGINE_STATUS.md",
        "README.md"
    ]
    for df in doc_files:
        src = os.path.join(WORKSPACE, df)
        if os.path.exists(src):
            shutil.copy(src, os.path.join(PACKAGE_DIR, "presentation_docs", os.path.basename(df)))

    # 2. Copy Presentation Figures (300 DPI)
    fig_patterns = [
        "IPsecTrace_FINAL_MASTER/figures/*.png",
        "IPsecTrace_FINAL_MASTER/figures/architecture/*.png",
        "IPsecTrace_FINAL_MASTER/figures/security/*.png",
        "results/figures/*.png"
    ]
    for pat in fig_patterns:
        for f in glob.glob(os.path.join(WORKSPACE, pat)):
            shutil.copy(f, os.path.join(PACKAGE_DIR, "presentation_figures", os.path.basename(f)))

    # 3. Copy Authoritative Results / Metrics
    res_files = [
        "results/final/native_metrics.csv",
        "results/final/native_metrics.json",
        "results/final/native_ablation.csv",
        "results/final/ood_metrics.json",
        "results/final_native_ipsec_model_comparison.csv",
        "results/enhanced_native_ipsec_metrics.json",
        "results/final_reproducibility_manifest.json"
    ]
    for rf in res_files:
        src = os.path.join(WORKSPACE, rf)
        if os.path.exists(src):
            shutil.copy(src, os.path.join(PACKAGE_DIR, "authoritative_metrics", os.path.basename(rf)))

    # 4. Copy Clean Processed Datasets
    data_files = [
        "data/processed/native_ipsec_large_dataset.csv",
        "data/processed/native_ipsec_enhanced_dataset.csv"
    ]
    for dtf in data_files:
        src = os.path.join(WORKSPACE, dtf)
        if os.path.exists(src):
            shutil.copy(src, os.path.join(PACKAGE_DIR, "datasets", os.path.basename(dtf)))

    # 5. Create README for the teammate inside the folder
    teammate_readme = """# IPsecTrace — SIH 2026 PPT & Presentation Handover Package

Welcome! Everything in this folder has been vetted, audited, and frozen for preparing the SIH 2026 PPT and presentation.

---

### 📂 Folder Contents:

1. **`presentation_docs/`**:
   - 📄 **`PPT_DATA.md`**: **START HERE!** Structured slide-by-slide text, problem statement, architecture, metrics, and references.
   - 📄 **`FINAL_PROJECT_CONTEXT.md`**: Complete technical single source of truth for judge Q&A defense.
   - ⚠️ **`DO_NOT_USE_STALE_RESULTS.md`**: List of old/superseded numbers to avoid.
   - 📄 **`SIH_SAFE_CLAIMS.md`**: What is safe to say vs. what to say with qualification.
   - 📄 **`CLAIM_EVIDENCE_MATRIX.md`**: Traceability of every claim to RFCs and empirical data.

2. **`presentation_figures/`**:
   - 📊 **`system_architecture_diagram.png`**: High-res 5-layer pipeline diagram for your architecture slide.
   - 📊 **`security_assessment_matrix.png`**: Deterministic RFC policy vs. AI classification flow.
   - 📊 **`native_ipsec_pipeline_comparison.png`**: Baseline vs. Enhanced F1 comparison chart.
   - 📊 **`native_ipsec_classwise_f1.png`**: ICMP (97.8%), Bulk (95.5%), Web (57.9%), Interactive (44.5%).
   - 📊 **`native_ipsec_feature_ablation.png`**: Feature importance ranking chart.
   - 📊 **`phase2_fig8_ood_rejection.png`**: Out-of-Distribution rejection curve.

3. **`authoritative_metrics/`**:
   - Raw CSVs and JSON files with all fold-level cross-validation results and 95% confidence intervals.

4. **`datasets/`**:
   - Canonical 5,482 and 1,829 Native IPsec flow-window CSV datasets.

---

### 🚀 Key Numbers to Put in PPT:
- **Primary Native IPsec Evaluation**:
  - Samples: **5,482 baseline flow windows (1.0s) / 1,829 enhanced multi-scale windows (3.0s)** (294 raw PCAPs, 157 genuine session groups)
  - Baseline (1.0s Window): Random Forest **58.32% Macro-F1** (vs 25.0% random baseline)
  - Enhanced Pipeline (3.0s Window + Quantiles & Direction): **XGBoost achieves 70.53% Macro-F1 / 63.40% Accuracy**
  - OOD Detection: **0.9077 AUROC** (Rejects 93.89% of unknown traffic at tau=0.60)
- **Auxiliary Large-Scale Benchmark**:
  - 18,842 flows (UNB ISCX): Random Forest **88.30% Macro-F1** (Auxiliary external validation)
"""
    with open(os.path.join(PACKAGE_DIR, "START_HERE_TEAMMATE_README.md"), "w", encoding="utf-8") as f:
        f.write(teammate_readme.strip() + "\n")

    # 6. Create ZIP Archive in Downloads
    print(f"Creating ZIP archive at {ZIP_OUT}...")
    with zipfile.ZipFile(ZIP_OUT, 'w', zipfile.ZIP_DEFLATED) as zf:
        for root, _, files in os.walk(PACKAGE_DIR):
            for f in files:
                fp = os.path.join(root, f)
                arc_p = os.path.relpath(fp, USER_DOWNLOADS)
                zf.write(fp, arc_p)

    zip_size_mb = os.path.getsize(ZIP_OUT) / (1024 * 1024)
    print(f"[SUCCESS] Handover package created in Downloads! Size: {zip_size_mb:.2f} MB")

if __name__ == "__main__":
    build_download_package()
