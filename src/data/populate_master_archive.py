import os
import shutil
import glob
import hashlib
import json
import zipfile

WORKSPACE = "/mnt/c/Users/Abhijay/ipsec"
MASTER_DIR = os.path.join(WORKSPACE, "IPsecTrace_FINAL_MASTER")

def copy_files():
    # Copy all SIH evidence
    for f in glob.glob(f"{WORKSPACE}/SIH_EVIDENCE/*"):
        if os.path.isfile(f):
            shutil.copy(f, f"{MASTER_DIR}/sih_evidence/")
            
    # Copy all figures
    for f in glob.glob(f"{WORKSPACE}/results/figures/*.png"):
        fname = os.path.basename(f)
        shutil.copy(f, f"{MASTER_DIR}/figures/")
        if "ablation" in fname:
            shutil.copy(f, f"{MASTER_DIR}/figures/ablation/")
        elif "ood" in fname:
            shutil.copy(f, f"{MASTER_DIR}/figures/ood/")
        elif "distribution" in fname:
            shutil.copy(f, f"{MASTER_DIR}/figures/dataset/")
        elif "matrix" in fname or "model" in fname or "leakage" in fname:
            shutil.copy(f, f"{MASTER_DIR}/figures/machine_learning/")
        else:
            shutil.copy(f, f"{MASTER_DIR}/figures/experiments/")

    # Copy authoritative results
    res_files = [
        "dataset_reconciliation.json", "dataset_reconciliation.csv", "dataset_semantic_matrix.csv",
        "group_size_distribution.csv", "feature_lineage_audit.csv", "group_split_audit.json",
        "group_split_audit.md", "phase2_metric_recalculation.csv", "ablation_audit.csv",
        "figure_provenance.csv", "count_reference_audit.csv", "reproducibility_hashes.txt",
        "final_native_ipsec_metrics.json", "enhanced_native_ipsec_metrics.json", "metrics.json",
        "model_comparison.csv", "error_analysis.csv", "features.csv", "esp_analysis.json"
    ]
    for rf in res_files:
        src = os.path.join(WORKSPACE, "results", rf)
        if os.path.exists(src):
            shutil.copy(src, f"{MASTER_DIR}/results/authoritative/")
            shutil.copy(src, f"{MASTER_DIR}/results/phase2/")

    # Copy source code categorized
    code_map = {
        "data": ["build_canonical_dataset.py", "canonical_builder.py", "dataset_forensics.py", "dataset_inspector.py", "data_quality_pipeline.py", "generate_all_sih_docs.py", "generate_native_reconciliation.py", "generate_sih_evidence.py", "unzip_datasets.py"],
        "features": ["feature_auditor.py", "flow_extractor.py", "run_feature_audit.py"],
        "ml": ["evaluate_models.py", "run_native_ipsec_ml_benchmark.py", "train_eval.py", "evaluate_enhanced_native_ipsec.py"],
        "audit": ["ablation_audit.py", "ablation_reconciliation.py", "classwise_performance_audit.py", "count_reference_auditor.py", "dataset_taxonomy_attack.py", "feature_leakage_audit.py", "group_split_audit.py", "hashing_and_provenance.py", "inventory_audit.py", "judge_qa_compiler.py", "ood_calibration_audit.py", "recalculate_metrics.py", "reconcile_dataset.py", "run_final_hardening_pass.py", "run_forensic_audit.py", "sample_arithmetic_audit.py", "trace_authoritative_results.py"],
        "testbed": ["extract_large_native_windows.py", "fast_generate_native_ipsec.py", "generate_large_native_ipsec_dataset.py", "generate_traffic.py", "process_native_pcaps.py", "setup_testbed.py", "extract_enhanced_native_features.py"],
        "analyzer": ["esp_parser.py", "ike_parser.py"],
        "visualization": ["plot_charts.py", "plot_phase2_charts.py"]
    }
    for cat, files in code_map.items():
        dst_dir = f"{MASTER_DIR}/source_code/{cat}"
        os.makedirs(dst_dir, exist_ok=True)
        for cf in files:
            src = os.path.join(WORKSPACE, "src", cat, cf)
            if not os.path.exists(src):
                # Search src recursively
                matches = glob.glob(f"{WORKSPACE}/src/**/{cf}", recursive=True)
                if matches:
                    src = matches[0]
            if os.path.exists(src):
                shutil.copy(src, dst_dir)

    print("Master archive file copy complete!")

if __name__ == "__main__":
    copy_files()
