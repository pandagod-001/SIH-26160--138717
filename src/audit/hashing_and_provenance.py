import os
import hashlib
import glob
import pandas as pd

def compute_hashes_and_provenance():
    """
    Computes cryptographic hashes for dataset/metric artifacts and maps figure provenance.
    """
    os.makedirs("results", exist_ok=True)

    artifacts_to_hash = [
        "data/processed/canonical_vpn_dataset.csv",
        "dataset_manifest.json",
        "results/features.csv",
        "results/metrics.json",
        "results/model_comparison.csv",
        "results/xgboost_experiment.csv",
        "results/ablation_study.csv",
        "results/error_analysis.csv",
        "results/phase2_metric_recalculation.csv"
    ]

    hash_lines = []
    hash_lines.append("# IPsecTrace Reproducibility Artifact Hashes (SHA-256 / MD5)\n")
    hash_lines.append(f"# Generated Date: 2026-09-24\n\n")

    for art in artifacts_to_hash:
        if os.path.exists(art):
            with open(art, "rb") as f:
                content = f.read()
                md5_val = hashlib.md5(content).hexdigest()
                sha256_val = hashlib.sha256(content).hexdigest()
                hash_lines.append(f"File: {art}\n  MD5:    {md5_val}\n  SHA256: {sha256_val}\n\n")

    with open("results/reproducibility_hashes.txt", "w") as f:
        f.writelines(hash_lines)

    # Figure Provenance Mapping
    figure_provenance_rows = [
        {"Figure File": "class_distribution.png", "Generating Script": "src/visualizer/plot_phase2_charts.py", "Source Data": "data/processed/canonical_vpn_dataset.csv", "Primary Metric / Visual": "Flow count by traffic category"},
        {"Figure File": "confusion_matrix_random_forest.png", "Generating Script": "src/visualizer/plot_phase2_charts.py", "Source Data": "results/metrics.json", "Primary Metric / Visual": "5-Fold GroupKFold RF Confusion Matrix"},
        {"Figure File": "confusion_matrix_xgboost.png", "Generating Script": "src/visualizer/plot_phase2_charts.py", "Source Data": "results/metrics.json", "Primary Metric / Visual": "5-Fold GroupKFold XGBoost Confusion Matrix"},
        {"Figure File": "feature_importance_random_forest.png", "Generating Script": "src/visualizer/plot_phase2_charts.py", "Source Data": "results/metrics.json", "Primary Metric / Visual": "Random Forest Gini Feature Importances"},
        {"Figure File": "feature_importance_xgboost.png", "Generating Script": "src/visualizer/plot_phase2_charts.py", "Source Data": "results/metrics.json", "Primary Metric / Visual": "XGBoost Split Feature Importances"},
        {"Figure File": "ablation_comparison.png", "Generating Script": "src/visualizer/plot_phase2_charts.py", "Source Data": "results/ablation_study.csv", "Primary Metric / Visual": "Ablation Subset Macro F1 Bar Chart"},
        {"Figure File": "cross_dataset_transfer.png", "Generating Script": "src/visualizer/plot_phase2_charts.py", "Source Data": "results/metrics.json", "Primary Metric / Visual": "Domain Transfer Performance Retention"},
        {"Figure File": "architecture_evidence.png", "Generating Script": "src/visualizer/plot_phase2_charts.py", "Source Data": "SIH_EVIDENCE/03_ARCHITECTURE.md", "Primary Metric / Visual": "Architecture Evidence Implementation Status"}
    ]

    df_fig = pd.DataFrame(figure_provenance_rows)
    df_fig.to_csv("results/figure_provenance.csv", index=False)

    print("[HASHING & PROVENANCE] Hashes saved to results/reproducibility_hashes.txt and figure provenance to results/figure_provenance.csv")

if __name__ == "__main__":
    compute_hashes_and_provenance()
