import pandas as pd
import numpy as np
import os
import json
import shutil
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GroupKFold
from sklearn.metrics import accuracy_score, f1_score

def run_real_ablation_experiment():
    csv_path = "data/processed/native_ipsec_large_dataset.csv"
    if not os.path.exists(csv_path):
        print("[ERROR] native_ipsec_large_dataset.csv not found")
        return

    df = pd.read_csv(csv_path)
    print(f"Loaded {len(df)} canonical Native IPsec samples across {df['experiment_group'].nunique()} groups.")

    classes = sorted(df['traffic_class'].unique())
    y = df['traffic_class'].map({c: i for i, c in enumerate(classes)}).values
    groups = df['experiment_group'].values

    feature_subsets = {
        "Set A (All 9 Features)": [
            "flow_duration_sec", "packets_per_sec", "bytes_per_sec",
            "mean_iat_sec", "std_iat_sec", "mean_packet_size_bytes",
            "std_packet_size_bytes", "min_packet_size_bytes", "max_packet_size_bytes"
        ],
        "Set B (Timing Only)": [
            "flow_duration_sec", "mean_iat_sec", "std_iat_sec"
        ],
        "Set C (Throughput Only)": [
            "packets_per_sec", "bytes_per_sec"
        ],
        "Set D (Packet Size Only)": [
            "mean_packet_size_bytes", "std_packet_size_bytes",
            "min_packet_size_bytes", "max_packet_size_bytes"
        ],
        "Set E (No IAT: Size+Throughput)": [
            "flow_duration_sec", "packets_per_sec", "bytes_per_sec",
            "mean_packet_size_bytes", "std_packet_size_bytes",
            "min_packet_size_bytes", "max_packet_size_bytes"
        ],
        "Set F (IAT Only)": [
            "mean_iat_sec", "std_iat_sec"
        ],
        "Set G (ByteRate Only)": [
            "bytes_per_sec"
        ]
    }

    gkf = GroupKFold(n_splits=5)
    ablation_summary = []
    fold_records = []

    for s_name, feats in feature_subsets.items():
        X = df[feats].fillna(0).values
        fold_f1s = []
        fold_accs = []

        for fold_idx, (train_idx, test_idx) in enumerate(gkf.split(X, y, groups=groups)):
            X_train, X_test = X[train_idx], X[test_idx]
            y_train, y_test = y[train_idx], y[test_idx]

            rf = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42, n_jobs=-1)
            rf.fit(X_train, y_train)
            y_pred = rf.predict(X_test)

            acc = accuracy_score(y_test, y_pred)
            f1 = f1_score(y_test, y_pred, average='macro')
            fold_accs.append(acc)
            fold_f1s.append(f1)

            fold_records.append({
                "subset": s_name,
                "fold": fold_idx + 1,
                "accuracy": round(acc, 4),
                "macro_f1": round(f1, 4)
            })

        mean_f1 = float(np.mean(fold_f1s))
        std_f1 = float(np.std(fold_f1s))
        ci95 = float(1.96 * (std_f1 / np.sqrt(5)))
        mean_acc = float(np.mean(fold_accs))

        ablation_summary.append({
            "subset_name": s_name,
            "feature_count": len(feats),
            "features": ", ".join(feats),
            "macro_f1_mean": round(mean_f1, 4),
            "macro_f1_std": round(std_f1, 4),
            "macro_f1_ci95": f"{mean_f1*100:.2f}% ± {ci95*100:.2f}%",
            "accuracy_mean": round(mean_acc, 4)
        })

    # Save outputs
    df_summary = pd.DataFrame(ablation_summary).sort_values(by="macro_f1_mean", ascending=False)
    df_folds = pd.DataFrame(fold_records)

    out_csv = "results/final_ablation_results.csv"
    out_folds_csv = "results/final_ablation_fold_metrics.csv"
    os.makedirs("results", exist_ok=True)
    df_summary.to_csv(out_csv, index=False)
    df_folds.to_csv(out_folds_csv, index=False)

    # Sync to master archive
    shutil.copy(out_csv, "IPsecTrace_FINAL_MASTER/results/authoritative/")
    shutil.copy(out_folds_csv, "IPsecTrace_FINAL_MASTER/results/authoritative/")

    print("\n=======================================================")
    print("   GENUINE RECOMPUTED ABLATION RESULTS (GroupKFold)   ")
    print("=======================================================")
    print(df_summary[["subset_name", "macro_f1_mean", "macro_f1_ci95", "accuracy_mean"]])

if __name__ == "__main__":
    run_real_ablation_experiment()
