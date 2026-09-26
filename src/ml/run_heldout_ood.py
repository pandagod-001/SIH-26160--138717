import pandas as pd
import numpy as np
import os
import json
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GroupKFold
from sklearn.metrics import roc_auc_score, precision_recall_curve, auc

def run_heldout_ood_evaluation():
    csv_path = "data/processed/native_ipsec_large_dataset.csv"
    if not os.path.exists(csv_path):
        print("[ERROR] Dataset not found")
        return

    df = pd.read_csv(csv_path)
    
    # Define In-Distribution (ID): Web, Bulk, Interactive
    # Define Out-of-Distribution (OOD): ICMP (distinct non-application protocol)
    id_df = df[df['traffic_class'] != 'ICMP'].copy()
    ood_df = df[df['traffic_class'] == 'ICMP'].copy()

    features = [
        "flow_duration_sec", "packets_per_sec", "bytes_per_sec",
        "mean_iat_sec", "std_iat_sec", "mean_packet_size_bytes",
        "std_packet_size_bytes", "min_packet_size_bytes", "max_packet_size_bytes"
    ]

    id_classes = sorted(id_df['traffic_class'].unique())
    y_id = id_df['traffic_class'].map({c: i for i, c in enumerate(id_classes)}).values
    X_id = id_df[features].fillna(0).values
    groups_id = id_df['experiment_group'].values

    X_ood = ood_df[features].fillna(0).values

    gkf = GroupKFold(n_splits=5)
    id_test_confidences = []
    ood_confidences = []

    for train_idx, test_idx in gkf.split(X_id, y_id, groups=groups_id):
        X_train, X_test = X_id[train_idx], X_id[test_idx]
        y_train, y_test = y_id[train_idx], y_id[test_idx]

        rf = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42, n_jobs=-1)
        rf.fit(X_train, y_train)

        # 1. Evaluate on UNTOUCHED held-out ID test split
        test_probs = rf.predict_proba(X_test)
        max_test_probs = np.max(test_probs, axis=1)
        id_test_confidences.extend(max_test_probs)

        # 2. Evaluate on unseen OOD samples
        ood_probs = rf.predict_proba(X_ood)
        max_ood_probs = np.max(ood_probs, axis=1)
        ood_confidences.extend(max_ood_probs)

    id_test_conf = np.array(id_test_confidences)
    ood_conf = np.array(ood_confidences)

    mean_id_conf = float(np.mean(id_test_conf))
    mean_ood_conf = float(np.mean(ood_conf))

    # Threshold Sweep
    thresholds = [0.5, 0.6, 0.7, 0.8, 0.9]
    sweep_results = []
    for t in thresholds:
        id_retention = float(np.mean(id_test_conf >= t))
        ood_rejection = float(np.mean(ood_conf < t))
        sweep_results.append({
            "threshold": t,
            "id_retention_rate": round(id_retention, 4),
            "ood_rejection_rate": round(ood_rejection, 4)
        })

    # AUROC Calculation (ID = 1, OOD = 0)
    y_true_ood = np.concatenate([np.ones(len(id_test_conf)), np.zeros(len(ood_conf))])
    y_scores_ood = np.concatenate([id_test_conf, ood_conf])
    auroc = float(roc_auc_score(y_true_ood, y_scores_ood))

    results = {
        "evaluation_type": "HELD_OUT_ID_VS_UNSEEN_OOD",
        "id_classes": id_classes,
        "ood_class": "ICMP",
        "total_id_samples": len(id_df),
        "total_ood_samples": len(ood_df),
        "mean_heldout_id_confidence": round(mean_id_conf, 4),
        "mean_unseen_ood_confidence": round(mean_ood_conf, 4),
        "auroc_score": round(auroc, 4),
        "threshold_sweep": sweep_results
    }

    os.makedirs("results", exist_ok=True)
    with open("results/final_ood_calibration_results.json", "w") as f:
        json.dump(results, f, indent=2)

    import shutil
    shutil.copy("results/final_ood_calibration_results.json", "IPsecTrace_FINAL_MASTER/results/authoritative/")

    print("\n=======================================================")
    print("   HELD-OUT OOD EVALUATION & CALIBRATION RESULTS      ")
    print("=======================================================")
    print(f"Mean Held-Out ID Confidence: {mean_id_conf*100:.2f}%")
    print(f"Mean Unseen OOD Confidence:  {mean_ood_conf*100:.2f}%")
    print(f"OOD Separation AUROC:        {auroc:.4f}")
    for s in sweep_results:
        print(f"  tau={s['threshold']:.2f} -> ID Retention: {s['id_retention_rate']*100:.2f}%, OOD Rejection: {s['ood_rejection_rate']*100:.2f}%")

if __name__ == "__main__":
    run_heldout_ood_evaluation()
