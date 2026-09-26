import os
import json
import glob
import pandas as pd
import numpy as np
from sklearn.model_selection import GroupKFold

from sklearn.dummy import DummyClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, confusion_matrix
import xgboost as xgb

def run_native_ipsec_ml_benchmark():
    print("=========================================================")
    print("   GENUINE NATIVE-IPSEC ML EXPERIMENTAL EVALUATION     ")
    print("=========================================================\n")

    csv_path = "data/processed/native_ipsec_large_dataset.csv"
    if not os.path.exists(csv_path):
        print(f"[ERROR] {csv_path} does not exist.")
        return

    df = pd.read_csv(csv_path)
    print(f"Loaded {len(df)} genuine native-IPsec flow-window samples.")
    print(f"Unique session groups: {df['experiment_group'].nunique()}")
    print("Class distribution:\n", df['traffic_class'].value_counts())

    # Features list (strictly non-identifying behavioural features)
    features = [
        "flow_duration_sec", "packets_per_sec", "bytes_per_sec",
        "mean_iat_sec", "std_iat_sec",
        "mean_packet_size_bytes", "std_packet_size_bytes",
        "min_packet_size_bytes", "max_packet_size_bytes"
    ]
    
    X = df[features].values
    y = df["traffic_class"].values
    groups = df["experiment_group"].values
    envs = df["environment_id"].values
    
    classes = sorted(list(np.unique(y)))
    class_to_idx = {c: i for i, c in enumerate(classes)}
    y_idx = np.array([class_to_idx[c] for c in y])

    # 1. GroupKFold 5-Fold Leakage-Free Cross Validation
    gkf = GroupKFold(n_splits=5)
    
    group_audit = []
    cross_fold_overlaps = 0

    fold_metrics = {"Dummy": [], "LogisticRegression": [], "RandomForest": [], "XGBoost": []}
    per_class_f1 = {"RandomForest": {c: [] for c in classes}}
    rf_conf_matrices = []

    # Calibration & Brier tracking
    all_y_true = []
    all_rf_probs = []

    for fold, (train_idx, test_idx) in enumerate(gkf.split(X, y_idx, groups=groups), 1):
        train_groups = set(groups[train_idx])
        test_groups = set(groups[test_idx])
        overlap = len(train_groups.intersection(test_groups))
        cross_fold_overlaps += overlap
        
        group_audit.append({
            "fold": fold,
            "train_samples": len(train_idx),
            "test_samples": len(test_idx),
            "train_groups": len(train_groups),
            "test_groups": len(test_groups),
            "cross_fold_group_overlap": overlap
        })

        X_tr, y_tr = X[train_idx], y_idx[train_idx]
        X_te, y_te = X[test_idx], y_idx[test_idx]

        # Dummy Baseline
        dummy = DummyClassifier(strategy="stratified", random_state=42)
        dummy.fit(X_tr, y_tr)
        y_pred_dummy = dummy.predict(X_te)
        fold_metrics["Dummy"].append({
            "accuracy": accuracy_score(y_te, y_pred_dummy),
            "macro_f1": f1_score(y_te, y_pred_dummy, average="macro")
        })

        # Logistic Regression
        lr = LogisticRegression(max_iter=1000, random_state=42)
        lr.fit(X_tr, y_tr)
        y_pred_lr = lr.predict(X_te)
        fold_metrics["LogisticRegression"].append({
            "accuracy": accuracy_score(y_te, y_pred_lr),
            "macro_f1": f1_score(y_te, y_pred_lr, average="macro")
        })

        # Random Forest
        rf = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42, n_jobs=-1)
        rf.fit(X_tr, y_tr)
        y_pred_rf = rf.predict(X_te)
        y_prob_rf = rf.predict_proba(X_te)

        all_y_true.extend(y_te)
        all_rf_probs.extend(y_prob_rf)

        acc_rf = accuracy_score(y_te, y_pred_rf)
        f1_rf = f1_score(y_te, y_pred_rf, average="macro")
        fold_metrics["RandomForest"].append({"accuracy": acc_rf, "macro_f1": f1_rf})
        
        for c in classes:
            c_idx = class_to_idx[c]
            c_f1 = f1_score(y_te == c_idx, y_pred_rf == c_idx, average="binary", zero_division=0)
            per_class_f1["RandomForest"][c].append(c_f1)
            
        rf_conf_matrices.append(confusion_matrix(y_te, y_pred_rf, labels=range(len(classes))))

        # XGBoost
        xgb_model = xgb.XGBClassifier(n_estimators=100, max_depth=6, learning_rate=0.1, random_state=42, n_jobs=-1)
        xgb_model.fit(X_tr, y_tr)
        y_pred_xgb = xgb_model.predict(X_te)
        fold_metrics["XGBoost"].append({
            "accuracy": accuracy_score(y_te, y_pred_xgb),
            "macro_f1": f1_score(y_te, y_pred_xgb, average="macro")
        })

    # Save group_split_audit.json
    with open("results/group_split_audit.json", "w") as f:
        json.dump({
            "total_canonical_native_samples": len(df),
            "total_unique_groups": int(df['experiment_group'].nunique()),
            "total_cross_fold_group_overlap": cross_fold_overlaps,
            "leakage_status": "ZERO_LEAKAGE" if cross_fold_overlaps == 0 else "LEAKAGE_DETECTED",
            "folds": group_audit
        }, f, indent=2)

    # 2. Calibration Computation (Expected Calibration Error & Brier Score)
    all_y_true = np.array(all_y_true)
    all_rf_probs = np.array(all_rf_probs)
    
    max_probs = np.max(all_rf_probs, axis=1)
    preds = np.argmax(all_rf_probs, axis=1)
    accuracies = (preds == all_y_true).astype(float)
    
    # ECE computation with 10 bins
    bins = np.linspace(0.0, 1.0, 11)
    bin_indices = np.digitize(max_probs, bins) - 1
    ece = 0.0
    for b in range(10):
        in_bin = (bin_indices == b)
        if np.sum(in_bin) > 0:
            bin_acc = np.mean(accuracies[in_bin])
            bin_conf = np.mean(max_probs[in_bin])
            ece += (np.sum(in_bin) / len(max_probs)) * np.abs(bin_acc - bin_conf)
            
    # Brier Score (multi-class)
    y_one_hot = np.zeros_like(all_rf_probs)
    y_one_hot[np.arange(len(all_y_true)), all_y_true] = 1.0
    brier_score = float(np.mean(np.sum((all_rf_probs - y_one_hot)**2, axis=1)))

    # 3. Feature Ablation Study under GroupKFold
    ablation_sets = {
        "Set A (All 9 Features)": list(range(9)),
        "Set B (Timing Only)": [0, 3, 4], # duration, mean_iat, std_iat
        "Set C (Throughput Only)": [1, 2], # pps, bps
        "Set D (Packet Size Only)": [5, 6, 7, 8], # mean, std, min, max packet sizes
        "Set E (No IAT)": [0, 1, 2, 5, 6, 7, 8],
        "Set F (IAT Only)": [3, 4],
        "Set G (ByteRate Only)": [2]
    }
    
    ablation_results = {}
    for set_name, feat_idxs in ablation_sets.items():
        sub_f1s = []
        for train_idx, test_idx in gkf.split(X, y_idx, groups=groups):
            X_tr_sub = X[train_idx][:, feat_idxs]
            X_te_sub = X[test_idx][:, feat_idxs]
            rf_sub = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42, n_jobs=-1)
            rf_sub.fit(X_tr_sub, y_idx[train_idx])
            sub_pred = rf_sub.predict(X_te_sub)
            sub_f1s.append(f1_score(y_idx[test_idx], sub_pred, average="macro"))
        ablation_results[set_name] = {
            "mean_macro_f1": float(np.mean(sub_f1s)),
            "std_macro_f1": float(np.std(sub_f1s))
        }

    # 4. Out-of-Distribution (OOD) Confidence Threshold Sweep
    # Treat ICMP as held-out / OOD traffic class to test rejection
    id_mask = (df["traffic_class"] != "ICMP").values
    ood_mask = (df["traffic_class"] == "ICMP").values
    
    X_id, y_id = X[id_mask], y_idx[id_mask]
    groups_id = groups[id_mask]
    X_ood = X[ood_mask]

    rf_id = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42, n_jobs=-1)
    rf_id.fit(X_id, y_id)

    id_max_probs = np.max(rf_id.predict_proba(X_id), axis=1)
    ood_max_probs = np.max(rf_id.predict_proba(X_ood), axis=1)

    thresholds = [0.50, 0.60, 0.70, 0.80, 0.90]
    ood_sweep = []
    for th in thresholds:
        id_retained = float(np.mean(id_max_probs >= th))
        ood_rejected = float(np.mean(ood_max_probs < th))
        ood_sweep.append({
            "threshold": th,
            "id_retention_rate": round(id_retained, 4),
            "ood_rejection_rate": round(ood_rejected, 4)
        })

    # 5. Unseen-Environment Evaluation (Leave-One-Environment-Out)
    unique_envs = sorted(list(df["environment_id"].unique()))
    env_results = {}
    for held_out_env in unique_envs:
        train_env_mask = (df["environment_id"] != held_out_env).values
        test_env_mask = (df["environment_id"] == held_out_env).values
        
        rf_env = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42, n_jobs=-1)
        rf_env.fit(X[train_env_mask], y_idx[train_env_mask])
        pred_env = rf_env.predict(X[test_env_mask])
        
        env_acc = accuracy_score(y_idx[test_env_mask], pred_env)
        env_f1 = f1_score(y_idx[test_env_mask], pred_env, average="macro")
        env_results[held_out_env] = {
            "test_samples": int(np.sum(test_env_mask)),
            "accuracy": round(float(env_acc), 4),
            "macro_f1": round(float(env_f1), 4)
        }

    # Aggregate Final Metrics
    final_metrics = {
        "dataset_summary": {
            "total_genuine_samples": len(df),
            "total_independent_sessions": int(df['experiment_group'].nunique()),
            "total_raw_pcaps": int(len(glob.glob("data/raw_native_ipsec/pcaps/*.pcap"))),
            "class_distribution": df['traffic_class'].value_counts().to_dict(),
            "environment_distribution": df['environment_id'].value_counts().to_dict(),
        },
        "models": {
            "Dummy": {
                "accuracy_mean": float(np.mean([m["accuracy"] for m in fold_metrics["Dummy"]])),
                "macro_f1_mean": float(np.mean([m["macro_f1"] for m in fold_metrics["Dummy"]])),
            },
            "LogisticRegression": {
                "accuracy_mean": float(np.mean([m["accuracy"] for m in fold_metrics["LogisticRegression"]])),
                "accuracy_std": float(np.std([m["accuracy"] for m in fold_metrics["LogisticRegression"]])),
                "macro_f1_mean": float(np.mean([m["macro_f1"] for m in fold_metrics["LogisticRegression"]])),
                "macro_f1_std": float(np.std([m["macro_f1"] for m in fold_metrics["LogisticRegression"]])),
            },
            "RandomForest": {
                "accuracy_mean": float(np.mean([m["accuracy"] for m in fold_metrics["RandomForest"]])),
                "accuracy_std": float(np.std([m["accuracy"] for m in fold_metrics["RandomForest"]])),
                "macro_f1_mean": float(np.mean([m["macro_f1"] for m in fold_metrics["RandomForest"]])),
                "macro_f1_std": float(np.std([m["macro_f1"] for m in fold_metrics["RandomForest"]])),
                "per_class_f1": {c: float(np.mean(per_class_f1["RandomForest"][c])) for c in classes},
                "mean_maximum_predicted_probability": float(np.mean(max_probs)),
                "expected_calibration_error": float(ece),
                "brier_score": float(brier_score)
            },
            "XGBoost": {
                "accuracy_mean": float(np.mean([m["accuracy"] for m in fold_metrics["XGBoost"]])),
                "accuracy_std": float(np.std([m["accuracy"] for m in fold_metrics["XGBoost"]])),
                "macro_f1_mean": float(np.mean([m["macro_f1"] for m in fold_metrics["XGBoost"]])),
                "macro_f1_std": float(np.std([m["macro_f1"] for m in fold_metrics["XGBoost"]]))
            }
        },
        "ablation_study": ablation_results,
        "ood_sweep": ood_sweep,
        "unseen_environment_test": env_results
    }

    os.makedirs("results", exist_ok=True)
    with open("results/final_native_ipsec_metrics.json", "w") as f:
        json.dump(final_metrics, f, indent=2)
    print("\nSaved final ML metrics to results/final_native_ipsec_metrics.json")

    # Aggregate confusion matrix
    total_conf_mat = np.sum(rf_conf_matrices, axis=0)
    print("\nRandom Forest Aggregate Confusion Matrix:")
    print("Classes:", classes)
    print(total_conf_mat)

    return final_metrics

if __name__ == "__main__":
    run_native_ipsec_ml_benchmark()
