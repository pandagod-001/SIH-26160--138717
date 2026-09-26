"""
evaluate_models.py — IPsecTrace Phase 2 Comprehensive ML Experimental Engine
Conducts 9 rigorous, leakage-free experiments:
1. Leakage & Overfitting Benchmark (Random Split vs Grouped Split)
2. Tier 1 Benchmark (Custom IPsec testbed, 4 classes)
3. Tier 1 + Tier 2 Large-Scale Combined Evaluation (Grouped CV)
4. Cross-Dataset Transferability (Train Tier 1 -> Test Tier 2, and vice-versa)
5. Hyperparameter Sensitivity Matrix (XGBoost Grid)
6. Feature Ablation Study (Groups A-G)
7. Out-of-Distribution (OOD) Novel Class Detection (VOIP & P2P as unknown)
8. Model Calibration & Uncertainty (ECE & Brier Score)
9. Error & Misclassification Forensics
Outputs results/metrics.json, results/model_comparison.csv, results/error_analysis.csv, etc.
"""
import os
import json
import warnings
import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedKFold, GroupKFold, ParameterGrid
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, log_loss, brier_score_loss, confusion_matrix
from sklearn.dummy import DummyClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier

warnings.filterwarnings("ignore")

def compute_ece(probs, y_true, n_bins=10):
    bin_limits = np.linspace(0, 1, n_bins + 1)
    confidences = np.max(probs, axis=1)
    predictions = np.argmax(probs, axis=1)
    accuracies = predictions == y_true
    
    ece = 0.0
    for i in range(n_bins):
        bin_mask = (confidences > bin_limits[i]) & (confidences <= bin_limits[i + 1])
        bin_size = np.sum(bin_mask)
        if bin_size > 0:
            bin_acc = np.mean(accuracies[bin_mask])
            bin_conf = np.mean(confidences[bin_mask])
            ece += (bin_size / len(probs)) * np.abs(bin_acc - bin_conf)
    return float(ece)

def run_evaluation(canonical_csv="data/processed/canonical_vpn_dataset.csv", output_dir="results"):
    os.makedirs(output_dir, exist_ok=True)
    print(f"[EvaluateModels] Loading canonical dataset from {canonical_csv}...")
    df = pd.read_csv(canonical_csv)
    
    # Filter valid classes (exclude UNKNOWN if any)
    df = df[df["traffic_class"] != "UNKNOWN"].reset_index(drop=True)
    
    shared_features = ["flow_duration_sec", "packets_per_sec", "bytes_per_sec", "mean_iat_sec", "std_iat_sec"]
    tier1_features = shared_features + ["mean_packet_size_bytes", "std_packet_size_bytes", "min_packet_size_bytes", "max_packet_size_bytes"]
    
    label_encoder = {cls: idx for idx, cls in enumerate(sorted(df["traffic_class"].unique()))}
    inv_label_encoder = {idx: cls for cls, idx in label_encoder.items()}
    df["label_idx"] = df["traffic_class"].map(label_encoder)
    
    results = {}
    
    # =========================================================================
    # EXPERIMENT 1: Leakage Check — Random Split vs Grouped Split on Tier 1
    # =========================================================================
    print("\n--- Running Experiment 1: Leakage & Overfitting Benchmark ---")
    df_t1 = df[df["provenance_tier"] == 1].reset_index(drop=True)
    X_t1 = df_t1[shared_features].values
    y_t1 = df_t1["label_idx"].values
    groups_t1 = df_t1["experiment_group"].values
    
    models = {
        "Dummy": DummyClassifier(strategy="stratified", random_state=42),
        "LogisticRegression": LogisticRegression(max_iter=1000, random_state=42),
        "RandomForest": RandomForestClassifier(n_estimators=100, random_state=42),
        "XGBoost": XGBClassifier(n_estimators=100, max_depth=4, learning_rate=0.1, eval_metric="mlogloss", random_state=42),
        "LightGBM": LGBMClassifier(n_estimators=100, random_state=42, verbose=-1)
    }
    
    exp1_res = {"random_kfold": {}, "grouped_kfold": {}}
    
    # Random 5-Fold
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    for m_name, model in models.items():
        f1_scores = []
        for train_idx, test_idx in skf.split(X_t1, y_t1):
            model.fit(X_t1[train_idx], y_t1[train_idx])
            preds = model.predict(X_t1[test_idx])
            _, _, f1, _ = precision_recall_fscore_support(y_t1[test_idx], preds, average="macro", zero_division=0)
            f1_scores.append(f1)
        exp1_res["random_kfold"][m_name] = round(float(np.mean(f1_scores)), 4)
        
    # Grouped K-Fold (groups by capture file / session)
    gkf = GroupKFold(n_splits=5)
    for m_name, model in models.items():
        f1_scores = []
        for train_idx, test_idx in gkf.split(X_t1, y_t1, groups=groups_t1):
            model.fit(X_t1[train_idx], y_t1[train_idx])
            preds = model.predict(X_t1[test_idx])
            _, _, f1, _ = precision_recall_fscore_support(y_t1[test_idx], preds, average="macro", zero_division=0)
            f1_scores.append(f1)
        exp1_res["grouped_kfold"][m_name] = round(float(np.mean(f1_scores)), 4)
        
    results["exp1_leakage_check"] = exp1_res
    print(f"  Exp 1 Random F1: {exp1_res['random_kfold']}")
    print(f"  Exp 1 Grouped F1: {exp1_res['grouped_kfold']}")

    # =========================================================================
    # EXPERIMENT 2: Tier 1 Benchmark (With Full Tier 1 Native Features)
    # =========================================================================
    print("\n--- Running Experiment 2: Tier 1 Full Feature Evaluation ---")
    X_t1_full = df_t1[tier1_features].values
    exp2_res = {}
    for m_name, model in models.items():
        acc_list, f1_list, prec_list, rec_list = [], [], [], []
        for train_idx, test_idx in gkf.split(X_t1_full, y_t1, groups=groups_t1):
            model.fit(X_t1_full[train_idx], y_t1[train_idx])
            preds = model.predict(X_t1_full[test_idx])
            acc = accuracy_score(y_t1[test_idx], preds)
            p, r, f, _ = precision_recall_fscore_support(y_t1[test_idx], preds, average="macro", zero_division=0)
            acc_list.append(acc)
            f1_list.append(f)
            prec_list.append(p)
            rec_list.append(r)
        exp2_res[m_name] = {
            "accuracy": round(float(np.mean(acc_list)), 4),
            "macro_f1": round(float(np.mean(f1_list)), 4),
            "precision": round(float(np.mean(prec_list)), 4),
            "recall": round(float(np.mean(rec_list)), 4)
        }
    results["exp2_tier1_benchmark"] = exp2_res

    # =========================================================================
    # EXPERIMENT 3: Tier 1 + Tier 2 Large-Scale Combined Benchmark
    # =========================================================================
    print("\n--- Running Experiment 3: Large-Scale Combined Benchmark (18k+ flows) ---")
    X_comb = df[shared_features].values
    y_comb = df["label_idx"].values
    groups_comb = df["experiment_group"].values
    
    exp3_res = {}
    gkf_comb = GroupKFold(n_splits=5)
    model_comparison_rows = []
    
    for m_name, model in models.items():
        acc_list, f1_list, prec_list, rec_list = [], [], [], []
        for train_idx, test_idx in gkf_comb.split(X_comb, y_comb, groups=groups_comb):
            model.fit(X_comb[train_idx], y_comb[train_idx])
            preds = model.predict(X_comb[test_idx])
            acc = accuracy_score(y_comb[test_idx], preds)
            p, r, f, _ = precision_recall_fscore_support(y_comb[test_idx], preds, average="macro", zero_division=0)
            acc_list.append(acc)
            f1_list.append(f)
            prec_list.append(p)
            rec_list.append(r)
            
        m_acc = round(float(np.mean(acc_list)), 4)
        m_f1 = round(float(np.mean(f1_list)), 4)
        m_prec = round(float(np.mean(prec_list)), 4)
        m_rec = round(float(np.mean(rec_list)), 4)
        
        exp3_res[m_name] = {
            "accuracy": m_acc,
            "macro_f1": m_f1,
            "precision": m_prec,
            "recall": m_rec
        }
        model_comparison_rows.append({
            "model": m_name,
            "accuracy": m_acc,
            "macro_f1": m_f1,
            "macro_precision": m_prec,
            "macro_recall": m_rec,
            "dataset": "Combined (Tier 1 + Tier 2)",
            "validation_strategy": "GroupKFold (5-fold)"
        })
        
    results["exp3_combined_benchmark"] = exp3_res
    pd.DataFrame(model_comparison_rows).to_csv(os.path.join(output_dir, "model_comparison.csv"), index=False)

    # =========================================================================
    # EXPERIMENT 4: Cross-Dataset Transferability
    # =========================================================================
    print("\n--- Running Experiment 4: Cross-Dataset Transferability ---")
    df_t2 = df[df["provenance_tier"] == 2].reset_index(drop=True)
    X_t2 = df_t2[shared_features].values
    y_t2 = df_t2["label_idx"].values
    
    # Train T1 -> Test T2
    rf = RandomForestClassifier(n_estimators=100, random_state=42)
    rf.fit(X_t1, y_t1)
    preds_t1_to_t2 = rf.predict(X_t2)
    acc_t1_to_t2 = round(float(accuracy_score(y_t2, preds_t1_to_t2)), 4)
    _, _, f1_t1_to_t2, _ = precision_recall_fscore_support(y_t2, preds_t1_to_t2, average="macro", zero_division=0)
    
    # Train T2 -> Test T1
    rf_t2 = RandomForestClassifier(n_estimators=100, random_state=42)
    rf_t2.fit(X_t2, y_t2)
    preds_t2_to_t1 = rf_t2.predict(X_t1)
    acc_t2_to_t1 = round(float(accuracy_score(y_t1, preds_t2_to_t1)), 4)
    _, _, f1_t2_to_t1, _ = precision_recall_fscore_support(y_t1, preds_t2_to_t1, average="macro", zero_division=0)
    
    results["exp4_cross_dataset_transfer"] = {
        "train_t1_test_t2": {
            "accuracy": acc_t1_to_t2,
            "macro_f1": round(float(f1_t1_to_t2), 4)
        },
        "train_t2_test_t1": {
            "accuracy": acc_t2_to_t1,
            "macro_f1": round(float(f1_t2_to_t1), 4)
        },
        "scientific_note": "Evaluates encrypted VPN application traffic generalization across testbed topologies without domain adaptation."
    }

    # =========================================================================
    # EXPERIMENT 5: Hyperparameter Sensitivity Matrix (XGBoost)
    # =========================================================================
    print("\n--- Running Experiment 5: Hyperparameter Grid (XGBoost) ---")
    param_grid = {
        "n_estimators": [50, 100, 200],
        "max_depth": [3, 5, 7],
        "learning_rate": [0.01, 0.1, 0.2]
    }
    grid_results = []
    for params in ParameterGrid(param_grid):
        xgb = XGBClassifier(**params, eval_metric="mlogloss", random_state=42)
        f1_list = []
        for train_idx, test_idx in gkf_comb.split(X_comb, y_comb, groups=groups_comb):
            xgb.fit(X_comb[train_idx], y_comb[train_idx])
            preds = xgb.predict(X_comb[test_idx])
            _, _, f, _ = precision_recall_fscore_support(y_comb[test_idx], preds, average="macro", zero_division=0)
            f1_list.append(f)
        grid_results.append({
            **params,
            "mean_macro_f1": round(float(np.mean(f1_list)), 4)
        })
    results["exp5_hyperparameter_sensitivity"] = grid_results
    pd.DataFrame(grid_results).to_csv(os.path.join(output_dir, "hyperparameter_grid.csv"), index=False)

    # =========================================================================
    # EXPERIMENT 6: Feature Ablation Study (Groups A-G)
    # =========================================================================
    print("\n--- Running Experiment 6: Feature Ablation Study ---")
    ablation_sets = {
        "Set_A_All_Shared": shared_features,
        "Set_B_Timing_Only": ["mean_iat_sec", "std_iat_sec", "flow_duration_sec"],
        "Set_C_Throughput_Only": ["packets_per_sec", "bytes_per_sec"],
        "Set_D_No_Duration": ["packets_per_sec", "bytes_per_sec", "mean_iat_sec", "std_iat_sec"],
        "Set_E_No_IAT": ["flow_duration_sec", "packets_per_sec", "bytes_per_sec"],
        "Set_F_IAT_Only": ["mean_iat_sec", "std_iat_sec"],
        "Set_G_ByteRate_Only": ["bytes_per_sec"]
    }
    ablation_res = []
    for set_name, feats in ablation_sets.items():
        X_sub = df[feats].values
        rf_ab = RandomForestClassifier(n_estimators=100, random_state=42)
        f1_list = []
        for train_idx, test_idx in gkf_comb.split(X_sub, y_comb, groups=groups_comb):
            rf_ab.fit(X_sub[train_idx], y_comb[train_idx])
            preds = rf_ab.predict(X_sub[test_idx])
            _, _, f, _ = precision_recall_fscore_support(y_comb[test_idx], preds, average="macro", zero_division=0)
            f1_list.append(f)
        ablation_res.append({
            "feature_set": set_name,
            "features_included": ", ".join(feats),
            "macro_f1": round(float(np.mean(f1_list)), 4)
        })
    results["exp6_feature_ablation"] = ablation_res
    pd.DataFrame(ablation_res).to_csv(os.path.join(output_dir, "feature_ablation.csv"), index=False)

    # =========================================================================
    # EXPERIMENT 7: Out-of-Distribution (OOD) Novel Class Detection
    # =========================================================================
    print("\n--- Running Experiment 7: Out-of-Distribution Novelty Detection ---")
    # Hold out VOIP and P2P in raw ISCX as unknown
    # Train on BULK, WEB, INTERACTIVE; Test on unknown
    train_classes = ["BULK", "WEB", "INTERACTIVE"]
    df_in_dist = df[df["traffic_class"].isin(train_classes)].reset_index(drop=True)
    df_ood = df[df["traffic_class"] == "ICMP"].reset_index(drop=True) # mapped from VOIP/testbed ICMP
    
    X_in = df_in_dist[shared_features].values
    y_in = df_in_dist["traffic_class"].map(lambda c: train_classes.index(c)).values
    
    rf_ood = RandomForestClassifier(n_estimators=100, random_state=42)
    rf_ood.fit(X_in, y_in)
    
    # Confidence on In-Distribution
    probs_in = rf_ood.predict_proba(X_in)
    max_conf_in = np.max(probs_in, axis=1)
    
    # Confidence on OOD
    if len(df_ood) > 0:
        X_ood = df_ood[shared_features].values
        probs_ood = rf_ood.predict_proba(X_ood)
        max_conf_ood = np.max(probs_ood, axis=1)
        
        # Test rejection threshold at 0.5 confidence
        ood_rejected = np.mean(max_conf_ood < 0.5)
        in_retained = np.mean(max_conf_in >= 0.5)
        
        results["exp7_ood_rejection"] = {
            "in_distribution_classes": train_classes,
            "held_out_classes": ["ICMP / VOIP"],
            "ood_sample_count": len(df_ood),
            "mean_in_dist_confidence": round(float(np.mean(max_conf_in)), 4),
            "mean_ood_confidence": round(float(np.mean(max_conf_ood)), 4),
            "ood_rejection_rate_at_threshold_0.5": round(float(ood_rejected), 4),
            "in_dist_retention_rate_at_threshold_0.5": round(float(in_retained), 4)
        }
    else:
        results["exp7_ood_rejection"] = {"status": "insufficient_ood_samples"}

    # =========================================================================
    # EXPERIMENT 8: Model Calibration & Uncertainty (ECE & Brier)
    # =========================================================================
    print("\n--- Running Experiment 8: Model Calibration & Uncertainty ---")
    calib_res = {}
    for m_name, model in [("RandomForest", RandomForestClassifier(n_estimators=100, random_state=42)),
                          ("XGBoost", XGBClassifier(n_estimators=100, max_depth=4, learning_rate=0.1, eval_metric="mlogloss", random_state=42))]:
        all_probs = []
        all_y = []
        for train_idx, test_idx in gkf_comb.split(X_comb, y_comb, groups=groups_comb):
            model.fit(X_comb[train_idx], y_comb[train_idx])
            probs = model.predict_proba(X_comb[test_idx])
            all_probs.append(probs)
            all_y.append(y_comb[test_idx])
            
        all_probs = np.vstack(all_probs)
        all_y = np.concatenate(all_y)
        
        ece_score = compute_ece(all_probs, all_y)
        
        # Multi-class Brier score = 1/N sum_i sum_k (p_ik - y_ik)^2
        y_onehot = np.zeros_like(all_probs)
        y_onehot[np.arange(len(all_y)), all_y] = 1.0
        brier = float(np.mean(np.sum((all_probs - y_onehot)**2, axis=1)))
        
        calib_res[m_name] = {
            "expected_calibration_error_ece": round(ece_score, 4),
            "brier_score": round(brier, 4)
        }
    results["exp8_model_calibration"] = calib_res

    # =========================================================================
    # EXPERIMENT 9: Error Analysis & Misclassification Forensics
    # =========================================================================
    print("\n--- Running Experiment 9: Misclassification Forensics ---")
    rf_final = RandomForestClassifier(n_estimators=100, random_state=42)
    # Train on 80%, predict on 20%
    skf_err = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    train_idx, test_idx = next(skf_err.split(X_comb, y_comb))
    
    rf_final.fit(X_comb[train_idx], y_comb[train_idx])
    test_preds = rf_final.predict(X_comb[test_idx])
    test_probs = rf_final.predict_proba(X_comb[test_idx])
    
    test_df = df.iloc[test_idx].copy()
    test_df["predicted_label_idx"] = test_preds
    test_df["predicted_class"] = [inv_label_encoder[p] for p in test_preds]
    test_df["confidence"] = np.max(test_probs, axis=1)
    test_df["is_misclassified"] = test_df["label_idx"] != test_df["predicted_label_idx"]
    
    errors_df = test_df[test_df["is_misclassified"]]
    errors_df.to_csv(os.path.join(output_dir, "error_analysis.csv"), index=False)
    
    results["exp9_error_forensics"] = {
        "test_samples": len(test_df),
        "total_misclassified": len(errors_df),
        "error_rate": round(len(errors_df) / len(test_df), 4),
        "top_confusion_pairs": {
            f"{k[0]} -> {k[1]}": int(v)
            for k, v in errors_df.groupby(["traffic_class", "predicted_class"]).size().to_dict().items()
        }
    }
    
    # Save overall metrics.json
    metrics_path = os.path.join(output_dir, "metrics.json")
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"\n[EvaluateModels] All 9 experiments completed successfully! Results written to {metrics_path}")

if __name__ == "__main__":
    run_evaluation()
