import os
import json
import pandas as pd
import numpy as np
import shutil
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.dummy import DummyClassifier
from sklearn.model_selection import GroupKFold
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, confusion_matrix, roc_auc_score
import xgboost as xgb

WORKSPACE = "/mnt/c/Users/Abhijay/ipsec"
DOCS_FINAL = os.path.join(WORKSPACE, "docs", "final")
RESULTS_FINAL = os.path.join(WORKSPACE, "results", "final")
os.makedirs(DOCS_FINAL, exist_ok=True)
os.makedirs(RESULTS_FINAL, exist_ok=True)

def execute_final_native_eval():
    csv_path = os.path.join(WORKSPACE, "data", "processed", "native_ipsec_large_dataset.csv")
    df = pd.read_csv(csv_path)

    features = [
        "flow_duration_sec", "packets_per_sec", "bytes_per_sec",
        "mean_iat_sec", "std_iat_sec", "mean_packet_size_bytes",
        "std_packet_size_bytes", "min_packet_size_bytes", "max_packet_size_bytes"
    ]

    classes = sorted(df['traffic_class'].unique())
    y = df['traffic_class'].map({c: i for i, c in enumerate(classes)}).values
    groups = df['experiment_group'].values
    X = df[features].fillna(0).values

    gkf = GroupKFold(n_splits=5)

    models = {
        "Random Forest (100 Trees)": RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42, n_jobs=-1),
        "XGBoost": xgb.XGBClassifier(n_estimators=100, max_depth=6, learning_rate=0.1, random_state=42, n_jobs=-1),
        "Logistic Regression": LogisticRegression(max_iter=1000, random_state=42),
        "Dummy (Stratified)": DummyClassifier(strategy="stratified", random_state=42)
    }

    metrics_summary = []
    fold_records = []
    all_y_true, all_y_pred = [], []

    for m_name, model in models.items():
        accs, precs, recs, f1s = [], [], [], []
        for fold_idx, (train_idx, test_idx) in enumerate(gkf.split(X, y, groups=groups)):
            X_train, X_test = X[train_idx], X[test_idx]
            y_train, y_test = y[train_idx], y[test_idx]

            model.fit(X_train, y_train)
            y_pred = model.predict(X_test)

            acc = accuracy_score(y_test, y_pred)
            prec = precision_score(y_test, y_pred, average='macro', zero_division=0)
            rec = recall_score(y_test, y_pred, average='macro', zero_division=0)
            f1 = f1_score(y_test, y_pred, average='macro', zero_division=0)

            accs.append(acc)
            precs.append(prec)
            recs.append(rec)
            f1s.append(f1)

            fold_records.append({
                "model": m_name,
                "fold": fold_idx + 1,
                "accuracy": round(acc, 4),
                "macro_precision": round(prec, 4),
                "macro_recall": round(rec, 4),
                "macro_f1": round(f1, 4)
            })

            if m_name == "Random Forest (100 Trees)":
                all_y_true.extend(y_test)
                all_y_pred.extend(y_pred)

        m_acc, s_acc = np.mean(accs), np.std(accs)
        m_f1, s_f1 = np.mean(f1s), np.std(f1s)
        ci95_f1 = 1.96 * (s_f1 / np.sqrt(5))
        ci95_acc = 1.96 * (s_acc / np.sqrt(5))

        metrics_summary.append({
            "model": m_name,
            "accuracy_mean": round(m_acc, 4),
            "accuracy_std": round(s_acc, 4),
            "accuracy_ci95": f"{m_acc*100:.2f}% ± {ci95_acc*100:.2f}%",
            "macro_precision_mean": round(np.mean(precs), 4),
            "macro_recall_mean": round(np.mean(recs), 4),
            "macro_f1_mean": round(m_f1, 4),
            "macro_f1_std": round(s_f1, 4),
            "macro_f1_ci95": f"{m_f1*100:.2f}% ± {ci95_f1*100:.2f}%"
        })

    # Save to results/final
    df_metrics = pd.DataFrame(metrics_summary)
    df_folds = pd.DataFrame(fold_records)

    df_metrics.to_csv(os.path.join(RESULTS_FINAL, "native_metrics.csv"), index=False)
    df_folds.to_csv(os.path.join(RESULTS_FINAL, "native_fold_results.csv"), index=False)

    with open(os.path.join(RESULTS_FINAL, "native_metrics.json"), "w") as f:
        json.dump({
            "samples": len(df),
            "pcaps": 294,
            "groups": int(df['experiment_group'].nunique()),
            "models": metrics_summary
        }, f, indent=2)

    # 2. Recompute Native Ablation
    ablation_subsets = {
        "Set A (All 9 Features)": features,
        "Set B (Timing Only)": ["flow_duration_sec", "mean_iat_sec", "std_iat_sec"],
        "Set C (Throughput Only)": ["packets_per_sec", "bytes_per_sec"],
        "Set D (Packet Size Only)": ["mean_packet_size_bytes", "std_packet_size_bytes", "min_packet_size_bytes", "max_packet_size_bytes"],
        "Set E (No IAT: Size+Throughput)": ["flow_duration_sec", "packets_per_sec", "bytes_per_sec", "mean_packet_size_bytes", "std_packet_size_bytes", "min_packet_size_bytes", "max_packet_size_bytes"],
        "Set F (IAT Only)": ["mean_iat_sec", "std_iat_sec"],
        "Set G (ByteRate Only)": ["bytes_per_sec"]
    }

    ablation_rows = []
    for s_name, feats in ablation_subsets.items():
        X_sub = df[feats].fillna(0).values
        sub_f1s = []
        for train_idx, test_idx in gkf.split(X_sub, y, groups=groups):
            X_tr, X_te = X_sub[train_idx], X_sub[test_idx]
            y_tr, y_te = y[train_idx], y[test_idx]
            rf = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42, n_jobs=-1)
            rf.fit(X_tr, y_tr)
            sub_f1s.append(f1_score(y_te, rf.predict(X_te), average='macro', zero_division=0))
        
        m_f1, s_f1 = np.mean(sub_f1s), np.std(sub_f1s)
        ablation_rows.append({
            "subset_name": s_name,
            "feature_count": len(feats),
            "macro_f1_mean": round(m_f1, 4),
            "macro_f1_std": round(s_f1, 4),
            "macro_f1_ci95": f"{m_f1*100:.2f}% ± {1.96*(s_f1/np.sqrt(5))*100:.2f}%"
        })

    df_ablation = pd.DataFrame(ablation_rows).sort_values(by="macro_f1_mean", ascending=False)
    df_ablation.to_csv(os.path.join(RESULTS_FINAL, "native_ablation.csv"), index=False)
    with open(os.path.join(RESULTS_FINAL, "native_ablation.json"), "w") as f:
        json.dump(ablation_rows, f, indent=2)

    # 3. Recompute Held-out OOD Evaluation
    id_df = df[df['traffic_class'] != 'ICMP'].copy()
    ood_df = df[df['traffic_class'] == 'ICMP'].copy()

    id_classes = sorted(id_df['traffic_class'].unique())
    y_id = id_df['traffic_class'].map({c: i for i, c in enumerate(id_classes)}).values
    X_id = id_df[features].fillna(0).values
    groups_id = id_df['experiment_group'].values
    X_ood = ood_df[features].fillna(0).values

    id_test_confidences = []
    ood_confidences = []

    for train_idx, test_idx in gkf.split(X_id, y_id, groups=groups_id):
        X_tr, X_te = X_id[train_idx], X_id[test_idx]
        y_tr, y_te = y_id[train_idx], y_id[test_idx]

        rf = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42, n_jobs=-1)
        rf.fit(X_tr, y_tr)

        id_test_confidences.extend(np.max(rf.predict_proba(X_te), axis=1))
        ood_confidences.extend(np.max(rf.predict_proba(X_ood), axis=1))

    id_test_conf = np.array(id_test_confidences)
    ood_conf = np.array(ood_confidences)

    y_true_ood = np.concatenate([np.ones(len(id_test_conf)), np.zeros(len(ood_conf))])
    y_scores_ood = np.concatenate([id_test_conf, ood_conf])
    auroc = float(roc_auc_score(y_true_ood, y_scores_ood))

    ood_res = {
        "evaluation_protocol": "HELD_OUT_ID_SPLIT_VS_UNSEEN_OOD",
        "id_classes": id_classes,
        "ood_class": "ICMP",
        "total_id_samples": len(id_df),
        "total_ood_samples": len(ood_df),
        "mean_heldout_id_confidence": round(float(np.mean(id_test_conf)), 4),
        "mean_unseen_ood_confidence": round(float(np.mean(ood_conf)), 4),
        "auroc_score": round(auroc, 4),
        "threshold_sweep": [
            {"threshold": 0.5, "id_retention": round(float(np.mean(id_test_conf >= 0.5)), 4), "ood_rejection": round(float(np.mean(ood_conf < 0.5)), 4)},
            {"threshold": 0.6, "id_retention": round(float(np.mean(id_test_conf >= 0.6)), 4), "ood_rejection": round(float(np.mean(ood_conf < 0.6)), 4)},
            {"threshold": 0.7, "id_retention": round(float(np.mean(id_test_conf >= 0.7)), 4), "ood_rejection": round(float(np.mean(ood_conf < 0.7)), 4)}
        ]
    }
    with open(os.path.join(RESULTS_FINAL, "ood_metrics.json"), "w") as f:
        json.dump(ood_res, f, indent=2)

    print("[SUCCESS] All results generated in results/final/")

if __name__ == "__main__":
    execute_final_native_eval()
