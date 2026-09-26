import json
import os
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GroupKFold
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, confusion_matrix
import xgboost as xgb

def evaluate_enhanced_pipeline():
    csv_path = "data/processed/native_ipsec_enhanced_dataset.csv"
    if not os.path.exists(csv_path):
        print("Enhanced dataset not found.")
        return

    df = pd.read_csv(csv_path)
    print(f"Loaded {len(df)} enhanced samples across {df['experiment_group'].nunique()} groups.")

    features = [
        "flow_duration_sec", "packets_per_sec", "bytes_per_sec",
        "mean_iat_sec", "std_iat_sec", "mean_packet_size_bytes",
        "std_packet_size_bytes", "min_packet_size_bytes", "max_packet_size_bytes",
        "pkt_len_p25", "pkt_len_p50", "pkt_len_p75", "pkt_len_p90",
        "directional_byte_ratio"
    ]

    X = df[features].fillna(0).values
    classes = sorted(df['traffic_class'].unique())
    y = df['traffic_class'].map({c: i for i, c in enumerate(classes)}).values
    groups = df['experiment_group'].values

    gkf = GroupKFold(n_splits=5)
    
    # 1. Random Forest on Enhanced Features
    rf_accs, rf_f1s = [], []
    y_true_all, y_pred_all = [], []

    for train_idx, test_idx in gkf.split(X, y, groups=groups):
        X_train, X_test = X[train_idx], X[test_idx]
        y_train, y_test = y[train_idx], y[test_idx]

        rf = RandomForestClassifier(n_estimators=150, max_depth=12, min_samples_split=4, random_state=42, n_jobs=-1)
        rf.fit(X_train, y_train)
        y_pred = rf.predict(X_test)

        rf_accs.append(accuracy_score(y_test, y_pred))
        rf_f1s.append(f1_score(y_test, y_pred, average='macro'))
        y_true_all.extend(y_test)
        y_pred_all.extend(y_pred)

    # 2. XGBoost on Enhanced Features
    xgb_accs, xgb_f1s = [], []
    for train_idx, test_idx in gkf.split(X, y, groups=groups):
        X_train, X_test = X[train_idx], X[test_idx]
        y_train, y_test = y[train_idx], y[test_idx]

        clf = xgb.XGBClassifier(n_estimators=150, max_depth=6, learning_rate=0.08, random_state=42, n_jobs=-1)
        clf.fit(X_train, y_train)
        y_pred = clf.predict(X_test)

        xgb_accs.append(accuracy_score(y_test, y_pred))
        xgb_f1s.append(f1_score(y_test, y_pred, average='macro'))

    cm = confusion_matrix(y_true_all, y_pred_all)

    results = {
        "dataset_name": "DS1_NATIVE_IPSEC_ENHANCED",
        "total_samples": len(df),
        "total_groups": int(df['experiment_group'].nunique()),
        "features_used": features,
        "random_forest_enhanced": {
            "accuracy_mean": float(np.mean(rf_accs)),
            "accuracy_std": float(np.std(rf_accs)),
            "macro_f1_mean": float(np.mean(rf_f1s)),
            "macro_f1_std": float(np.std(rf_f1s))
        },
        "xgboost_enhanced": {
            "accuracy_mean": float(np.mean(xgb_accs)),
            "accuracy_std": float(np.std(xgb_accs)),
            "macro_f1_mean": float(np.mean(xgb_f1s)),
            "macro_f1_std": float(np.std(xgb_f1s))
        },
        "confusion_matrix": cm.tolist(),
        "classes": classes
    }

    os.makedirs("results", exist_ok=True)
    with open("results/enhanced_native_ipsec_metrics.json", "w") as f:
        json.dump(results, f, indent=2)

    print("\n=======================================================")
    print("   ENHANCED FEATURE PIPELINE RESULTS (GroupKFold)      ")
    print("=======================================================")
    print(f"Random Forest  -> Accuracy: {np.mean(rf_accs)*100:.2f}% ± {np.std(rf_accs)*100:.2f}%, Macro-F1: {np.mean(rf_f1s)*100:.2f}% ± {np.std(rf_f1s)*100:.2f}%")
    print(f"XGBoost        -> Accuracy: {np.mean(xgb_accs)*100:.2f}% ± {np.std(xgb_accs)*100:.2f}%, Macro-F1: {np.mean(xgb_f1s)*100:.2f}% ± {np.std(xgb_f1s)*100:.2f}%")
    print(f"Saved results to results/enhanced_native_ipsec_metrics.json")

if __name__ == "__main__":
    evaluate_enhanced_pipeline()
