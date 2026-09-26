import pandas as pd
import numpy as np
import os
import json
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.dummy import DummyClassifier
from sklearn.model_selection import GroupKFold
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, classification_report
import xgboost as xgb
import shutil

def run_native_models_comparison():
    csv_path = "data/processed/native_ipsec_large_dataset.csv"
    if not os.path.exists(csv_path):
        print("[ERROR] Dataset not found")
        return

    df = pd.read_csv(csv_path)
    features = [
        "flow_duration_sec", "packets_per_sec", "bytes_per_sec",
        "mean_iat_sec", "std_iat_sec", "mean_packet_size_bytes",
        "std_packet_size_bytes", "min_packet_size_bytes", "max_packet_size_bytes"
    ]

    X = df[features].fillna(0).values
    classes = sorted(df['traffic_class'].unique())
    y = df['traffic_class'].map({c: i for i, c in enumerate(classes)}).values
    groups = df['experiment_group'].values

    models = {
        "Dummy (Stratified)": DummyClassifier(strategy="stratified", random_state=42),
        "Logistic Regression": LogisticRegression(max_iter=1000, random_state=42),
        "Random Forest (100 Trees)": RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42, n_jobs=-1),
        "XGBoost": xgb.XGBClassifier(n_estimators=100, max_depth=6, learning_rate=0.1, random_state=42, n_jobs=-1)
    }

    gkf = GroupKFold(n_splits=5)
    model_rows = []
    fold_rows = []

    for m_name, model in models.items():
        accs, precs, recs, f1s, w_f1s = [], [], [], [], []
        
        for fold_idx, (train_idx, test_idx) in enumerate(gkf.split(X, y, groups=groups)):
            X_train, X_test = X[train_idx], X[test_idx]
            y_train, y_test = y[train_idx], y[test_idx]

            model.fit(X_train, y_train)
            y_pred = model.predict(X_test)

            acc = accuracy_score(y_test, y_pred)
            prec = precision_score(y_test, y_pred, average='macro', zero_division=0)
            rec = recall_score(y_test, y_pred, average='macro', zero_division=0)
            f1 = f1_score(y_test, y_pred, average='macro', zero_division=0)
            wf1 = f1_score(y_test, y_pred, average='weighted', zero_division=0)

            accs.append(acc)
            precs.append(prec)
            recs.append(rec)
            f1s.append(f1)
            w_f1s.append(wf1)

            fold_rows.append({
                "model": m_name,
                "fold": fold_idx + 1,
                "accuracy": round(acc, 4),
                "macro_precision": round(prec, 4),
                "macro_recall": round(rec, 4),
                "macro_f1": round(f1, 4),
                "weighted_f1": round(wf1, 4)
            })

        mean_acc, std_acc = np.mean(accs), np.std(accs)
        mean_f1, std_f1 = np.mean(f1s), np.std(f1s)
        ci95 = 1.96 * (std_f1 / np.sqrt(5))

        model_rows.append({
            "model": m_name,
            "accuracy_mean": round(mean_acc, 4),
            "accuracy_std": round(std_acc, 4),
            "accuracy_ci95": f"{mean_acc*100:.2f}% ± {1.96*(std_acc/np.sqrt(5))*100:.2f}%",
            "macro_precision_mean": round(np.mean(precs), 4),
            "macro_recall_mean": round(np.mean(recs), 4),
            "macro_f1_mean": round(mean_f1, 4),
            "macro_f1_std": round(std_f1, 4),
            "macro_f1_ci95": f"{mean_f1*100:.2f}% ± {ci95*100:.2f}%",
            "weighted_f1_mean": round(np.mean(w_f1s), 4)
        })

    df_models = pd.DataFrame(model_rows).sort_values(by="macro_f1_mean", ascending=False)
    df_folds = pd.DataFrame(fold_rows)

    out_comp = "results/final_native_ipsec_model_comparison.csv"
    out_fold = "results/final_native_ipsec_fold_metrics.csv"

    df_models.to_csv(out_comp, index=False)
    df_folds.to_csv(out_fold, index=False)

    shutil.copy(out_comp, "IPsecTrace_FINAL_MASTER/results/authoritative/")
    shutil.copy(out_fold, "IPsecTrace_FINAL_MASTER/results/authoritative/")

    print("\n=======================================================")
    print("   PRIMARY NATIVE IPSEC MODEL COMPARISON (5-Fold GKF)  ")
    print("=======================================================")
    print(df_models[["model", "accuracy_mean", "macro_f1_mean", "macro_f1_ci95"]])

if __name__ == "__main__":
    run_native_models_comparison()
