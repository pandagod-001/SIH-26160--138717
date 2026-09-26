import os
import json
import numpy as np
import pandas as pd
from sklearn.model_selection import GroupKFold
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.dummy import DummyClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, balanced_accuracy_score, precision_recall_fscore_support, confusion_matrix

try:
    from xgboost import XGBClassifier
    XGB_AVAILABLE = True
except ImportError:
    XGB_AVAILABLE = False

try:
    from lightgbm import LGBMClassifier
    LGBM_AVAILABLE = True
except ImportError:
    LGBM_AVAILABLE = False

def recalculate_metrics_with_ci(csv_path="data/processed/canonical_vpn_dataset.csv", out_csv="results/phase2_metric_recalculation.csv"):
    """
    Recomputes fold-level metrics across 5 GroupKFold splits and calculates mean, std dev, and 95% CIs.
    """
    os.makedirs("results", exist_ok=True)

    if not os.path.exists(csv_path):
        print(f"[ERROR] Canonical dataset {csv_path} not found.")
        return

    df = pd.read_csv(csv_path)
    feature_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    X = df[feature_cols].copy().fillna(0)
    y = df["traffic_class"].copy()
    groups = df["experiment_group"].copy()

    le = LabelEncoder()
    y_enc = le.fit_transform(y)

    models = {
        "Dummy (Baseline)": DummyClassifier(strategy="most_frequent"),
        "Logistic Regression": LogisticRegression(max_iter=1000, random_state=42),
        "Random Forest": RandomForestClassifier(n_estimators=100, random_state=42)
    }
    if XGB_AVAILABLE:
        models["XGBoost"] = XGBClassifier(n_estimators=100, max_depth=5, learning_rate=0.1, random_state=42, eval_metric="mlogloss")
    if LGBM_AVAILABLE:
        models["LightGBM"] = LGBMClassifier(n_estimators=100, random_state=42, verbose=-1)

    gkf = GroupKFold(n_splits=5)
    recalc_rows = []

    for name, clf in models.items():
        fold_accs = []
        fold_b_accs = []
        fold_precs = []
        fold_recs = []
        fold_f1s = []

        for train_idx, val_idx in gkf.split(X, y_enc, groups=groups):
            X_tr, X_va = X.iloc[train_idx], X.iloc[val_idx]
            y_tr, y_va = y_enc[train_idx], y_enc[val_idx]

            scaler = StandardScaler()
            X_tr_s = scaler.fit_transform(X_tr)
            X_va_s = scaler.transform(X_va)

            clf.fit(X_tr_s, y_tr)
            preds = clf.predict(X_va_s)

            acc = accuracy_score(y_va, preds)
            b_acc = balanced_accuracy_score(y_va, preds)
            prec, rec, f1, _ = precision_recall_fscore_support(y_va, preds, average="macro", zero_division=0)

            fold_accs.append(acc)
            fold_b_accs.append(b_acc)
            fold_precs.append(prec)
            fold_recs.append(rec)
            fold_f1s.append(f1)

        # Calculate mean, std, and 95% Confidence Interval (1.96 * std / sqrt(N))
        mean_acc = np.mean(fold_accs)
        std_acc = np.std(fold_accs)
        ci95_acc = 1.96 * std_acc / np.sqrt(len(fold_accs))

        mean_f1 = np.mean(fold_f1s)
        std_f1 = np.std(fold_f1s)
        ci95_f1 = 1.96 * std_f1 / np.sqrt(len(fold_f1s))

        mean_prec = np.mean(fold_precs)
        mean_rec = np.mean(fold_recs)

        recalc_rows.append({
            "Model": name,
            "Accuracy Mean": round(float(mean_acc), 4),
            "Accuracy Std": round(float(std_acc), 4),
            "Accuracy 95% CI": f"{mean_acc:.4f} ± {ci95_acc:.4f}",
            "Macro F1 Mean": round(float(mean_f1), 4),
            "Macro F1 Std": round(float(std_f1), 4),
            "Macro F1 95% CI": f"{mean_f1:.4f} ± {ci95_f1:.4f}",
            "Macro Precision Mean": round(float(mean_prec), 4),
            "Macro Recall Mean": round(float(mean_rec), 4)
        })

    df_recalc = pd.DataFrame(recalc_rows)
    df_recalc.to_csv(out_csv, index=False)
    print(f"[METRIC RECALC] Recalculated metrics with fold-level CIs saved to {out_csv}")
    print(df_recalc.to_string(index=False))
    return df_recalc

if __name__ == "__main__":
    recalculate_metrics_with_ci()
