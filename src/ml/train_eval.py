import os
import json
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.dummy import DummyClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix

try:
    from xgboost import XGBClassifier
    XGB_AVAILABLE = True
except ImportError:
    XGB_AVAILABLE = False

def train_and_evaluate_models(features_csv="results/features.csv", metrics_out="results/metrics.json", comp_out="results/model_comparison.csv"):
    """
    Trains ML baseline classifiers on flow features with strict flow-level splitting.
    Outputs metrics.json and model_comparison.csv.
    """
    os.makedirs(os.path.dirname(metrics_out), exist_ok=True)
    os.makedirs(os.path.dirname(comp_out), exist_ok=True)

    if not os.path.exists(features_csv):
        print(f"[ERROR] Features file {features_csv} not found.")
        return {}

    df = pd.read_csv(features_csv)
    if df.empty or len(df) < 4:
        print("[WARN] Insufficient samples in features dataset for ML training.")
        metrics = {
            "status": "insufficient_data",
            "message": "Fewer than 4 flow samples extracted; statistical reporting only."
        }
        with open(metrics_out, "w") as f:
            json.dump(metrics, f, indent=2)
        return metrics

    # Feature columns (strictly statistical payload features, excluding IDs/labels)
    feature_cols = [
        "packet_count", "total_bytes", "mean_packet_size", "median_packet_size",
        "std_packet_size", "min_packet_size", "max_packet_size", "p25_packet_size",
        "p75_packet_size", "flow_duration_sec", "packets_per_sec", "bytes_per_sec",
        "mean_iat_sec", "std_iat_sec", "fwd_packet_count", "rev_packet_count",
        "fwd_bytes", "rev_bytes", "burst_count", "mean_burst_packets"
    ]

    # Clean data & fill missing
    X = df[feature_cols].copy().fillna(0)
    y = df["traffic_class"].copy()

    classes = np.unique(y)
    print(f"[ML] Training dataset: {len(X)} samples across classes: {list(classes)}")

    # Flow-level train/test split (70% train / 30% test)
    # If sample count is small, use stratified split or 60/40
    test_size = 0.3 if len(X) >= 10 else 0.4
    try:
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=test_size, random_state=42, stratify=y)
    except ValueError:
        # Fallback if class counts too small for stratified
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=test_size, random_state=42)

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    models = {
        "Dummy (Most Frequent)": DummyClassifier(strategy="most_frequent"),
        "Logistic Regression": LogisticRegression(max_iter=1000, random_state=42),
        "Random Forest": RandomForestClassifier(n_estimators=100, random_state=42)
    }

    if XGB_AVAILABLE and len(classes) > 1:
        # XGBoost requires label encoding
        label_map = {cls: idx for idx, cls in enumerate(classes)}
        models["XGBoost"] = XGBClassifier(random_state=42, eval_metric="mlogloss")

    results_summary = []
    detailed_metrics = {
        "dataset_info": {
            "total_samples": len(X),
            "train_samples": len(X_train),
            "test_samples": len(X_test),
            "num_features": len(feature_cols),
            "classes": list(classes)
        },
        "models": {}
    }

    best_model_name = ""
    best_f1 = -1.0
    best_cm = []

    for name, clf in models.items():
        print(f"[ML] Training {name}...")
        if name == "XGBoost":
            y_train_enc = y_train.map(label_map)
            clf.fit(X_train_scaled, y_train_enc)
            preds_enc = clf.predict(X_test_scaled)
            inv_map = {idx: cls for cls, idx in label_map.items()}
            preds = [inv_map[p] for p in preds_enc]
        else:
            clf.fit(X_train_scaled, y_train)
            preds = clf.predict(X_test_scaled)

        acc = float(accuracy_score(y_test, preds))
        prec_macro, rec_macro, f1_macro, _ = precision_recall_fscore_support(y_test, preds, average="macro", zero_division=0)
        _, _, f1_weighted, _ = precision_recall_fscore_support(y_test, preds, average="weighted", zero_division=0)

        cm = confusion_matrix(y_test, preds, labels=classes).tolist()

        model_res = {
            "accuracy": round(acc, 4),
            "macro_precision": round(float(prec_macro), 4),
            "macro_recall": round(float(rec_macro), 4),
            "macro_f1": round(float(f1_macro), 4),
            "weighted_f1": round(float(f1_weighted), 4),
            "confusion_matrix": cm
        }
        detailed_metrics["models"][name] = model_res

        results_summary.append({
            "Model": name,
            "Accuracy": round(acc, 4),
            "Macro Precision": round(float(prec_macro), 4),
            "Macro Recall": round(float(rec_macro), 4),
            "Macro F1": round(float(f1_macro), 4),
            "Weighted F1": round(float(f1_weighted), 4)
        })

        if float(f1_macro) > best_f1:
            best_f1 = float(f1_macro)
            best_model_name = name
            best_cm = cm

    # Save outputs
    with open(metrics_out, "w") as f:
        json.dump(detailed_metrics, f, indent=2)

    comp_df = pd.DataFrame(results_summary)
    comp_df.to_csv(comp_out, index=False)
    print(f"[ML] Metrics written to {metrics_out} and comparison to {comp_out}")

    return detailed_metrics

if __name__ == "__main__":
    train_and_evaluate_models()
