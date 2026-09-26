import os
import json
import pandas as pd
import xgboost as xgb

def export_trained_model():
    csv_path = "data/processed/native_ipsec_enhanced_dataset.csv"
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Processed dataset not found: {csv_path}")

    df = pd.read_csv(csv_path)
    features = [
        "flow_duration_sec", "packets_per_sec", "bytes_per_sec",
        "mean_iat_sec", "std_iat_sec", "mean_packet_size_bytes",
        "std_packet_size_bytes", "min_packet_size_bytes", "max_packet_size_bytes",
        "pkt_len_p25", "pkt_len_p50", "pkt_len_p75", "pkt_len_p90",
        "directional_byte_ratio"
    ]
    classes = sorted(df['traffic_class'].unique())
    X = df[features].fillna(0).values
    y = df['traffic_class'].map({c: i for i, c in enumerate(classes)}).values

    print(f"Training XGBoost on {len(df)} authentic samples with classes: {classes}...")
    clf = xgb.XGBClassifier(
        n_estimators=150,
        max_depth=6,
        learning_rate=0.08,
        random_state=42,
        n_jobs=-1
    )
    clf.fit(X, y)

    out_model = "backend/models/xgb_native_ipsec.json"
    out_meta = "backend/models/model_metadata.json"
    os.makedirs(os.path.dirname(out_model), exist_ok=True)
    
    clf.save_model(out_model)
    
    metadata = {
        "model_name": "XGBoost Native IPsec Classifier (Enhanced)",
        "model_version": "v2.0-session-isolated",
        "training_dataset": "DS1_NATIVE_IPSEC_ENHANCED (1829 samples)",
        "total_training_samples": len(df),
        "classes": classes,
        "features": features
    }
    with open(out_meta, "w") as f:
        json.dump(metadata, f, indent=2)

    print(f"Successfully exported model to {out_model} ({os.path.getsize(out_model)} bytes)")
    print(f"Successfully exported metadata to {out_meta}")

if __name__ == "__main__":
    export_trained_model()
