import os
import sys
import json
import numpy as np
import pandas as pd
from sklearn.model_selection import GroupKFold
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, confusion_matrix

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from src.ml.run_sequence_experiment import extract_dataset_all_views

def run_forensic_audit():
    print("=================================================================")
    print("      IPsecTrace INDEPENDENT FORENSIC BENCHMARK AUDIT          ")
    print("=================================================================")
    
    csv_path = "data/processed/native_ipsec_enhanced_dataset.csv"
    pcap_dir = "data/raw_native_ipsec/pcaps"
    
    df, seq_arr, ctx_arr, mask_arr = extract_dataset_all_views(csv_path, pcap_dir)
    
    classes = sorted(df['traffic_class'].unique())
    class_to_idx = {c: i for i, c in enumerate(classes)}
    y = df['traffic_class'].map(class_to_idx).values
    groups = df['experiment_group'].values
    pcaps = df['pcap_source'].values
    
    gkf = GroupKFold(n_splits=5)
    
    print(f"Total Windows: {len(df)}")
    print(f"Total PCAPs: {df['pcap_source'].nunique()}")
    print(f"Total Experiment Groups: {df['experiment_group'].nunique()}")
    print(f"Total Classes: {classes}")
    
    fold_audit = []
    
    for fold, (train_idx, test_idx) in enumerate(gkf.split(df, y, groups), 1):
        train_groups = set(groups[train_idx])
        test_groups = set(groups[test_idx])
        group_overlap = train_groups.intersection(test_groups)
        
        train_pcaps = set(pcaps[train_idx])
        test_pcaps = set(pcaps[test_idx])
        pcap_overlap = train_pcaps.intersection(test_pcaps)
        
        y_train = y[train_idx]
        y_test = y[test_idx]
        
        fold_info = {
            "fold": fold,
            "train_windows": len(train_idx),
            "test_windows": len(test_idx),
            "train_groups": len(train_groups),
            "test_groups": len(test_groups),
            "group_overlap_count": len(group_overlap),
            "train_pcaps": len(train_pcaps),
            "test_pcaps": len(test_pcaps),
            "pcap_overlap_count": len(pcap_overlap),
            "test_class_dist": {classes[i]: int(np.sum(y_test == i)) for i in range(len(classes))},
            "test_environments": sorted(df.iloc[test_idx]['environment_id'].dropna().unique().tolist())
        }
        fold_audit.append(fold_info)
        
        print(f"\n--- Fold {fold} Partition Audit ---")
        print(f"Train Windows: {len(train_idx)}, Test Windows: {len(test_idx)}")
        print(f"Train PCAPs: {len(train_pcaps)}, Test PCAPs: {len(test_pcaps)}, PCAP Overlap: {len(pcap_overlap)}")
        print(f"Train Groups: {len(train_groups)}, Test Groups: {len(test_groups)}, Group Overlap: {len(group_overlap)}")
        print(f"Test Class Dist: {fold_info['test_class_dist']}")
        print(f"Test Environments: {fold_info['test_environments']}")
        
        if len(group_overlap) > 0 or len(pcap_overlap) > 0:
            print("CRITICAL ERROR: PARTITION LEAKAGE DETECTED!")
        else:
            print("VERIFICATION PASSED: 0% Group and 0% PCAP overlap.")

    os.makedirs("results", exist_ok=True)
    with open("results/audit_partition_integrity.json", "w") as f:
        json.dump(fold_audit, f, indent=2)
    print("\nSaved partition audit to results/audit_partition_integrity.json")

if __name__ == "__main__":
    run_forensic_audit()
