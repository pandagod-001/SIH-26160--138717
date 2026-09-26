import os
import sys
import json
import numpy as np
import pandas as pd
from sklearn.model_selection import GroupKFold

def check_splits_fast():
    csv_path = "data/processed/native_ipsec_enhanced_dataset.csv"
    df = pd.read_csv(csv_path)
    
    classes = sorted(df['traffic_class'].unique())
    class_to_idx = {c: i for i, c in enumerate(classes)}
    y = df['traffic_class'].map(class_to_idx).values
    groups = df['experiment_group'].values
    pcaps = df['pcap_source'].values
    
    gkf = GroupKFold(n_splits=5)
    
    print(f"Total Windows: {len(df)}")
    print(f"Total PCAPs: {df['pcap_source'].nunique()}")
    print(f"Total Experiment Groups: {df['experiment_group'].nunique()}")
    
    fold_audit = []
    
    for fold, (train_idx, test_idx) in enumerate(gkf.split(df, y, groups), 1):
        train_groups = set(groups[train_idx])
        test_groups = set(groups[test_idx])
        group_overlap = train_groups.intersection(test_groups)
        
        train_pcaps = set(pcaps[train_idx])
        test_pcaps = set(pcaps[test_idx])
        pcap_overlap = train_pcaps.intersection(test_pcaps)
        
        y_test = y[test_idx]
        
        fold_info = {
            "fold": fold,
            "train_windows": int(len(train_idx)),
            "test_windows": int(len(test_idx)),
            "train_groups": int(len(train_groups)),
            "test_groups": int(len(test_groups)),
            "group_overlap_count": int(len(group_overlap)),
            "train_pcaps": int(len(train_pcaps)),
            "test_pcaps": int(len(test_pcaps)),
            "pcap_overlap_count": int(len(pcap_overlap)),
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
        
        assert len(group_overlap) == 0, f"Fold {fold} has group overlap!"
        assert len(pcap_overlap) == 0, f"Fold {fold} has PCAP overlap!"

    os.makedirs("results", exist_ok=True)
    with open("results/audit_partition_integrity.json", "w") as f:
        json.dump(fold_audit, f, indent=2)
    print("\n[SUCCESS] Saved partition audit to results/audit_partition_integrity.json")

if __name__ == "__main__":
    check_splits_fast()
