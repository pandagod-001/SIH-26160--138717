import time
import os
from src.data.dataset_forensics import profile_all_datasets
from src.features.feature_auditor import audit_features
from src.data.build_canonical_dataset import build_canonical_dataset
from src.ml.evaluate_models import run_phase2_model_evaluations
from src.visualizer.plot_phase2_charts import generate_phase2_figures

def run_complete_phase2_pipeline():
    print("\n=======================================================")
    print("   IPsecTrace PHASE 2 EXPERIMENTAL SUITE INITIATED   ")
    print("=======================================================\n")
    
    t0 = time.time()

    # Step 1: Dataset Forensics & Inventory
    print("[PHASE 1/5] Profiling multi-dataset archives & generating inventory...")
    profile_all_datasets()

    # Step 2: Feature Audit & Data Quality Check
    print("\n[PHASE 2/5] Auditing non-payload features & leakage prevention rules...")
    audit_features()

    # Step 3: Build Canonical Processed Dataset
    print("\n[PHASE 3/5] Standardizing multi-source raw datasets into canonical benchmark...")
    build_canonical_dataset()

    # Step 4: Leakage-Safe Model Evaluations & Experiments
    print("\n[PHASE 4/5] Executing grouped splitting, XGBoost/RF deep comparison, ablation & transfer learning...")
    run_phase2_model_evaluations()

    # Step 5: Visual Analytics & Figure Generation
    print("\n[PHASE 5/5] Generating publication-grade charts & figures...")
    generate_phase2_figures()

    elapsed = time.time() - t0
    print("\n=======================================================")
    print(f"   PHASE 2 SUITE COMPLETED SUCCESSFULLY IN {elapsed:.2f}s!   ")
    print("=======================================================\n")

if __name__ == "__main__":
    run_complete_phase2_pipeline()
