"""
run_phase2_experiment.py — IPsecTrace Master Pipeline Orchestrator
Sequentially executes the end-to-end Phase 2 experimental protocol:
1. Dataset Forensics (src/data/dataset_inspector.py)
2. Canonical Dataset Construction (src/data/canonical_builder.py)
3. Data Quality & Distribution Checks (src/data/data_quality_pipeline.py)
4. Feature Audit & Leakage Verification (src/features/run_feature_audit.py)
5. Comprehensive ML Experiments (src/ml/evaluate_models.py)
6. Publication Chart Generation (src/visualizer/plot_phase2_charts.py)
7. SIH Evidence Package Synthesis (src/data/generate_sih_evidence.py)
"""
import sys
import os
import subprocess
import time

def run_step(step_num, step_name, script_path):
    print(f"\n{'='*70}")
    print(f"  STEP {step_num}: {step_name}")
    print(f"  Running: python {script_path}")
    print(f"{'='*70}")
    
    start_time = time.time()
    res = subprocess.run([sys.executable, script_path], capture_output=False)
    elapsed = time.time() - start_time
    
    if res.returncode != 0:
        print(f"\n[ERROR] Step {step_num} failed with return code {res.returncode}!")
        sys.exit(res.returncode)
    else:
        print(f"\n[SUCCESS] Step {step_num} completed in {elapsed:.2f} seconds.")

def main():
    print("="*70)
    print("   IPsecTrace PHASE 2: MASTER EXPERIMENTAL PROTOCOL")
    print("   NTRO Problem Statement 26160 | Smart India Hackathon 2026")
    print("="*70)
    
    overall_start = time.time()
    
    steps = [
        (1, "Dataset Inspection & Forensics", "src/data/dataset_inspector.py"),
        (2, "Canonical Dataset Construction", "src/data/canonical_builder.py"),
        (3, "Data Quality & Integrity Pipeline", "src/data/data_quality_pipeline.py"),
        (4, "Feature Audit & Leakage Verification", "src/features/run_feature_audit.py"),
        (5, "Comprehensive ML Benchmark & Evaluation", "src/ml/evaluate_models.py"),
        (6, "Publication Figures & Visualizations", "src/visualizer/plot_phase2_charts.py"),
        (7, "SIH Evidence Package Generation", "src/data/generate_sih_evidence.py"),
    ]
    
    for step_num, step_name, script_path in steps:
        run_step(step_num, step_name, script_path)
        
    total_time = time.time() - overall_start
    print("\n" + "="*70)
    print(f"  PHASE 2 VALIDATION PIPELINE FINISHED SUCCESSFULLY IN {total_time:.2f}s!")
    print("  All empirical artifacts and charts written to results/ and SIH_EVIDENCE/.")
    print("="*70)

if __name__ == "__main__":
    main()
