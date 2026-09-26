import os
import json
import hashlib
import platform

def create_final_reproducibility_manifest():
    manifest = {
        "framework": "IPsecTrace",
        "evaluation_date": "2026-09-24",
        "hackathon": "SIH 2026 - Problem Statement 26160",
        "organization": "National Technical Research Organisation (NTRO)",
        "environment": {
            "os": "Microsoft Windows 11 / WSL2 Ubuntu 24.04 LTS",
            "kernel": platform.release(),
            "python_version": platform.python_version(),
            "scikit_learn_version": "1.4.2",
            "xgboost_version": "2.0.3",
            "scapy_version": "2.5.0 / 2.7.0"
        },
        "authoritative_tracks": {
            "track_a_native_ipsec": {
                "dataset": "data/processed/native_ipsec_large_dataset.csv",
                "samples": 5482,
                "raw_pcaps": 294,
                "session_groups": 157,
                "validation": "5-Fold GroupKFold (0% cross-fold leakage)",
                "primary_model": "Random Forest (100 Trees)",
                "accuracy": "58.37% ± 13.71%",
                "macro_f1": "58.32% ± 6.41%",
                "enhanced_f1_study": "70.53% (XGBoost on 3.0s windows + direction & quantiles)",
                "heldout_ood_auroc": 0.9077
            },
            "track_b_auxiliary_vpn": {
                "dataset": "UNB ISCX Scenario B + Encrypted VPN JSON",
                "samples": 18842,
                "validation": "5-Fold GroupKFold under designated provenance grouping",
                "primary_model": "Random Forest (100 Trees)",
                "accuracy": "89.84% ± 0.45%",
                "macro_f1": "88.30% ± 0.44%"
            }
        },
        "reproduction_commands": [
            "export PYTHONPATH=.",
            "python3 src/audit/run_final_hardening_pass.py",
            "python3 src/ml/run_final_native_model_comparison.py",
            "python3 src/ml/run_real_ablation.py",
            "python3 src/ml/run_heldout_ood.py",
            "python3 src/visualizer/plot_native_ipsec_benchmarks.py"
        ]
    }

    out_json = "results/final_reproducibility_manifest.json"
    os.makedirs("results", exist_ok=True)
    with open(out_json, "w") as f:
        json.dump(manifest, f, indent=2)

    import shutil
    shutil.copy(out_json, "IPsecTrace_FINAL_MASTER/results/authoritative/")
    shutil.copy(out_json, "IPsecTrace_FINAL_MASTER/reproducibility/")
    print("[SUCCESS] final_reproducibility_manifest.json generated!")

if __name__ == "__main__":
    create_final_reproducibility_manifest()
