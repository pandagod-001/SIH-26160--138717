import os
import shutil
import glob
import hashlib
import json
import zipfile

WORKSPACE = "/mnt/c/Users/Abhijay/ipsec"
MASTER_DIR = os.path.join(WORKSPACE, "IPsecTrace_FINAL_MASTER")

def make_dirs():
    dirs = [
        MASTER_DIR,
        os.path.join(MASTER_DIR, "figures", "architecture"),
        os.path.join(MASTER_DIR, "figures", "dataset"),
        os.path.join(MASTER_DIR, "figures", "experiments"),
        os.path.join(MASTER_DIR, "figures", "machine_learning"),
        os.path.join(MASTER_DIR, "figures", "ablation"),
        os.path.join(MASTER_DIR, "figures", "ood"),
        os.path.join(MASTER_DIR, "figures", "security"),
        os.path.join(MASTER_DIR, "figures", "historical"),
        os.path.join(MASTER_DIR, "results", "authoritative"),
        os.path.join(MASTER_DIR, "results", "phase1"),
        os.path.join(MASTER_DIR, "results", "phase2"),
        os.path.join(MASTER_DIR, "results", "audit"),
        os.path.join(MASTER_DIR, "results", "historical"),
        os.path.join(MASTER_DIR, "datasets", "dataset_cards"),
        os.path.join(MASTER_DIR, "datasets", "provenance"),
        os.path.join(MASTER_DIR, "datasets", "schemas"),
        os.path.join(MASTER_DIR, "source_code", "data"),
        os.path.join(MASTER_DIR, "source_code", "features"),
        os.path.join(MASTER_DIR, "source_code", "ml"),
        os.path.join(MASTER_DIR, "source_code", "audit"),
        os.path.join(MASTER_DIR, "source_code", "testbed"),
        os.path.join(MASTER_DIR, "source_code", "analyzer"),
        os.path.join(MASTER_DIR, "source_code", "visualization"),
        os.path.join(MASTER_DIR, "research", "papers"),
        os.path.join(MASTER_DIR, "research", "RFCs"),
        os.path.join(MASTER_DIR, "research", "NIST"),
        os.path.join(MASTER_DIR, "research", "research_notes"),
        os.path.join(MASTER_DIR, "sih_evidence"),
        os.path.join(MASTER_DIR, "reproducibility"),
    ]
    for d in dirs:
        os.makedirs(d, exist_ok=True)
    print(f"Created directory structure at {MASTER_DIR}")

if __name__ == "__main__":
    make_dirs()
