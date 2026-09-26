import os
import shutil
import glob

WORKSPACE = "/mnt/c/Users/Abhijay/ipsec"
ARCHIVE_SUPERSEDED = os.path.join(WORKSPACE, "archive", "superseded")
DOCS_DIR = os.path.join(WORKSPACE, "docs")
os.makedirs(ARCHIVE_SUPERSEDED, exist_ok=True)
os.makedirs(DOCS_DIR, exist_ok=True)

# Files at root to move to archive/superseded
ROOT_SUPERSEDED = [
    "CURRENT_NATIVE_IPSEC_PIPELINE.md",
    "DATASET_RECONCILIATION.md",
    "ML_NATIVE_IPSEC_RESULTS.md",
    "NATIVE_IPSEC_DATASET_RESEARCH.md",
    "NATIVE_IPSEC_EXPERIMENT_REPORT.md",
    "PROJECT_STATUS.md",
    "RUN_EXPERIMENT.md",
    "SECOND_PHASE_STATUS.md",
    "ENHANCED_FEATURE_STUDY.md",
    "environment_report.md"
]

for f in ROOT_SUPERSEDED:
    src = os.path.join(WORKSPACE, f)
    if os.path.exists(src):
        dst = os.path.join(ARCHIVE_SUPERSEDED, f)
        shutil.move(src, dst)
        print(f"Archived root file: {f} -> archive/superseded/")

print("Root cleanup complete.")
