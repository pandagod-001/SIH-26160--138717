import os
import shutil
import json

base_dir = "IPsecTrace_RESEARCH_PACKAGE"
if os.path.exists(base_dir):
    shutil.rmtree(base_dir)

# Create directory tree
folders = [
    "00_START_HERE",
    "01_PROBLEM_STATEMENT",
    "02_PROPOSED_IDEA",
    "03_USER_WORKFLOW",
    "04_ARCHITECTURE",
    "05_TECH_STACK",
    "06_DATASET",
    "07_IMPLEMENTATION",
    "08_EXPERIMENTS",
    "09_RESULTS",
    "10_REAL_PCAP",
    "11_SECURITY_ASSESSMENT",
    "12_LIMITATIONS",
    "13_FINAL_PAPER",
    "14_FINAL_PPT",
    "15_REFERENCES",
    "99_AUDIT"
]

for f in folders:
    os.makedirs(os.path.join(base_dir, f), exist_ok=True)

# Copy Visuals & Metrics
shutil.copytree("results/final/architecture", os.path.join(base_dir, "04_ARCHITECTURE", "figures"), dirs_exist_ok=True)
shutil.copytree("results/final/figures", os.path.join(base_dir, "09_RESULTS", "figures"), dirs_exist_ok=True)
shutil.copytree("results/final/confusion_matrices", os.path.join(base_dir, "09_RESULTS", "confusion_matrices"), dirs_exist_ok=True)
shutil.copytree("results/final/metrics", os.path.join(base_dir, "09_RESULTS", "metrics"), dirs_exist_ok=True)
shutil.copytree("results/final/pcap_demos", os.path.join(base_dir, "10_REAL_PCAP", "figures"), dirs_exist_ok=True)

print("[SUCCESS] Research Package Folder Structure Created.")
