import os
import shutil

base_pkg = "IPsecTrace_RESEARCH_PACKAGE"

# Copy all canonical docs from docs/ into the package subfolders
doc_mappings = [
    ("docs/00_README.md", "00_START_HERE/README.md"),
    ("docs/01_RESEARCH_OVERVIEW.md", "00_START_HERE/PROJECT_OVERVIEW.md"),
    ("docs/02_PROBLEM_STATEMENT.md", "01_PROBLEM_STATEMENT/problem_statement.md"),
    ("docs/03_SYSTEM_ARCHITECTURE.md", "04_ARCHITECTURE/architecture.md"),
    ("docs/04_DATASET_AND_METHODOLOGY.md", "06_DATASET/dataset.md"),
    ("docs/05_DETERMINISTIC_PROTOCOL_FORENSICS.md", "07_IMPLEMENTATION/packet_analysis.md"),
    ("docs/06_ML_AND_REPRESENTATION_LEARNING.md", "07_IMPLEMENTATION/ml_pipeline.md"),
    ("docs/07_RESULTS_AND_ABLATION.md", "08_EXPERIMENTS/experiments.md"),
    ("docs/08_OOD_AND_NOVELTY.md", "09_RESULTS/ood.md"),
    ("docs/09_REAL_PCAP_DEMONSTRATIONS.md", "10_REAL_PCAP/demonstrations.md"),
    ("docs/10_SECURITY_ASSESSMENT.md", "11_SECURITY_ASSESSMENT/security_assessment.md"),
    ("docs/11_LIMITATIONS_AND_FUTURE_WORK.md", "12_LIMITATIONS/limitations.md"),
    ("docs/12_FINAL_PPT_NARRATIVE.md", "14_FINAL_PPT/ppt_narrative.md"),
    ("docs/13_FINAL_PAPER_STRUCTURE.md", "13_FINAL_PAPER/paper_structure.md"),
    ("FINAL_REPOSITORY_AUDIT.md", "99_AUDIT/final_repository_audit.md"),
    ("research_validation_summary.md", "08_EXPERIMENTS/validation_summary.md"),
    ("research_sequence_experiment_v2.md", "08_EXPERIMENTS/research_sequence_experiment_v2.md")
]

for src, dst in doc_mappings:
    if os.path.exists(src):
        dst_path = os.path.join(base_pkg, dst)
        os.makedirs(os.path.dirname(dst_path), exist_ok=True)
        shutil.copy(src, dst_path)

# Duplicate into specific subfolder docs for comprehensive reading
shutil.copy("docs/07_RESULTS_AND_ABLATION.md", os.path.join(base_pkg, "09_RESULTS", "benchmark.md"))
shutil.copy("docs/07_RESULTS_AND_ABLATION.md", os.path.join(base_pkg, "08_EXPERIMENTS", "ablation.md"))
shutil.copy("docs/04_DATASET_AND_METHODOLOGY.md", os.path.join(base_pkg, "06_DATASET", "methodology.md"))
shutil.copy("docs/01_RESEARCH_OVERVIEW.md", os.path.join(base_pkg, "02_PROPOSED_IDEA", "research_story.md"))
shutil.copy("docs/02_PROBLEM_STATEMENT.md", os.path.join(base_pkg, "01_PROBLEM_STATEMENT", "research_motivation.md"))
shutil.copy("docs/03_SYSTEM_ARCHITECTURE.md", os.path.join(base_pkg, "03_USER_WORKFLOW", "system_workflow.md"))

print("[SUCCESS] All documentation copied and mapped to package tree.")
