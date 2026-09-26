import os
import re
import shutil
import zipfile

WORKSPACE = "/mnt/c/Users/Abhijay/ipsec"
MASTER_DIR = os.path.join(WORKSPACE, "IPsecTrace_FINAL_MASTER")
DOCS_DIR = os.path.join(WORKSPACE, "docs")
USER_DOWNLOADS = "/mnt/c/Users/Abhijay/Downloads"

TARGET_DIRS = [
    DOCS_DIR,
    MASTER_DIR,
    os.path.join(WORKSPACE, "results", "final"),
    os.path.join(USER_DOWNLOADS, "IPsecTrace_SIH2026_PRESENTATION_PACKAGE")
]

# Replacement mapping for all stale strings
EXACT_REPLACEMENTS = [
    # 1. Stale OOD Confidence numbers
    (r"0\.9265", "0.6616"),
    (r"0\.6478", "0.4363"),
    (r"92\.65%", "66.16%"),
    (r"64\.78%", "43.63%"),

    # 2. Stale Softmax Confidence terminology
    (r"Softmax Confidence", "Mean Maximum Predicted Probability"),
    (r"Softmax confidence", "Mean maximum predicted probability"),
    (r"softmax confidence", "mean maximum predicted probability"),

    # 3. Stale Replay Protection claim
    (r"REPLAY_PROTECTION\s*=\s*PASS", "REPLAY_SEQUENCE_PROGRESSION = VERIFIED (Receiver Window Not Observable)"),
    (r"Anti-Replay Protection:\s*PROVEN HEALTHY", "ESP Sequence Progression: VERIFIED (Window Not Observable)"),
    (r"Anti-replay protection:\s*PROVEN HEALTHY", "ESP Sequence Progression: VERIFIED (Window Not Observable)"),

    # 4. Inaccurate Ablation claim
    (r">99% of full performance", "96.7% of full baseline performance"),
    (r">99%", "96.7%"),

    # 5. Overstated Group claims
    (r"38 experiment groups", "157 genuine session groups"),
    (r"38 groups", "157 genuine session groups"),
    (r"90 groups", "157 genuine session groups"),
    (r"90 experiment groups", "157 genuine session groups")
]

def clean_all_notes():
    updated_files = 0
    scanned_files = 0

    for base_dir in TARGET_DIRS:
        if not os.path.exists(base_dir):
            continue
        for root, dirs, files in os.walk(base_dir):
            if "archive" in root or "superseded" in root:
                continue
            for f in files:
                if f.endswith((".md", ".json", ".txt", ".csv")):
                    p = os.path.join(root, f)
                    if "DO_NOT_USE_STALE_RESULTS.md" in p or "clean_and_sync_all_notes.py" in p:
                        continue
                    scanned_files += 1
                    try:
                        with open(p, "r", encoding="utf-8") as fp:
                            content = fp.read()
                        
                        new_content = content
                        for pat, repl in EXACT_REPLACEMENTS:
                            new_content = re.sub(pat, repl, new_content)
                        
                        if new_content != content:
                            with open(p, "w", encoding="utf-8") as fp:
                                fp.write(new_content)
                            updated_files += 1
                    except Exception as e:
                        print(f"Error processing {p}: {e}")

    print(f"[CLEANUP] Scanned {scanned_files} files across active directories. Updated {updated_files} files.")

def rebuild_both_zips():
    # 1. Rebuild IPsecTrace_FINAL_MASTER_ARCHIVE.zip
    master_zip = os.path.join(WORKSPACE, "IPsecTrace_FINAL_MASTER_ARCHIVE.zip")
    print(f"Rebuilding {master_zip}...")
    with zipfile.ZipFile(master_zip, 'w', zipfile.ZIP_DEFLATED) as zf:
        for root, _, files in os.walk(MASTER_DIR):
            for f in files:
                full_p = os.path.join(root, f)
                arc_p = os.path.relpath(full_p, WORKSPACE)
                zf.write(full_p, arc_p)
    print(f"Master ZIP updated! Size: {os.path.getsize(master_zip)/(1024*1024):.2f} MB")

    # 2. Rebuild Downloads Handover ZIP
    downloads_pkg = os.path.join(USER_DOWNLOADS, "IPsecTrace_SIH2026_PRESENTATION_PACKAGE")
    downloads_zip = os.path.join(USER_DOWNLOADS, "IPsecTrace_SIH2026_PRESENTATION_PACKAGE.zip")
    
    # Sync docs to downloads package first
    src_docs = [
        os.path.join(DOCS_DIR, "PPT_DATA.md"),
        os.path.join(DOCS_DIR, "FINAL_PROJECT_CONTEXT.md"),
        os.path.join(DOCS_DIR, "DO_NOT_USE_STALE_RESULTS.md"),
        os.path.join(WORKSPACE, "README.md")
    ]
    for sd in src_docs:
        if os.path.exists(sd):
            shutil.copy(sd, os.path.join(downloads_pkg, "presentation_docs"))
            
    print(f"Rebuilding {downloads_zip}...")
    with zipfile.ZipFile(downloads_zip, 'w', zipfile.ZIP_DEFLATED) as zf:
        for root, _, files in os.walk(downloads_pkg):
            for f in files:
                full_p = os.path.join(root, f)
                arc_p = os.path.relpath(full_p, USER_DOWNLOADS)
                zf.write(full_p, arc_p)
    print(f"Downloads Handover ZIP updated! Size: {os.path.getsize(downloads_zip)/(1024*1024):.2f} MB")

if __name__ == "__main__":
    clean_all_notes()
    rebuild_both_zips()
