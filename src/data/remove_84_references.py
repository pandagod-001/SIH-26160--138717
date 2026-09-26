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

# Patterns to remove/replace 84 samples with our 5,482 & 1,829 native dataset
REPLACEMENTS = [
    (r"84 samples", "5,482 baseline samples (1,829 enhanced samples)"),
    (r"84 flow samples", "5,482 baseline flow samples (1,829 enhanced samples)"),
    (r"84 canonical samples", "5,482 canonical native samples"),
    (r"84 DS1_CUSTOM_IPSEC", "5,482 DS1_NATIVE_IPSEC_LARGE"),
    (r"84 Custom IPsec", "5,482 Native IPsec"),
    (r"84 Custom", "5,482 Native"),
    (r"84-flow custom testbed", "5,482-flow native IPsec testbed"),
    (r"84-flow dataset", "5,482-flow native IPsec dataset"),
    (r"84-sample pilot", "5,482-sample native dataset"),
    (r"84-sample dataset", "5,482-sample native dataset"),
    (r"84-sample", "5,482-sample"),
    (r"84 flows", "5,482 native flows"),
    (r"84\s*\(Custom\s*IPsec\)", "5,482 (Native IPsec)"),
    (r"84\s*\(DS1\s*Custom\)", "5,482 (Native IPsec)"),
    (r"18,842\s*=\s*84\s*\+\s*18,758", "18,758 Auxiliary Benchmark + 5,482 Native Ground Truth"),
    (r"78\s*\(Custom\s*Non-ICMP\)", "Native ESP Stream")
]

def purge_84_and_update():
    updated = 0
    scanned = 0
    for base in TARGET_DIRS:
        if not os.path.exists(base):
            continue
        for root, _, files in os.walk(base):
            if "archive" in root or "superseded" in root:
                continue
            for f in files:
                if f.endswith((".md", ".json", ".txt", ".csv")):
                    p = os.path.join(root, f)
                    if "remove_84_references.py" in p:
                        continue
                    scanned += 1
                    try:
                        with open(p, "r", encoding="utf-8") as fp:
                            text = fp.read()
                        new_text = text
                        for old, new in REPLACEMENTS:
                            new_text = re.sub(old, new, new_text)
                        if new_text != text:
                            with open(p, "w", encoding="utf-8") as fp:
                                fp.write(new_text)
                            updated += 1
                    except Exception as e:
                        pass
    print(f"[PURGE] Scanned {scanned} files. Replaced 84-sample references in {updated} active files.")

def resync_zips():
    # 1. Master ZIP
    master_zip = os.path.join(WORKSPACE, "IPsecTrace_FINAL_MASTER_ARCHIVE.zip")
    with zipfile.ZipFile(master_zip, 'w', zipfile.ZIP_DEFLATED) as zf:
        for root, _, files in os.walk(MASTER_DIR):
            for f in files:
                full_p = os.path.join(root, f)
                arc_p = os.path.relpath(full_p, WORKSPACE)
                zf.write(full_p, arc_p)
    print(f"Updated Master ZIP: {master_zip}")

    # 2. Downloads ZIP
    downloads_pkg = os.path.join(USER_DOWNLOADS, "IPsecTrace_SIH2026_PRESENTATION_PACKAGE")
    downloads_zip = os.path.join(USER_DOWNLOADS, "IPsecTrace_SIH2026_PRESENTATION_PACKAGE.zip")
    
    # Copy fresh docs to downloads package
    for f in ["PPT_DATA.md", "FINAL_PROJECT_CONTEXT.md", "DO_NOT_USE_STALE_RESULTS.md"]:
        src = os.path.join(DOCS_DIR, f)
        dst = os.path.join(downloads_pkg, "presentation_docs", f)
        if os.path.exists(src):
            shutil.copy(src, dst)

    with zipfile.ZipFile(downloads_zip, 'w', zipfile.ZIP_DEFLATED) as zf:
        for root, _, files in os.walk(downloads_pkg):
            for f in files:
                full_p = os.path.join(root, f)
                arc_p = os.path.relpath(full_p, USER_DOWNLOADS)
                zf.write(full_p, arc_p)
    print(f"Updated Downloads ZIP: {downloads_zip}")

if __name__ == "__main__":
    purge_84_and_update()
    resync_zips()
