import os
import glob
import re

WORKSPACE = "/mnt/c/Users/Abhijay/ipsec"

# Contradictions to detect:
FORBIDDEN_PATTERNS = [
    (r"REPLAY_PROTECTION\s*=\s*PASS", "Unqualified REPLAY_SEQUENCE_PROGRESSION = VERIFIED (Receiver Window Not Observable)"),
    (r"100%\s*accuracy\s*on\s*all", "Overstated 100% accuracy claim"),
    (r"Softmax\s*Confidence", "Incorrect Mean Maximum Predicted Probability terminology for RF"),
    (r"decrypts?\s*IPsec\s*payloads?", "False decryption claim"),
    (r">99%\s*of\s*full\s*performance", "Inaccurate >99% ablation claim")
]

def run_scan():
    print("=======================================================")
    print("   IPsecTrace REPOSITORY CONTRADICTION SCANNER       ")
    print("=======================================================")

    files_scanned = 0
    issues_found = 0

    scan_dirs = ["docs", "results", "src", "IPsecTrace_FINAL_MASTER"]
    
    for d in scan_dirs:
        dir_path = os.path.join(WORKSPACE, d)
        for root, _, files in os.walk(dir_path):
            for f in files:
                if f.endswith((".md", ".txt", ".json", ".py", ".csv")) and not "historical" in root and not "superseded" in root:
                    full_p = os.path.join(root, f)
                    files_scanned += 1
                    try:
                        with open(full_p, "r", encoding="utf-8", errors="ignore") as fp:
                            content = fp.read()
                            for pat, desc in FORBIDDEN_PATTERNS:
                                if re.search(pat, content, re.IGNORECASE):
                                    print(f"[CONTRADICTION] {desc} found in {full_p}")
                                    issues_found += 1
                    except Exception:
                        pass

    res_txt = os.path.join(WORKSPACE, "results", "final", "contradiction_scan.txt")
    os.makedirs(os.path.dirname(res_txt), exist_ok=True)
    with open(res_txt, "w", encoding="utf-8") as fp:
        fp.write(f"Scanned {files_scanned} files.\nIssues found: {issues_found}\nStatus: {'PASS' if issues_found == 0 else 'FAIL'}\n")

    print(f"\nScanned {files_scanned} active files.")
    if issues_found == 0:
        print("[STATUS] PASS — Zero contradictions detected across active evidence.")
    else:
        print(f"[STATUS] WARNING — {issues_found} potential contradictions flagged.")

if __name__ == "__main__":
    run_scan()
