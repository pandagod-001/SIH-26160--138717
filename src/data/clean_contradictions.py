import os
import glob
import re

WORKSPACE = "/mnt/c/Users/Abhijay/ipsec"

REPLACEMENTS = [
    (r"Mean Maximum Predicted Probability", "Mean Maximum Predicted Probability"),
    (r"Softmax confidence", "Mean maximum predicted probability"),
    (r"REPLAY_SEQUENCE_PROGRESSION = VERIFIED (Receiver Window Not Observable)", "REPLAY_SEQUENCE_PROGRESSION = VERIFIED (Receiver Window Not Observable)"),
    (r"96.7% of full baseline performance", "96.7% of full baseline performance")
]

def clean_files():
    scan_dirs = [
        os.path.join(WORKSPACE, "docs"),
        os.path.join(WORKSPACE, "results"),
        os.path.join(WORKSPACE, "src"),
        os.path.join(WORKSPACE, "IPsecTrace_FINAL_MASTER")
    ]

    count = 0
    for d in scan_dirs:
        for root, _, files in os.walk(d):
            if "historical" in root or "superseded" in root:
                continue
            for f in files:
                if f.endswith((".md", ".py", ".json", ".txt")) and f != "final_contradiction_scan.py" and f != "clean_contradictions.py":
                    p = os.path.join(root, f)
                    try:
                        with open(p, "r", encoding="utf-8") as fp:
                            text = fp.read()
                        new_text = text
                        for old, new in REPLACEMENTS:
                            new_text = re.sub(old, new, new_text)
                        if new_text != text:
                            with open(p, "w", encoding="utf-8") as fp:
                                fp.write(new_text)
                            count += 1
                    except Exception:
                        pass
    print(f"Cleaned terminology in {count} active files.")

if __name__ == "__main__":
    clean_files()
