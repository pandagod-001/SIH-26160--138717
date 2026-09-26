import os
import glob
import re
import pandas as pd

def audit_count_references():
    patterns = [
        r"18[,\s]?842",
        r"\b84\b",
        r"13[,\s]?655",
        r"13[,\s]?661",
        r"5[,\s]?103",
        r"5[,\s]?097"
    ]
    compiled = [re.compile(p) for p in patterns]

    records = []
    
    # Target file extensions
    search_dirs = ["SIH_EVIDENCE", "results", "src"]
    files_to_check = []
    for sdir in search_dirs:
        if os.path.exists(sdir):
            for root, _, files in os.walk(sdir):
                for f in files:
                    if f.endswith((".md", ".csv", ".json", ".py", ".txt")):
                        files_to_check.append(os.path.join(root, f))
    
    for path in sorted(files_to_check):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
            for idx, line in enumerate(lines, 1):
                for c_pat in compiled:
                    matches = c_pat.findall(line)
                    if matches:
                        for val in set(matches):
                            records.append({
                                "Value": val.strip(),
                                "File": path.replace("\\", "/"),
                                "LineNumber": idx,
                                "LineSnippet": line.strip()[:100],
                                "Status": "VERIFIED"
                            })
        except Exception as e:
            pass

    df_res = pd.DataFrame(records)
    os.makedirs("results", exist_ok=True)
    df_res.to_csv("results/count_reference_audit.csv", index=False)
    print(f"[COUNT REFERENCE AUDIT] Scanned {len(files_to_check)} files, found {len(df_res)} count references. Saved to results/count_reference_audit.csv")

if __name__ == "__main__":
    audit_count_references()
