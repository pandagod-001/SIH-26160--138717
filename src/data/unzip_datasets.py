import zipfile
import os
import sys

def extract_all():
    base_dir = "/mnt/c/Users/Abhijay/ipsec" if os.path.exists("/mnt/c/Users/Abhijay/ipsec") else "."
    target_dir = os.path.join(base_dir, "data", "raw_external")
    os.makedirs(target_dir, exist_ok=True)

    zip_files = [f for f in os.listdir(base_dir) if f.endswith(".zip") and f != "SIH_EVIDENCE.zip"]
    print(f"Found {len(zip_files)} dataset zip archives: {zip_files}")

    for zf in zip_files:
        zip_path = os.path.join(base_dir, zf)
        out_sub = os.path.join(target_dir, zf.replace(".zip", ""))
        os.makedirs(out_sub, exist_ok=True)
        print(f"Extracting {zf} -> {out_sub}...")
        try:
            with zipfile.ZipFile(zip_path, 'r') as z:
                z.extractall(out_sub)
            print(f"[SUCCESS] Extracted {zf}")
        except Exception as e:
            print(f"[ERROR] Failed extracting {zf}: {e}")

if __name__ == "__main__":
    extract_all()
