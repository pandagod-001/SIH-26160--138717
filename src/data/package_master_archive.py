import os
import hashlib
import zipfile
import glob

WORKSPACE = "/mnt/c/Users/Abhijay/ipsec"
MASTER_DIR = os.path.join(WORKSPACE, "IPsecTrace_FINAL_MASTER")
ZIP_OUT = os.path.join(WORKSPACE, "IPsecTrace_FINAL_MASTER_ARCHIVE.zip")

def create_manifest():
    manifest_lines = ["# IPsecTrace MASTER ARCHIVE MANIFEST", "Relative Path | Size Bytes | SHA-256 Hash", "-"*80]
    all_files = []
    for root, dirs, files in os.walk(MASTER_DIR):
        for f in files:
            full_path = os.path.join(root, f)
            rel_path = os.path.relpath(full_path, MASTER_DIR)
            size = os.path.getsize(full_path)
            h = hashlib.sha256()
            with open(full_path, "rb") as fp:
                while chunk := fp.read(65536):
                    h.update(chunk)
            sha = h.hexdigest()
            manifest_lines.append(f"{rel_path} | {size} | {sha}")
            all_files.append((full_path, rel_path))

    manifest_path = os.path.join(MASTER_DIR, "MASTER_ARCHIVE_MANIFEST.txt")
    with open(manifest_path, "w", encoding="utf-8") as fp:
        fp.write("\n".join(manifest_lines) + "\n")
    print(f"Generated manifest with {len(all_files)} entries.")

    print(f"Creating final zip at {ZIP_OUT}...")
    with zipfile.ZipFile(ZIP_OUT, 'w', zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(MASTER_DIR):
            for f in files:
                full_p = os.path.join(root, f)
                arc_p = os.path.relpath(full_p, WORKSPACE)
                zf.write(full_p, arc_p)

    zip_size = os.path.getsize(ZIP_OUT)
    print(f"Final master zip created successfully! Size: {zip_size / (1024*1024):.2f} MB")

if __name__ == "__main__":
    create_manifest()
