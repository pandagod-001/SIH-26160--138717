import os
import zipfile

zip_filename = "IPsecTrace_FINAL_RESEARCH_PACKAGE.zip"
source_dir = "IPsecTrace_RESEARCH_PACKAGE"

if os.path.exists(zip_filename):
    os.remove(zip_filename)

file_count = 0
with zipfile.ZipFile(zip_filename, "w", zipfile.ZIP_DEFLATED) as zipf:
    for root, dirs, files in os.walk(source_dir):
        for file in files:
            file_path = os.path.join(root, file)
            arcname = os.path.relpath(file_path, os.path.dirname(source_dir))
            zipf.write(file_path, arcname)
            file_count += 1

zip_size_mb = os.path.getsize(zip_filename) / (1024 * 1024)
print(f"[SUCCESS] Created {zip_filename}")
print(f"Total files in ZIP: {file_count}")
print(f"ZIP Size: {zip_size_mb:.2f} MB")
