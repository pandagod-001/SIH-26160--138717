#!/bin/bash
apt-get install -y unzip
cd /mnt/c/Users/Abhijay/ipsec
mkdir -p data/raw_external

for f in *.zip; do
    if [ "$f" != "SIH_EVIDENCE.zip" ]; then
        out_dir="data/raw_external/${f%.zip}"
        mkdir -p "$out_dir"
        echo "Unzipping $f into $out_dir..."
        unzip -q -o "$f" -d "$out_dir" &
    fi
done

wait
echo "ALL DATASET ARCHIVES UNZIPPED SUCCESSFULLY!"
