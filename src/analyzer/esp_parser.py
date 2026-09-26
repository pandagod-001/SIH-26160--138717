import sys
import json
import os
from scapy.all import rdpcap, IP

def parse_esp_pcap(pcap_path):
    """
    Deterministically parses ESP/AH packets from raw PCAP files.
    Extracts observable protocol header metadata without decrypting application payloads.
    """
    if not os.path.exists(pcap_path):
        return []

    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        print(f"[ERROR] Failed reading PCAP {pcap_path}: {e}")
        return []

    esp_records = []

    for idx, pkt in enumerate(packets):
        if IP in pkt:
            ip_layer = pkt[IP]
            # Check for ESP (IP Protocol 50) or AH (IP Protocol 51)
            if ip_layer.proto == 50: # Encapsulating Security Payload (ESP)
                raw_payload = bytes(ip_layer.payload)
                if len(raw_payload) >= 8:
                    spi = int.from_bytes(raw_payload[0:4], byteorder='big')
                    seq = int.from_bytes(raw_payload[4:8], byteorder='big')
                    
                    record = {
                        "packet_index": idx,
                        "timestamp": float(pkt.time),
                        "protocol": "ESP",
                        "proto_number": 50,
                        "src_ip": ip_layer.src,
                        "dst_ip": ip_layer.dst,
                        "spi": hex(spi),
                        "spi_raw": spi,
                        "sequence_number": seq,
                        "packet_length": len(pkt),
                        "payload_length": len(raw_payload),
                        "direction": "forward" if ip_layer.src == "10.0.0.1" else "reverse",
                        "payload_decrypted": False,
                        "encrypted_content": "[ENCRYPTED ESP PAYLOAD]"
                    }
                    esp_records.append(record)
            elif ip_layer.proto == 51: # Authentication Header (AH)
                record = {
                    "packet_index": idx,
                    "timestamp": float(pkt.time),
                    "protocol": "AH",
                    "proto_number": 51,
                    "src_ip": ip_layer.src,
                    "dst_ip": ip_layer.dst,
                    "packet_length": len(pkt),
                    "direction": "forward" if ip_layer.src == "10.0.0.1" else "reverse"
                }
                esp_records.append(record)

    return esp_records

if __name__ == "__main__":
    pcap_file = sys.argv[1] if len(sys.argv) > 1 else "data/raw/icmp/traffic.pcap"
    records = parse_esp_pcap(pcap_file)
    print(f"Parsed {len(records)} ESP packets from {pcap_file}")
    if records:
        print(json.dumps(records[0], indent=2))
