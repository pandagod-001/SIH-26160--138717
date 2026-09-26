import sys
import json
import os
from scapy.all import rdpcap, UDP, IP

def parse_ike_pcap(pcap_path):
    """
    Deterministically parses IKE packets from raw PCAP files according to RFC 7296.
    Extracts IKE header, SA proposals, and observable transform IDs directly from packet bytes.
    """
    if not os.path.exists(pcap_path):
        return []

    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        return []

    ike_sessions = []
    
    for idx, pkt in enumerate(packets):
        if UDP in pkt and (pkt[UDP].sport in [500, 4500] or pkt[UDP].dport in [500, 4500]):
            payload = bytes(pkt[UDP].payload)
            if len(payload) < 28:
                continue

            # IKE Header Parsing (RFC 7296 Section 3.1)
            init_spi = payload[0:8].hex()
            resp_spi = payload[8:16].hex()
            next_payload_code = payload[16]
            version_byte = payload[17]
            major_ver = (version_byte >> 4) & 0x0F
            minor_ver = version_byte & 0x0F
            exchange_type_code = payload[18]
            flags = payload[19]
            msg_id = int.from_bytes(payload[20:24], byteorder='big')
            length = int.from_bytes(payload[24:28], byteorder='big')

            exchange_type_map = {
                34: "IKE_SA_INIT",
                35: "IKE_AUTH",
                36: "CREATE_CHILD_SA",
                37: "INFORMATIONAL"
            }
            exchange_type = exchange_type_map.get(exchange_type_code, f"UNKNOWN_EXCHANGE_{exchange_type_code}")

            # Stateful Payload Iterator (RFC 7296 Section 3.2)
            # Parsing SA (Security Association) Payload (Payload Type 33)
            current_payload_code = next_payload_code
            offset = 28
            
            enc_transforms = []
            integ_transforms = []
            dh_transforms = []

            while offset < len(payload) and current_payload_code != 0:
                if offset + 4 > len(payload):
                    break
                p_next = payload[offset]
                p_crit = (payload[offset+1] >> 7) & 1
                p_len = int.from_bytes(payload[offset+2:offset+4], byteorder='big')
                if p_len < 4 or offset + p_len > len(payload):
                    break

                # If Payload is SA (Type 33)
                if current_payload_code == 33:
                    # Parse Proposal Sub-structures inside SA Payload (RFC 7296 Section 3.3)
                    prop_offset = offset + 4
                    while prop_offset + 8 <= offset + p_len:
                        prop_last = payload[prop_offset]
                        prop_len = int.from_bytes(payload[prop_offset+2:prop_offset+4], byteorder='big')
                        prop_num = payload[prop_offset+4]
                        proto_id = payload[prop_offset+5] # 1=IKE, 2=AH, 3=ESP
                        spi_size = payload[prop_offset+6]
                        num_transforms = payload[prop_offset+7]

                        if prop_len < 8:
                            break

                        trans_offset = prop_offset + 8 + spi_size
                        while trans_offset + 8 <= prop_offset + prop_len:
                            t_last = payload[trans_offset]
                            t_len = int.from_bytes(payload[trans_offset+2:trans_offset+4], byteorder='big')
                            t_type = payload[trans_offset+4] # 1=ENCR, 2=PRF, 3=INTEG, 4=D-H, 5=ESN
                            t_id = int.from_bytes(payload[trans_offset+6:trans_offset+8], byteorder='big')

                            if t_type == 1: # ENCR
                                enc_map = {1: "DES", 2: "3DES", 12: "AES-CBC", 14: "AES-CTR", 18: "AES-GCM-16", 19: "AES-GCM-8", 20: "AES-GCM-12", 28: "CHACHA20_POLY1305"}
                                enc_transforms.append(enc_map.get(t_id, f"ENCR_ID_{t_id}"))
                            elif t_type == 3: # INTEG
                                integ_map = {1: "AUTH_HMAC_MD5_96", 2: "AUTH_HMAC_SHA1_96", 12: "AUTH_HMAC_SHA2_256_128", 13: "AUTH_HMAC_SHA2_384_192", 14: "AUTH_HMAC_SHA2_512_256"}
                                integ_transforms.append(integ_map.get(t_id, f"INTEG_ID_{t_id}"))
                            elif t_type == 4: # D-H Group
                                dh_map = {1: "MODP-768", 2: "MODP-1024", 5: "MODP-1536", 14: "MODP-2048 (Group 14)", 15: "MODP-3072", 16: "MODP-4096", 19: "ECP-256 (Group 19)", 20: "ECP-384 (Group 20)"}
                                dh_transforms.append(dh_map.get(t_id, f"DH_GROUP_{t_id}"))

                            if t_len < 8 or t_last == 0:
                                break
                            trans_offset += t_len

                        if prop_last == 0:
                            break
                        prop_offset += prop_len

                offset += p_len
                current_payload_code = p_next

            # Format extracted transforms
            enc_str = ", ".join(enc_transforms) if enc_transforms else "UNKNOWN / NOT_PARSED_IN_PAYLOAD"
            integ_str = ", ".join(integ_transforms) if integ_transforms else "UNKNOWN / NOT_PARSED_IN_PAYLOAD"
            dh_str = ", ".join(dh_transforms) if dh_transforms else "UNKNOWN / NOT_PARSED_IN_PAYLOAD"

            session_entry = {
                "packet_index": idx,
                "timestamp": float(pkt.time),
                "src_ip": pkt[IP].src if IP in pkt else "unknown",
                "dst_ip": pkt[IP].dst if IP in pkt else "unknown",
                "src_port": pkt[UDP].sport,
                "dst_port": pkt[UDP].dport,
                "ike_version": f"{major_ver}.{minor_ver}",
                "exchange_type": exchange_type,
                "exchange_type_code": exchange_type_code,
                "initiator_spi": f"0x{init_spi}",
                "responder_spi": f"0x{resp_spi}",
                "message_id": msg_id,
                "flags": hex(flags),
                "length_bytes": length,
                "parsed_encryption_transforms": enc_str,
                "parsed_integrity_transforms": integ_str,
                "parsed_dh_groups": dh_str,
                "transform_extraction_status": "PARSED_FROM_SA_PROPOSAL" if enc_transforms else "NO_SA_PROPOSAL_PAYLOAD_OBSERVED"
            }
            ike_sessions.append(session_entry)

    return ike_sessions

if __name__ == "__main__":
    pcap_file = sys.argv[1] if len(sys.argv) > 1 else "data/raw_native_ipsec/pcaps/EXP_BULK_ENV_CLEAN_SESS_0001.pcap"
    results = parse_ike_pcap(pcap_file)
    print(json.dumps(results, indent=2))
