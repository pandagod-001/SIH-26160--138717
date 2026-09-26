from scapy.all import UDP, IP
from typing import List, Dict, Any, Optional

class IKEAnalyzer:
    """
    Control Plane Analyzer according to RFC 7296 (IKEv2) / RFC 2409 (IKEv1).
    Extracts observable transform suites and exchange structures without fabrication.
    Identifies Initiator vs. Responder directionality directly from RFC 7296 Header Flags.
    """

    EXCHANGE_MAP = {
        34: "IKE_SA_INIT",
        35: "IKE_AUTH",
        36: "CREATE_CHILD_SA",
        37: "INFORMATIONAL"
    }

    ENCR_MAP = {
        1: "DES",
        2: "3DES",
        12: "AES-CBC",
        14: "AES-CTR",
        18: "AES-GCM-16",
        19: "AES-GCM-8",
        20: "AES-GCM-12",
        28: "CHACHA20_POLY1305"
    }

    INTEG_MAP = {
        1: "AUTH_HMAC_MD5_96",
        2: "AUTH_HMAC_SHA1_96",
        12: "AUTH_HMAC_SHA2_256_128",
        13: "AUTH_HMAC_SHA2_384_192",
        14: "AUTH_HMAC_SHA2_512_256"
    }

    DH_MAP = {
        1: "MODP-768",
        2: "MODP-1024",
        5: "MODP-1536",
        14: "MODP-2048 (Group 14)",
        15: "MODP-3072",
        16: "MODP-4096",
        19: "ECP-256 (Group 19)",
        20: "ECP-384 (Group 20)"
    }

    @classmethod
    def extract_ike_events(cls, packets: List[Any]) -> List[Dict[str, Any]]:
        events = []
        for idx, pkt in enumerate(packets):
            if UDP in pkt and (pkt[UDP].sport in [500, 4500] or pkt[UDP].dport in [500, 4500]):
                payload = bytes(pkt[UDP].payload)
                if len(payload) < 28:
                    continue

                init_spi = payload[0:8].hex()
                resp_spi = payload[8:16].hex()
                next_payload = payload[16]
                ver_byte = payload[17]
                major_ver = (ver_byte >> 4) & 0x0F
                minor_ver = ver_byte & 0x0F
                exchange_code = payload[18]
                flags = payload[19]
                msg_id = int.from_bytes(payload[20:24], byteorder='big')
                length = int.from_bytes(payload[24:28], byteorder='big')

                exchange_name = cls.EXCHANGE_MAP.get(exchange_code, f"UNKNOWN_EXCHANGE_{exchange_code}")

                # RFC 7296 Section 3.1: Flags Bitmask
                # Bit 3 (0x08): Initiator bit. If 1, sender is the original IKE initiator.
                # Bit 5 (0x20): Response bit. If 1, message is a response.
                is_initiator = bool((flags >> 3) & 0x01)
                is_response = bool((flags >> 5) & 0x01)

                src_ip = pkt[IP].src if IP in pkt else "unknown"
                dst_ip = pkt[IP].dst if IP in pkt else "unknown"

                if is_initiator:
                    initiator_ip = src_ip
                    responder_ip = dst_ip
                else:
                    initiator_ip = dst_ip
                    responder_ip = src_ip

                # Parse SA Proposals (Payload Type 33)
                enc_transforms = []
                integ_transforms = []
                dh_transforms = []

                curr_payload = next_payload
                offset = 28

                while offset < len(payload) and curr_payload != 0:
                    if offset + 4 > len(payload):
                        break
                    p_next = payload[offset]
                    p_len = int.from_bytes(payload[offset+2:offset+4], byteorder='big')
                    if p_len < 4 or offset + p_len > len(payload):
                        break

                    if curr_payload == 33: # SA Payload
                        prop_offset = offset + 4
                        while prop_offset + 8 <= offset + p_len:
                            prop_last = payload[prop_offset]
                            prop_len = int.from_bytes(payload[prop_offset+2:prop_offset+4], byteorder='big')
                            spi_size = payload[prop_offset+6]
                            
                            if prop_len < 8:
                                break

                            trans_offset = prop_offset + 8 + spi_size
                            while trans_offset + 8 <= prop_offset + prop_len:
                                t_last = payload[trans_offset]
                                t_len = int.from_bytes(payload[trans_offset+2:trans_offset+4], byteorder='big')
                                t_type = payload[trans_offset+4] # 1=ENCR, 3=INTEG, 4=DH
                                t_id = int.from_bytes(payload[trans_offset+6:trans_offset+8], byteorder='big')

                                if t_type == 1:
                                    enc_transforms.append(cls.ENCR_MAP.get(t_id, f"ENCR_ID_{t_id}"))
                                elif t_type == 3:
                                    integ_transforms.append(cls.INTEG_MAP.get(t_id, f"INTEG_ID_{t_id}"))
                                elif t_type == 4:
                                    dh_transforms.append(cls.DH_MAP.get(t_id, f"DH_GROUP_{t_id}"))

                                if t_len < 8 or t_last == 0:
                                    break
                                trans_offset += t_len

                            if prop_last == 0:
                                break
                            prop_offset += prop_len

                    offset += p_len
                    curr_payload = p_next

                events.append({
                    "packet_index": idx,
                    "timestamp": float(pkt.time),
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": int(pkt[UDP].sport),
                    "dst_port": int(pkt[UDP].dport),
                    "ike_version": f"{major_ver}.{minor_ver}",
                    "exchange_type": exchange_name,
                    "exchange_type_code": exchange_code,
                    "initiator_spi": f"0x{init_spi}",
                    "responder_spi": f"0x{resp_spi}",
                    "message_id": msg_id,
                    "flags": hex(flags),
                    "is_initiator": is_initiator,
                    "is_response": is_response,
                    "initiator_ip": initiator_ip,
                    "responder_ip": responder_ip,
                    "length_bytes": length,
                    "encryption_transforms": ", ".join(enc_transforms) if enc_transforms else None,
                    "integrity_transforms": ", ".join(integ_transforms) if integ_transforms else None,
                    "dh_groups": ", ".join(dh_transforms) if dh_transforms else None,
                    "transform_status": "OBSERVED_FROM_PROPOSAL" if enc_transforms else "ENCRYPTED_OR_ABSENT"
                })

        return events
