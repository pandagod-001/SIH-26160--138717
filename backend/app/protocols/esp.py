from scapy.all import IP
from typing import List, Dict, Any, Optional

class ESPAnalyzer:
    """
    Data Plane Analyzer for Encapsulating Security Payload (ESP, IP proto 50) and AH (proto 51).
    Strict Defensive Boundary: Never attempts payload decryption.
    Maintains explicit content_observability = NOT_OBSERVABLE.

    Direction Resolution Policy:
    1. IKE Evidence: If IKE events establish initiator/responder IPs for this endpoint pair:
       - packet.src == initiator_ip  -> direction = "forward", source = "IKE_INITIATOR", confidence = "HIGH"
       - packet.src == responder_ip  -> direction = "reverse", source = "IKE_INITIATOR", confidence = "HIGH"
    2. Data-Plane Fallback: If no IKE is present:
       - First observed endpoint pair (A -> B) sets provisional forward direction.
       - packet.src == A             -> direction = "forward", source = "FIRST_OBSERVED", confidence = "PROVISIONAL"
       - packet.src == B             -> direction = "reverse", source = "FIRST_OBSERVED", confidence = "PROVISIONAL"
    - NEVER uses IP address ranges (10.*, 172.16.*, 192.168.*) or lexicographic ordering to infer direction.
    """

    @classmethod
    def extract_esp_records(cls, packets: List[Any], ike_events: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
        records = []
        
        # 1. Build IKE initiator lookup map for (endpoint pair)
        ike_initiator_map: Dict[frozenset, str] = {}
        if ike_events:
            for ike in ike_events:
                src = ike.get("src_ip")
                dst = ike.get("dst_ip")
                init_ip = ike.get("initiator_ip")
                if src and dst and init_ip and src != "unknown" and dst != "unknown":
                    pair_key = frozenset([src, dst])
                    if pair_key not in ike_initiator_map:
                        ike_initiator_map[pair_key] = init_ip

        # 2. Dynamic tracking of first observed direction per endpoint pair
        first_observed_src_map: Dict[frozenset, str] = {}

        for idx, pkt in enumerate(packets):
            if IP in pkt:
                ip_layer = pkt[IP]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                pair_key = frozenset([src_ip, dst_ip])

                # Determine direction dynamically
                if pair_key in ike_initiator_map:
                    initiator_ip = ike_initiator_map[pair_key]
                    if src_ip == initiator_ip:
                        direction = "forward"
                    else:
                        direction = "reverse"
                    direction_source = "IKE_INITIATOR"
                    direction_confidence = "HIGH"
                else:
                    if pair_key not in first_observed_src_map:
                        first_observed_src_map[pair_key] = src_ip
                    
                    first_src = first_observed_src_map[pair_key]
                    if src_ip == first_src:
                        direction = "forward"
                    else:
                        direction = "reverse"
                    direction_source = "FIRST_OBSERVED"
                    direction_confidence = "PROVISIONAL"
                
                # Protocol 50: ESP
                if ip_layer.proto == 50:
                    raw_payload = bytes(ip_layer.payload)
                    if len(raw_payload) >= 8:
                        spi = int.from_bytes(raw_payload[0:4], byteorder='big')
                        seq = int.from_bytes(raw_payload[4:8], byteorder='big')

                        records.append({
                            "packet_index": idx,
                            "timestamp": float(pkt.time),
                            "protocol": "ESP",
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "spi": hex(spi),
                            "spi_raw": spi,
                            "sequence_number": seq,
                            "packet_length": len(pkt),
                            "payload_length": len(raw_payload),
                            "direction": direction,
                            "direction_source": direction_source,
                            "direction_confidence": direction_confidence,
                            "payload_visibility": "ENCRYPTED",
                            "content_observability": "NOT_OBSERVABLE"
                        })
                # Protocol 51: AH
                elif ip_layer.proto == 51:
                    raw_payload = bytes(ip_layer.payload)
                    spi = int.from_bytes(raw_payload[4:8], byteorder='big') if len(raw_payload) >= 8 else 0
                    seq = int.from_bytes(raw_payload[8:12], byteorder='big') if len(raw_payload) >= 12 else 0

                    records.append({
                        "packet_index": idx,
                        "timestamp": float(pkt.time),
                        "protocol": "AH",
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "spi": hex(spi),
                        "spi_raw": spi,
                        "sequence_number": seq,
                        "packet_length": len(pkt),
                        "payload_length": len(raw_payload),
                        "direction": direction,
                        "direction_source": direction_source,
                        "direction_confidence": direction_confidence,
                        "payload_visibility": "INTEGRITY_PROTECTED",
                        "content_observability": "NOT_OBSERVABLE"
                    })

        return records
