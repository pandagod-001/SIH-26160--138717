from typing import List, Dict, Any

class SAReconstructor:
    """
    Reconstructs Security Association (SA) instances from observable packet headers (SPI, IP pair).
    Associates related control plane IKE events.
    """

    @staticmethod
    def reconstruct_sessions(esp_records: List[Dict[str, Any]], ike_events: List[Dict[str, Any]], analysis_id: str = "ANL") -> List[Dict[str, Any]]:
        if not esp_records:
            return []

        # Group ESP packets by SPI and endpoints
        groups: Dict[str, List[Dict[str, Any]]] = {}
        for pkt in esp_records:
            key = f"{pkt['src_ip']}->{pkt['dst_ip']}_{pkt['spi']}"
            if key not in groups:
                groups[key] = []
            groups[key].append(pkt)

        sessions = []
        for idx, (key, pkts) in enumerate(groups.items()):
            first_pkt = pkts[0]
            last_pkt = pkts[-1]
            first_seen = min(p["timestamp"] for p in pkts)
            last_seen = max(p["timestamp"] for p in pkts)
            total_bytes = sum(p["packet_length"] for p in pkts)
            
            # Count related IKE events by IP match
            src_ip = first_pkt["src_ip"]
            dst_ip = first_pkt["dst_ip"]
            related_ike = [
                ike for ike in ike_events
                if (ike["src_ip"] == src_ip and ike["dst_ip"] == dst_ip) or
                   (ike["src_ip"] == dst_ip and ike["dst_ip"] == src_ip)
            ]

            session_id = f"{analysis_id}_SA_{idx:02d}_{first_pkt['spi'][-8:]}"
            duration = max(last_seen - first_seen, 0.0001)

            sessions.append({
                "session_id": session_id,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "spi": first_pkt["spi"],
                "first_seen": first_seen,
                "last_seen": last_seen,
                "duration_sec": duration,
                "packet_count": len(pkts),
                "byte_count": total_bytes,
                "direction": first_pkt["direction"],
                "related_ike_events": len(related_ike),
                "confidence": 1.0 if len(pkts) >= 3 else 0.7,
                "status": "ESTABLISHED" if len(pkts) >= 5 else "TRANSIENT"
            })

        return sessions
