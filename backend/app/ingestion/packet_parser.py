import os
import shutil
import uuid
import scapy.all as scapy
from scapy.all import rdpcap, IP, UDP
from typing import Dict, Any, List, Tuple

class PacketParser:
    """
    Ingests and parses PCAP/PCAPNG streams.
    Extracts raw packet metrics and isolates IPsec protocols (IKE, ESP, AH).
    """

    @staticmethod
    def parse_pcap_file(file_path: str) -> Tuple[List[Any], Dict[str, Any], List[str]]:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"PCAP file not found: {file_path}")

        parse_errors = []
        try:
            packets = rdpcap(file_path)
        except Exception as e:
            parse_errors.append(f"Scapy failed reading PCAP: {str(e)}")
            return [], {}, parse_errors

        total_pkts = len(packets)
        ike_count = 0
        esp_count = 0
        ah_count = 0
        
        timestamps = []
        sources = set()
        destinations = set()

        for idx, pkt in enumerate(packets):
            try:
                if pkt.time is not None:
                    timestamps.append(float(pkt.time))

                if IP in pkt:
                    ip = pkt[IP]
                    sources.add(ip.src)
                    destinations.add(ip.dst)

                    if ip.proto == 50:
                        esp_count += 1
                    elif ip.proto == 51:
                        ah_count += 1
                    elif UDP in pkt:
                        udp = pkt[UDP]
                        if udp.sport in [500, 4500] or udp.dport in [500, 4500]:
                            ike_count += 1
            except Exception as e:
                parse_errors.append(f"Error parsing packet #{idx}: {str(e)}")

        start_time = min(timestamps) if timestamps else None
        end_time = max(timestamps) if timestamps else None
        duration = (end_time - start_time) if (start_time is not None and end_time is not None) else 0.0

        summary = {
            "packet_count": total_pkts,
            "ike_packet_count": ike_count,
            "esp_packet_count": esp_count,
            "ah_packet_count": ah_count,
            "start_time": start_time,
            "end_time": end_time,
            "duration_sec": max(float(duration), 0.0),
            "unique_sources": sorted(list(sources)),
            "unique_destinations": sorted(list(destinations))
        }

        return packets, summary, parse_errors
