import numpy as np
from typing import List, Dict, Any

class FlowWindowBuilder:
    """
    Groups encrypted packets into deterministic time windows (default: 3.0s).
    Extracts multi-scale encrypted flow statistics without payload inspection.
    """

    FEATURE_NAMES = [
        "flow_duration_sec", "packets_per_sec", "bytes_per_sec",
        "mean_iat_sec", "std_iat_sec", "mean_packet_size_bytes",
        "std_packet_size_bytes", "min_packet_size_bytes", "max_packet_size_bytes",
        "pkt_len_p25", "pkt_len_p50", "pkt_len_p75", "pkt_len_p90",
        "directional_byte_ratio"
    ]

    @classmethod
    def build_flow_windows(
        cls, 
        esp_records: List[Dict[str, Any]], 
        window_sec: float = 3.0, 
        analysis_id: str = "analysis"
    ) -> List[Dict[str, Any]]:
        if not esp_records:
            return []

        # Sort packets chronologically
        pkts = sorted(esp_records, key=lambda x: x["timestamp"])
        min_time = pkts[0]["timestamp"]
        max_time = pkts[-1]["timestamp"]

        windows = []
        win_idx = 0
        current_start = min_time

        while current_start <= max_time:
            current_end = current_start + window_sec
            win_pkts = [p for p in pkts if current_start <= p["timestamp"] < current_end]

            if len(win_pkts) >= 2:
                timestamps = [p["timestamp"] for p in win_pkts]
                sizes = [p["packet_length"] for p in win_pkts]
                fwd_pkts = [p for p in win_pkts if p.get("direction") == "forward"]
                rev_pkts = [p for p in win_pkts if p.get("direction") == "reverse"]

                dur = max(max(timestamps) - min(timestamps), 0.0001)
                iats = np.diff(timestamps) if len(timestamps) > 1 else np.array([0.0])

                fwd_bytes = sum(p["packet_length"] for p in fwd_pkts)
                rev_bytes = sum(p["packet_length"] for p in rev_pkts)
                total_bytes = sum(sizes)
                ratio = float(fwd_bytes / total_bytes) if total_bytes > 0 else 0.5

                # Inter-arrival burst metric (< 0.1s)
                bursts = 1
                curr_b = 1
                b_lens = []
                for iat in iats:
                    if iat < 0.1:
                        curr_b += 1
                    else:
                        b_lens.append(curr_b)
                        curr_b = 1
                        bursts += 1
                b_lens.append(curr_b)

                session_id = f"SESSION_{win_pkts[0]['spi'][-8:]}" if "spi" in win_pkts[0] else "SESSION_GENERIC"

                window_record = {
                    "window_id": f"{analysis_id}_W{win_idx:03d}",
                    "session_id": session_id,
                    "start_time": current_start,
                    "end_time": current_end,
                    "duration_sec": float(dur),
                    "packet_count": len(win_pkts),
                    "byte_count": total_bytes,
                    "mean_packet_size": float(np.mean(sizes)),
                    "median_packet_size": float(np.median(sizes)),
                    "std_packet_size": float(np.std(sizes)),
                    "min_packet_size": int(np.min(sizes)),
                    "max_packet_size": int(np.max(sizes)),
                    "packets_per_sec": float(len(win_pkts) / dur),
                    "bytes_per_sec": float(total_bytes / dur),
                    "mean_iat_sec": float(np.mean(iats)),
                    "std_iat_sec": float(np.std(iats)),
                    "fwd_packets": len(fwd_pkts),
                    "rev_packets": len(rev_pkts),
                    "fwd_bytes": fwd_bytes,
                    "rev_bytes": rev_bytes,
                    "directional_byte_ratio": ratio,
                    "burst_count": bursts,
                    "mean_burst_packets": float(np.mean(b_lens)),
                    
                    # ML 14-Feature Canonical Vector Mapping
                    "mean_packet_size_bytes": float(np.mean(sizes)),
                    "std_packet_size_bytes": float(np.std(sizes)),
                    "min_packet_size_bytes": int(np.min(sizes)),
                    "max_packet_size_bytes": int(np.max(sizes)),
                    "pkt_len_p25": float(np.percentile(sizes, 25)),
                    "pkt_len_p50": float(np.percentile(sizes, 50)),
                    "pkt_len_p75": float(np.percentile(sizes, 75)),
                    "pkt_len_p90": float(np.percentile(sizes, 90)),
                }
                windows.append(window_record)
                win_idx += 1

            current_start += window_sec

        return windows
