import os
import numpy as np
from typing import List, Dict, Any, Optional

class PacketSequenceExtractor:
    """
    Extracts observable packet-sequence representations from ESP records.
    Strictly observes Layer 3/4 header dynamics without payload decryption.
    
    Packet Feature Representation per step (length L):
    1. packet_length: normalized float [0.0, 1.0] (div by MTU 1500)
    2. inter_arrival_time: normalized log-scaled IAT in seconds
    3. direction: +1.0 (forward) or -1.0 (reverse)
    4. sequence_position: normalized step index (i / L)
    """

    FEATURE_DIM = 4
    CONTEXT_DIM = 4

    @classmethod
    def extract_context_from_window(
        cls,
        win_pkts: List[Dict[str, Any]],
        ike_events: Optional[List[Dict[str, Any]]] = None
    ) -> np.ndarray:
        """
        Extracts genuine deterministic protocol/session context (4 features):
        1. is_esp: 1.0 if ESP, 0.0 otherwise
        2. direction_confidence_high: 1.0 if direction source is IKE_INITIATOR, 0.0 if PROVISIONAL
        3. ike_present: 1.0 if IKE handshake observed, 0.0 otherwise
        4. session_packet_density: normalized packet count (len(win_pkts) / 50.0)
        """
        if not win_pkts:
            return np.zeros(cls.CONTEXT_DIM, dtype=np.float32)

        is_esp = 1.0 if win_pkts[0].get("protocol") == "ESP" else 0.0
        dir_conf = 1.0 if win_pkts[0].get("direction_confidence") == "HIGH" else 0.0
        ike_present = 1.0 if (ike_events and len(ike_events) > 0) else 0.0
        pkt_density = min(float(len(win_pkts)) / 50.0, 2.0)

        return np.array([is_esp, dir_conf, ike_present, pkt_density], dtype=np.float32)

    @classmethod
    def extract_sequence_from_window(
        cls,
        win_pkts: List[Dict[str, Any]],
        max_seq_len: int = 32
    ) -> Dict[str, np.ndarray]:
        """
        Transforms packets inside a flow window into a fixed-length tensor representation.
        Returns:
            - 'features': np.ndarray of shape (max_seq_len, FEATURE_DIM)
            - 'mask': np.ndarray of shape (max_seq_len,) bool mask (True = valid, False = pad)
            - 'seq_len': int actual valid length
        """
        if not win_pkts:
            return {
                "features": np.zeros((max_seq_len, cls.FEATURE_DIM), dtype=np.float32),
                "mask": np.zeros(max_seq_len, dtype=bool),
                "seq_len": 0
            }

        # Sort chronologically within window
        sorted_pkts = sorted(win_pkts, key=lambda x: x["timestamp"])
        timestamps = [p["timestamp"] for p in sorted_pkts]
        sizes = [p["packet_length"] for p in sorted_pkts]
        directions = [1.0 if p.get("direction") == "forward" else -1.0 for p in sorted_pkts]

        # Compute IATs within window
        if len(timestamps) > 1:
            iats = [0.0] + list(np.diff(timestamps))
        else:
            iats = [0.0]

        actual_len = min(len(sorted_pkts), max_seq_len)
        features = np.zeros((max_seq_len, cls.FEATURE_DIM), dtype=np.float32)
        mask = np.zeros(max_seq_len, dtype=bool)

        for i in range(actual_len):
            # 1. Normalized packet size (clamped 0 to 1.5)
            norm_size = min(float(sizes[i]) / 1500.0, 1.5)
            
            # 2. Log-scaled normalized IAT
            raw_iat = max(float(iats[i]), 0.0)
            norm_iat = float(np.log1p(raw_iat * 10.0))  # Smooth scale for ms-to-sec intervals
            
            # 3. Direction (-1 or +1)
            dir_val = float(directions[i])
            
            # 4. Normalized position in sequence
            norm_pos = float(i / max(actual_len - 1, 1))

            features[i] = [norm_size, norm_iat, dir_val, norm_pos]
            mask[i] = True

        return {
            "features": features,
            "mask": mask,
            "seq_len": actual_len
        }
