from typing import List, Dict, Any, Optional

class EvidenceExplanationGenerator:
    """
    Evidence-Grounded AI Explanation Layer.
    
    Combines authoritative deterministic protocol evidence with multi-model behavioral inferences.
    Every explanation statement explicitly identifies its provenance source:
    - DETERMINISTIC (IKE parameters, ESP/AH headers, SPI, replay state)
    - BASELINE_ML (14-feature XGBoost statistical classifier)
    - SEQUENCE_ML (Lightweight packet sequence Transformer)
    - PROTOCOL_AWARE_SEQUENCE_ML (Context-augmented sequence Transformer)
    - MULTIVIEW_ML (Fused tabular + sequence + context network)
    - OOD (Embedding-distance novelty detector)
    
    Guarantees:
    - Never infers or overrides cryptographic parameters from raw traffic.
    - Grounded strictly in observable evidence objects.
    """

    @classmethod
    def generate_explanation(
        cls,
        protocol_evidence: Dict[str, Any],
        behavioral_evidence: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        explanations = []

        # 1. Deterministic Protocol Layer Statements
        if protocol_evidence.get("ipsec_detected"):
            ike_ver = protocol_evidence.get("ike_version")
            if ike_ver and ike_ver != "unknown":
                explanations.append({
                    "source": "DETERMINISTIC",
                    "category": "CONTROL_PLANE_SECURITY",
                    "statement": f"Observed authoritative IKEv{ike_ver} handshake negotiation.",
                    "details": {
                        "ike_version": ike_ver,
                        "encryption_transforms": protocol_evidence.get("encryption_transforms"),
                        "dh_groups": protocol_evidence.get("dh_groups")
                    }
                })
            else:
                explanations.append({
                    "source": "DETERMINISTIC",
                    "category": "CONTROL_PLANE_SECURITY",
                    "statement": "ESP data-plane traffic detected without observable IKE control-plane handshake.",
                    "details": {
                        "notes": "Capture initiated mid-session or pure data-plane interface."
                    }
                })

            spi_list = protocol_evidence.get("spi_list", [])
            dir_src = protocol_evidence.get("direction_source", "UNKNOWN")
            dir_conf = protocol_evidence.get("direction_confidence", "UNKNOWN")
            explanations.append({
                "source": "DETERMINISTIC",
                "category": "DATA_PLANE_TELEMETRY",
                "statement": f"ESP data-plane active with {len(spi_list)} unique SPI(s); direction derived via {dir_src} (Confidence: {dir_conf}).",
                "details": {
                    "spis": spi_list[:4],
                    "direction_source": dir_src,
                    "direction_confidence": dir_conf
                }
            })

        # 2. Behavioral ML Inferences
        base_pred = behavioral_evidence.get("baseline_prediction")
        base_conf = behavioral_evidence.get("baseline_confidence")
        base_margin = behavioral_evidence.get("baseline_margin")
        if base_pred:
            explanations.append({
                "source": "BASELINE_ML",
                "category": "TRAFFIC_CLASSIFICATION",
                "statement": f"14-feature statistical baseline classifies traffic as {base_pred} (Confidence: {base_conf*100:.1f}%, Margin: {base_margin*100:.1f}%).",
                "details": {
                    "predicted_class": base_pred,
                    "confidence": base_conf,
                    "margin": base_margin
                }
            })

        seq_pred = behavioral_evidence.get("sequence_prediction")
        seq_conf = behavioral_evidence.get("sequence_confidence")
        if seq_pred:
            explanations.append({
                "source": "SEQUENCE_ML",
                "category": "TEMPORAL_SEQUENCE_LEARNING",
                "statement": f"Packet sequence Transformer observed fine-grained packet sizes and inter-arrival dynamics, predicting {seq_pred} (Confidence: {seq_conf*100:.1f}%).",
                "details": {
                    "predicted_class": seq_pred,
                    "confidence": seq_conf
                }
            })

        multi_pred = behavioral_evidence.get("multiview_prediction")
        multi_conf = behavioral_evidence.get("multiview_confidence")
        if multi_pred:
            explanations.append({
                "source": "MULTIVIEW_ML",
                "category": "MULTI_VIEW_FUSION",
                "statement": f"Multi-view network fused tabular statistics, packet temporal dynamics, and protocol context to infer workload as {multi_pred} (Confidence: {multi_conf*100:.1f}%).",
                "details": {
                    "predicted_class": multi_pred,
                    "confidence": multi_conf
                }
            })

        # 3. Novelty & OOD Statements
        ood_status = behavioral_evidence.get("novelty_status", "NOT_AVAILABLE")
        ood_score = behavioral_evidence.get("novelty_score")
        ood_thresh = behavioral_evidence.get("novelty_threshold")
        if ood_status == "KNOWN":
            explanations.append({
                "source": "OOD",
                "category": "DISTRIBUTION_ALIGNMENT",
                "statement": "Traffic sequence representation aligns with known native-IPsec distribution clusters.",
                "details": {
                    "novelty_status": ood_status,
                    "score": ood_score,
                    "threshold": ood_thresh
                }
            })
        elif ood_status == "UNKNOWN":
            explanations.append({
                "source": "OOD",
                "category": "DISTRIBUTION_ALIGNMENT",
                "statement": f"Traffic sequence representation lies outside the known training distribution (Score: {ood_score:.3f} vs Threshold: {ood_thresh:.3f}).",
                "details": {
                    "novelty_status": ood_status,
                    "score": ood_score,
                    "threshold": ood_thresh
                }
            })
        else:
            explanations.append({
                "source": "OOD",
                "category": "DISTRIBUTION_ALIGNMENT",
                "statement": "Novelty status is NOT_AVAILABLE (insufficient packet sequence depth for embedding distance calculation).",
                "details": {
                    "novelty_status": "NOT_AVAILABLE"
                }
            })

        return explanations
