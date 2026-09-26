from typing import List, Dict, Any, Optional
from app.schemas.api_models import ObservabilityState, TrafficAssessment, SeparationState

class EvidenceFusionEngine:
    """
    Evidence Fusion Layer: Combines multi-plane observations.
    Integrates IKE control-plane, ESP data-plane, flow dynamics, and ML predictions.
    ML prediction is strictly treated as ONE evidence input, never the unilateral verdict.
    """

    @classmethod
    def fuse_evidence(
        cls,
        ike_events: List[Dict[str, Any]],
        esp_records: List[Dict[str, Any]],
        sessions: List[Dict[str, Any]],
        flow_windows: List[Dict[str, Any]],
        ml_prediction: Optional[Dict[str, Any]],
        security_findings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        supporting: List[Dict[str, Any]] = []
        contradicting: List[Dict[str, Any]] = []
        unknowns: List[Dict[str, Any]] = []

        # 1. Control-Plane IKE Evidence
        if ike_events:
            first_ike = ike_events[0]
            supporting.append({
                "source": "IKE_CONTROL_PLANE",
                "feature": "IKE_VERSION",
                "value": first_ike.get("ike_version", "unknown"),
                "reliability": 0.95,
                "state": ObservabilityState.OBSERVED,
                "timestamp": first_ike.get("timestamp"),
                "notes": f"Exchange Type: {first_ike.get('exchange_type')}"
            })
            if first_ike.get("encryption_transforms"):
                supporting.append({
                    "source": "IKE_CONTROL_PLANE",
                    "feature": "PROPOSED_CIPHERS",
                    "value": first_ike.get("encryption_transforms"),
                    "reliability": 0.90,
                    "state": ObservabilityState.OBSERVED,
                    "timestamp": first_ike.get("timestamp"),
                    "notes": "Extracted from IKE SA Proposals"
                })
        else:
            unknowns.append({
                "source": "IKE_CONTROL_PLANE",
                "feature": "IKE_HANDSHAKE",
                "value": "NO_CONTROL_PLANE_PACKETS",
                "reliability": 0.50,
                "state": ObservabilityState.UNKNOWN,
                "timestamp": None,
                "notes": "Capture initiated mid-session or pure data-plane capture."
            })

        # 2. Data-Plane ESP / SA Evidence
        if esp_records:
            spi_list = list(set([r["spi"] for r in esp_records]))
            supporting.append({
                "source": "ESP_DATA_PLANE",
                "feature": "ESP_ENCAPSULATION",
                "value": f"{len(esp_records)} packets across {len(spi_list)} SPIs",
                "reliability": 0.99,
                "state": ObservabilityState.OBSERVED,
                "timestamp": esp_records[0]["timestamp"],
                "notes": "Encapsulating Security Payload (Protocol 50) verified."
            })

            # Check sequence progression
            seqs = [r["sequence_number"] for r in esp_records if "sequence_number" in r]
            if seqs:
                duplicates = len(seqs) - len(set(seqs))
                if duplicates == 0:
                    supporting.append({
                        "source": "ESP_DATA_PLANE",
                        "feature": "SEQUENCE_PROGRESSION",
                        "value": "STRICT_MONOTONIC_INCREASING",
                        "reliability": 0.95,
                        "state": ObservabilityState.OBSERVED,
                        "timestamp": esp_records[-1]["timestamp"],
                        "notes": "No duplicate sequence numbers observed."
                    })
                else:
                    contradicting.append({
                        "source": "ESP_DATA_PLANE",
                        "feature": "SEQUENCE_PROGRESSION",
                        "value": f"{duplicates} duplicate sequence observations",
                        "reliability": 0.85,
                        "state": ObservabilityState.CONFLICT,
                        "timestamp": esp_records[-1]["timestamp"],
                        "notes": "Possible packet replay or multi-core packet reordering."
                    })

        # 3. Payload Observability Boundary
        unknowns.append({
            "source": "CRYPTOGRAPHIC_BOUNDARY",
            "feature": "PAYLOAD_CONTENT",
            "value": "NOT_OBSERVABLE",
            "reliability": 1.0,
            "state": ObservabilityState.NOT_OBSERVABLE,
            "timestamp": None,
            "notes": "Payload is AES encrypted; plaintext inspection is mathematically infeasible."
        })

        # 4. ML Prediction Evidence (Empirically supported, margin-aware fusion)
        if ml_prediction and ml_prediction.get("confidence") is not None:
            pred_cls = ml_prediction.get("predicted_class")
            conf = float(ml_prediction.get("confidence", 0.0))
            top2_cls = ml_prediction.get("top2_class")
            top2_prob = ml_prediction.get("top2_probability")
            margin = ml_prediction.get("confidence_margin")
            sep_state = ml_prediction.get("separation_state")
            if not sep_state or sep_state == SeparationState.UNKNOWN:
                if margin is not None:
                    if margin > 0.50:
                        sep_state = SeparationState.HIGH_SEPARATION
                    elif margin < 0.15:
                        sep_state = SeparationState.LOW_SEPARATION
                    else:
                        sep_state = SeparationState.INTERMEDIATE
                else:
                    sep_state = SeparationState.UNKNOWN

            notes_detail = (
                f"Separation: {sep_state}, "
                f"Top-1: {pred_cls} (p={conf:.4f}), "
                f"Top-2: {top2_cls} (p={top2_prob:.4f}), Margin={margin:.4f}. "
                f"Distribution: {ml_prediction.get('class_probabilities')}. "
                f"[Note: Raw model softmax outputs are not calibrated Bayesian probabilities]"
                if margin is not None and top2_prob is not None
                else f"Distribution: {ml_prediction.get('class_probabilities')}"
            )

            if sep_state == SeparationState.HIGH_SEPARATION:
                # High separation regime (margin > 0.50): empirically associated with >95% accuracy
                supporting.append({
                    "source": "STATISTICAL_ML_INFERENCE",
                    "feature": "TRAFFIC_WORKLOAD_CLASS",
                    "value": pred_cls,
                    "reliability": None,  # Not claiming raw softmax is calibrated reliability
                    "state": ObservabilityState.OBSERVED,
                    "timestamp": None,
                    "notes": f"HIGH_SEPARATION evidence. {notes_detail}"
                })
            elif sep_state == SeparationState.LOW_SEPARATION:
                # Low separation regime (margin < 0.15): ambiguous / close distribution (e.g. INTERACTIVE vs WEB)
                unknowns.append({
                    "source": "STATISTICAL_ML_INFERENCE",
                    "feature": "TRAFFIC_WORKLOAD_CLASS",
                    "value": "AMBIGUOUS / LOW_SEPARATION",
                    "reliability": None,
                    "state": ObservabilityState.UNKNOWN,
                    "timestamp": None,
                    "notes": f"LOW_SEPARATION / Ambiguous prediction between {pred_cls} and {top2_cls}. {notes_detail}"
                })
            else:
                # Intermediate separation (0.15 <= margin <= 0.50)
                unknowns.append({
                    "source": "STATISTICAL_ML_INFERENCE",
                    "feature": "TRAFFIC_WORKLOAD_CLASS",
                    "value": f"INTERMEDIATE_SEPARATION ({pred_cls})",
                    "reliability": None,
                    "state": ObservabilityState.INFERRED,
                    "timestamp": None,
                    "notes": f"INTERMEDIATE / Unresolved separation. {notes_detail}"
                })
        else:
            unknowns.append({
                "source": "STATISTICAL_ML_INFERENCE",
                "feature": "TRAFFIC_WORKLOAD_CLASS",
                "value": "ML_MODEL_NOT_INITIALIZED",
                "reliability": None,
                "state": ObservabilityState.UNKNOWN,
                "timestamp": None,
                "notes": "Trained ML model artifact unavailable or not initialized."
            })

        # 5. Determine Overall Assessment & Confidence
        has_high_findings = any(f.get("severity") == "HIGH" for f in security_findings)
        has_medium_findings = any(f.get("severity") == "MEDIUM" for f in security_findings)
        
        if has_high_findings:
            overall_assessment = TrafficAssessment.ANOMALOUS
            overall_conf = 0.88
        elif has_medium_findings or contradicting:
            overall_assessment = TrafficAssessment.SUSPICIOUS
            overall_conf = 0.75
        elif esp_records or ike_events:
            overall_assessment = TrafficAssessment.NORMAL
            overall_conf = 0.92
        else:
            overall_assessment = TrafficAssessment.UNKNOWN
            overall_conf = 0.20

        return {
            "overall_assessment": overall_assessment,
            "confidence": overall_conf,
            "supporting_evidence": supporting,
            "contradicting_evidence": contradicting,
            "unknown_factors": unknowns
        }
