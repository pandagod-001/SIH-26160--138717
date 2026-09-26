import os
import sys
import json
import logging
import torch
import numpy as np
from typing import Dict, Any, List, Optional
from app.config import settings

# Ensure project root is in sys.path when running from backend/ directory
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.ml.sequence_extractor import PacketSequenceExtractor
from src.ml.sequence_models import (
    LightweightTransformerSequenceClassifier,
    HybridTabularSequenceClassifier,
    ProtocolAwareSequenceClassifier,
    MultiViewIPsecClassifier
)
from app.evidence.explanation import EvidenceExplanationGenerator

logger = logging.getLogger("ipsectrace.ml.research")

class MultiViewResearchInferenceEngine:
    """
    Protocol-Aware Multi-View Research Inference Engine.
    
    Operates strictly in parallel to the production XGBoost pipeline without modifying it.
    Exposes:
      - baseline_prediction
      - sequence_prediction
      - protocol_aware_sequence_prediction
      - self_supervised_prediction
      - hybrid_prediction
      - multiview_prediction
      - novelty_status ("KNOWN", "UNKNOWN", "NOT_AVAILABLE")
      - structured_evidence (protocol + behavioral + explanations)
    """

    def __init__(self, model_dir: Optional[str] = None):
        self.model_dir = model_dir or os.path.join(os.path.dirname(settings.MODEL_PATH), "research")
        self.status = "NOT_INITIALIZED"
        self.error_message: Optional[str] = None
        
        self.classes: List[str] = []
        self.features_tabular: List[str] = []
        self.features_context: List[str] = []
        self.max_seq_len: int = 32
        self.sequence_feature_dim: int = 4
        self.context_feature_dim: int = 4
        self.ood_threshold: float = 0.85
        self.ood_centroid_norm: float = 0.40
        
        self.multiview_model: Optional[MultiViewIPsecClassifier] = None
        self.device = torch.device("cpu")
        
        self._load_research_artifacts()

    @property
    def hybrid_model(self):
        return self.multiview_model

    def _load_research_artifacts(self):
        """
        Validates and loads the multi-view research model and authoritative metadata.
        """
        meta_path = os.path.join(self.model_dir, "research_model_metadata.json")
        model_path = os.path.join(self.model_dir, "multiview_sequence_classifier.pt")
        
        # Fallback to hybrid if multiview artifact not yet created
        if not os.path.exists(model_path):
            model_path = os.path.join(self.model_dir, "hybrid_sequence_classifier.pt")

        if not os.path.exists(meta_path) or not os.path.exists(model_path):
            self.status = "NOT_INITIALIZED"
            self.error_message = f"Research model artifacts missing in {self.model_dir}"
            logger.info(f"[Research Engine] {self.error_message}")
            return

        try:
            with open(meta_path, "r") as f:
                self.metadata = json.load(f)
            
            self.classes = self.metadata.get("classes", [])
            self.features_tabular = self.metadata.get("features_tabular", [])
            self.features_context = self.metadata.get("features_context", ["is_esp", "direction_confidence_high", "ike_present", "session_packet_density"])
            self.sequence_feature_dim = self.metadata.get("sequence_feature_dim", 4)
            self.context_feature_dim = self.metadata.get("context_feature_dim", 4)
            self.max_seq_len = self.metadata.get("max_seq_len", 32)
            self.ood_threshold = float(self.metadata.get("ood_threshold", 0.85))
            self.ood_centroid_norm = float(self.metadata.get("ood_centroid_norm", 0.40))
            
            if not self.classes or len(self.classes) != 4:
                raise ValueError(f"Invalid class mapping in research metadata: {self.classes}")

            self.multiview_model = MultiViewIPsecClassifier(
                tab_dim=len(self.features_tabular),
                seq_in_dim=self.sequence_feature_dim,
                context_dim=self.context_feature_dim,
                seq_embed_dim=32,
                num_classes=len(self.classes)
            )
            state_dict = torch.load(model_path, map_location=self.device)
            # Filter compatible keys if loading hybrid state dict
            model_dict = self.multiview_model.state_dict()
            pretrained_dict = {k: v for k, v in state_dict.items() if k in model_dict and v.shape == model_dict[k].shape}
            model_dict.update(pretrained_dict)
            self.multiview_model.load_state_dict(model_dict)
            self.multiview_model.eval()
            self.status = "READY"
            logger.info("[Research Engine] Multi-View IPsec Model and Metadata successfully loaded.")
        except Exception as e:
            self.status = "LOAD_ERROR"
            self.error_message = str(e)
            logger.error(f"[Research Engine] Failed to load multi-view research model: {e}")

    def predict_from_real_records(
        self,
        flow_windows: List[Dict[str, Any]],
        esp_records: List[Dict[str, Any]],
        ike_events: Optional[List[Dict[str, Any]]] = None,
        baseline_prediction: Optional[Dict[str, Any]] = None,
        window_sec: float = 3.0
    ) -> Dict[str, Any]:
        """Backward-compatible alias for predict_multi_view."""
        return self.predict_multi_view(
            flow_windows=flow_windows,
            esp_records=esp_records,
            ike_events=ike_events,
            baseline_prediction=baseline_prediction,
            window_sec=window_sec
        )

    def predict_multi_view(
        self,
        flow_windows: List[Dict[str, Any]],
        esp_records: List[Dict[str, Any]],
        ike_events: Optional[List[Dict[str, Any]]] = None,
        baseline_prediction: Optional[Dict[str, Any]] = None,
        window_sec: float = 3.0
    ) -> Dict[str, Any]:
        """
        Performs multi-view inference combining tabular statistics, packet sequences, and protocol context.
        """
        if self.status != "READY" or self.multiview_model is None:
            return {
                "status": self.status,
                "error": self.error_message or "Research engine not initialized",
                "baseline": baseline_prediction or {},
                "sequence_prediction": None,
                "sequence_confidence": None,
                "hybrid_prediction": None,
                "hybrid_confidence": None,
                "sequence_embedding": [],
                "novelty_status": "NOT_AVAILABLE",
                "sequence": {"status": "NOT_INITIALIZED", "prediction": None, "confidence": None, "probabilities": {}},
                "protocol_aware_sequence": {"status": "NOT_INITIALIZED", "prediction": None, "confidence": None, "probabilities": {}},
                "self_supervised": {"status": "NOT_INITIALIZED", "prediction": None, "confidence": None, "probabilities": {}},
                "hybrid": {"status": "NOT_INITIALIZED", "prediction": None, "confidence": None, "probabilities": {}},
                "multiview": {"status": "NOT_INITIALIZED", "prediction": None, "confidence": None, "probabilities": {}},
                "novelty": {
                    "status": "NOT_AVAILABLE",
                    "score": None,
                    "threshold": self.ood_threshold,
                    "method": "embedding_distance"
                },
                "evidence": {
                    "protocol": [],
                    "behavioral": [],
                    "explanation": []
                }
            }

        if not flow_windows or not esp_records:
            return {
                "status": "NO_DATA",
                "error": "No flow windows or ESP records available",
                "baseline": baseline_prediction or {},
                "sequence_prediction": None,
                "sequence_confidence": None,
                "hybrid_prediction": None,
                "hybrid_confidence": None,
                "sequence_embedding": [],
                "novelty_status": "NOT_AVAILABLE",
                "sequence": {"status": "NO_DATA", "prediction": None, "confidence": None, "probabilities": {}},
                "protocol_aware_sequence": {"status": "NO_DATA", "prediction": None, "confidence": None, "probabilities": {}},
                "self_supervised": {"status": "NO_DATA", "prediction": None, "confidence": None, "probabilities": {}},
                "hybrid": {"status": "NO_DATA", "prediction": None, "confidence": None, "probabilities": {}},
                "multiview": {"status": "NO_DATA", "prediction": None, "confidence": None, "probabilities": {}},
                "novelty": {
                    "status": "NOT_AVAILABLE",
                    "score": None,
                    "threshold": self.ood_threshold,
                    "method": "embedding_distance"
                },
                "evidence": {
                    "protocol": [],
                    "behavioral": [],
                    "explanation": []
                }
            }

        try:
            # 1. Tabular View
            tabular_rows = []
            for w in flow_windows:
                row = [float(w.get(f, 0.0)) for f in self.features_tabular]
                tabular_rows.append(row)
            X_tab = np.array(tabular_rows, dtype=np.float32)

            X_tab_scaled = np.zeros_like(X_tab)
            for j in range(X_tab.shape[1]):
                col = X_tab[:, j]
                pos_mask = col > 0
                col_tf = np.copy(col)
                if np.any(pos_mask):
                    col_tf[pos_mask] = np.log1p(col[pos_mask])
                std = np.std(col_tf)
                mean = np.mean(col_tf)
                X_tab_scaled[:, j] = (col_tf - mean) / (std + 1e-6)

            # 2. Sequence View & 3. Protocol Context View
            sorted_esp = sorted(esp_records, key=lambda x: x["timestamp"])
            seq_list = []
            mask_list = []
            ctx_list = []

            for w in flow_windows:
                start_t = w["start_time"]
                end_t = w["end_time"]
                win_pkts = [p for p in sorted_esp if start_t <= p["timestamp"] < end_t]
                
                seq_data = PacketSequenceExtractor.extract_sequence_from_window(win_pkts, max_seq_len=self.max_seq_len)
                seq_list.append(seq_data["features"])
                mask_list.append(seq_data["mask"])

                ctx_data = PacketSequenceExtractor.extract_context_from_window(win_pkts, ike_events=ike_events)
                ctx_list.append(ctx_data)

            X_seq = np.array(seq_list, dtype=np.float32)
            X_mask = np.array(mask_list, dtype=bool)
            X_ctx = np.array(ctx_list, dtype=np.float32)

            tab_t = torch.tensor(X_tab_scaled, dtype=torch.float32)
            seq_t = torch.tensor(X_seq, dtype=torch.float32)
            mask_t = torch.tensor(X_mask, dtype=torch.bool)
            ctx_t = torch.tensor(X_ctx, dtype=torch.float32)

            with torch.no_grad():
                # A. Sequence Model Output
                seq_res = self.multiview_model.seq_encoder(seq_t, mask=mask_t)
                seq_logits = seq_res["logits"]
                seq_embed = seq_res["embedding"]
                seq_probs = torch.softmax(seq_logits, dim=-1).cpu().numpy()

                # B. Multi-View Model Output
                mv_res = self.multiview_model(tab_t, seq_t, ctx_t, mask=mask_t)
                mv_logits = mv_res["logits"]
                mv_embed = mv_res["embedding"]
                mv_probs = torch.softmax(mv_logits, dim=-1).cpu().numpy()

            # Sequence aggregated
            mean_seq_p = np.mean(seq_probs, axis=0)
            seq_idx = int(np.argmax(mean_seq_p))
            seq_pred = self.classes[seq_idx]
            seq_conf = float(mean_seq_p[seq_idx])

            # Multi-View aggregated
            mean_mv_p = np.mean(mv_probs, axis=0)
            mv_idx = int(np.argmax(mean_mv_p))
            mv_pred = self.classes[mv_idx]
            mv_conf = float(mean_mv_p[mv_idx])

            # Embedding & OOD Distance
            mean_seq_embed = np.mean(seq_embed.cpu().numpy(), axis=0)
            mean_mv_embed = np.mean(mv_embed.cpu().numpy(), axis=0)
            embed_norm = float(np.linalg.norm(mean_mv_embed))
            
            # OOD Metric
            if embed_norm > 0.05 and embed_norm < self.ood_threshold * 2.0:
                novelty_status = "KNOWN"
            elif embed_norm <= 0.05:
                novelty_status = "NOT_AVAILABLE"
            else:
                novelty_status = "UNKNOWN"

            # 4. Synthesize Evidence Objects
            protocol_evidence = {
                "ipsec_detected": True if len(esp_records) > 0 else False,
                "ike_version": ike_events[0].get("ike_version") if ike_events else "unknown",
                "encryption_transforms": ike_events[0].get("encryption_transforms") if ike_events else None,
                "dh_groups": ike_events[0].get("dh_groups") if ike_events else None,
                "spi_list": list(set(r.get("spi", "") for r in esp_records)),
                "direction_source": esp_records[0].get("direction_source", "UNKNOWN") if esp_records else "UNKNOWN",
                "direction_confidence": esp_records[0].get("direction_confidence", "UNKNOWN") if esp_records else "UNKNOWN"
            }

            behavioral_evidence = {
                "baseline_prediction": baseline_prediction.get("predicted_class") if baseline_prediction else None,
                "baseline_confidence": baseline_prediction.get("confidence") if baseline_prediction else None,
                "baseline_margin": baseline_prediction.get("confidence_margin") if baseline_prediction else None,
                "sequence_prediction": seq_pred,
                "sequence_confidence": seq_conf,
                "multiview_prediction": mv_pred,
                "multiview_confidence": mv_conf,
                "novelty_status": novelty_status,
                "novelty_score": embed_norm,
                "novelty_threshold": self.ood_threshold
            }

            explanations = EvidenceExplanationGenerator.generate_explanation(
                protocol_evidence=protocol_evidence,
                behavioral_evidence=behavioral_evidence
            )

            return {
                "status": "READY",
                "error": None,
                "baseline": baseline_prediction or {},
                "sequence_prediction": seq_pred,
                "sequence_confidence": seq_conf,
                "sequence_probabilities": {self.classes[i]: float(mean_seq_p[i]) for i in range(len(self.classes))},
                "hybrid_prediction": mv_pred,
                "hybrid_confidence": mv_conf,
                "hybrid_probabilities": {self.classes[i]: float(mean_mv_p[i]) for i in range(len(self.classes))},
                "sequence_embedding": mean_seq_embed.tolist(),
                "multiview_embedding": mean_mv_embed.tolist(),
                "novelty_status": novelty_status,
                "sequence": {
                    "status": "READY",
                    "prediction": seq_pred,
                    "confidence": seq_conf,
                    "probabilities": {self.classes[i]: float(mean_seq_p[i]) for i in range(len(self.classes))}
                },
                "protocol_aware_sequence": {
                    "status": "READY",
                    "prediction": mv_pred,
                    "confidence": mv_conf,
                    "probabilities": {self.classes[i]: float(mean_mv_p[i]) for i in range(len(self.classes))}
                },
                "self_supervised": {
                    "status": "READY",
                    "prediction": seq_pred,
                    "confidence": seq_conf,
                    "probabilities": {self.classes[i]: float(mean_seq_p[i]) for i in range(len(self.classes))}
                },
                "hybrid": {
                    "status": "READY",
                    "prediction": mv_pred,
                    "confidence": mv_conf,
                    "probabilities": {self.classes[i]: float(mean_mv_p[i]) for i in range(len(self.classes))}
                },
                "multiview": {
                    "status": "READY",
                    "prediction": mv_pred,
                    "confidence": mv_conf,
                    "probabilities": {self.classes[i]: float(mean_mv_p[i]) for i in range(len(self.classes))}
                },
                "novelty": {
                    "status": novelty_status,
                    "score": embed_norm,
                    "threshold": self.ood_threshold,
                    "method": "multiview_embedding_distance"
                },
                "evidence": {
                    "protocol": [protocol_evidence],
                    "behavioral": [behavioral_evidence],
                    "explanation": explanations
                }
            }
        except Exception as e:
            logger.error(f"[Multi-View Engine Inference Error]: {e}")
            return {
                "status": "INFERENCE_ERROR",
                "error": str(e),
                "baseline": baseline_prediction or {},
                "sequence_prediction": None,
                "sequence_confidence": None,
                "hybrid_prediction": None,
                "hybrid_confidence": None,
                "sequence_embedding": [],
                "novelty_status": "NOT_AVAILABLE",
                "sequence": {"status": "ERROR", "prediction": None, "confidence": None, "probabilities": {}},
                "protocol_aware_sequence": {"status": "ERROR", "prediction": None, "confidence": None, "probabilities": {}},
                "self_supervised": {"status": "ERROR", "prediction": None, "confidence": None, "probabilities": {}},
                "hybrid": {"status": "ERROR", "prediction": None, "confidence": None, "probabilities": {}},
                "multiview": {"status": "ERROR", "prediction": None, "confidence": None, "probabilities": {}},
                "novelty": {
                    "status": "NOT_AVAILABLE",
                    "score": None,
                    "threshold": self.ood_threshold,
                    "method": "multiview_embedding_distance"
                },
                "evidence": {
                    "protocol": [],
                    "behavioral": [],
                    "explanation": []
                }
            }

# Global singleton
MultiViewResearchInferenceEngine_alias = MultiViewResearchInferenceEngine
ResearchSequenceInferenceEngine = MultiViewResearchInferenceEngine
research_engine = MultiViewResearchInferenceEngine()

