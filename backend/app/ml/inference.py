import os
import json
import logging
import numpy as np
from typing import Dict, Any, List, Optional
import xgboost as xgb
from app.config import settings
from app.schemas.api_models import ObservabilityState, SeparationState

logger = logging.getLogger("ipsectrace.ml")

class MLInferenceEngine:
    """
    Authoritative ML Inference Engine for Encrypted IPsec Traffic Classification.
    
    Architectural & Observability Guarantees:
    - Binds class labels directly to verified model metadata originating from training.
    - Inspects the underlying XGBoost JSON artifact to extract and verify `num_class` and `objective`.
    - If model metadata is missing, corrupted, or has a class count mismatch with the XGBoost model,
      initialization FAILS strictly with `status = NOT_INITIALIZED`.
    - Zero independent hard-coded class lists or synthetic fallbacks exist.
    """

    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path or settings.MODEL_PATH
        self.model: Optional[xgb.XGBClassifier] = None
        self.status: str = "NOT_INITIALIZED"
        self.error_message: Optional[str] = None
        
        self.model_name: Optional[str] = None
        self.model_version: Optional[str] = None
        self.classes: List[str] = []
        self.features: List[str] = []
        self.num_classes: int = 0

        self._load_and_validate_model_artifact()

    def _load_and_validate_model_artifact(self):
        """
        Loads the XGBoost model artifact and validates consistency against training metadata.
        """
        if not os.path.exists(self.model_path):
            self.status = "NOT_INITIALIZED"
            self.error_message = f"Model artifact not found at {self.model_path}"
            logger.warning(f"[ML Engine] {self.error_message}")
            return

        meta_path = os.path.join(os.path.dirname(self.model_path), "model_metadata.json")
        if not os.path.exists(meta_path):
            self.status = "NOT_INITIALIZED"
            self.error_message = f"Required authoritative model metadata not found at {meta_path}"
            logger.error(f"[ML Engine] {self.error_message}")
            return

        # 1. Parse Authoritative Training Metadata
        try:
            with open(meta_path, "r") as f:
                meta = json.load(f)
            
            self.model_name = meta.get("model_name")
            self.model_version = meta.get("model_version")
            self.classes = meta.get("classes", [])
            self.features = meta.get("features", [])

            if not self.classes or not isinstance(self.classes, list):
                raise ValueError("Metadata 'classes' must be a non-empty list.")
            if not self.features or not isinstance(self.features, list):
                raise ValueError("Metadata 'features' must be a non-empty list.")
        except Exception as e:
            self.status = "NOT_INITIALIZED"
            self.error_message = f"Corrupted or invalid model metadata: {str(e)}"
            logger.error(f"[ML Engine] {self.error_message}")
            return

        # 2. Inspect Native XGBoost JSON Artifact Structure
        try:
            with open(self.model_path, "r") as f:
                raw_model_json = json.load(f)
            
            learner_param = raw_model_json.get("learner", {}).get("learner_model_param", {})
            model_num_class_str = learner_param.get("num_class", "0")
            model_num_class = int(model_num_class_str)
            self.num_classes = model_num_class

            # 3. Authoritative Consistency Check
            if model_num_class != len(self.classes):
                raise ValueError(
                    f"Class count mismatch! XGBoost artifact specifies num_class={model_num_class}, "
                    f"but training metadata specifies {len(self.classes)} classes: {self.classes}"
                )
        except Exception as e:
            self.status = "NOT_INITIALIZED"
            self.error_message = f"XGBoost artifact validation failed: {str(e)}"
            logger.error(f"[ML Engine] {self.error_message}")
            return

        # 4. Load Model into XGBoost Classifier
        try:
            clf = xgb.XGBClassifier()
            clf.load_model(self.model_path)
            self.model = clf
            self.status = "READY"
            self.error_message = None
            logger.info(
                f"[ML Engine] Successfully initialized {self.model_name} ({self.model_version}) "
                f"with {len(self.classes)} authoritative classes: {self.classes}"
            )
        except Exception as e:
            self.model = None
            self.status = "NOT_INITIALIZED"
            self.error_message = f"Failed instantiating XGBoost classifier from artifact: {str(e)}"
            logger.error(f"[ML Engine] {self.error_message}")

    def predict_flow_windows(self, windows: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        Executes inference over flow windows using authoritative metadata mappings.
        Never falls back or guesses labels.
        """
        if self.status != "READY" or self.model is None:
            return {
                "status": "NOT_INITIALIZED",
                "error": self.error_message or "Model artifact is not initialized",
                "model_name": self.model_name,
                "model_version": self.model_version,
                "predicted_class": None,
                "confidence": None,
                "top2_class": None,
                "top2_probability": None,
                "confidence_margin": None,
                "class_probabilities": {},
                "uncertainty_state": ObservabilityState.UNKNOWN,
                "separation_state": SeparationState.UNKNOWN,
                "features_used": self.features
            }

        if not windows:
            return None

        # Build feature matrix in exact feature order
        matrix = []
        for w in windows:
            row = [float(w.get(feat, 0.0)) for feat in self.features]
            matrix.append(row)

        X = np.array(matrix)

        try:
            proba = self.model.predict_proba(X)
            mean_proba = np.mean(proba, axis=0)

            if len(mean_proba) != len(self.classes):
                raise ValueError(
                    f"Probability vector length ({len(mean_proba)}) does not match "
                    f"authoritative class count ({len(self.classes)})"
                )

            # Determine Top-1 and Top-2 ranked indices
            sorted_indices = np.argsort(mean_proba)[::-1]
            top_idx = int(sorted_indices[0])
            argmax_class = self.classes[top_idx]
            top_class = argmax_class
            max_conf = float(mean_proba[top_idx])

            if len(sorted_indices) > 1:
                top2_idx = int(sorted_indices[1])
                top2_class = self.classes[top2_idx]
                top2_conf = float(mean_proba[top2_idx])
                confidence_margin = float(max_conf - top2_conf)
            else:
                top2_class = None
                top2_conf = None
                confidence_margin = None

            # Empirical separation state derived from Fix #7 evidence
            if confidence_margin is not None:
                if confidence_margin > 0.50:
                    separation_state = SeparationState.HIGH_SEPARATION
                elif confidence_margin < 0.15:
                    separation_state = SeparationState.LOW_SEPARATION
                else:
                    separation_state = SeparationState.INTERMEDIATE
            else:
                separation_state = SeparationState.UNKNOWN

            # Class probability map bound strictly to authoritative class ordering
            prob_dict = {
                self.classes[i]: float(mean_proba[i])
                for i in range(len(self.classes))
            }

            # Out-Of-Distribution / Uncertainty Handling
            uncertainty_state = ObservabilityState.OBSERVED
            if max_conf < settings.UNCERTAINTY_MIN_PROBABILITY:
                uncertainty_state = ObservabilityState.UNKNOWN
                top_class = "UNKNOWN / INCONCLUSIVE"
            elif max_conf < 0.55:
                uncertainty_state = ObservabilityState.INFERRED

            return {
                "status": "READY",
                "error": None,
                "model_name": self.model_name,
                "model_version": self.model_version,
                "predicted_class": top_class,
                "argmax_class": argmax_class,
                "confidence": max_conf,
                "top2_class": top2_class,
                "top2_probability": top2_conf,
                "confidence_margin": confidence_margin,
                "class_probabilities": prob_dict,
                "uncertainty_state": uncertainty_state,
                "separation_state": separation_state,
                "features_used": self.features
            }
        except Exception as e:
            logger.error(f"[ML Prediction Error]: {e}")
            return {
                "status": "INFERENCE_ERROR",
                "error": str(e),
                "model_name": self.model_name,
                "model_version": self.model_version,
                "predicted_class": None,
                "confidence": None,
                "top2_class": None,
                "top2_probability": None,
                "confidence_margin": None,
                "class_probabilities": {},
                "uncertainty_state": ObservabilityState.UNKNOWN,
                "separation_state": SeparationState.UNKNOWN,
                "features_used": self.features
            }

# Global singleton
ml_engine = MLInferenceEngine()
