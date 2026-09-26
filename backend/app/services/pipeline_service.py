import os
import uuid
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from app.ingestion.packet_parser import PacketParser
from app.protocols.ike import IKEAnalyzer
from app.protocols.esp import ESPAnalyzer
from app.sessions.sa_reconstructor import SAReconstructor
from app.features.flow_builder import FlowWindowBuilder
from app.ml.inference import ml_engine
from app.ml.research_service import research_engine
from app.security.rules import SecurityRuleEngine
from app.evidence.fusion import EvidenceFusionEngine
from app.database.repository import AnalysisRepository

class AnalysisPipelineService:
    """
    End-to-End Orchestrator:
    PCAP Ingestion -> Protocol Parsing -> SA Reconstruction -> Flow Windows -> ML (Baseline & Research) -> Evidence Fusion -> Security Rules -> Persistence.
    """

    @classmethod
    def execute_pipeline(cls, db: Session, file_path: str, original_filename: str) -> str:
        analysis_id = f"ANL_{uuid.uuid4().hex[:8].upper()}"
        
        # 1. Register Analysis
        AnalysisRepository.create_analysis(db, analysis_id, original_filename, file_path)

        try:
            # 2. Ingest and parse packets
            packets, summary, parse_errors = PacketParser.parse_pcap_file(file_path)

            # 3. Control Plane Extraction (IKE)
            ike_events = IKEAnalyzer.extract_ike_events(packets)

            # 4. Data Plane Extraction (ESP/AH with dynamic IKE / First-Observed direction resolution)
            esp_records = ESPAnalyzer.extract_esp_records(packets, ike_events=ike_events)

            # 5. SA / SPI Session Reconstruction
            sessions = SAReconstructor.reconstruct_sessions(esp_records, ike_events, analysis_id=analysis_id)

            # 6. Flow Window Aggregation (3.0s multi-scale windows)
            flow_windows = FlowWindowBuilder.build_flow_windows(
                esp_records=esp_records,
                window_sec=3.0,
                analysis_id=analysis_id
            )

            # 7. ML Inference (Baseline XGBoost)
            ml_prediction = ml_engine.predict_flow_windows(flow_windows)

            # 7b. Parallel Experimental Multi-View & Protocol-Aware Sequence Inference (Non-Blocking)
            try:
                research_prediction = research_engine.predict_multi_view(
                    flow_windows=flow_windows,
                    esp_records=esp_records,
                    ike_events=ike_events,
                    baseline_prediction=ml_prediction,
                    window_sec=3.0
                )
            except Exception as res_err:
                research_prediction = {
                    "status": "NOT_INITIALIZED",
                    "error": str(res_err),
                    "baseline": ml_prediction or {},
                    "sequence": {"status": "ERROR"},
                    "protocol_aware_sequence": {"status": "ERROR"},
                    "self_supervised": {"status": "ERROR"},
                    "hybrid": {"status": "ERROR"},
                    "multiview": {"status": "ERROR"},
                    "novelty": {"status": "NOT_AVAILABLE"},
                    "evidence": {"protocol": [], "behavioral": [], "explanation": []}
                }

            # 8. Security & Policy Rules (Deterministic Authority)
            findings = SecurityRuleEngine.evaluate_rules(
                ike_events=ike_events,
                esp_records=esp_records,
                sessions=sessions,
                flow_windows=flow_windows
            )

            # 9. Evidence Fusion
            evidence_summary = EvidenceFusionEngine.fuse_evidence(
                ike_events=ike_events,
                esp_records=esp_records,
                sessions=sessions,
                flow_windows=flow_windows,
                ml_prediction=ml_prediction,
                security_findings=findings
            )

            # 10. Persist complete record
            AnalysisRepository.save_complete_analysis_results(
                db=db,
                analysis_id=analysis_id,
                summary=summary,
                ike_events=ike_events,
                sessions=sessions,
                flow_windows=flow_windows,
                ml_prediction=ml_prediction,
                findings=findings,
                evidence_summary=evidence_summary,
                research_prediction=research_prediction
            )

            return analysis_id
        except Exception as e:
            analysis = AnalysisRepository.get_analysis(db, analysis_id)
            if analysis:
                analysis.status = "FAILED"
                analysis.error_message = str(e)
                db.commit()
            raise e
