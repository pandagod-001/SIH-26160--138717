import json
from typing import Optional, List, Dict, Any
from sqlalchemy.orm import Session
from app.database.models import (
    DBAnalysis, DBIKEEvent, DBIPsecSession, DBFlowWindow, 
    DBMLPrediction, DBResearchPrediction, DBSecurityFinding, DBEvidenceItem
)

class AnalysisRepository:
    """
    Persistence Repository for IPsecTrace Analysis entities.
    """

    @staticmethod
    def create_analysis(db: Session, analysis_id: str, filename: str, file_path: str) -> DBAnalysis:
        analysis = DBAnalysis(
            id=analysis_id,
            filename=filename,
            file_path=file_path,
            status="PROCESSING"
        )
        db.add(analysis)
        db.commit()
        db.refresh(analysis)
        return analysis

    @staticmethod
    def get_analysis(db: Session, analysis_id: str) -> Optional[DBAnalysis]:
        return db.query(DBAnalysis).filter(DBAnalysis.id == analysis_id).first()

    @staticmethod
    def list_analyses(db: Session, limit: int = 50) -> List[DBAnalysis]:
        return db.query(DBAnalysis).order_by(DBAnalysis.created_at.desc()).limit(limit).all()

    @staticmethod
    def save_complete_analysis_results(
        db: Session,
        analysis_id: str,
        summary: Dict[str, Any],
        ike_events: List[Dict[str, Any]],
        sessions: List[Dict[str, Any]],
        flow_windows: List[Dict[str, Any]],
        ml_prediction: Optional[Dict[str, Any]],
        findings: List[Dict[str, Any]],
        evidence_summary: Dict[str, Any],
        research_prediction: Optional[Dict[str, Any]] = None
    ):
        analysis = db.query(DBAnalysis).filter(DBAnalysis.id == analysis_id).first()
        if not analysis:
            return

        # Update analysis summary
        analysis.status = "COMPLETED"
        analysis.packet_count = summary.get("packet_count", 0)
        analysis.ike_packet_count = summary.get("ike_packet_count", 0)
        analysis.esp_packet_count = summary.get("esp_packet_count", 0)
        analysis.ah_packet_count = summary.get("ah_packet_count", 0)
        analysis.start_time = summary.get("start_time")
        analysis.end_time = summary.get("end_time")
        analysis.duration_sec = summary.get("duration_sec", 0.0)
        analysis.overall_assessment = str(evidence_summary.get("overall_assessment", "UNKNOWN"))
        analysis.confidence = float(evidence_summary.get("confidence", 0.0))

        # Save IKE events
        for ike in ike_events:
            db_ike = DBIKEEvent(
                analysis_id=analysis_id,
                packet_index=ike.get("packet_index", 0),
                timestamp=ike.get("timestamp", 0.0),
                src_ip=ike.get("src_ip", ""),
                dst_ip=ike.get("dst_ip", ""),
                src_port=ike.get("src_port", 0),
                dst_port=ike.get("dst_port", 0),
                ike_version=ike.get("ike_version", ""),
                exchange_type=ike.get("exchange_type", ""),
                exchange_type_code=ike.get("exchange_type_code", 0),
                initiator_spi=ike.get("initiator_spi", ""),
                responder_spi=ike.get("responder_spi", ""),
                message_id=ike.get("message_id", 0),
                flags=ike.get("flags", ""),
                length_bytes=ike.get("length_bytes", 0),
                encryption_transforms=ike.get("encryption_transforms"),
                integrity_transforms=ike.get("integrity_transforms"),
                dh_groups=ike.get("dh_groups"),
                transform_status=ike.get("transform_status", "")
            )
            db.add(db_ike)

        # Save Sessions
        for s in sessions:
            db_sess = DBIPsecSession(
                id=s["session_id"],
                analysis_id=analysis_id,
                src_ip=s["src_ip"],
                dst_ip=s["dst_ip"],
                spi=s["spi"],
                first_seen=s["first_seen"],
                last_seen=s["last_seen"],
                duration_sec=s["duration_sec"],
                packet_count=s["packet_count"],
                byte_count=s["byte_count"],
                direction=s["direction"],
                related_ike_events=s["related_ike_events"],
                confidence=s["confidence"],
                status=s["status"]
            )
            db.add(db_sess)

        # Save Flow Windows
        for w in flow_windows:
            db_win = DBFlowWindow(
                id=w["window_id"],
                analysis_id=analysis_id,
                session_id=w["session_id"],
                start_time=w["start_time"],
                end_time=w["end_time"],
                duration_sec=w["duration_sec"],
                packet_count=w["packet_count"],
                byte_count=w["byte_count"],
                mean_packet_size=w["mean_packet_size"],
                median_packet_size=w["median_packet_size"],
                std_packet_size=w["std_packet_size"],
                min_packet_size=w["min_packet_size"],
                max_packet_size=w["max_packet_size"],
                packets_per_sec=w["packets_per_sec"],
                bytes_per_sec=w["bytes_per_sec"],
                mean_iat_sec=w["mean_iat_sec"],
                std_iat_sec=w["std_iat_sec"],
                fwd_packets=w["fwd_packets"],
                rev_packets=w["rev_packets"],
                fwd_bytes=w["fwd_bytes"],
                rev_bytes=w["rev_bytes"],
                directional_byte_ratio=w["directional_byte_ratio"],
                burst_count=w["burst_count"],
                mean_burst_packets=w["mean_burst_packets"]
            )
            db.add(db_win)

        # Save ML Prediction
        if ml_prediction:
            db_ml = DBMLPrediction(
                analysis_id=analysis_id,
                model_name=ml_prediction.get("model_name"),
                model_version=ml_prediction.get("model_version"),
                predicted_class=ml_prediction.get("predicted_class"),
                confidence=ml_prediction.get("confidence"),
                top2_class=ml_prediction.get("top2_class"),
                top2_probability=ml_prediction.get("top2_probability"),
                confidence_margin=ml_prediction.get("confidence_margin"),
                probabilities_json=json.dumps(ml_prediction.get("class_probabilities", {})) if ml_prediction.get("class_probabilities") else None,
                uncertainty_state=str(ml_prediction.get("uncertainty_state", "UNKNOWN")),
                separation_state=str(ml_prediction.get("separation_state", "UNKNOWN")),
                features_json=json.dumps(ml_prediction.get("features_used", [])) if ml_prediction.get("features_used") else None
            )
            db.add(db_ml)

        # Save Research Prediction
        if research_prediction:
            seq_block = research_prediction.get("sequence", {})
            hyb_block = research_prediction.get("hybrid", {})
            nov_block = research_prediction.get("novelty", {})
            
            db_res = DBResearchPrediction(
                analysis_id=analysis_id,
                status=research_prediction.get("status", "NOT_INITIALIZED"),
                sequence_prediction=research_prediction.get("sequence_prediction") or seq_block.get("prediction"),
                sequence_confidence=research_prediction.get("sequence_confidence") or seq_block.get("confidence"),
                sequence_probabilities_json=json.dumps(research_prediction.get("sequence_probabilities") or seq_block.get("probabilities", {})),
                hybrid_prediction=research_prediction.get("hybrid_prediction") or hyb_block.get("prediction"),
                hybrid_confidence=research_prediction.get("hybrid_confidence") or hyb_block.get("confidence"),
                hybrid_probabilities_json=json.dumps(research_prediction.get("hybrid_probabilities") or hyb_block.get("probabilities", {})),
                sequence_embedding_json=json.dumps(research_prediction.get("sequence_embedding", [])),
                novelty_status=research_prediction.get("novelty_status") or nov_block.get("status", "NOT_AVAILABLE"),
                error=research_prediction.get("error"),
                full_payload_json=json.dumps(research_prediction)
            )
            db.add(db_res)

        # Save Findings
        for f in findings:
            db_f = DBSecurityFinding(
                id=f["finding_id"],
                analysis_id=analysis_id,
                severity=str(f["severity"]),
                category=f["category"],
                title=f["title"],
                description=f["description"],
                evidence=f["evidence"],
                confidence=f["confidence"],
                observability=str(f["observability"]),
                recommendation=f["recommendation"]
            )
            db.add(db_f)

        # Save Evidence Items
        for item in evidence_summary.get("supporting_evidence", []):
            db.add(DBEvidenceItem(
                analysis_id=analysis_id,
                source=item["source"],
                feature=item["feature"],
                value_str=str(item["value"]),
                reliability=item["reliability"],
                state=str(item["state"]),
                timestamp=item.get("timestamp"),
                notes=item.get("notes")
            ))
        for item in evidence_summary.get("contradicting_evidence", []):
            db.add(DBEvidenceItem(
                analysis_id=analysis_id,
                source=item["source"],
                feature=item["feature"],
                value_str=str(item["value"]),
                reliability=item["reliability"],
                state=str(item["state"]),
                timestamp=item.get("timestamp"),
                notes=item.get("notes")
            ))
        for item in evidence_summary.get("unknown_factors", []):
            db.add(DBEvidenceItem(
                analysis_id=analysis_id,
                source=item["source"],
                feature=item["feature"],
                value_str=str(item["value"]),
                reliability=item["reliability"],
                state=str(item["state"]),
                timestamp=item.get("timestamp"),
                notes=item.get("notes")
            ))

        db.commit()
