import json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database.models import SessionLocal, DBAnalysis
from app.database.repository import AnalysisRepository

router = APIRouter(tags=["Analysis Query"])

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.get("/analyses/{analysis_id}")
def get_analysis_summary(analysis_id: str, db: Session = Depends(get_db)):
    analysis = AnalysisRepository.get_analysis(db, analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis ID not found.")
    
    return {
        "analysis_id": analysis.id,
        "filename": analysis.filename,
        "status": analysis.status,
        "created_at": analysis.created_at.isoformat() if analysis.created_at else None,
        "overall_assessment": analysis.overall_assessment,
        "confidence": analysis.confidence,
        "traffic_summary": {
            "total_packets": analysis.packet_count,
            "ike_packets": analysis.ike_packet_count,
            "esp_packets": analysis.esp_packet_count,
            "ah_packets": analysis.ah_packet_count,
            "duration_sec": analysis.duration_sec
        },
        "session_count": len(analysis.sessions),
        "flow_window_count": len(analysis.flow_windows),
        "findings_count": len(analysis.findings)
    }

@router.get("/analyses/{analysis_id}/ike")
def get_analysis_ike(analysis_id: str, db: Session = Depends(get_db)):
    analysis = AnalysisRepository.get_analysis(db, analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis ID not found.")
    
    return [
        {
            "packet_index": e.packet_index,
            "timestamp": e.timestamp,
            "src_ip": e.src_ip,
            "dst_ip": e.dst_ip,
            "src_port": e.src_port,
            "dst_port": e.dst_port,
            "ike_version": e.ike_version,
            "exchange_type": e.exchange_type,
            "exchange_type_code": e.exchange_type_code,
            "initiator_spi": e.initiator_spi,
            "responder_spi": e.responder_spi,
            "message_id": e.message_id,
            "flags": e.flags,
            "length_bytes": e.length_bytes,
            "encryption_transforms": e.encryption_transforms,
            "integrity_transforms": e.integrity_transforms,
            "dh_groups": e.dh_groups,
            "transform_status": e.transform_status
        }
        for e in analysis.ike_events
    ]

@router.get("/analyses/{analysis_id}/sessions")
def get_analysis_sessions(analysis_id: str, db: Session = Depends(get_db)):
    analysis = AnalysisRepository.get_analysis(db, analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis ID not found.")
    
    return [
        {
            "session_id": s.id,
            "src_ip": s.src_ip,
            "dst_ip": s.dst_ip,
            "spi": s.spi,
            "first_seen": s.first_seen,
            "last_seen": s.last_seen,
            "duration_sec": s.duration_sec,
            "packet_count": s.packet_count,
            "byte_count": s.byte_count,
            "direction": s.direction,
            "related_ike_events": s.related_ike_events,
            "confidence": s.confidence,
            "status": s.status
        }
        for s in analysis.sessions
    ]

@router.get("/analyses/{analysis_id}/flows")
def get_analysis_flows(analysis_id: str, db: Session = Depends(get_db)):
    analysis = AnalysisRepository.get_analysis(db, analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis ID not found.")
    
    return [
        {
            "window_id": w.id,
            "session_id": w.session_id,
            "start_time": w.start_time,
            "end_time": w.end_time,
            "duration_sec": w.duration_sec,
            "packet_count": w.packet_count,
            "byte_count": w.byte_count,
            "mean_packet_size": w.mean_packet_size,
            "packets_per_sec": w.packets_per_sec,
            "bytes_per_sec": w.bytes_per_sec,
            "mean_iat_sec": w.mean_iat_sec,
            "directional_byte_ratio": w.directional_byte_ratio,
            "burst_count": w.burst_count
        }
        for w in analysis.flow_windows
    ]

@router.get("/analyses/{analysis_id}/features")
def get_analysis_features(analysis_id: str, db: Session = Depends(get_db)):
    analysis = AnalysisRepository.get_analysis(db, analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis ID not found.")
    
    features = []
    for w in analysis.flow_windows:
        features.append({
            "window_id": w.id,
            "flow_duration_sec": w.duration_sec,
            "packets_per_sec": w.packets_per_sec,
            "bytes_per_sec": w.bytes_per_sec,
            "mean_iat_sec": w.mean_iat_sec,
            "std_iat_sec": w.std_iat_sec,
            "mean_packet_size_bytes": w.mean_packet_size,
            "std_packet_size_bytes": w.std_packet_size,
            "min_packet_size_bytes": w.min_packet_size,
            "max_packet_size_bytes": w.max_packet_size,
            "directional_byte_ratio": w.directional_byte_ratio,
            "burst_count": w.burst_count
        })
    return features

@router.get("/analyses/{analysis_id}/prediction")
def get_analysis_prediction(analysis_id: str, db: Session = Depends(get_db)):
    analysis = AnalysisRepository.get_analysis(db, analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis ID not found.")
    
    pred = analysis.predictions[0] if analysis.predictions else None
    res = analysis.research_predictions[0] if analysis.research_predictions else None
    
    baseline_dict = {
        "model_name": pred.model_name,
        "model_version": pred.model_version,
        "predicted_class": pred.predicted_class,
        "confidence": pred.confidence,
        "top2_class": pred.top2_class,
        "top2_probability": pred.top2_probability,
        "confidence_margin": pred.confidence_margin,
        "class_probabilities": json.loads(pred.probabilities_json) if pred.probabilities_json else {},
        "uncertainty_state": pred.uncertainty_state,
        "separation_state": pred.separation_state,
        "features_used": json.loads(pred.features_json) if pred.features_json else []
    } if pred else {"status": "NO_PREDICTION_AVAILABLE"}

    research_dict = {
        "status": res.status,
        "sequence_prediction": res.sequence_prediction,
        "sequence_confidence": res.sequence_confidence,
        "sequence_probabilities": json.loads(res.sequence_probabilities_json) if res.sequence_probabilities_json else {},
        "hybrid_prediction": res.hybrid_prediction,
        "hybrid_confidence": res.hybrid_confidence,
        "hybrid_probabilities": json.loads(res.hybrid_probabilities_json) if res.hybrid_probabilities_json else {},
        "sequence_embedding": json.loads(res.sequence_embedding_json) if res.sequence_embedding_json else [],
        "novelty_status": res.novelty_status,
        "error": res.error
    } if res else {
        "status": "NOT_INITIALIZED",
        "sequence_prediction": None,
        "sequence_confidence": None,
        "sequence_probabilities": {},
        "hybrid_prediction": None,
        "hybrid_confidence": None,
        "hybrid_probabilities": {},
        "sequence_embedding": [],
        "novelty_status": "NOT_AVAILABLE",
        "error": None
    }

    # Backward-compatible format + unified baseline/research objects
    return {
        "baseline": baseline_dict,
        "research": research_dict,
        # Preserve legacy top-level keys for 100% backward compatibility
        "model_name": pred.model_name if pred else None,
        "model_version": pred.model_version if pred else None,
        "predicted_class": pred.predicted_class if pred else None,
        "confidence": pred.confidence if pred else None,
        "top2_class": pred.top2_class if pred else None,
        "top2_probability": pred.top2_probability if pred else None,
        "confidence_margin": pred.confidence_margin if pred else None,
        "class_probabilities": json.loads(pred.probabilities_json) if pred and pred.probabilities_json else {},
        "uncertainty_state": pred.uncertainty_state if pred else "UNKNOWN",
        "separation_state": pred.separation_state if pred else "UNKNOWN",
        "features_used": json.loads(pred.features_json) if pred and pred.features_json else []
    }

@router.get("/analyses/{analysis_id}/research")
def get_analysis_research(analysis_id: str, db: Session = Depends(get_db)):
    analysis = AnalysisRepository.get_analysis(db, analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis ID not found.")
    
    res = analysis.research_predictions[0] if analysis.research_predictions else None
    if res and res.full_payload_json:
        try:
            payload = json.loads(res.full_payload_json)
            # Ensure top-level legacy keys exist for backward-compatibility
            payload.setdefault("sequence_embedding", json.loads(res.sequence_embedding_json) if res.sequence_embedding_json else [])
            payload.setdefault("sequence_prediction", res.sequence_prediction)
            payload.setdefault("sequence_confidence", res.sequence_confidence)
            payload.setdefault("hybrid_prediction", res.hybrid_prediction)
            payload.setdefault("hybrid_confidence", res.hybrid_confidence)
            payload.setdefault("novelty_status", res.novelty_status)
            return payload
        except Exception:
            pass

    if not res:
        return {
            "status": "NOT_INITIALIZED",
            "sequence_prediction": None,
            "sequence_confidence": None,
            "hybrid_prediction": None,
            "hybrid_confidence": None,
            "sequence_embedding": [],
            "novelty_status": "NOT_AVAILABLE",
            "baseline": {},
            "sequence": {},
            "protocol_aware_sequence": {},
            "self_supervised": {},
            "hybrid": {},
            "multiview": {},
            "novelty": {"status": "NOT_AVAILABLE"},
            "evidence": {"protocol": [], "behavioral": [], "explanation": []},
            "error": "No research prediction found for this analysis."
        }

    return {
        "status": res.status,
        "sequence_prediction": res.sequence_prediction,
        "sequence_confidence": res.sequence_confidence,
        "sequence_probabilities": json.loads(res.sequence_probabilities_json) if res.sequence_probabilities_json else {},
        "hybrid_prediction": res.hybrid_prediction,
        "hybrid_confidence": res.hybrid_confidence,
        "hybrid_probabilities": json.loads(res.hybrid_probabilities_json) if res.hybrid_probabilities_json else {},
        "sequence_embedding": json.loads(res.sequence_embedding_json) if res.sequence_embedding_json else [],
        "novelty_status": res.novelty_status,
        "error": res.error
    }

@router.get("/analyses/{analysis_id}/findings")
def get_analysis_findings(analysis_id: str, db: Session = Depends(get_db)):
    analysis = AnalysisRepository.get_analysis(db, analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis ID not found.")
    
    return [
        {
            "finding_id": f.id,
            "severity": f.severity,
            "category": f.category,
            "title": f.title,
            "description": f.description,
            "evidence": f.evidence,
            "confidence": f.confidence,
            "observability": f.observability,
            "recommendation": f.recommendation
        }
        for f in analysis.findings
    ]

@router.get("/analyses/{analysis_id}/evidence")
def get_analysis_evidence(analysis_id: str, db: Session = Depends(get_db)):
    analysis = AnalysisRepository.get_analysis(db, analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis ID not found.")
    
    return [
        {
            "source": e.source,
            "feature": e.feature,
            "value": e.value_str,
            "reliability": e.reliability,
            "state": e.state,
            "timestamp": e.timestamp,
            "notes": e.notes
        }
        for e in analysis.evidence
    ]

@router.get("/analyses/{analysis_id}/report")
def get_analysis_report(analysis_id: str, db: Session = Depends(get_db)):
    analysis = AnalysisRepository.get_analysis(db, analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis ID not found.")
    
    pred = analysis.predictions[0] if analysis.predictions else None
    res = analysis.research_predictions[0] if analysis.research_predictions else None

    pred_data = {
        "model_name": pred.model_name,
        "model_version": pred.model_version,
        "predicted_class": pred.predicted_class,
        "confidence": pred.confidence,
        "top2_class": pred.top2_class,
        "top2_probability": pred.top2_probability,
        "confidence_margin": pred.confidence_margin,
        "class_probabilities": json.loads(pred.probabilities_json) if pred.probabilities_json else {},
        "uncertainty_state": pred.uncertainty_state,
        "separation_state": pred.separation_state
    } if pred else None

    research_data = {
        "status": res.status,
        "sequence_prediction": res.sequence_prediction,
        "sequence_confidence": res.sequence_confidence,
        "sequence_probabilities": json.loads(res.sequence_probabilities_json) if res.sequence_probabilities_json else {},
        "hybrid_prediction": res.hybrid_prediction,
        "hybrid_confidence": res.hybrid_confidence,
        "hybrid_probabilities": json.loads(res.hybrid_probabilities_json) if res.hybrid_probabilities_json else {},
        "sequence_embedding": json.loads(res.sequence_embedding_json) if res.sequence_embedding_json else [],
        "novelty_status": res.novelty_status,
        "error": res.error
    } if res else {
        "status": "NOT_INITIALIZED",
        "sequence_prediction": None,
        "sequence_confidence": None,
        "sequence_probabilities": {},
        "hybrid_prediction": None,
        "hybrid_confidence": None,
        "hybrid_probabilities": {},
        "sequence_embedding": [],
        "novelty_status": "NOT_AVAILABLE",
        "error": None
    }

    return {
        "analysis_id": analysis.id,
        "summary": {
            "status": analysis.status,
            "overall_assessment": analysis.overall_assessment,
            "confidence": analysis.confidence,
            "filename": analysis.filename,
            "created_at": analysis.created_at.isoformat() if analysis.created_at else None
        },
        "traffic": {
            "packets": analysis.packet_count,
            "ike_packets": analysis.ike_packet_count,
            "esp_packets": analysis.esp_packet_count,
            "ah_packets": analysis.ah_packet_count,
            "duration_sec": analysis.duration_sec
        },
        "sessions": [
            {
                "session_id": s.id,
                "src_ip": s.src_ip,
                "dst_ip": s.dst_ip,
                "spi": s.spi,
                "duration_sec": s.duration_sec,
                "packet_count": s.packet_count,
                "byte_count": s.byte_count,
                "direction": s.direction
            }
            for s in analysis.sessions
        ],
        "ml": pred_data,
        "research": research_data,
        "findings": [
            {
                "finding_id": f.id,
                "severity": f.severity,
                "category": f.category,
                "title": f.title,
                "description": f.description,
                "evidence": f.evidence,
                "confidence": f.confidence,
                "observability": f.observability,
                "recommendation": f.recommendation
            }
            for f in analysis.findings
        ],
        "evidence": [
            {
                "source": e.source,
                "feature": e.feature,
                "value": e.value_str,
                "reliability": e.reliability,
                "state": e.state,
                "notes": e.notes
            }
            for e in analysis.evidence
        ],
        "limitations": [
            "Encrypted payload contents are strictly NOT_OBSERVABLE without private cryptographic keys.",
            "Receiver kernel SADB replay window bitmask is internal host state and not directly observable on passive wire."
        ]
    }
