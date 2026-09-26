import os
import shutil
from fastapi import APIRouter, UploadFile, File, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database.models import SessionLocal
from app.config import settings
from app.services.pipeline_service import AnalysisPipelineService
from app.database.repository import AnalysisRepository

router = APIRouter(tags=["PCAP Ingestion"])

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.post("/pcaps/upload")
def upload_pcap(file: UploadFile = File(...), db: Session = Depends(get_db)):
    if not file.filename.endswith((".pcap", ".pcapng", ".cap")):
        raise HTTPException(status_code=400, detail="Only .pcap, .pcapng, or .cap files are supported.")

    os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
    saved_path = os.path.join(settings.UPLOAD_DIR, file.filename)

    contents = file.file.read()
    with open(saved_path, "wb") as buffer:
        buffer.write(contents)

    try:
        analysis_id = AnalysisPipelineService.execute_pipeline(
            db=db,
            file_path=saved_path,
            original_filename=file.filename
        )
        
        analysis = AnalysisRepository.get_analysis(db, analysis_id)
        return {
            "analysis_id": analysis.id,
            "filename": analysis.filename,
            "packet_count": analysis.packet_count,
            "ike_packet_count": analysis.ike_packet_count,
            "esp_packet_count": analysis.esp_packet_count,
            "ah_packet_count": analysis.ah_packet_count,
            "start_time": analysis.start_time,
            "end_time": analysis.end_time,
            "duration_sec": analysis.duration_sec,
            "status": analysis.status,
            "overall_assessment": analysis.overall_assessment,
            "confidence": analysis.confidence
        }
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Pipeline processing failed: {str(e)}")
