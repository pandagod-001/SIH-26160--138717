import os
import pathlib
from app.database.models import SessionLocal, init_db
from app.services.pipeline_service import AnalysisPipelineService

if __name__ == "__main__":
    init_db()
    db = SessionLocal()
    base_dir = pathlib.Path(__file__).resolve().parent.parent
    pcap_path = str(base_dir / "data" / "raw_native_ipsec" / "pcaps" / "EXP_BULK_ENV_CLEAN_SESS_0001.pcap")
    
    print(f"Testing pipeline with {pcap_path}...")
    try:
        anl_id = AnalysisPipelineService.execute_pipeline(db, pcap_path, "EXP_BULK_ENV_CLEAN_SESS_0001.pcap")
        print("Pipeline succeeded! Analysis ID:", anl_id)
    except Exception as e:
        import traceback
        traceback.print_exc()
