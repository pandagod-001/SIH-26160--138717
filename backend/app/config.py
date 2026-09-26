import os
from pydantic import BaseModel

class Settings(BaseModel):
    APP_NAME: str = "IPsecTrace Defensive Traffic Analysis Engine"
    API_V1_PREFIX: str = "/api/v1"
    DEBUG: bool = False
    
    # Storage & Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./ipsectrace.db")
    UPLOAD_DIR: str = os.getenv("UPLOAD_DIR", "./uploads")
    MODEL_PATH: str = os.getenv("MODEL_PATH", "./models/xgb_native_ipsec.json")
    
    # Analysis Parameters
    DEFAULT_WINDOW_SEC: float = float(os.getenv("FLOW_WINDOW_SEC", "3.0"))
    IAT_BURST_THRESHOLD_SEC: float = 0.1
    
    # Uncertainty Thresholds
    UNCERTAINTY_MIN_PROBABILITY: float = 0.40
    UNCERTAINTY_MIN_PACKETS: int = 3

settings = Settings()

os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
os.makedirs(os.path.dirname(settings.MODEL_PATH) or ".", exist_ok=True)
