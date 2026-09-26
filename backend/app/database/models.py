import datetime
from sqlalchemy import create_engine, Column, String, Integer, Float, Boolean, Text, ForeignKey, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from app.config import settings

Base = declarative_base()
engine = create_engine(settings.DATABASE_URL, connect_args={"check_same_thread": False} if "sqlite" in settings.DATABASE_URL else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

class DBAnalysis(Base):
    __tablename__ = "analyses"

    id = Column(String, primary_key=True, index=True)
    filename = Column(String, nullable=False)
    file_path = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    status = Column(String, default="PENDING")
    error_message = Column(Text, nullable=True)
    
    # Summary metrics
    packet_count = Column(Integer, default=0)
    ike_packet_count = Column(Integer, default=0)
    esp_packet_count = Column(Integer, default=0)
    ah_packet_count = Column(Integer, default=0)
    start_time = Column(Float, nullable=True)
    end_time = Column(Float, nullable=True)
    duration_sec = Column(Float, default=0.0)
    
    overall_assessment = Column(String, default="UNKNOWN")
    confidence = Column(Float, default=0.0)
    
    # Relationships
    ike_events = relationship("DBIKEEvent", back_populates="analysis", cascade="all, delete-orphan")
    sessions = relationship("DBIPsecSession", back_populates="analysis", cascade="all, delete-orphan")
    flow_windows = relationship("DBFlowWindow", back_populates="analysis", cascade="all, delete-orphan")
    findings = relationship("DBSecurityFinding", back_populates="analysis", cascade="all, delete-orphan")
    evidence = relationship("DBEvidenceItem", back_populates="analysis", cascade="all, delete-orphan")
    predictions = relationship("DBMLPrediction", back_populates="analysis", cascade="all, delete-orphan")
    research_predictions = relationship("DBResearchPrediction", back_populates="analysis", cascade="all, delete-orphan")

class DBIKEEvent(Base):
    __tablename__ = "ike_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    analysis_id = Column(String, ForeignKey("analyses.id"), index=True)
    packet_index = Column(Integer)
    timestamp = Column(Float)
    src_ip = Column(String)
    dst_ip = Column(String)
    src_port = Column(Integer)
    dst_port = Column(Integer)
    ike_version = Column(String)
    exchange_type = Column(String)
    exchange_type_code = Column(Integer)
    initiator_spi = Column(String)
    responder_spi = Column(String)
    message_id = Column(Integer)
    flags = Column(String)
    length_bytes = Column(Integer)
    encryption_transforms = Column(Text, nullable=True)
    integrity_transforms = Column(Text, nullable=True)
    dh_groups = Column(Text, nullable=True)
    transform_status = Column(String)

    analysis = relationship("DBAnalysis", back_populates="ike_events")

class DBIPsecSession(Base):
    __tablename__ = "ipsec_sessions"

    id = Column(String, primary_key=True)
    analysis_id = Column(String, ForeignKey("analyses.id"), index=True)
    src_ip = Column(String)
    dst_ip = Column(String)
    spi = Column(String, index=True)
    first_seen = Column(Float)
    last_seen = Column(Float)
    duration_sec = Column(Float)
    packet_count = Column(Integer)
    byte_count = Column(Integer)
    direction = Column(String)
    related_ike_events = Column(Integer, default=0)
    confidence = Column(Float, default=1.0)
    status = Column(String, default="ACTIVE")

    analysis = relationship("DBAnalysis", back_populates="sessions")

class DBFlowWindow(Base):
    __tablename__ = "flow_windows"

    id = Column(String, primary_key=True)
    analysis_id = Column(String, ForeignKey("analyses.id"), index=True)
    session_id = Column(String, index=True)
    start_time = Column(Float)
    end_time = Column(Float)
    duration_sec = Column(Float)
    packet_count = Column(Integer)
    byte_count = Column(Integer)
    mean_packet_size = Column(Float)
    median_packet_size = Column(Float)
    std_packet_size = Column(Float)
    min_packet_size = Column(Integer)
    max_packet_size = Column(Integer)
    packets_per_sec = Column(Float)
    bytes_per_sec = Column(Float)
    mean_iat_sec = Column(Float)
    std_iat_sec = Column(Float)
    fwd_packets = Column(Integer)
    rev_packets = Column(Integer)
    fwd_bytes = Column(Integer)
    rev_bytes = Column(Integer)
    directional_byte_ratio = Column(Float)
    burst_count = Column(Integer)
    mean_burst_packets = Column(Float)

    analysis = relationship("DBAnalysis", back_populates="flow_windows")

class DBMLPrediction(Base):
    __tablename__ = "ml_predictions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    analysis_id = Column(String, ForeignKey("analyses.id"), index=True)
    model_name = Column(String)
    model_version = Column(String)
    predicted_class = Column(String)
    confidence = Column(Float)
    top2_class = Column(String, nullable=True)
    top2_probability = Column(Float, nullable=True)
    confidence_margin = Column(Float, nullable=True)
    probabilities_json = Column(Text)
    uncertainty_state = Column(String)
    separation_state = Column(String, nullable=True)
    features_json = Column(Text)

    analysis = relationship("DBAnalysis", back_populates="predictions")

class DBResearchPrediction(Base):
    __tablename__ = "research_predictions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    analysis_id = Column(String, ForeignKey("analyses.id"), index=True)
    status = Column(String, default="NOT_INITIALIZED")
    sequence_prediction = Column(String, nullable=True)
    sequence_confidence = Column(Float, nullable=True)
    sequence_probabilities_json = Column(Text, nullable=True)
    hybrid_prediction = Column(String, nullable=True)
    hybrid_confidence = Column(Float, nullable=True)
    hybrid_probabilities_json = Column(Text, nullable=True)
    sequence_embedding_json = Column(Text, nullable=True)
    novelty_status = Column(String, default="NOT_AVAILABLE")
    error = Column(Text, nullable=True)
    full_payload_json = Column(Text, nullable=True)

    analysis = relationship("DBAnalysis", back_populates="research_predictions")

class DBSecurityFinding(Base):
    __tablename__ = "security_findings"

    id = Column(String, primary_key=True)
    analysis_id = Column(String, ForeignKey("analyses.id"), index=True)
    severity = Column(String)
    category = Column(String)
    title = Column(String)
    description = Column(Text)
    evidence = Column(Text)
    confidence = Column(Float)
    observability = Column(String)
    recommendation = Column(Text)

    analysis = relationship("DBAnalysis", back_populates="findings")

class DBEvidenceItem(Base):
    __tablename__ = "evidence_items"

    id = Column(Integer, primary_key=True, autoincrement=True)
    analysis_id = Column(String, ForeignKey("analyses.id"), index=True)
    source = Column(String)
    feature = Column(String)
    value_str = Column(String)
    reliability = Column(Float, nullable=True)
    state = Column(String)
    timestamp = Column(Float, nullable=True)
    notes = Column(Text, nullable=True)

    analysis = relationship("DBAnalysis", back_populates="evidence")

def init_db():
    Base.metadata.create_all(bind=engine)
