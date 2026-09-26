from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from enum import Enum

class ObservabilityState(str, Enum):
    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    UNKNOWN = "UNKNOWN"
    NOT_OBSERVABLE = "NOT_OBSERVABLE"
    CONFLICT = "CONFLICT"

class SeparationState(str, Enum):
    HIGH_SEPARATION = "HIGH_SEPARATION"
    INTERMEDIATE = "INTERMEDIATE"
    LOW_SEPARATION = "LOW_SEPARATION"
    UNKNOWN = "UNKNOWN"

class TrafficAssessment(str, Enum):
    NORMAL = "NORMAL"
    SUSPICIOUS = "SUSPICIOUS"
    ANOMALOUS = "ANOMALOUS"
    UNKNOWN = "UNKNOWN"

class SeverityLevel(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

# IKE Models
class IKEEventSchema(BaseModel):
    packet_index: int
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    ike_version: str
    exchange_type: str
    exchange_type_code: int
    initiator_spi: str
    responder_spi: str
    message_id: int
    flags: str
    length_bytes: int
    encryption_transforms: Optional[str] = None
    integrity_transforms: Optional[str] = None
    dh_groups: Optional[str] = None
    transform_status: str

# ESP Models
class ESPPacketSchema(BaseModel):
    packet_index: int
    timestamp: float
    protocol: str
    src_ip: str
    dst_ip: str
    spi: str
    spi_raw: int
    sequence_number: int
    packet_length: int
    payload_length: int
    direction: str
    direction_source: str = "FIRST_OBSERVED"
    direction_confidence: str = "PROVISIONAL"
    payload_visibility: str = "ENCRYPTED"
    content_observability: str = "NOT_OBSERVABLE"

# Session Models
class IPsecSessionSchema(BaseModel):
    session_id: str
    src_ip: str
    dst_ip: str
    spi: str
    first_seen: float
    last_seen: float
    duration_sec: float
    packet_count: int
    byte_count: int
    direction: str
    related_ike_events: int
    confidence: float
    status: str

# Flow Window Models
class FlowWindowSchema(BaseModel):
    window_id: str
    session_id: str
    start_time: float
    end_time: float
    duration_sec: float
    packet_count: int
    byte_count: int
    mean_packet_size: float
    median_packet_size: float
    std_packet_size: float
    min_packet_size: int
    max_packet_size: int
    packets_per_sec: float
    bytes_per_sec: float
    mean_iat_sec: float
    std_iat_sec: float
    fwd_packets: int
    rev_packets: int
    fwd_bytes: int
    rev_bytes: int
    directional_byte_ratio: float
    burst_count: int
    mean_burst_packets: float

# ML Models
class MLPredictionSchema(BaseModel):
    model_name: Optional[str] = None
    model_version: Optional[str] = None
    predicted_class: Optional[str] = None
    confidence: Optional[float] = None
    top2_class: Optional[str] = None
    top2_probability: Optional[float] = None
    confidence_margin: Optional[float] = None
    class_probabilities: Dict[str, float] = {}
    uncertainty_state: ObservabilityState = ObservabilityState.UNKNOWN
    separation_state: SeparationState = SeparationState.UNKNOWN
    features_used: List[str] = []

class ResearchPredictionSchema(BaseModel):
    status: str = "NOT_INITIALIZED"
    baseline: Dict[str, Any] = {}
    sequence: Dict[str, Any] = {}
    protocol_aware_sequence: Dict[str, Any] = {}
    self_supervised: Dict[str, Any] = {}
    hybrid: Dict[str, Any] = {}
    multiview: Dict[str, Any] = {}
    novelty: Dict[str, Any] = {}
    evidence: Dict[str, Any] = {}
    # Legacy fields preserved for backward compatibility
    sequence_prediction: Optional[str] = None
    sequence_confidence: Optional[float] = None
    sequence_probabilities: Dict[str, float] = {}
    hybrid_prediction: Optional[str] = None
    hybrid_confidence: Optional[float] = None
    hybrid_probabilities: Dict[str, float] = {}
    sequence_embedding: List[float] = []
    novelty_status: str = "NOT_AVAILABLE"
    error: Optional[str] = None

# Evidence Models
class EvidenceItemSchema(BaseModel):
    source: str
    feature: str
    value: Any
    reliability: Optional[float] = None
    state: ObservabilityState
    timestamp: Optional[float] = None
    notes: Optional[str] = None

class EvidenceSummarySchema(BaseModel):
    overall_assessment: TrafficAssessment
    confidence: float
    supporting_evidence: List[EvidenceItemSchema]
    contradicting_evidence: List[EvidenceItemSchema]
    unknown_factors: List[EvidenceItemSchema]

# Security Finding Models
class SecurityFindingSchema(BaseModel):
    finding_id: str
    severity: SeverityLevel
    category: str
    title: str
    description: str
    evidence: str
    confidence: float
    observability: ObservabilityState
    recommendation: str

# Upload & Overview Responses
class PCAPUploadResponse(BaseModel):
    analysis_id: str
    filename: str
    packet_count: int
    ike_packet_count: int
    esp_packet_count: int
    ah_packet_count: int
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    duration_sec: float
    unique_sources: List[str]
    unique_destinations: List[str]
    status: str

class AnalysisSummaryResponse(BaseModel):
    analysis_id: str
    filename: str
    created_at: str
    status: str
    overall_assessment: TrafficAssessment
    confidence: float
    packet_summary: Dict[str, int]
    session_count: int
    flow_window_count: int
    finding_count: int
    ml_prediction: Optional[MLPredictionSchema] = None
    research: Optional[ResearchPredictionSchema] = None

class FullAnalysisReportResponse(BaseModel):
    analysis_id: str
    summary: Dict[str, Any]
    traffic_summary: Dict[str, Any]
    sessions: List[IPsecSessionSchema]
    flow_windows: List[FlowWindowSchema]
    ml: Optional[MLPredictionSchema]
    research: Optional[ResearchPredictionSchema] = None
    findings: List[SecurityFindingSchema]
    evidence_fusion: EvidenceSummarySchema
    limitations: List[str]
