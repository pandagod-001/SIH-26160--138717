import os
import json
import pathlib
import pytest
from scapy.all import Ether, IP, UDP, Raw
from fastapi.testclient import TestClient
from app.main import app
from app.ingestion.packet_parser import PacketParser
from app.protocols.ike import IKEAnalyzer
from app.protocols.esp import ESPAnalyzer
from app.sessions.sa_reconstructor import SAReconstructor
from app.features.flow_builder import FlowWindowBuilder
from app.ml.inference import ml_engine, MLInferenceEngine
from app.security.rules import SecurityRuleEngine
from app.evidence.fusion import EvidenceFusionEngine
from app.database.models import init_db

init_db()

client = TestClient(app)

BASE_DIR = pathlib.Path(__file__).resolve().parent.parent.parent
TEST_PCAP = str(BASE_DIR / "data" / "raw_native_ipsec" / "pcaps" / "EXP_BULK_ENV_CLEAN_SESS_0001.pcap")

def test_health_endpoint():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["cryptographic_observability"] == "HEADER_ONLY_NO_DECRYPTION"

def test_real_model_loading_and_authoritative_metadata():
    engine = MLInferenceEngine(model_path="models/xgb_native_ipsec.json")
    assert engine.status == "READY"
    assert engine.model is not None
    assert engine.error_message is None
    import xgboost as xgb
    assert isinstance(engine.model, xgb.XGBClassifier)
    assert engine.classes == ["BULK", "ICMP", "INTERACTIVE", "WEB"]
    assert len(engine.classes) == engine.num_classes == 4
    assert len(engine.features) == 14

def test_missing_model_causes_not_initialized_and_no_prediction():
    engine = MLInferenceEngine(model_path="models/non_existent_model_file.json")
    assert engine.status == "NOT_INITIALIZED"
    assert engine.model is None
    assert "not found" in engine.error_message.lower()

    dummy_windows = [{"flow_duration_sec": 3.0, "packets_per_sec": 10.0}]
    pred = engine.predict_flow_windows(dummy_windows)
    
    assert pred is not None
    assert pred["status"] == "NOT_INITIALIZED"
    assert pred["predicted_class"] is None
    assert pred["confidence"] is None
    assert pred["top2_class"] is None
    assert pred["top2_probability"] is None
    assert pred["confidence_margin"] is None
    assert pred["class_probabilities"] == {}
    assert pred["uncertainty_state"] == "UNKNOWN"
    assert pred["error"] is not None

def test_training_inference_round_trip_and_class_ordering(tmp_path):
    engine = MLInferenceEngine(model_path="models/xgb_native_ipsec.json")
    assert engine.status == "READY"

    dummy_window = {feat: 10.0 for feat in engine.features}
    res = engine.predict_flow_windows([dummy_window])

    assert res["status"] == "READY"
    probs = res["class_probabilities"]
    assert len(probs) == len(engine.classes) == 4
    for c in engine.classes:
        assert c in probs
        assert 0.0 <= probs[c] <= 1.0

    assert abs(sum(probs.values()) - 1.0) < 1e-4
    top_c = max(probs, key=probs.get)
    assert res["argmax_class"] == top_c
    assert res["confidence"] == probs[top_c]

def test_negative_class_count_mismatch_fails_initialization(tmp_path):
    bad_meta = {
        "model_name": "Test Model",
        "model_version": "v1.0",
        "classes": ["BULK", "ICMP", "INTERACTIVE"],
        "features": ["feat1", "feat2"]
    }
    meta_file = tmp_path / "model_metadata.json"
    with open(meta_file, "w") as f:
        json.dump(bad_meta, f)

    model_copy = tmp_path / "xgb_native_ipsec.json"
    import shutil
    shutil.copy("models/xgb_native_ipsec.json", model_copy)

    engine = MLInferenceEngine(model_path=str(model_copy))
    assert engine.status == "NOT_INITIALIZED"
    assert engine.model is None
    assert "class count mismatch" in engine.error_message.lower()

# ==============================================================================
# FIX #3 DYNAMIC DIRECTION RESOLUTION TESTS (TESTS 1 - 7)
# ==============================================================================

def test_direction_test1_10_dot_subnet_not_hardcoded_forward():
    """TEST 1: 10.0.0.1 -> 10.0.0.2 does NOT automatically imply FORWARD because of IP prefix."""
    # When 10.0.0.2 sends the FIRST packet, it must be FORWARD (FIRST_OBSERVED) and 10.0.0.1 must be REVERSE
    raw_esp_1 = bytes.fromhex("0000000100000001") + b"A"*32 # SPI=0x1, Seq=1
    raw_esp_2 = bytes.fromhex("0000000200000001") + b"B"*32 # SPI=0x2, Seq=1

    pkt1 = Ether()/IP(src="10.0.0.2", dst="10.0.0.1", proto=50)/Raw(load=raw_esp_1)
    pkt1.time = 1000.0
    pkt2 = Ether()/IP(src="10.0.0.1", dst="10.0.0.2", proto=50)/Raw(load=raw_esp_2)
    pkt2.time = 1001.0

    records = ESPAnalyzer.extract_esp_records([pkt1, pkt2], ike_events=None)
    assert len(records) == 2
    assert records[0]["direction"] == "forward"
    assert records[0]["direction_source"] == "FIRST_OBSERVED"
    assert records[0]["src_ip"] == "10.0.0.2"

    assert records[1]["direction"] == "reverse"
    assert records[1]["direction_source"] == "FIRST_OBSERVED"
    assert records[1]["src_ip"] == "10.0.0.1"

def test_direction_test2_172_16_subnet_dynamic_resolution():
    """TEST 2: 172.16.0.1 -> 172.16.0.2 direction works dynamically."""
    raw_esp = bytes.fromhex("000000AA00000001") + b"X"*32
    pkt1 = Ether()/IP(src="172.16.0.5", dst="172.16.0.10", proto=50)/Raw(load=raw_esp)
    pkt1.time = 2000.0

    records = ESPAnalyzer.extract_esp_records([pkt1], ike_events=None)
    assert records[0]["direction"] == "forward"
    assert records[0]["direction_source"] == "FIRST_OBSERVED"

def test_direction_test3_public_ip_dynamic_resolution():
    """TEST 3: Public IP -> Public IP direction works without private-IP assumptions."""
    raw_esp_fwd = bytes.fromhex("000000FF00000001") + b"P"*32
    raw_esp_rev = bytes.fromhex("000000FE00000001") + b"Q"*32

    pkt1 = Ether()/IP(src="198.51.100.4", dst="203.0.113.8", proto=50)/Raw(load=raw_esp_fwd)
    pkt1.time = 3000.0
    pkt2 = Ether()/IP(src="203.0.113.8", dst="198.51.100.4", proto=50)/Raw(load=raw_esp_rev)
    pkt2.time = 3001.0

    records = ESPAnalyzer.extract_esp_records([pkt1, pkt2], ike_events=None)
    assert records[0]["direction"] == "forward"
    assert records[0]["src_ip"] == "198.51.100.4"
    assert records[1]["direction"] == "reverse"
    assert records[1]["src_ip"] == "203.0.113.8"

def test_direction_test4_ike_present_initiator_evidence():
    """TEST 4: IKE-present capture derives direction from RFC 7296 Initiator/Responder flags."""
    # Dummy IKE event establishing 192.0.2.100 as the original IKE Initiator
    mock_ike_events = [{
        "src_ip": "192.0.2.100",
        "dst_ip": "192.0.2.200",
        "initiator_ip": "192.0.2.100",
        "responder_ip": "192.0.2.200",
        "is_initiator": True
    }]

    raw_esp_init = bytes.fromhex("0000010000000001") + b"I"*32
    raw_esp_resp = bytes.fromhex("0000020000000001") + b"R"*32

    # Even if Responder packet arrives first on wire, IKE evidence binds Initiator to FORWARD
    pkt_resp_first = Ether()/IP(src="192.0.2.200", dst="192.0.2.100", proto=50)/Raw(load=raw_esp_resp)
    pkt_resp_first.time = 4000.0
    pkt_init_second = Ether()/IP(src="192.0.2.100", dst="192.0.2.200", proto=50)/Raw(load=raw_esp_init)
    pkt_init_second.time = 4001.0

    records = ESPAnalyzer.extract_esp_records([pkt_resp_first, pkt_init_second], ike_events=mock_ike_events)
    assert records[0]["direction"] == "reverse"
    assert records[0]["direction_source"] == "IKE_INITIATOR"
    assert records[0]["direction_confidence"] == "HIGH"

    assert records[1]["direction"] == "forward"
    assert records[1]["direction_source"] == "IKE_INITIATOR"
    assert records[1]["direction_confidence"] == "HIGH"

def test_direction_test5_esp_only_pcap_first_observed():
    """TEST 5: ESP-only capture uses FIRST_OBSERVED and marks direction_source explicitly."""
    raw_esp = bytes.fromhex("0000030000000001") + b"E"*32
    pkt = Ether()/IP(src="11.22.33.44", dst="55.66.77.88", proto=50)/Raw(load=raw_esp)
    pkt.time = 5000.0

    records = ESPAnalyzer.extract_esp_records([pkt], ike_events=[])
    assert records[0]["direction"] == "forward"
    assert records[0]["direction_source"] == "FIRST_OBSERVED"
    assert records[0]["direction_confidence"] == "PROVISIONAL"

def test_direction_test6_bidirectional_flow_ratio_impact():
    """TEST 6 & Requirement 5: Verify directional_byte_ratio is computed dynamically from resolved directions."""
    raw_esp_fwd = bytes.fromhex("0000000100000001") + b"A"*60 # 68 bytes total
    raw_esp_rev = bytes.fromhex("0000000200000001") + b"B"*140 # 148 bytes total

    pkt_fwd = Ether()/IP(src="1.1.1.1", dst="2.2.2.2", proto=50)/Raw(load=raw_esp_fwd)
    pkt_fwd.time = 6000.0
    pkt_rev = Ether()/IP(src="2.2.2.2", dst="1.1.1.1", proto=50)/Raw(load=raw_esp_rev)
    pkt_rev.time = 6001.0

    records = ESPAnalyzer.extract_esp_records([pkt_fwd, pkt_rev], ike_events=None)
    windows = FlowWindowBuilder.build_flow_windows(records, window_sec=3.0)
    
    assert len(windows) == 1
    w = windows[0]
    assert w["fwd_packets"] == 1
    assert w["rev_packets"] == 1
    assert w["fwd_bytes"] == len(pkt_fwd)
    assert w["rev_bytes"] == len(pkt_rev)
    expected_ratio = float(len(pkt_fwd) / (len(pkt_fwd) + len(pkt_rev)))
    assert abs(w["directional_byte_ratio"] - expected_ratio) < 1e-4

def test_direction_test7_multiple_sessions_independent_direction_state():
    """TEST 7: Multiple sessions maintain independent dynamic direction states without cross-contamination."""
    # Session 1: 1.1.1.1 -> 1.1.1.2
    pkt_s1 = Ether()/IP(src="1.1.1.1", dst="1.1.1.2", proto=50)/Raw(load=bytes.fromhex("0000000100000001")+b"S1")
    pkt_s1.time = 7000.0
    # Session 2: 9.9.9.9 -> 8.8.8.8
    pkt_s2 = Ether()/IP(src="9.9.9.9", dst="8.8.8.8", proto=50)/Raw(load=bytes.fromhex("0000000200000001")+b"S2")
    pkt_s2.time = 7000.5

    records = ESPAnalyzer.extract_esp_records([pkt_s1, pkt_s2], ike_events=None)
    assert len(records) == 2
    assert records[0]["src_ip"] == "1.1.1.1" and records[0]["direction"] == "forward"
    assert records[1]["src_ip"] == "9.9.9.9" and records[1]["direction"] == "forward"

# ==============================================================================
# INTEGRATION TESTS
# ==============================================================================

def test_packet_parsing_and_extraction():
    if not os.path.exists(TEST_PCAP):
        pytest.skip("Test PCAP not found in data/raw_native_ipsec/pcaps/")

    packets, summary, errors = PacketParser.parse_pcap_file(TEST_PCAP)
    assert len(packets) > 0
    assert summary["packet_count"] > 0
    assert summary["esp_packet_count"] > 0

    esp_records = ESPAnalyzer.extract_esp_records(packets)
    assert len(esp_records) == summary["esp_packet_count"]
    assert esp_records[0]["protocol"] == "ESP"
    assert esp_records[0]["payload_visibility"] == "ENCRYPTED"
    assert esp_records[0]["content_observability"] == "NOT_OBSERVABLE"
    assert esp_records[0]["direction_source"] in ["IKE_INITIATOR", "FIRST_OBSERVED"]

def test_session_and_flow_reconstruction():
    if not os.path.exists(TEST_PCAP):
        pytest.skip("Test PCAP not found in data/raw_native_ipsec/pcaps/")

    packets, _, _ = PacketParser.parse_pcap_file(TEST_PCAP)
    esp_records = ESPAnalyzer.extract_esp_records(packets)
    ike_events = IKEAnalyzer.extract_ike_events(packets)

    sessions = SAReconstructor.reconstruct_sessions(esp_records, ike_events)
    assert len(sessions) > 0
    assert "spi" in sessions[0]

    windows = FlowWindowBuilder.build_flow_windows(esp_records, window_sec=3.0)
    assert len(windows) > 0
    assert "mean_packet_size" in windows[0]
    assert "packets_per_sec" in windows[0]

def test_ml_inference_and_uncertainty():
    if not os.path.exists(TEST_PCAP):
        pytest.skip("Test PCAP not found in data/raw_native_ipsec/pcaps/")

    packets, _, _ = PacketParser.parse_pcap_file(TEST_PCAP)
    esp_records = ESPAnalyzer.extract_esp_records(packets)
    windows = FlowWindowBuilder.build_flow_windows(esp_records, window_sec=3.0)

    pred = ml_engine.predict_flow_windows(windows)
    assert pred is not None
    assert pred["status"] == "READY"
    assert pred["predicted_class"] in ml_engine.classes
    assert pred["confidence"] is not None
    assert 0.0 <= pred["confidence"] <= 1.0
    assert len(pred["class_probabilities"]) == len(ml_engine.classes) == 4

def test_evidence_fusion_and_security_rules():
    if not os.path.exists(TEST_PCAP):
        pytest.skip("Test PCAP not found in data/raw_native_ipsec/pcaps/")

    packets, _, _ = PacketParser.parse_pcap_file(TEST_PCAP)
    esp_records = ESPAnalyzer.extract_esp_records(packets)
    ike_events = IKEAnalyzer.extract_ike_events(packets)
    sessions = SAReconstructor.reconstruct_sessions(esp_records, ike_events)
    windows = FlowWindowBuilder.build_flow_windows(esp_records, window_sec=3.0)
    ml_pred = ml_engine.predict_flow_windows(windows)

    findings = SecurityRuleEngine.evaluate_rules(ike_events, esp_records, sessions, windows)
    assert len(findings) > 0

    fusion = EvidenceFusionEngine.fuse_evidence(
        ike_events, esp_records, sessions, windows, ml_pred, findings
    )
    assert "overall_assessment" in fusion
    assert "confidence" in fusion
    assert len(fusion["supporting_evidence"]) > 0

def test_end_to_end_api_upload_and_queries():
    if not os.path.exists(TEST_PCAP):
        pytest.skip("Test PCAP not found in data/raw_native_ipsec/pcaps/")

    with open(TEST_PCAP, "rb") as f:
        response = client.post(
            "/api/v1/pcaps/upload",
            files={"file": ("EXP_BULK_ENV_CLEAN_SESS_0001.pcap", f, "application/vnd.tcpdump.pcap")}
        )
    
    assert response.status_code == 200
    res_data = response.json()
    analysis_id = res_data["analysis_id"]
    assert analysis_id.startswith("ANL_")
    assert res_data["packet_count"] > 0

    # Test summary query
    sum_res = client.get(f"/api/v1/analyses/{analysis_id}")
    assert sum_res.status_code == 200
    assert sum_res.json()["analysis_id"] == analysis_id

    # Test sessions query
    sess_res = client.get(f"/api/v1/analyses/{analysis_id}/sessions")
    assert sess_res.status_code == 200
    assert len(sess_res.json()) > 0

    # Test flows query
    flow_res = client.get(f"/api/v1/analyses/{analysis_id}/flows")
    assert flow_res.status_code == 200

    # Test prediction query
    pred_res = client.get(f"/api/v1/analyses/{analysis_id}/prediction")
    assert pred_res.status_code == 200
    p_data = pred_res.json()
    assert p_data["predicted_class"] in ml_engine.classes
    assert p_data["confidence"] is not None
    assert "top2_class" in p_data
    assert "top2_probability" in p_data
    assert "confidence_margin" in p_data

    # Test findings query
    find_res = client.get(f"/api/v1/analyses/{analysis_id}/findings")
    assert find_res.status_code == 200

    # Test report query
    rep_res = client.get(f"/api/v1/analyses/{analysis_id}/report")
    assert rep_res.status_code == 200
    rep_data = rep_res.json()
    assert "summary" in rep_data
    assert "evidence" in rep_data
    assert "limitations" in rep_data
    assert rep_data["ml"]["confidence_margin"] is not None

# ==============================================================================
# FIX #6 CONFIDENCE MARGIN UNIT TESTS (CASES A, B, C & INDEPENDENCE)
# ==============================================================================

class DummyPredictor:
    def __init__(self, mock_proba):
        self.mock_proba = mock_proba

    def predict_proba(self, X):
        import numpy as np
        return np.tile(self.mock_proba, (len(X), 1))

def test_fix6_case_a_ambiguous_margin():
    """Case A: WEB=0.51, INTERACTIVE=0.47, ICMP=0.01, BULK=0.01 -> Margin = 0.04"""
    import numpy as np
    engine = MLInferenceEngine(model_path="models/xgb_native_ipsec.json")
    # Authoritative class order: [0: BULK, 1: ICMP, 2: INTERACTIVE, 3: WEB]
    engine.model = DummyPredictor(np.array([0.01, 0.01, 0.47, 0.51]))
    
    dummy_windows = [{feat: 1.0 for feat in engine.features}]
    res = engine.predict_flow_windows(dummy_windows)
    
    assert res["status"] == "READY"
    assert res["predicted_class"] == "WEB"
    assert abs(res["confidence"] - 0.51) < 1e-4
    assert res["top2_class"] == "INTERACTIVE"
    assert abs(res["top2_probability"] - 0.47) < 1e-4
    assert abs(res["confidence_margin"] - 0.04) < 1e-4

def test_fix6_case_b_decisive_margin():
    """Case B: WEB=0.97, INTERACTIVE=0.01, ICMP=0.01, BULK=0.01 -> Margin = 0.96"""
    import numpy as np
    engine = MLInferenceEngine(model_path="models/xgb_native_ipsec.json")
    # Authoritative class order: [0: BULK, 1: ICMP, 2: INTERACTIVE, 3: WEB]
    engine.model = DummyPredictor(np.array([0.01, 0.01, 0.01, 0.97]))
    
    dummy_windows = [{feat: 1.0 for feat in engine.features}]
    res = engine.predict_flow_windows(dummy_windows)
    
    assert res["status"] == "READY"
    assert res["predicted_class"] == "WEB"
    assert abs(res["confidence"] - 0.97) < 1e-4
    assert res["top2_class"] in ["BULK", "ICMP", "INTERACTIVE"]
    assert abs(res["top2_probability"] - 0.01) < 1e-4
    assert abs(res["confidence_margin"] - 0.96) < 1e-4

def test_fix6_case_c_not_initialized_clean_nulls():
    """Case C: Model NOT_INITIALIZED -> all ML prediction/confidence/margin fields are None"""
    engine = MLInferenceEngine(model_path="models/missing.json")
    assert engine.status == "NOT_INITIALIZED"
    
    res = engine.predict_flow_windows([{feat: 1.0 for feat in engine.features}])
    assert res["status"] == "NOT_INITIALIZED"
    assert res["predicted_class"] is None
    assert res["confidence"] is None
    assert res["top2_class"] is None
    assert res["top2_probability"] is None
    assert res["confidence_margin"] is None
    assert res["uncertainty_state"] == "UNKNOWN"

def test_fix6_security_rules_independent_of_ml():
    """Security rule findings must evaluate identically regardless of whether ML is High-Conf, Low-Conf, or None."""
    mock_esp = [{
        "spi": "0x12345678",
        "sequence_number": 1,
        "src_ip": "1.1.1.1",
        "dst_ip": "2.2.2.2",
        "packet_length": 100,
        "timestamp": 1000.0
    }]
    mock_ike = [{
        "ike_version": "1.0", # Triggers HIGH severity finding
        "exchange_type": "ID_PROT",
        "timestamp": 999.0
    }]

    findings = SecurityRuleEngine.evaluate_rules(
        ike_events=mock_ike,
        esp_records=mock_esp,
        sessions=[],
        flow_windows=[]
    )
    
    # Verify HIGH severity finding for IKEv1
    severities = [f["severity"] for f in findings]
    assert "HIGH" in severities
    
    # Evidence fusion with no ML
    fusion_no_ml = EvidenceFusionEngine.fuse_evidence(
        ike_events=mock_ike,
        esp_records=mock_esp,
        sessions=[],
        flow_windows=[],
        ml_prediction=None,
        security_findings=findings
    )
    assert fusion_no_ml["overall_assessment"] == "ANOMALOUS"

    # Evidence fusion with misleading/high-confidence ML
    mock_ml_benign = {
        "predicted_class": "WEB",
        "confidence": 0.99,
        "top2_class": "INTERACTIVE",
        "top2_probability": 0.01,
        "confidence_margin": 0.98,
        "class_probabilities": {"WEB": 0.99, "INTERACTIVE": 0.01, "ICMP": 0.0, "BULK": 0.0},
        "uncertainty_state": "OBSERVED"
    }
    fusion_with_ml = EvidenceFusionEngine.fuse_evidence(
        ike_events=mock_ike,
        esp_records=mock_esp,
        sessions=[],
        flow_windows=[],
        ml_prediction=mock_ml_benign,
        security_findings=findings
    )
    # Security Rule HIGH severity finding strictly determines overall assessment
    assert fusion_with_ml["overall_assessment"] == "ANOMALOUS"

# ==============================================================================
# FIX #8 EMPIRICALLY SUPPORTED EVIDENCE FUSION TESTS (CASES A - E)
# ==============================================================================

def test_fix8_case_a_low_separation_ambiguous():
    """CASE A: Low separation (margin=0.04 < 0.15) -> LOW_SEPARATION, not treated as strong supporting evidence."""
    import numpy as np
    engine = MLInferenceEngine(model_path="models/xgb_native_ipsec.json")
    # Authoritative class order: [0: BULK, 1: ICMP, 2: INTERACTIVE, 3: WEB]
    engine.model = DummyPredictor(np.array([0.01, 0.01, 0.47, 0.51]))
    
    res = engine.predict_flow_windows([{feat: 1.0 for feat in engine.features}])
    assert res["separation_state"] == "LOW_SEPARATION"
    assert abs(res["confidence_margin"] - 0.04) < 1e-4

    fusion = EvidenceFusionEngine.fuse_evidence(
        ike_events=[],
        esp_records=[{"spi": "0x1", "sequence_number": 1, "timestamp": 1000.0}],
        sessions=[],
        flow_windows=[],
        ml_prediction=res,
        security_findings=[]
    )
    
    # Verify top-1 class is NOT in supporting evidence
    supporting_sources = [item["source"] for item in fusion["supporting_evidence"]]
    assert "STATISTICAL_ML_INFERENCE" not in supporting_sources

    # Verify present in unknown_factors as AMBIGUOUS / LOW_SEPARATION
    ml_unknowns = [item for item in fusion["unknown_factors"] if item["source"] == "STATISTICAL_ML_INFERENCE"]
    assert len(ml_unknowns) == 1
    assert ml_unknowns[0]["value"] == "AMBIGUOUS / LOW_SEPARATION"
    assert ml_unknowns[0]["reliability"] is None  # No fabricated calibrated reliability

def test_fix8_case_b_high_separation():
    """CASE B: High separation (margin=0.96 > 0.50) -> HIGH_SEPARATION, included in supporting evidence."""
    import numpy as np
    engine = MLInferenceEngine(model_path="models/xgb_native_ipsec.json")
    engine.model = DummyPredictor(np.array([0.01, 0.01, 0.01, 0.97]))
    
    res = engine.predict_flow_windows([{feat: 1.0 for feat in engine.features}])
    assert res["separation_state"] == "HIGH_SEPARATION"
    assert abs(res["confidence_margin"] - 0.96) < 1e-4

    fusion = EvidenceFusionEngine.fuse_evidence(
        ike_events=[],
        esp_records=[{"spi": "0x1", "sequence_number": 1, "timestamp": 1000.0}],
        sessions=[],
        flow_windows=[],
        ml_prediction=res,
        security_findings=[]
    )
    
    # Verify top-1 class is in supporting evidence
    ml_supporting = [item for item in fusion["supporting_evidence"] if item["source"] == "STATISTICAL_ML_INFERENCE"]
    assert len(ml_supporting) == 1
    assert ml_supporting[0]["value"] == "WEB"
    assert ml_supporting[0]["reliability"] is None  # Raw softmax not fabricated as calibrated reliability
    assert "HIGH_SEPARATION" in ml_supporting[0]["notes"]

def test_fix8_case_c_intermediate_separation():
    """CASE C: Intermediate separation (0.15 <= margin=0.30 <= 0.50) -> INTERMEDIATE, no fabricated reliability."""
    import numpy as np
    engine = MLInferenceEngine(model_path="models/xgb_native_ipsec.json")
    # WEB=0.60, INTERACTIVE=0.30, ICMP=0.05, BULK=0.05 -> Margin = 0.30
    engine.model = DummyPredictor(np.array([0.05, 0.05, 0.30, 0.60]))
    
    res = engine.predict_flow_windows([{feat: 1.0 for feat in engine.features}])
    assert res["separation_state"] == "INTERMEDIATE"
    assert abs(res["confidence_margin"] - 0.30) < 1e-4

    fusion = EvidenceFusionEngine.fuse_evidence(
        ike_events=[],
        esp_records=[{"spi": "0x1", "sequence_number": 1, "timestamp": 1000.0}],
        sessions=[],
        flow_windows=[],
        ml_prediction=res,
        security_findings=[]
    )
    
    # Verify in unknown_factors with INTERMEDIATE state
    ml_unknowns = [item for item in fusion["unknown_factors"] if item["source"] == "STATISTICAL_ML_INFERENCE"]
    assert len(ml_unknowns) == 1
    assert "INTERMEDIATE" in ml_unknowns[0]["value"]
    assert ml_unknowns[0]["reliability"] is None

def test_fix8_case_d_security_rule_override():
    """CASE D: Protocol finding (e.g. IKEv1 deprecated) takes absolute priority over high-margin ML."""
    mock_ml_decisive = {
        "predicted_class": "BULK",
        "confidence": 0.999,
        "top2_class": "WEB",
        "top2_probability": 0.001,
        "confidence_margin": 0.998,
        "class_probabilities": {"BULK": 0.999, "WEB": 0.001, "ICMP": 0.0, "INTERACTIVE": 0.0},
        "uncertainty_state": "OBSERVED",
        "separation_state": "HIGH_SEPARATION"
    }
    mock_ike = [{"ike_version": "1.0", "exchange_type": "ID_PROT", "timestamp": 100.0}]
    findings = SecurityRuleEngine.evaluate_rules(mock_ike, [], [], [])
    
    fusion = EvidenceFusionEngine.fuse_evidence(
        ike_events=mock_ike,
        esp_records=[],
        sessions=[],
        flow_windows=[],
        ml_prediction=mock_ml_decisive,
        security_findings=findings
    )
    assert fusion["overall_assessment"] == "ANOMALOUS"

def test_fix8_case_e_model_not_initialized():
    """CASE E: Model NOT_INITIALIZED -> unknown_factors contains ML_MODEL_NOT_INITIALIZED."""
    engine = MLInferenceEngine(model_path="models/missing.json")
    res = engine.predict_flow_windows([{feat: 1.0 for feat in engine.features}])
    
    assert res["status"] == "NOT_INITIALIZED"
    assert res["separation_state"] == "UNKNOWN"

    fusion = EvidenceFusionEngine.fuse_evidence(
        ike_events=[],
        esp_records=[],
        sessions=[],
        flow_windows=[],
        ml_prediction=res,
        security_findings=[]
    )
    
    ml_unknowns = [item for item in fusion["unknown_factors"] if item["source"] == "STATISTICAL_ML_INFERENCE"]
    assert len(ml_unknowns) == 1
    assert ml_unknowns[0]["value"] == "ML_MODEL_NOT_INITIALIZED"
    assert ml_unknowns[0]["reliability"] is None


# ==============================================================================
# RESEARCH SEQUENCE MODEL BACKEND INTEGRATION TESTS
# ==============================================================================

def test_research_model_loading_and_authoritative_metadata():
    from app.ml.research_service import ResearchSequenceInferenceEngine
    engine = ResearchSequenceInferenceEngine()
    assert engine.status == "READY"
    assert engine.hybrid_model is not None
    assert engine.classes == ["BULK", "ICMP", "INTERACTIVE", "WEB"]
    assert len(engine.features_tabular) == 14
    assert engine.sequence_feature_dim == 4
    assert engine.max_seq_len == 32

def test_research_model_missing_artifacts_causes_not_initialized():
    from app.ml.research_service import ResearchSequenceInferenceEngine
    engine = ResearchSequenceInferenceEngine(model_dir="backend/models/non_existent_research_dir")
    assert engine.status == "NOT_INITIALIZED"
    assert engine.hybrid_model is None
    
    res = engine.predict_from_real_records([], [])
    assert res["status"] == "NOT_INITIALIZED"
    assert res["sequence_prediction"] is None
    assert res["hybrid_prediction"] is None
    assert res["novelty_status"] == "NOT_AVAILABLE"

def test_research_sequence_inference_dynamic_prediction():
    from app.ml.research_service import research_engine
    if not os.path.exists(TEST_PCAP):
        pytest.skip(f"Test PCAP not found at {TEST_PCAP}")
        
    packets, _, _ = PacketParser.parse_pcap_file(TEST_PCAP)
    esp_records = ESPAnalyzer.extract_esp_records(packets)
    windows = FlowWindowBuilder.build_flow_windows(esp_records, window_sec=3.0)
    
    res = research_engine.predict_from_real_records(
        flow_windows=windows,
        esp_records=esp_records,
        window_sec=3.0
    )
    
    assert res["status"] == "READY"
    assert res["sequence_prediction"] in ["BULK", "ICMP", "INTERACTIVE", "WEB"]
    assert res["hybrid_prediction"] in ["BULK", "ICMP", "INTERACTIVE", "WEB"]
    assert 0.0 <= res["sequence_confidence"] <= 1.0
    assert 0.0 <= res["hybrid_confidence"] <= 1.0
    assert len(res["sequence_embedding"]) == 32
    assert res["novelty_status"] in ["KNOWN", "UNKNOWN"]
    assert sum(res["sequence_probabilities"].values()) == pytest.approx(1.0, rel=1e-2)

def test_research_failure_isolation_in_pipeline():
    from app.services.pipeline_service import AnalysisPipelineService
    from app.database.models import SessionLocal
    if not os.path.exists(TEST_PCAP):
        pytest.skip(f"Test PCAP not found at {TEST_PCAP}")
        
    db = SessionLocal()
    try:
        # Pipeline executes both baseline and research safely
        analysis_id = AnalysisPipelineService.execute_pipeline(db, TEST_PCAP, "test_upload.pcap")
        assert analysis_id is not None
        
        # Test unified prediction endpoint
        resp_pred = client.get(f"/api/v1/analyses/{analysis_id}/prediction")
        assert resp_pred.status_code == 200
        data = resp_pred.json()
        assert "baseline" in data
        assert "research" in data
        assert data["baseline"]["predicted_class"] in ["BULK", "ICMP", "INTERACTIVE", "WEB"]
        assert data["research"]["status"] == "READY"
        assert data["research"]["sequence_prediction"] in ["BULK", "ICMP", "INTERACTIVE", "WEB"]
        assert data["research"]["novelty_status"] in ["KNOWN", "UNKNOWN", "NOT_AVAILABLE"]
        
        # Test direct research endpoint
        resp_res = client.get(f"/api/v1/analyses/{analysis_id}/research")
        assert resp_res.status_code == 200
        res_data = resp_res.json()
        assert res_data["status"] == "READY"
        assert len(res_data["sequence_embedding"]) == 32
        
        # Test report endpoint contains both
        resp_rep = client.get(f"/api/v1/analyses/{analysis_id}/report")
        assert resp_rep.status_code == 200
        rep_data = resp_rep.json()
        assert "ml" in rep_data
        assert "research" in rep_data
        assert rep_data["research"]["status"] == "READY"
    finally:
        db.close()



