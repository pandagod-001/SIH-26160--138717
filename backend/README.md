# IPsecTrace Defensive Traffic Analysis Prototype

IPsecTrace is an AI-powered defensive IPsec VPN protocol analyzer and security assessment engine designed for **Smart India Hackathon 2026** (Problem Statement: 26160 / NTRO).

The backend executes comprehensive multi-plane analysis across **IKE control plane**, **ESP/AH data plane**, **SPI-session reconstruction**, **multi-scale flow windowing**, **statistical ML inference**, **rule-based security audit**, and **evidence fusion** without decrypting encrypted payloads.

---

## 1. System Architecture

```text
PCAP Upload / Wire Stream
          │
   [Packet Parser] (Scapy Ingestion)
          │
  ┌───────┴────────────────────────┐
  ▼                                ▼
[IKE Control Plane]         [ESP/AH Data Plane]
(RFC 7296 Proposals,         (RFC 4303 SPI, Sequence,
 Ciphers, DH Groups)         Direction, Observability)
  │                                │
  └───────┬────────────────────────┘
          ▼
 [SA / SPI Reconstruction]
          │
 [Flow Window Aggregation] (3.0s Multi-Scale Windows)
          │
 [Feature Vector Builder] (14 Canonical Statistical Metrics)
          │
  ┌───────┴────────────────────────┐
  ▼                                ▼
[ML Inference Engine]       [Security Rule Engine]
(XGBoost / Random Forest     (IKE Ciphers, Replay Window,
 Class Proba & Uncertainty)   Policy Observability Limits)
  │                                │
  └───────┬────────────────────────┘
          ▼
   [Evidence Fusion]
 (Multi-Plane Synthesis, Supporting/Contradicting/Unknowns)
          │
   [SQLite Persistence]
          │
   [FastAPI REST Engine]
```

---

## 2. Quickstart & Local Installation

### Prerequisites
- Python 3.10+ (Ubuntu/Debian, WSL2, or macOS/Windows)
- SQLite3

### Installation

1. Navigate to the backend directory:
   ```bash
   cd backend
   ```
2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Copy environment configuration:
   ```bash
   cp .env.example .env
   ```

### Starting the Backend Server

Run locally with Uvicorn:
```bash
PYTHONPATH=. uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
The API is available at:
- Interactive Swagger UI: `http://localhost:8000/docs`
- Health Check: `http://localhost:8000/api/v1/health`

---

## 3. Running Automated Tests

Run the complete test suite against authentic Native IPsec captures:
```bash
PYTHONPATH=. pytest tests/test_prototype.py -v
```

---

## 4. REST API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/health` | Service health status and cryptographic observability mode |
| `POST` | `/api/v1/pcaps/upload` | Upload `.pcap`/`.pcapng` and trigger complete analysis pipeline |
| `GET` | `/api/v1/analyses/{analysis_id}` | Analysis overview summary and packet breakdown |
| `GET` | `/api/v1/analyses/{analysis_id}/ike` | Extracted IKE control-plane events and SA proposals |
| `GET` | `/api/v1/analyses/{analysis_id}/sessions`| Reconstructed Security Association (SA) sessions |
| `GET` | `/api/v1/analyses/{analysis_id}/flows` | Time-windowed flow aggregates |
| `GET` | `/api/v1/analyses/{analysis_id}/features`| 14-dimensional statistical feature vectors |
| `GET` | `/api/v1/analyses/{analysis_id}/prediction`| ML model classification probabilities and uncertainty state |
| `GET` | `/api/v1/analyses/{analysis_id}/findings`| Rule-based security findings & policy evaluation |
| `GET` | `/api/v1/analyses/{analysis_id}/evidence`| Full evidence items (supporting, conflicting, unknown) |
| `GET` | `/api/v1/analyses/{analysis_id}/report` | Complete unified JSON report ready for dashboard rendering |

---

## 5. Example End-to-End Workflow with cURL

### 1. Upload a PCAP
```bash
curl -X POST "http://localhost:8000/api/v1/pcaps/upload" \
  -F "file=@../data/raw_native_ipsec/pcaps/EXP_BULK_ENV_CLEAN_SESS_0001.pcap"
```
*Response:*
```json
{
  "analysis_id": "ANL_A1B2C3D4",
  "filename": "EXP_BULK_ENV_CLEAN_SESS_0001.pcap",
  "packet_count": 183,
  "ike_packet_count": 0,
  "esp_packet_count": 183,
  "ah_packet_count": 0,
  "start_time": 1790199476.382115,
  "end_time": 1790199476.400581,
  "duration_sec": 0.018466,
  "status": "COMPLETED",
  "overall_assessment": "NORMAL",
  "confidence": 0.92
}
```

### 2. Fetch Full Unified Assessment Report
```bash
curl -X GET "http://localhost:8000/api/v1/analyses/ANL_A1B2C3D4/report"
```

---

## 6. Cryptographic Observability Guarantees

1. **Defensive Boundary**: IPsecTrace **never decrypts** ESP payload contents or attempts mathematical plaintext inference.
2. **Explicit Uncertainty**: Non-observable elements (such as receiver kernel SADB replay window bitmasks) are explicitly reported as `NOT_OBSERVABLE` rather than guessed or fabricated.
3. **Evidence Fusion**: ML predictions are treated as **one** statistical evidence input among protocol rules, sequence checks, and control-plane metrics.
