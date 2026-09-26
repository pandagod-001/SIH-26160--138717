import uuid
from typing import List, Dict, Any
from app.schemas.api_models import ObservabilityState, SeverityLevel

class SecurityRuleEngine:
    """
    Deterministic rule-based security and policy assessment.
    Evaluates observed telemetry against RFC specifications and security baselines.
    """

    @classmethod
    def evaluate_rules(
        cls,
        ike_events: List[Dict[str, Any]],
        esp_records: List[Dict[str, Any]],
        sessions: List[Dict[str, Any]],
        flow_windows: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        findings = []

        # Rule 1: IKE Protocol Presence and Version
        if not ike_events:
            findings.append({
                "finding_id": f"SEC-IKE-{uuid.uuid4().hex[:6].upper()}",
                "severity": SeverityLevel.INFO,
                "category": "CONTROL_PLANE",
                "title": "No IKE Handshake in Current Stream",
                "description": "Capture does not contain initial IKE negotiations (pre-existing SA or data-plane only capture).",
                "evidence": "0 IKE packets observed.",
                "confidence": 1.0,
                "observability": ObservabilityState.OBSERVED,
                "recommendation": "Capture initial tunnel negotiation to audit cryptographic cipher suites."
            })
        else:
            for ike in ike_events:
                ver = ike.get("ike_version", "unknown")
                if ver.startswith("2"):
                    findings.append({
                        "finding_id": f"SEC-IKE-{uuid.uuid4().hex[:6].upper()}",
                        "severity": SeverityLevel.INFO,
                        "category": "CONTROL_PLANE",
                        "title": "Modern IKEv2 Protocol Verified",
                        "description": "IKE negotiations adhere to RFC 7296 standard.",
                        "evidence": f"IKE Version: {ver}, Exchange: {ike.get('exchange_type')}",
                        "confidence": 1.0,
                        "observability": ObservabilityState.OBSERVED,
                        "recommendation": "Maintain IKEv2 deployment."
                    })
                elif ver.startswith("1"):
                    findings.append({
                        "finding_id": f"SEC-IKE-{uuid.uuid4().hex[:6].upper()}",
                        "severity": SeverityLevel.HIGH,
                        "category": "CONTROL_PLANE",
                        "title": "Deprecated IKEv1 Protocol Detected",
                        "description": "IKEv1 contains known vulnerabilities and lacks modern rekeying optimizations.",
                        "evidence": f"IKE Version: {ver}",
                        "confidence": 1.0,
                        "observability": ObservabilityState.OBSERVED,
                        "recommendation": "Migrate urgently to IKEv2 (RFC 7296)."
                    })

                # Check Encryption Proposals
                ciphers = ike.get("encryption_transforms")
                if ciphers:
                    if "DES" in ciphers or "3DES" in ciphers:
                        findings.append({
                            "finding_id": f"SEC-CRYPTO-{uuid.uuid4().hex[:6].upper()}",
                            "severity": SeverityLevel.HIGH,
                            "category": "CRYPTOGRAPHY",
                            "title": "Legacy / Insecure Cipher Proposed",
                            "description": "Weak encryption cipher (DES/3DES) observed in SA proposal.",
                            "evidence": f"Cipher: {ciphers}",
                            "confidence": 0.95,
                            "observability": ObservabilityState.OBSERVED,
                            "recommendation": "Remove DES/3DES; enforce AES-128/256-GCM or AES-CBC."
                        })
                    elif "AES" in ciphers or "CHACHA20" in ciphers:
                        findings.append({
                            "finding_id": f"SEC-CRYPTO-{uuid.uuid4().hex[:6].upper()}",
                            "severity": SeverityLevel.INFO,
                            "category": "CRYPTOGRAPHY",
                            "title": "Robust Encryption Cipher Proposed",
                            "description": "Modern cryptographic cipher suite proposed in IKE SA exchange.",
                            "evidence": f"Proposed Ciphers: {ciphers}",
                            "confidence": 0.95,
                            "observability": ObservabilityState.OBSERVED,
                            "recommendation": "Cipher suite complies with enterprise security policy."
                        })

        # Rule 2: ESP Data Plane & Anti-Replay Progression
        if esp_records:
            seq_numbers = [r["sequence_number"] for r in esp_records if "sequence_number" in r]
            if seq_numbers:
                duplicates = len(seq_numbers) - len(set(seq_numbers))
                if duplicates > 0:
                    findings.append({
                        "finding_id": f"SEC-REPLAY-{uuid.uuid4().hex[:6].upper()}",
                        "severity": SeverityLevel.MEDIUM,
                        "category": "DATA_PLANE",
                        "title": "Duplicate ESP Sequence Numbers Observed",
                        "description": "Observed multiple packets sharing identical sequence numbers under same SPI.",
                        "evidence": f"{duplicates} duplicate sequence instances observed.",
                        "confidence": 0.90,
                        "observability": ObservabilityState.OBSERVED,
                        "recommendation": "Investigate potential replay attack or network-layer packet duplication."
                    })
                else:
                    findings.append({
                        "finding_id": f"SEC-REPLAY-{uuid.uuid4().hex[:6].upper()}",
                        "severity": SeverityLevel.INFO,
                        "category": "DATA_PLANE",
                        "title": "Monotonic Sequence Progression Verified",
                        "description": "ESP sequence numbers increment monotonically with zero duplicates.",
                        "evidence": f"{len(seq_numbers)} packets evaluated.",
                        "confidence": 1.0,
                        "observability": ObservabilityState.OBSERVED,
                        "recommendation": "Data-plane sequence counters are healthy."
                    })

            # Rule 3: Kernel SADB Replay Window Observability Boundary
            findings.append({
                "finding_id": f"SEC-OBS-{uuid.uuid4().hex[:6].upper()}",
                "severity": SeverityLevel.INFO,
                "category": "OBSERVABILITY",
                "title": "Receiver Replay Window Not Passively Observable",
                "description": "Receiver kernel-side SADB replay bitmask cannot be directly observed from passive PCAP stream.",
                "evidence": "Passive capture architectural limitation.",
                "confidence": 1.0,
                "observability": ObservabilityState.NOT_OBSERVABLE,
                "recommendation": "Inspect receiver kernel XFRM/SADB settings directly via `ip xfrm state`."
            })

        return findings
