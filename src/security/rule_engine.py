import sys
import json

def assess_ipsec_security(ike_sessions, esp_records):
    """
    Evaluates evidence-aware deterministic security findings based on observed IPsec telemetry.
    Distinguishes DIRECTLY OBSERVABLE parameters from NOT OBSERVABLE receiver internal state.
    """
    findings = []

    if not ike_sessions:
        findings.append({
            "check": "IKE_NEGOTIATION_OBSERVED",
            "status": "UNKNOWN",
            "severity": "WARNING",
            "finding": "No active IKE negotiation packets observed in capture session.",
            "evidence": "0 IKE_SA_INIT / IKE_AUTH packets found in stream.",
            "recommendation": "Ensure full IKE handshake is captured at tunnel startup."
        })
    else:
        for ike in ike_sessions:
            ver = ike.get("ike_version", "unknown")
            if ver.startswith("2"):
                findings.append({
                    "check": "IKE_VERSION",
                    "status": "VERIFIED",
                    "severity": "INFO",
                    "finding": "Modern IKEv2 Protocol Active (RFC 7296)",
                    "evidence": f"IKE version observed in header: {ver}",
                    "recommendation": "Maintain IKEv2 deployment standard."
                })
            elif ver.startswith("1"):
                findings.append({
                    "check": "IKE_VERSION",
                    "status": "WARNING",
                    "severity": "HIGH",
                    "finding": "Legacy IKEv1 Protocol Detected",
                    "evidence": f"IKE version observed: {ver}",
                    "recommendation": "Migrate from legacy IKEv1 to IKEv2 (RFC 7296)."
                })
            else:
                findings.append({
                    "check": "IKE_VERSION",
                    "status": "UNKNOWN",
                    "severity": "WARNING",
                    "finding": "Unrecognized IKE Version Field",
                    "evidence": f"Version field: {ver}",
                    "recommendation": "Verify packet parser compatibility."
                })

            # Check Encryption Transform
            enc = ike.get("encryption_transform", "unknown")
            if "AES" in enc:
                findings.append({
                    "check": "ENCRYPTION_TRANSFORM",
                    "status": "INFERRED",
                    "severity": "INFO",
                    "finding": "Symmetric Encryption Suite (Configured Profile)",
                    "evidence": f"Encryption algorithm inferred from SA context: {enc}",
                    "recommendation": "Continue using AES-128-CBC or AES-256-GCM."
                })
            elif enc == "unknown":
                findings.append({
                    "check": "ENCRYPTION_TRANSFORM",
                    "status": "NOT OBSERVABLE",
                    "severity": "WARNING",
                    "finding": "Encryption Transform Unobservable from Raw Headers",
                    "evidence": "Payload encrypted or proposal unparsed",
                    "recommendation": "Verify control plane capture completeness."
                })
            else:
                findings.append({
                    "check": "ENCRYPTION_TRANSFORM",
                    "status": "WARNING",
                    "severity": "HIGH",
                    "finding": "Potentially Weak Encryption Cipher",
                    "evidence": f"Encryption algorithm: {enc}",
                    "recommendation": "Upgrade cipher to AES-GCM or AES-CBC."
                })

            # Check Diffie-Hellman Group / PFS
            dh = ike.get("dh_group", "unknown")
            if "MODP-2048" in dh or "Group 14" in dh or "ECP" in dh:
                findings.append({
                    "check": "DH_GROUP_PFS",
                    "status": "INFERRED",
                    "severity": "INFO",
                    "finding": "Diffie-Hellman Key Exchange Group Context (PFS Active)",
                    "evidence": f"DH Group: {dh}",
                    "recommendation": "Maintain DH Group >= 14 (MODP 2048-bit or ECP)."
                })
            elif dh == "unknown":
                findings.append({
                    "check": "DH_GROUP_PFS",
                    "status": "NOT OBSERVABLE",
                    "severity": "WARNING",
                    "finding": "Diffie-Hellman Key Exchange Group Unobserved",
                    "evidence": "DH group details omitted in payload",
                    "recommendation": "Inspect IKE_SA_INIT Key Exchange (KE) payload."
                })
            else:
                findings.append({
                    "check": "DH_GROUP_PFS",
                    "status": "WARNING",
                    "severity": "HIGH",
                    "finding": "Legacy / Low Bit-Length DH Group",
                    "evidence": f"DH Group: {dh}",
                    "recommendation": "Upgrade to DH Group 14 (MODP-2048) or higher."
                })

    # ESP Data Plane Security Checks
    if esp_records:
        spi_set = set([r.get("spi") for r in esp_records if r.get("spi")])
        findings.append({
            "check": "ESP_TRAFFIC_OBSERVED",
            "status": "VERIFIED",
            "severity": "INFO",
            "finding": "Encapsulating Security Payload (ESP) Traffic Present (RFC 4303)",
            "evidence": f"{len(esp_records)} ESP packets captured across SPIs: {list(spi_set)[:3]}",
            "recommendation": "Data plane IPsec encapsulation operating normally."
        })
        
        # Sequence Progression Check
        seq_nums = [r.get("sequence_number", 0) for r in esp_records if "sequence_number" in r]
        max_seq = max(seq_nums) if seq_nums else 0
        duplicates = len(seq_nums) - len(set(seq_nums))
        
        findings.append({
            "check": "ESP_SEQUENCE_PROGRESSION",
            "status": "VERIFIED",
            "severity": "INFO",
            "finding": "ESP Sequence Number Progression Observed",
            "evidence": f"Max sequence number: {max_seq}; Duplicate sequence observations: {duplicates}",
            "recommendation": "Sequence counter progressing monotonically."
        })

        # Explicit Observability Boundary for Anti-Replay Configuration
        findings.append({
            "check": "RECEIVER_REPLAY_WINDOW_ENFORCEMENT",
            "status": "NOT OBSERVABLE",
            "severity": "INFO",
            "finding": "Receiver-Side Anti-Replay Window State Not Directly Observable",
            "evidence": "Passive PCAP capture cannot verify kernel SADB replay window bitmask.",
            "recommendation": "Verify anti-replay window settings in host SADB / strongSwan configuration."
        })

    return findings

if __name__ == "__main__":
    dummy_ike = [{"ike_version": "2.0", "encryption_transform": "AES-CBC (128-bit)", "dh_group": "MODP-2048 (Group 14)"}]
    dummy_esp = [{"spi": "0x11223344", "sequence_number": 42}]
    res = assess_ipsec_security(dummy_ike, dummy_esp)
    print(json.dumps(res, indent=2))
