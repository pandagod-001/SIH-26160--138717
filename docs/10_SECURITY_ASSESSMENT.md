# 10. Security Assessment & Evidence Fusion

## 1. Separation of Evidence Categories

IPsecTrace enforces a strict architectural boundary between deterministic cryptographic facts and probabilistic machine learning outputs:

```
        DETERMINISTIC EVIDENCE                     BEHAVIORAL AI EVIDENCE
  (IKE Ciphers, DH Groups, PFS, SPI, Replay)     (Traffic Class, Confidence Margin)
                 │                                              │
                 └───────────────────────┬──────────────────────┘
                                         │
                                         ▼
                            EVIDENCE FUSION ENGINE
                                         │
                                         ▼
                            SECURITY ASSESSMENT REPORT
```

1. **Deterministic Cryptographic Facts**:
   - Authority: Scapy / Binary packet parsers.
   - Outputs: Encryption algorithms (`AES-GCM-256`, `AES-CBC-128`, `3DES`), DH groups (`Group 14`, `Curve25519`), replay counters, PFS status.
   - **Rule**: Cryptographic compliance rules ALWAYS override ML. ML cannot invent or alter these parameters.
2. **Behavioral AI Evidence**:
   - Authority: Hybrid Tabular + Sequence Model (Model C).
   - Outputs: Application traffic class (`BULK`, `ICMP`, `INTERACTIVE`, `WEB`) and confidence margins.
3. **Experimental Novelty Evidence**:
   - Authority: Distance-to-centroid OOD scorer.
   - Outputs: `KNOWN` / `UNKNOWN` status.

---

## 2. Structured Evidence-Grounded Attribution Example

```json
{
  "explanation": [
    {
      "source": "DETERMINISTIC",
      "category": "SECURITY_POLICY",
      "statement": "Deterministic cryptographic inspection confirmed IPsec tunnel with IKEv2 negotiation and active ESP encapsulation."
    },
    {
      "source": "HYBRID_ML",
      "category": "TRAFFIC_CLASSIFICATION",
      "statement": "Hybrid AI classified encrypted flow behavior as 'WEB' with 96.84% confidence and 94.12% margin based on joint tabular statistics and burst timing."
    },
    {
      "source": "OOD",
      "category": "NOVELTY_ASSESSMENT",
      "statement": "Observed flow embedding distance (5.42) is within the nominal native-IPsec distribution threshold (8.99); novelty status is KNOWN."
    }
  ]
}
```
