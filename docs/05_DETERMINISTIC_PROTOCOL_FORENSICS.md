# 05. Deterministic Protocol Forensics

## 1. Authoritative Protocol Extraction
In IPsecTrace, **deterministic protocol facts remain authoritative**. Machine learning models are strictly prohibited from inferring or altering cryptographic attributes.

### Extracted Deterministic Parameters:
1. **IKE Protocol Negotiation**:
   - IKE Version (IKEv1 vs IKEv2)
   - Encryption Transforms (`AES-GCM-256`, `AES-CBC-128`, `3DES`, `DES`)
   - Integrity / Authentication Algorithms (`HMAC-SHA256`, `HMAC-SHA1`, `MD5`)
   - Diffie-Hellman Exchange Groups (`Group 14 (2048-bit)`, `Group 19 (Curve25519)`, `Group 2 (1024-bit)`)
   - Perfect Forward Secrecy (PFS) state
2. **Encapsulating Security Payload (ESP proto 50)**:
   - Security Parameter Index (SPI) tracking (Inbound vs Outbound)
   - Sequence Number counters
   - Replay protection window state
3. **Multi-Factor Direction Inference**:
   - Resolves initiator vs responder flow direction using IKE state, private IP subnets (`RFC 1918`), and initial packet arrival order.

---

## 2. Security Compliance Rule Engine
The deterministic rule engine (`backend/app/security/rules.py`) audits configurations against security policies:
- `RULE_DEPRECATED_CIPHER_DES`: Severity **CRITICAL** (DES is cryptographically broken).
- `RULE_DEPRECATED_CIPHER_3DES`: Severity **HIGH** (3DES vulnerable to Sweet32 attacks).
- `RULE_WEAK_DH_GROUP`: Severity **HIGH** (DH Group 1 / Group 2 insufficient for modern security).
- `RULE_NO_REPLAY_PROTECTION`: Severity **HIGH** (Missing or unmonitored sequence counter state).
