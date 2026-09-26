# 02. Problem Statement & Research Motivation

## 1. The Core Problem
Virtual Private Networks (VPNs) built upon the **IP Security (IPsec)** framework (RFC 4301) provide robust end-to-end confidentiality, integrity, and replay protection for enterprise and national infrastructure communications. 

However, this strong encryption fundamentally disrupts standard network monitoring:
- **Encapsulating Security Payload (ESP proto 50)** encrypts transport layer headers (TCP/UDP ports) and user data.
- **Deep Packet Inspection (DPI) Failure**: Conventional intrusion detection systems (IDS) and traffic analyzers cannot inspect payloads without obtaining session keys or breaking cryptography.
- **Traffic Obfuscation**: Malicious command-and-control (C2) activity, data exfiltration, or unauthorized services can blend unnoticed into legitimate IPsec VPN tunnels.

---

## 2. Limitations of Prior Art
1. **Aggregate Statistical Classifiers**: Standard machine learning models (e.g. Random Forest, standard XGBoost) compute aggregate flow statistics (e.g. mean packet size, total bytes, flow duration). These summaries discard fine-grained temporal dynamics such as packet bursts, request-response timing, and inter-arrival intervals, leading to severe misclassification between interactive terminal traffic and low-volume web browsing.
2. **Opaque Black-Box Models**: Deep learning classifiers often act as uncalibrated black boxes, overconfidently mispredicting unseen or out-of-distribution network protocols without uncertainty estimation.
3. **Disconnection from Control-Plane Evidence**: Prior methods isolate ML from deterministic Layer 3/4 control-plane evidence (such as IKE negotiations, cryptographic transform strength, and replay window status).

---

## 3. The IPsecTrace Solution
IPsecTrace introduces a **protocol-aware multi-view architecture** that unites:
- **Deterministic Protocol Forensics** for authoritative compliance and cryptographic auditing.
- **Temporal Sequence Learning (Transformer)** for fine-grained encrypted burst dynamics.
- **Hybrid Multi-View Fusion** to resolve the web vs interactive traffic bottleneck without payload decryption.
