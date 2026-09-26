# 11. Scientific Limitations & Future Research

## 1. Verified System Limitations

1. **Testbed Scope**: The 1,829-window dataset originates from controlled Linux / StrongSwan IPsec instances across 4 network profiles. Universal generalization across arbitrary global enterprise networks is not established.
2. **WEB vs INTERACTIVE Overlap**: While Model C significantly reduced confusion (achieving 63.46% F1 on INTERACTIVE vs 38.46% in XGBoost), short bursty HTTP requests and interactive SSH keystrokes still share temporal similarities.
3. **Homogeneous Context Invariance**: In a pure native-IPsec testbed, static context markers (`is_esp=1`) provide zero discriminative entropy, causing Model D to underperform (61.33% accuracy). Context features require multi-protocol environments (e.g. WireGuard vs IPsec vs OpenVPN) to be effective.
4. **No Cryptographic Decryption**: Payloads remain encrypted; the system does not recover keys or decrypt ciphertext.
5. **Experimental OOD**: Distance-to-centroid novelty detection is evaluated under controlled perturbations and does not guarantee open-set recognition against adversarial mimicry.

---

## 2. Future Research Directions

- **Multi-Tunnel Environment Evaluation**: Expanding datasets to include mixed WireGuard, OpenVPN, and TLS 1.3 tunnels to leverage multi-view protocol context.
- **Adaptive Attention Sequence Models**: Integrating self-supervised pretraining directly into the hybrid tabular-sequence encoder.
- **Hardware-Accelerated Ingestion**: Implementing DPDK / eBPF kernel bypass for real-time 100 Gbps line-rate traffic classification.
