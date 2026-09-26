# 13. IPsecTrace — Final Research Paper Structure

**Title**: Protocol-Aware Multi-View AI Architecture for Native IPsec Security Analysis & Encrypted Traffic Inference  
**Keywords**: Encrypted Traffic Classification, IPsec / ESP Forensics, Transformer Self-Attention, Multi-View Learning, Open-Set Novelty Detection.

---

### Abstract
Encrypted Virtual Private Network (VPN) tunnels utilizing the IP Security (IPsec) protocol encrypt Layer 4 transport headers and payloads inside Encapsulating Security Payloads (ESP), rendering conventional deep packet inspection ineffective. Traditional statistical machine learning models discard temporal packet order, leading to severe misclassification between interactive terminal sessions and low-volume web browsing. This paper introduces **IPsecTrace**, an integrated security analysis and traffic inference architecture that combines deterministic control-plane forensics with encrypted-side temporal representation learning. IPsecTrace deploys a dual-branch hybrid architecture fusing 14 aggregate statistical flow properties with a lightweight 2-layer Transformer sequence encoder. Evaluated on 1,829 native-IPsec flow windows across 294 capture files under strict 5-fold capture-disjoint cross-validation, the hybrid model achieves **80.25% accuracy** and **81.89% Macro-F1** (a **+13.35 percentage-point improvement** over canonical XGBoost), resolving the interactive traffic classification bottleneck. Furthermore, distance-to-centroid novelty estimation yields an AUROC of **0.9962** on out-of-distribution traffic without decrypting ESP payloads.

---

### Section Outline
1. **Introduction & Motivation**
2. **Related Work**: Encrypted Traffic Analysis, Sequence Modeling, Multi-View Learning.
3. **Threat Model & Problem Formulation**
4. **IPsecTrace System Architecture**:
   - Deterministic Protocol Parsing (IKEv1/v2, ESP proto 50, SPIs, Replay Protection).
   - Tabular Statistical Branch (14 Features).
   - Temporal Sequence Branch (Transformer Self-Attention Encoder).
   - Multi-View Fusion & Latent Projections.
   - Open-Set Novelty Detection & Distance Thresholding.
   - Evidence-Grounded Attribution.
5. **Experimental Dataset & Evaluation Protocol**:
   - `DS1_NATIVE_IPSEC_ENHANCED` (1,829 windows, 294 PCAPs, 157 groups).
   - Strict 5-Fold `GroupKFold` on `experiment_group` (0% PCAP leakage).
6. **Results & Ablation Analysis**:
   - Benchmark across Models A, B1, B2, B3, C, and D.
   - Forensic Analysis of the +13.35% Hybrid Gain.
   - Self-Supervised Learning Pretraining Impact (+5.35%).
   - Negative Multi-View Context Result.
7. **Real-PCAP Demonstrations & Security Risk Auditing**
8. **Limitations, Discussion & Future Work**
9. **Conclusion & References**
