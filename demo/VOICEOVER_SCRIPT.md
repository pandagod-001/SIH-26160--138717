# IPsecTrace — 60-SECOND PRESENTATION VOICEOVER SCRIPT

This script provides natural, spoken English voiceover narration synchronized with the 60-second live demonstration video.

---

## 1. Narration Timeline & Stage Synchronization

| Timestamp | Visual Stage & Action | Spoken Voiceover Narration |
| :--- | :--- | :--- |
| **00:00 – 00:06** | **Title & Engine Initializing**<br>Terminal displays system banner, XGBoost, and PyTorch Transformer engine readiness. | *"This is IPsecTrace: a protocol-aware cybersecurity framework for analyzing encrypted IPsec network tunnels without requiring payload decryption."* |
| **00:06 – 00:15** | **Packet Ingestion & ESP Dissection**<br>Scapy parses 306 packets, identifying 183 encrypted ESP Protocol 50 frames in 212 ms. | *"Here, real encrypted traffic enters our pipeline. IPsecTrace passively ingests raw frames, dissecting Encapsulating Security Payloads while preserving 100% user privacy."* |
| **00:15 – 00:25** | **Session Tracking & Windows**<br>SPI discovery (`0x1`, `0x3e9`), 2 active SAs, 3.0s non-overlapping windows. | *"The platform deterministically reconstructs active Security Associations, tracks SPI identifiers, and segments flows into strict 3-second non-overlapping temporal windows."* |
| **00:25 – 00:35** | **Dual-View Feature Extraction**<br>14 tabular metrics + `[32, 4]` packet burst vectors extracted with isolated scalers. | *"Next, the encrypted stream is represented across two complementary views: 14 aggregate statistical features and a micro-level temporal packet sequence tensor."* |
| **00:35 – 00:46** | **Hybrid AI Classification**<br>Winning Model C fuses tabular & sequence transformer -> BULK at 97.46% (margin 99.69%). | *"Our winning Hybrid Model C fuses both representations, classifying the encrypted transfer as BULK with 97.5% confidence and scoring out-of-distribution novelty at 0.9962 AUROC."* |
| **00:46 – 00:54** | **Deterministic Compliance Audit**<br>NIST SP 800-77 audit, anti-replay verification passes independently of ML. | *"Crucially, deterministic protocol facts maintain absolute authority: cryptographic compliance, SA expiration, and anti-replay counters are evaluated independently of machine learning."* |
| **00:54 – 01:00** | **Attribution & Completion**<br>Composite SOC report generated, zero-decryption verified. | *"This produces transparent, evidence-grounded attribution for SOC analysts—ensuring deep visibility and privacy in zero-trust networks."* |

---

## 2. Voiceover Audio Recording Recommendations

- **Target Word Count**: ~140 words (ideal pacing for a 50–55 second natural delivery).
- **Tone**: Authoritative, professional, calm, academic cybersecurity researcher voice.
- **Recording Format**: 44.1 kHz / 48 kHz WAV or MP3.
- **Save Location**: `demo/assets/voiceover_bulk.wav` (Optional integration via `--voiceover`).
