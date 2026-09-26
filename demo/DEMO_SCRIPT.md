# IPsecTrace — 60-SECOND LIVE PROTOTYPE VIDEO STORYBOARD & SCRIPT

This script provides second-by-second narration and visual cues for recording a compelling, professional 60-second prototype demonstration of IPsecTrace.

---

## 1. Timing, Visual Focus & Narration Table

| Timestamp | Visual Focus / Action | Terminal Command & Output | Suggested Narration / Voiceover |
| :--- | :--- | :--- | :--- |
| **00:00 – 00:05** | **Title Card / Banner**<br>Terminal at 1080p, crisp cyan branding. | `python demo/run_demo.py --class-type BULK --record` | *"Introducing IPsecTrace: a protocol-aware AI framework for encrypted IPsec traffic forensics and security auditing."* |
| **00:05 – 00:15** | **[01] & [02] Ingestion & ESP Dissection**<br>Packet counters, Protocol 50 recognition. | `Packets: 306 frames`<br>`Encrypted ESP: 183 packets`<br>`Dissection Time: 212 ms` | *"Here, real encrypted traffic traverses an IPsec tunnel. IPsecTrace passively ingests raw frames, dissecting ESP encapsulations without requiring payload decryption."* |
| **00:15 – 00:28** | **[03] Session & Windows**<br>SPI discovery, 3.0s non-overlapping windows. | `Sessions: 2 bidirectional flows`<br>`SPIs: 0x1, 0x3e9`<br>`Windows: 1 (3.0s window)` | *"The system reconstructs bidirectional SA flows, tracks SPI identifiers, and generates 3-second non-overlapping flow windows, preserving strict temporal boundaries."* |
| **00:28 – 00:42** | **[04] Hybrid AI & OOD Novelty**<br>Tabular + Transformer fusion classification. | `Predicted: BULK`<br>`Top-1 Prob: 97.46%`<br>`Margin: 99.69% [HIGH_SEPARATION]`<br>`OOD Dist: 6.103 [KNOWN]` | *"Our winning Hybrid Model C fuses 14 statistical flow features with a temporal packet Transformer, classifying encrypted bulk transfers with 97.5% confidence while scoring novelty via SSL embeddings."* |
| **00:42 – 00:54** | **[05] Deterministic Security Audit**<br>Replay counter, NIST compliance. | `Anti-Replay Test: PASS`<br>`Rule Audit: Deterministic Authority` | *"Crucially, deterministic protocol facts maintain supreme authority: cryptographic suites, SA lifespans, and anti-replay counters are audited independently of probabilistic AI."* |
| **00:54 – 01:00** | **[06] Evidence Fusion & Completion**<br>Unified SOC attribution summary. | `[SUCCESS] DEMONSTRATION COMPLETE`<br>`REAL IPsec ANALYZED | ZERO DECRYPTION` | *"This delivers transparent, evidence-grounded attribution for SOC analysts—ensuring deep visibility while guaranteeing 100% user privacy."* |

---

## 2. Recording Best Practices

1. **Terminal Setup**:
   - Resolution: `1920 x 1080` (16:9 widescreen)
   - Font: `Consolas`, `Cascadia Code`, or `JetBrains Mono` at **22pt**
   - Background: Dark Navy / Pure Black (`#0F172A`)
2. **Command to Launch Presentation Recording**:
   ```bash
   bash demo/record_demo.sh
   ```
3. **Alternative Quick Demonstrations**:
   ```bash
   # Web traffic demonstration
   python demo/run_demo.py --class-type WEB

   # ICMP diagnostic probe demonstration
   python demo/run_demo.py --class-type ICMP
   ```
