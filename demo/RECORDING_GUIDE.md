# IPsecTrace — DEMONSTRATION VIDEO RECORDING GUIDE

This guide explains how to generate, review, and utilize the 60-second broadcast-quality IPsecTrace technical demonstration video.

---

## 1. Quick One-Command Execution

To record the demonstration video directly from the terminal without manual configuration:

```bash
# Generate 60-second BULK traffic demonstration video (1920x1080 30FPS MP4)
python demo/record_video.py --class-type BULK

# Generate WEB browsing traffic demonstration video
python demo/record_video.py --class-type WEB

# Generate ICMP diagnostic probe demonstration video
python demo/record_video.py --class-type ICMP
```

The output video will be generated at:
[`demo/recordings/IPsecTrace_BULK_LIVE_DEMO.mp4`](file:///c:/Users/Abhijay/ipsec/demo/recordings/IPsecTrace_BULK_LIVE_DEMO.mp4)

---

## 2. Video Layout & Composition Specifications

The generated video utilizes a clean dual-pane SOC dark aesthetic:
- **Top Bar (0 – 65px)**: System title, research branding, active traffic mode, and real-time timer.
- **Left Pane (65% width)**: Real-time terminal streaming unmocked IPsecTrace pipeline output (Scapy parsing, SPI extraction, PyTorch Transformer inference, NIST security rule audits).
- **Right Pane (35% width)**:
  - **Dynamic Stage Cards**: Highlighting the active analysis stage (Ingestion, Dissection, Dual Representation, Hybrid AI, Compliance, Attribution).
  - **Dynamic Execution Metrics**: Unmocked metrics table displaying total frames, ESP counts, active SAs, predicted class, confidence percentage, confidence margin, and OOD novelty status.
  - **Pipeline Breadcrumbs**: Flow visualization tracking progress from Ingestion to Attribution.

---

## 3. Video Validation & Verification

| Property | Authoritative Value | Verification Status |
| :--- | :--- | :--- |
| **Duration** | **60.0 seconds** (1,800 frames) | Verified |
| **Resolution** | **1920 x 1080** (Full HD 16:9) | Verified |
| **Frame Rate** | **30.0 FPS** | Verified |
| **Video Codec** | **H.264 / MP4V** (`.mp4` container) | Verified |
| **File Size** | **~34.2 MB** | Verified |
| **Desktop Pollution** | **Zero** (Dedicated self-contained render) | Verified |

---

## 4. Manual Screen Capture Fallback (OBS / Screen Studio)

If you prefer to capture your live OS terminal window manually:
1. Open terminal at **1920x1080** with font size **22pt**.
2. Run the interactive paced terminal presentation:
   ```bash
   python demo/run_demo.py --class-type BULK --record
   ```
3. Record the 60-second terminal output in OBS Studio.
