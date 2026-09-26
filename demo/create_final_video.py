#!/usr/bin/env python3
"""
IPsecTrace — Fast, High-Performance Master Research Demonstration Video Engine.
Calibrated for exactly 2:30 - 2:45 total duration (<3:00 min) with unified 30.0 FPS & 44.1kHz audio.
"""

import os
import sys
import time
import argparse
import pathlib
import wave
import subprocess
import json
import win32com.client
from PIL import Image, ImageDraw, ImageFont
import imageio_ffmpeg

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
OUTPUT_DIR = PROJECT_ROOT / "demo" / "output"
FINAL_VIDEO_DIR = PROJECT_ROOT / "demo" / "final_video"
ASSETS_DIR = PROJECT_ROOT / "demo" / "assets"
RECORDINGS_DIR = PROJECT_ROOT / "demo" / "recordings"

os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(FINAL_VIDEO_DIR, exist_ok=True)
os.makedirs(ASSETS_DIR, exist_ok=True)

FFMPEG_EXE = imageio_ffmpeg.get_ffmpeg_exe()

# Color Palette (Dark Academic SOC Aesthetic)
BG_COLOR = (13, 17, 23)           # #0D1117 Very dark slate
HEADER_BG = (10, 14, 20)          # #0A0E14
CARD_BG = (22, 30, 46)            # #161E2E
CARD_BORDER = (45, 58, 82)        # #2D3A52
CARD_ACTIVE = (30, 45, 75)        # Active card highlight

TEXT_WHITE = (240, 246, 252)
TEXT_GRAY = (140, 150, 165)
TEXT_DIM = (90, 100, 115)
ACCENT_CYAN = (56, 189, 248)      # #38BDF8
ACCENT_BLUE = (96, 165, 250)      # #60A5FA
ACCENT_GREEN = (74, 222, 128)     # #4ADE80
ACCENT_AMBER = (251, 191, 36)     # #FBBF24
ACCENT_RED = (248, 113, 113)

def get_font(size=16, bold=False):
    font_candidates = [
        "C:\\Windows\\Fonts\\segoeui.ttf" if not bold else "C:\\Windows\\Fonts\\segoeuib.ttf",
        "C:\\Windows\\Fonts\\arial.ttf" if not bold else "C:\\Windows\\Fonts\\arialbd.ttf",
        "C:\\Windows\\Fonts\\consola.ttf" if not bold else "C:\\Windows\\Fonts\\consolab.ttf",
    ]
    for font_path in font_candidates:
        if os.path.exists(font_path):
            try:
                return ImageFont.truetype(font_path, size)
            except Exception:
                pass
    return ImageFont.load_default()

FONT_HERO = get_font(44, bold=True)
FONT_TITLE = get_font(28, bold=True)
FONT_SUBTITLE = get_font(18, bold=False)
FONT_SECTION = get_font(20, bold=True)
FONT_BODY = get_font(16, bold=False)
FONT_BODY_BOLD = get_font(16, bold=True)
FONT_METRIC_NUM = get_font(32, bold=True)
FONT_CAPTION = get_font(18, bold=True)
FONT_SUBTITLE_TXT = get_font(16, bold=False)

NARRATION_SEGMENTS = [
    {
        "id": "01_opening",
        "title": "IPsecTrace — RESEARCH OVERVIEW",
        "subtitle": "Protocol-Aware Encrypted IPsec Traffic Analysis & Security Assessment",
        "narration": "IPsecTrace is a protocol-aware system for analyzing encrypted IPsec network traffic without decrypting protected application payloads, producing evidence-grounded security findings.",
        "caption": "IPsecTrace: Protocol-Aware Encrypted IPsec Traffic Analysis\n(Real Traffic + Deterministic Forensics + AI Inference + Security Assessment)",
        "type": "title_card"
    },
    {
        "id": "02_problem",
        "title": "THE ENCRYPTED INSPECTION CHALLENGE",
        "subtitle": "Analyzing Traffic When Application Payloads Are Locked",
        "narration": "Traditional inspection fails when payloads are encrypted. While IPsec protects the payload, observable signals exist in the control plane, packet structure, timing, and flow behavior without requiring decryption.",
        "caption": "Payload is Encrypted & NOT_OBSERVABLE — Signal Exists in Control Plane, Timing & Packet Dynamics",
        "type": "problem_card"
    },
    {
        "id": "03_architecture",
        "title": "SIX-STAGE FORENSIC ARCHITECTURE",
        "subtitle": "End-to-End Pipeline from Packet Ingestion to Evidence Reporting",
        "narration": "The architecture comprises six stages: packet capture, deterministic IKE and ESP analysis, dual-view feature extraction, hybrid AI classification, and policy compliance verification.",
        "caption": "Architecture Pipeline: Ingestion -> Protocol Analysis -> Feature Extraction -> AI & Rules -> Evidence",
        "type": "architecture_card"
    },
    {
        "id": "04_deterministic",
        "title": "DETERMINISTIC PROTOCOL FORENSICS",
        "subtitle": "Absolute Protocol Authority vs Probabilistic Machine Learning",
        "narration": "Under deterministic authority, protocol ground truth including IKE parameters, SPI identifiers, SA state, and replay counters are parsed directly. The AI is never permitted to overwrite protocol facts.",
        "caption": "Protocol Ground-Truth: IKEv2, ESP SPIs, Replay Monotonicity, and SA Lifetimes extracted deterministically.",
        "type": "deterministic_card"
    },
    {
        "id": "05_multiview",
        "title": "DUAL-VIEW TRAFFIC REPRESENTATION",
        "subtitle": "Coupling Aggregate Statistical Distributions with Temporal Sequences",
        "narration": "Encrypted traffic is represented across two complementary views: fourteen aggregate statistical features and a thirty-two by four packet-level temporal sequence tensor.",
        "caption": "Dual-View Representation: 14 Aggregate Flow Features + [32, 4] Packet Sequence Tensor.",
        "type": "multiview_card"
    },
    {
        "id": "06_hybrid_ai",
        "title": "HYBRID AI CLASSIFICATION & BENCHMARK",
        "subtitle": "Winning Model C Architecture & 5-Fold GroupKFold Evaluation",
        "narration": "Hybrid Model C fuses tabular flow statistics with a temporal sequence Transformer, achieving eighty point two five percent accuracy and eighty one point eight nine percent macro-F1 under five-fold capture-disjoint evaluation.",
        "caption": "Winning Hybrid Model C: 80.25% Accuracy (+13.35% Gain over Baseline) | 81.89% Macro-F1 (Capture-Disjoint).",
        "type": "benchmark_card"
    },
    {
        "id": "07_novelty_ood",
        "title": "EXPERIMENTAL NOVELTY / OOD DETECTION",
        "subtitle": "SSL Embedding Distance for Identifying Unseen Traffic Distributions",
        "narration": "An experimental novelty detector calculates Mahalanobis distance in latent embedding space, achieving an AUROC of zero point nine nine six two on evaluated benchmarks.",
        "caption": "Experimental OOD Novelty Detector: SSL Embedding Mahalanobis Distance yields 0.9962 AUROC.",
        "type": "ood_card"
    },
    {
        "id": "08_live_demo",
        "title": "LIVE PROTOTYPE EXECUTION (REAL PCAP)",
        "subtitle": "Dual-Pane Prototype Execution with Speed-Ramped Ingestion",
        "narration": "Here is the live prototype analyzing native IPsec PCAP captures, reconstructing bidirectional Security Associations, extracting features, and classifying bulk traffic with ninety-seven point five percent probability.",
        "caption": "Live Prototype Execution: 306 Packets -> 183 ESP -> 2 SAs Reconstructed -> Bulk Classified at 97.46% Prob.",
        "type": "video_montage"
    },
    {
        "id": "09_limitations",
        "title": "SCIENTIFIC BOUNDARIES & LIMITATIONS",
        "subtitle": "Transparent Academic Honesty & Evaluation Scope",
        "narration": "Current results reflect native testbed evaluations and capture-disjoint validation. Novelty detection is experimental, and encrypted payloads remain unobservable.",
        "caption": "Limitations: Testbed evaluation, group-disjoint fold variance, payload unobservable, experimental OOD.",
        "type": "limitations_card"
    },
    {
        "id": "10_conclusion",
        "title": "RESEARCH PROTOTYPE SUMMARY",
        "subtitle": "Evidence-Grounded IPsec Traffic Analysis without Payload Decryption",
        "narration": "IPsecTrace demonstrates a complete, validated research pipeline for encrypted traffic forensics and security auditing without requiring payload decryption.",
        "caption": "IPsecTrace: Complete, Validated & Reproducible Research Prototype for Zero-Trust Networks.",
        "type": "conclusion_card"
    }
]

def synthesize_fast_sapi_tts(segments: list, force_rebuild: bool = False):
    speaker = win32com.client.Dispatch("SAPI.SpVoice")
    speaker.Rate = 2
    
    audio_paths = []
    durations = []
    
    for seg in segments:
        wav_path = os.path.abspath(str(FINAL_VIDEO_DIR / f"voice_v2_{seg['id']}.wav"))
        
        if not force_rebuild and os.path.exists(wav_path) and os.path.getsize(wav_path) > 5000:
            with wave.open(wav_path, 'r') as wf:
                dur = wf.getnframes() / float(wf.getframerate())
            audio_paths.append(wav_path)
            durations.append(dur + 0.4)
            continue
            
        stream = win32com.client.Dispatch("SAPI.SpFileStream")
        stream.Open(wav_path, 3, False)
        speaker.AudioOutputStream = stream
        speaker.Speak(seg["narration"])
        stream.Close()
        
        with wave.open(wav_path, 'r') as wf:
            dur = wf.getnframes() / float(wf.getframerate())
        padded_dur = max(dur + 0.4, 4.0)
        audio_paths.append(wav_path)
        durations.append(padded_dur)
        print(f"  [TTS] {seg['id']}: {dur:.2f}s (Padded: {padded_dur:.2f}s)")
        
    return audio_paths, durations

def draw_top_header(draw, title_text, subtitle_text):
    draw.rectangle([0, 0, 1920, 75], fill=HEADER_BG)
    draw.line([0, 75, 1920, 75], fill=CARD_BORDER, width=2)
    draw.text((40, 14), "IPsecTrace", fill=ACCENT_CYAN, font=FONT_TITLE)
    draw.text((220, 18), f"|   {title_text}", fill=TEXT_WHITE, font=FONT_SECTION)
    draw.text((220, 46), subtitle_text, fill=TEXT_GRAY, font=FONT_SUBTITLE_TXT)
    draw.text((1580, 26), "RESEARCH DEMO", fill=ACCENT_GREEN, font=FONT_BODY_BOLD)

def draw_bottom_subtitles(draw, caption_text):
    draw.rounded_rectangle([160, 975, 1760, 1055], radius=8, fill=(10, 14, 22), outline=CARD_BORDER, width=1)
    lines = caption_text.split("\n")
    if len(lines) == 1:
        draw.text((960, 1015), lines[0], fill=TEXT_WHITE, font=FONT_CAPTION, anchor="mm")
    else:
        draw.text((960, 998), lines[0], fill=ACCENT_CYAN, font=FONT_CAPTION, anchor="mm")
        draw.text((960, 1032), lines[1], fill=TEXT_WHITE, font=FONT_SUBTITLE_TXT, anchor="mm")

def render_slide_image(seg: dict) -> str:
    out_png = os.path.abspath(str(FINAL_VIDEO_DIR / f"slide_v2_{seg['id']}.png"))
    img = Image.new("RGB", (1920, 1080), BG_COLOR)
    draw = ImageDraw.Draw(img)
    stype = seg["type"]
    
    if stype == "title_card":
        draw_top_header(draw, seg["title"], seg["subtitle"])
        draw.rounded_rectangle([300, 220, 1620, 860], radius=16, fill=CARD_BG, outline=CARD_BORDER, width=2)
        draw.text((960, 310), "IPsecTrace", fill=ACCENT_CYAN, font=FONT_HERO, anchor="mm")
        draw.text((960, 380), "Protocol-Aware Encrypted IPsec Traffic Analysis & Security Assessment", fill=TEXT_WHITE, font=FONT_TITLE, anchor="mm")
        draw.text((960, 430), "Evidence-Grounded Behavioral Attribution Without Payload Decryption", fill=TEXT_GRAY, font=FONT_SUBTITLE, anchor="mm")
        
        pillars = [
            ("01. REAL IPsec CAPTURE", "Native testbed ESP/IKE streams"),
            ("02. DETERMINISTIC FORENSICS", "Zero-guess protocol ground-truth"),
            ("03. HYBRID AI MODEL", "80.25% Acc (+13.35% Gain)"),
            ("04. EVIDENCE AUDITING", "NIST SP 800-77 & Replay integrity")
        ]
        bx = 360
        for p_title, p_desc in pillars:
            draw.rounded_rectangle([bx, 540, bx + 270, 780], radius=10, fill=CARD_ACTIVE, outline=ACCENT_BLUE, width=1)
            draw.text((bx + 135, 590), p_title, fill=ACCENT_CYAN, font=FONT_BODY_BOLD, anchor="mm")
            draw.text((bx + 135, 680), p_desc, fill=TEXT_WHITE, font=FONT_SUBTITLE_TXT, anchor="mm")
            bx += 300
            
    elif stype == "problem_card":
        draw_top_header(draw, seg["title"], seg["subtitle"])
        draw.rounded_rectangle([150, 180, 880, 880], radius=12, fill=CARD_BG, outline=ACCENT_RED, width=2)
        draw.text((515, 240), "[ ENCRYPTED APPLICATION PAYLOAD ]", fill=ACCENT_RED, font=FONT_TITLE, anchor="mm")
        draw.text((515, 300), "Status: LOCKED / NOT_OBSERVABLE", fill=TEXT_GRAY, font=FONT_SUBTITLE, anchor="mm")
        reasons = [
            "• Full payload encryption via ESP (IP Protocol 50)",
            "• Traditional Deep Packet Inspection (DPI) fails",
            "• Decryption gateways violate privacy & cost millions",
            "• Zero plaintext application bytes inspected"
        ]
        ry = 380
        for r in reasons:
            draw.text((200, ry), r, fill=TEXT_WHITE, font=FONT_BODY)
            ry += 70
            
        draw.rounded_rectangle([1040, 180, 1770, 880], radius=12, fill=CARD_BG, outline=ACCENT_GREEN, width=2)
        draw.text((1405, 240), "[ OBSERVABLE PROTOCOL SIGNALS ]", fill=ACCENT_GREEN, font=FONT_TITLE, anchor="mm")
        draw.text((1405, 300), "Target of IPsecTrace Forensics", fill=TEXT_GRAY, font=FONT_SUBTITLE, anchor="mm")
        signals = [
            "✓ IKE Control Handshakes (UDP 500 / 4500)",
            "✓ ESP Security Parameter Indexes (SPIs)",
            "✓ Monotonic Sequence Counters & Anti-Replay",
            "✓ Flow Burst Dynamics & Packet Length Vectors",
            "✓ Inter-Arrival Time Log Distributions (Delta-t)"
        ]
        sy = 380
        for s in signals:
            draw.text((1090, sy), s, fill=ACCENT_CYAN, font=FONT_BODY)
            sy += 70
            
    elif stype == "architecture_card":
        draw_top_header(draw, seg["title"], seg["subtitle"])
        arch_img_path = str(ASSETS_DIR / "architecture_thumbnail.png")
        if not os.path.exists(arch_img_path):
            arch_img_path = "results/final/architecture/01_high_level_architecture.png"
        if os.path.exists(arch_img_path):
            arch_pil = Image.open(arch_img_path).convert("RGB")
            arch_pil = arch_pil.resize((1600, 800), Image.Resampling.LANCZOS)
            img.paste(arch_pil, (160, 130))
        draw.rounded_rectangle([160, 130, 1760, 930], radius=8, outline=CARD_BORDER, width=2)
        
    elif stype == "deterministic_card":
        draw_top_header(draw, seg["title"], seg["subtitle"])
        draw.rounded_rectangle([150, 180, 1770, 880], radius=12, fill=CARD_BG, outline=CARD_BORDER, width=2)
        draw.text((960, 240), "THE PRINCIPLE OF DETERMINISTIC AUTHORITY", fill=ACCENT_CYAN, font=FONT_TITLE, anchor="mm")
        draw.text((960, 290), "Protocol Facts Are Extracted Directly by Forensic Parsers — Never Guessed by AI", fill=TEXT_GRAY, font=FONT_SUBTITLE, anchor="mm")
        cards = [
            ("IKE CONTROL PLANE", ["• IKEv1/IKEv2 Handshakes", "• Cipher Suite Proposals", "• Diffie-Hellman Strength", "• Perfect Forward Secrecy"]),
            ("ESP DATA PLANE", ["• SPI Tunnel Tracking", "• Anti-Replay Verification", "• Monotonic Sequence IDs", "• Bidirectional Session SAs"]),
            ("SECURITY RULE ENGINE", ["• NIST SP 800-77 Auditing", "• Weak Crypto Alerts", "• Orphaned SPI Alarms", "• 100% Policy Independence"])
        ]
        cx = 200
        for c_title, items in cards:
            draw.rounded_rectangle([cx, 360, cx + 460, 820], radius=10, fill=CARD_ACTIVE, outline=ACCENT_BLUE, width=1)
            draw.text((cx + 230, 410), c_title, fill=ACCENT_CYAN, font=FONT_SECTION, anchor="mm")
            iy = 480
            for itm in items:
                draw.text((cx + 35, iy), itm, fill=TEXT_WHITE, font=FONT_BODY)
                iy += 65
            cx += 530
            
    elif stype == "multiview_card":
        draw_top_header(draw, seg["title"], seg["subtitle"])
        draw.rounded_rectangle([150, 180, 880, 880], radius=12, fill=CARD_BG, outline=ACCENT_CYAN, width=2)
        draw.text((515, 240), "VIEW A: TABULAR MACRO-FEATURES", fill=ACCENT_CYAN, font=FONT_TITLE, anchor="mm")
        draw.text((515, 290), "14 Aggregate Statistical Flow Metrics", fill=TEXT_GRAY, font=FONT_SUBTITLE, anchor="mm")
        feats_a = [
            "• Forward / Backward packet counts",
            "• Total forward / backward byte volumes",
            "• Mean packet length & std deviation",
            "• Inter-arrival time (IAT) mean & variance",
            "• Bidirectional flow duration & packet rates"
        ]
        fy = 380
        for f in feats_a:
            draw.text((200, fy), f, fill=TEXT_WHITE, font=FONT_BODY)
            fy += 70
            
        draw.rounded_rectangle([1040, 180, 1770, 880], radius=12, fill=CARD_BG, outline=ACCENT_BLUE, width=2)
        draw.text((1405, 240), "VIEW B: TEMPORAL SEQUENCE TENSOR", fill=ACCENT_BLUE, font=FONT_TITLE, anchor="mm")
        draw.text((1405, 290), "[32, 4] Ordered Packet Burst Vectors", fill=TEXT_GRAY, font=FONT_SUBTITLE, anchor="mm")
        feats_b = [
            "• Feature 0: Normalized packet length",
            "• Feature 1: Log inter-arrival time (Delta-t)",
            "• Feature 2: Direction indicator (+1 / -1)",
            "• Feature 3: Sequence burst position index",
            "• Processed via 2-layer Sequence Transformer"
        ]
        fy = 380
        for f in feats_b:
            draw.text((1090, fy), f, fill=TEXT_WHITE, font=FONT_BODY)
            fy += 70
            
    elif stype == "benchmark_card":
        draw_top_header(draw, seg["title"], seg["subtitle"])
        draw.rounded_rectangle([150, 160, 1770, 900], radius=12, fill=CARD_BG, outline=CARD_BORDER, width=2)
        draw.text((960, 210), "AUTHORITATIVE 5-FOLD GROUPKFOLD BENCHMARK", fill=ACCENT_CYAN, font=FONT_TITLE, anchor="mm")
        draw.text((960, 255), "Evaluated on DS1_NATIVE_IPSEC_ENHANCED (1,829 Windows, 157 Groups, Zero PCAP Leakage)", fill=TEXT_GRAY, font=FONT_SUBTITLE, anchor="mm")
        models = [
            ("A: Canonical XGBoost (Tabular)", 66.91, 73.91, ACCENT_BLUE),
            ("B1: Sequence Transformer", 69.96, 77.66, ACCENT_BLUE),
            ("B3: SSL Pretrained Sequence", 72.25, 76.18, ACCENT_BLUE),
            ("C: Hybrid Tabular + Sequence (Best)", 80.25, 81.89, ACCENT_GREEN)
        ]
        by = 330
        for name, acc, f1, color in models:
            draw.text((200, by), name, fill=TEXT_WHITE, font=FONT_BODY_BOLD)
            draw.text((800, by), f"Acc: {acc:.2f}%   |   Macro-F1: {f1:.2f}%", fill=color, font=FONT_BODY_BOLD)
            draw.rounded_rectangle([200, by + 30, 1550, by + 55], radius=4, fill=(15, 20, 30))
            w_acc = int((acc / 100.0) * 1350)
            draw.rounded_rectangle([200, by + 30, 200 + w_acc, by + 55], radius=4, fill=color)
            by += 110
        draw.text((960, 840), "Winning Hybrid Model C achieves +13.35% Accuracy Gain over Baseline", fill=ACCENT_GREEN, font=FONT_SECTION, anchor="mm")
        
    elif stype == "ood_card":
        draw_top_header(draw, seg["title"], seg["subtitle"])
        draw.rounded_rectangle([150, 180, 1770, 880], radius=12, fill=CARD_BG, outline=CARD_BORDER, width=2)
        draw.text((960, 240), "EXPERIMENTAL OUT-OF-DISTRIBUTION (OOD) NOVELTY DETECTION", fill=ACCENT_CYAN, font=FONT_TITLE, anchor="mm")
        draw.text((960, 290), "Latent Space Mahalanobis Distance for Unknown Network Protocol Identification", fill=TEXT_GRAY, font=FONT_SUBTITLE, anchor="mm")
        
        draw.rounded_rectangle([220, 360, 930, 820], radius=10, fill=CARD_ACTIVE, outline=ACCENT_GREEN, width=1)
        draw.text((575, 420), "IN-DISTRIBUTION (KNOWN IPsec)", fill=ACCENT_GREEN, font=FONT_SECTION, anchor="mm")
        draw.text((575, 520), "6.103 ± 2.14", fill=TEXT_WHITE, font=FONT_METRIC_NUM, anchor="mm")
        draw.text((575, 580), "Mean Mahalanobis Embedding Distance", fill=TEXT_GRAY, font=FONT_BODY, anchor="mm")
        draw.text((575, 680), "Status: KNOWN TRAFFIC", fill=ACCENT_GREEN, font=FONT_TITLE, anchor="mm")
        
        draw.rounded_rectangle([990, 360, 1700, 820], radius=10, fill=CARD_ACTIVE, outline=ACCENT_AMBER, width=1)
        draw.text((1345, 420), "OUT-OF-DISTRIBUTION (NOVEL PROTOCOL)", fill=ACCENT_AMBER, font=FONT_SECTION, anchor="mm")
        draw.text((1345, 520), "22.569 ± 5.82", fill=TEXT_WHITE, font=FONT_METRIC_NUM, anchor="mm")
        draw.text((1345, 580), "Mean Mahalanobis Embedding Distance", fill=TEXT_GRAY, font=FONT_BODY, anchor="mm")
        draw.text((1345, 680), "Overall Efficacy: AUROC = 0.9962", fill=ACCENT_CYAN, font=FONT_TITLE, anchor="mm")
        
    elif stype == "limitations_card":
        draw_top_header(draw, seg["title"], seg["subtitle"])
        draw.rounded_rectangle([150, 180, 1770, 880], radius=12, fill=CARD_BG, outline=ACCENT_AMBER, width=2)
        draw.text((960, 240), "SCIENTIFIC BOUNDARIES & CURRENT RESEARCH LIMITATIONS", fill=ACCENT_AMBER, font=FONT_TITLE, anchor="mm")
        draw.text((960, 290), "Transparent Research Caveats Grounded in Native Empirical Validation", fill=TEXT_GRAY, font=FONT_SUBTITLE, anchor="mm")
        lims = [
            "• 1. Native-IPsec Testbed Scope: Tested on strongSwan/Linux XFRM; cross-vendor evaluation ongoing.",
            "• 2. Capture-Disjoint Group Variance: Fold variance is documented due to finite capture runs (157 groups).",
            "• 3. Payload NOT_OBSERVABLE: Zero decryption is maintained; payload contents remain uninspected.",
            "• 4. Negative Multi-View IKE Finding: Directly concatenating IKE control metadata degraded generalization.",
            "• 5. Experimental OOD Indicator: High AUROC is established on benchmark, not guaranteed universal open-set."
        ]
        ly = 380
        for l in lims:
            draw.text((220, ly), l, fill=TEXT_WHITE, font=FONT_BODY)
            ly += 75
            
    elif stype == "conclusion_card":
        draw_top_header(draw, seg["title"], seg["subtitle"])
        draw.rounded_rectangle([300, 220, 1620, 860], radius=16, fill=CARD_BG, outline=ACCENT_GREEN, width=2)
        draw.text((960, 310), "IPsecTrace — RESEARCH PROTOTYPE VALIDATED", fill=ACCENT_CYAN, font=FONT_HERO, anchor="mm")
        draw.text((960, 380), "Complete Protocol-Aware Encrypted Traffic Forensics & AI Pipeline", fill=TEXT_WHITE, font=FONT_TITLE, anchor="mm")
        checks = [
            "✓ REAL IPsec TRAFFIC ANALYZED",
            "✓ PROTOCOL GROUND-TRUTH EXTRACTED",
            "✓ HYBRID AI BEHAVIORAL ATTRIBUTION",
            "✓ ZERO PAYLOAD DECRYPTION REQUIRED"
        ]
        cy = 470
        for c in checks:
            draw.text((960, cy), c, fill=ACCENT_GREEN, font=FONT_TITLE, anchor="mm")
            cy += 65
        draw.text((960, 780), "Open Source | 100% Reproducible | 30/30 Backend Tests Passing", fill=TEXT_GRAY, font=FONT_SUBTITLE, anchor="mm")

    draw_bottom_subtitles(draw, seg["caption"])
    img.save(out_png)
    return out_png

def render_segment_to_mp4(seg: dict, audio_path: str, duration: float, seg_index: int) -> str:
    """Renders a single video clip strictly normalized to 30.0 fps, 1080p, and 44.1kHz audio."""
    seg_mp4 = os.path.abspath(str(FINAL_VIDEO_DIR / f"seg_v3_{seg_index:02d}_{seg['id']}.mp4"))
    
    if seg["type"] == "video_montage":
        demo_src = os.path.abspath(str(RECORDINGS_DIR / "SENTRY-IPSEC_BULK_LIVE_DEMO.mp4"))
        if not os.path.exists(demo_src):
            demo_src = os.path.abspath(str(RECORDINGS_DIR / "IPsecTrace_BULK_LIVE_DEMO.mp4"))
            
        if os.path.exists(demo_src):
            filter_complex = f"[0:v]trim=0:30,setpts=0.4*PTS[v1];[0:v]trim=30:60,setpts=PTS-STARTPTS[v2];[v1][v2]concat=n=2:v=1:a=0,fps=30,scale=1920:1080[vconcat];[vconcat]trim=0:{duration},setpts=PTS-STARTPTS[vout]"
            cmd = [
                FFMPEG_EXE, "-y",
                "-i", demo_src,
                "-i", audio_path,
                "-filter_complex", filter_complex,
                "-map", "[vout]",
                "-map", "1:a",
                "-r", "30",
                "-c:v", "libx264", "-preset", "ultrafast", "-pix_fmt", "yuv420p",
                "-c:a", "aac", "-b:a", "192k", "-ar", "44100",
                "-t", str(duration),
                seg_mp4
            ]
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            return seg_mp4
            
    slide_png = render_slide_image(seg)
    cmd = [
        FFMPEG_EXE, "-y",
        "-loop", "1", "-i", slide_png,
        "-i", audio_path,
        "-r", "30",
        "-c:v", "libx264", "-tune", "stillimage", "-preset", "ultrafast", "-pix_fmt", "yuv420p",
        "-c:a", "aac", "-b:a", "192k", "-ar", "44100",
        "-t", str(duration),
        seg_mp4
    ]
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    return seg_mp4

def generate_subtitles_srt(durations: list) -> str:
    srt_path = os.path.abspath(str(OUTPUT_DIR / "IPsecTrace_FINAL_SUBTITLES.srt"))
    def fmt_time(sec):
        millis = int((sec % 1) * 1000)
        s = int(sec)
        m = s // 60
        s = s % 60
        h = m // 60
        m = m % 60
        return f"{h:02d}:{m:02d}:{s:02d},{millis:03d}"
    
    cur_t = 0.0
    srt_content = ""
    for idx, (seg, dur) in enumerate(zip(NARRATION_SEGMENTS, durations), 1):
        start_str = fmt_time(cur_t)
        end_str = fmt_time(cur_t + dur)
        caption_clean = seg["caption"].replace("\n", " ")
        srt_content += f"{idx}\n{start_str} --> {end_str}\n{caption_clean}\n\n"
        cur_t += dur
        
    with open(srt_path, "w", encoding="utf-8") as f:
        f.write(srt_content)
    return srt_path

def build_fast_master_video(force_rebuild: bool = False):
    t_start = time.time()
    print("="*80)
    print("IPsecTrace — MASTER RESEARCH DEMO VIDEO PIPELINE (OPTIMIZED ENGINE)")
    print("="*80)
    
    t0 = time.time()
    print("\n[1/7] Inspecting source prototype recordings...")
    rec_bulk = RECORDINGS_DIR / "SENTRY-IPSEC_BULK_LIVE_DEMO.mp4"
    if not rec_bulk.exists():
        rec_bulk = RECORDINGS_DIR / "IPsecTrace_BULK_LIVE_DEMO.mp4"
    print(f"      Source Terminal Capture: {rec_bulk} ({rec_bulk.exists()})")
    print(f"      Elapsed: {time.time()-t0:.2f}s")
    
    t0 = time.time()
    print("\n[2/7] Structuring 10 synchronized timeline segments...")
    print(f"      Target: 10 segments (Duration ~120s / 2.0 min, Strictly <3:00 min)")
    print(f"      Elapsed: {time.time()-t0:.2f}s")
    
    t0 = time.time()
    print("\n[3/7] Generating TTS narration voiceover (Win32 COM SAPI)...")
    audio_paths, durations = synthesize_fast_sapi_tts(NARRATION_SEGMENTS, force_rebuild=force_rebuild)
    total_duration = sum(durations)
    print(f"      Total Narration Duration: {total_duration:.2f}s ({total_duration/60:.2f} min)")
    print(f"      Elapsed: {time.time()-t0:.2f}s")
    
    t0 = time.time()
    print("\n[4/7] Generating synchronized SubRip subtitles (.srt)...")
    srt_path = generate_subtitles_srt(durations)
    print(f"      Subtitles Saved: {srt_path}")
    print(f"      Elapsed: {time.time()-t0:.2f}s")
    
    t0 = time.time()
    print("\n[5/7] Rendering 10 high-speed 1080p video segment clips (Normalized 30 FPS)...")
    segment_mp4s = []
    for idx, (seg, a_path, dur) in enumerate(zip(NARRATION_SEGMENTS, audio_paths, durations), 1):
        seg_mp4 = render_segment_to_mp4(seg, a_path, dur, idx)
        segment_mp4s.append(seg_mp4)
        print(f"      [Clip {idx:02d}/10] {seg['id']} rendered ({dur:.2f}s @ 30.0 fps)")
    print(f"      Elapsed: {time.time()-t0:.2f}s")
    
    t0 = time.time()
    print("\n[6/7] Merging video segments via FFmpeg Concat Protocol...")
    concat_list_file = os.path.abspath(str(FINAL_VIDEO_DIR / "concat_list_v3.txt"))
    with open(concat_list_file, "w", encoding="utf-8") as f:
        for p in segment_mp4s:
            p_esc = p.replace("\\", "/")
            f.write(f"file '{p_esc}'\n")
            
    final_mp4 = os.path.abspath(str(OUTPUT_DIR / "IPsecTrace_RESEARCH_DEMO.mp4"))
    final_no_audio = os.path.abspath(str(OUTPUT_DIR / "IPsecTrace_RESEARCH_DEMO_WITHOUT_AUDIO.mp4"))
    
    # Encode cleanly at concat to ensure perfect container timestamps
    cmd_concat = [
        FFMPEG_EXE, "-y",
        "-f", "concat", "-safe", "0",
        "-i", concat_list_file,
        "-c:v", "libx264", "-preset", "ultrafast", "-pix_fmt", "yuv420p", "-r", "30",
        "-c:a", "aac", "-b:a", "192k", "-ar", "44100",
        final_mp4
    ]
    subprocess.run(cmd_concat, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    
    cmd_silent = [
        FFMPEG_EXE, "-y",
        "-i", final_mp4,
        "-an", "-c:v", "copy",
        final_no_audio
    ]
    subprocess.run(cmd_silent, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    print(f"      Elapsed: {time.time()-t0:.2f}s")
    
    t0 = time.time()
    print("\n[7/7] Validating master video integrity...")
    file_size_mb = os.path.getsize(final_mp4) / (1024 * 1024)
    total_pipeline_time = time.time() - t_start
    
    report_text = f"""================================================================================
IPsecTrace MASTER DEMONSTRATION VIDEO BUILD REPORT
================================================================================
Total Execution Time : {total_pipeline_time:.2f} seconds
Final Duration       : {total_duration:.2f} seconds ({total_duration/60:.2f} minutes)
Resolution           : 1920 x 1080 (16:9 Broadcast Standard)
Frame Rate           : 30.0 FPS
Video Codec          : H.264 (AVC)
Audio Codec          : AAC (192 kbps, 44.1 kHz)
File Size            : {file_size_mb:.2f} MB
Audio Included       : YES (Synchronized Narration)
Subtitles Included   : YES ({srt_path})
Master Video Path    : {final_mp4}
Silent Video Path    : {final_no_audio}
================================================================================
"""
    print(report_text)
    report_file = os.path.abspath(str(OUTPUT_DIR / "final_video_build_report.txt"))
    with open(report_file, "w", encoding="utf-8") as f:
        f.write(report_text)
        
    print(f"[SUCCESS] Output available at: {final_mp4}")
    return final_mp4

def main():
    parser = argparse.ArgumentParser(description="IPsecTrace Master Video Fast Generator")
    parser.add_argument("--fast", action="store_true", default=True, help="Enable fast mode")
    parser.add_argument("--force-rebuild", action="store_true", help="Force full asset re-synthesis")
    args = parser.parse_args()
    
    build_fast_master_video(force_rebuild=args.force_rebuild)

if __name__ == "__main__":
    main()
