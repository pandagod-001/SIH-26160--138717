import matplotlib.pyplot as plt
import matplotlib.patches as patches
import os

def create_architecture_and_security_figures():
    arch_dir = "IPsecTrace_FINAL_MASTER/figures/architecture"
    sec_dir = "IPsecTrace_FINAL_MASTER/figures/security"
    hist_dir = "IPsecTrace_FINAL_MASTER/figures/historical"
    os.makedirs(arch_dir, exist_ok=True)
    os.makedirs(sec_dir, exist_ok=True)
    os.makedirs(hist_dir, exist_ok=True)

    # 1. System Architecture Diagram
    fig, ax = plt.subplots(figsize=(12, 7))
    ax.axis('off')

    # Draw boxes
    boxes = [
        ("Layer 1: Testbed & Ingestion", ["Linux XFRM Namespaces", "Scapy Offline PCAP Parser", "Network Emulation (tc netem)"], 0.05, 0.65, 0.25, 0.28, '#D4E6F1'),
        ("Layer 2: Protocol Planes", ["Control Plane: IKEv2 Parser", "Data Plane: ESP/AH Extractor", "SA / SPI State Reconstruction"], 0.38, 0.65, 0.25, 0.28, '#D5F5E3'),
        ("Layer 3: Evidence Fusion", ["Cross-Plane Session Graph", "Behavioral Feature Extractor", "Observability Matrix"], 0.71, 0.65, 0.25, 0.28, '#FCF3CF'),
        ("Layer 4: AI Inference Engine", ["GroupKFold Random Forest / XGB", "Quantile & Directional Features", "OOD Detector (tau=0.60)"], 0.20, 0.15, 0.28, 0.35, '#FADBD8'),
        ("Layer 5: Security Policy & UI", ["Deterministic RFC Rules", "Confidence & Severity Decoupling", "Analyst Dashboard & Evidence Trace"], 0.58, 0.15, 0.28, 0.35, '#E8DAEF'),
    ]

    for title, items, x, y, w, h, color in boxes:
        rect = patches.FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02", facecolor=color, edgecolor='#2C3E50', linewidth=1.5)
        ax.add_patch(rect)
        ax.text(x + w/2, y + h - 0.04, title, ha='center', va='top', fontsize=11, fontweight='bold', color='#1A5276')
        for idx, item in enumerate(items):
            ax.text(x + 0.02, y + h - 0.10 - (idx * 0.07), f"• {item}", ha='left', va='top', fontsize=9.5, color='#2C3E50')

    # Arrows
    ax.annotate('', xy=(0.37, 0.79), xytext=(0.31, 0.79), arrowprops=dict(arrowstyle="->", lw=2, color='#2C3E50'))
    ax.annotate('', xy=(0.70, 0.79), xytext=(0.64, 0.79), arrowprops=dict(arrowstyle="->", lw=2, color='#2C3E50'))
    ax.annotate('', xy=(0.34, 0.51), xytext=(0.50, 0.64), arrowprops=dict(arrowstyle="->", lw=2, color='#2C3E50'))
    ax.annotate('', xy=(0.72, 0.51), xytext=(0.83, 0.64), arrowprops=dict(arrowstyle="->", lw=2, color='#2C3E50'))

    plt.title("IPsecTrace Layered System Architecture & Cross-Plane Pipeline", fontsize=14, fontweight='bold', pad=20)
    plt.tight_layout()
    plt.savefig(os.path.join(arch_dir, "system_architecture_diagram.png"), dpi=300)
    plt.close()

    # 2. Security Decision Matrix
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.axis('off')

    sec_boxes = [
        ("Deterministic Control-Plane Checks (RFC 7296 / 4303)", 
         ["1. IKE Proposal Compliance (Approved AES-GCM / SHA-256)",
          "2. Weak Cipher / Legacy Flagging (3DES, MD5 Prohibited)",
          "3. ESP SPI Negotiation Validation",
          "4. Anti-Replay Sequence Window Tracking"], 0.1, 0.55, 0.8, 0.38, '#EAEDED'),
        ("AI-Assisted Encrypted Flow Assessment", 
         ["1. Behavioral Traffic Categorization (Web, Bulk, Interactive)",
          "2. Directional Asymmetry & Quantile Payload Modeling",
          "3. Out-of-Distribution (OOD) Unknown Flow Detection",
          "4. Explicit Confidence Reporting (Mean Max Prob)"], 0.1, 0.08, 0.8, 0.38, '#FEF9E7')
    ]

    for title, items, x, y, w, h, color in sec_boxes:
        rect = patches.FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02", facecolor=color, edgecolor='#34495E', linewidth=1.5)
        ax.add_patch(rect)
        ax.text(x + w/2, y + h - 0.05, title, ha='center', va='top', fontsize=12, fontweight='bold', color='#1B4F72')
        for idx, item in enumerate(items):
            ax.text(x + 0.04, y + h - 0.12 - (idx * 0.06), item, ha='left', va='top', fontsize=10.5, color='#2C3E50')

    plt.title("IPsecTrace Security Assessment & Decision Engine Architecture", fontsize=14, fontweight='bold', pad=20)
    plt.tight_layout()
    plt.savefig(os.path.join(sec_dir, "security_assessment_matrix.png"), dpi=300)
    plt.close()

    # 3. Copy baseline figure to historical
    src_fig = "results/figures/phase2_fig1_leakage_benchmark.png"
    if os.path.exists(src_fig):
        import shutil
        shutil.copy(src_fig, os.path.join(hist_dir, "phase1_leakage_historical_benchmark.png"))

    print("[SUCCESS] Architecture, security, and historical figures generated!")

if __name__ == "__main__":
    create_architecture_and_security_figures()
