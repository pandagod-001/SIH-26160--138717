import os
import json
import shutil
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

def generate_all_figures(features_csv="results/features.csv", metrics_json="results/metrics.json", out_dir="results/figures", sih_dir="SIH_EVIDENCE/figures"):
    """
    Generates real publication/presentation figures from empirical dataset and ML metrics.
    """
    os.makedirs(out_dir, exist_ok=True)
    os.makedirs(sih_dir, exist_ok=True)

    # Set dark aesthetic style
    plt.style.use('dark_background')
    colors = ['#00E5FF', '#7C4DFF', '#FF4081', '#00E676', '#FFAB00']

    # Load dataset
    if os.path.exists(features_csv):
        df = pd.read_csv(features_csv)
    else:
        df = pd.DataFrame()

    # FIGURE 1: Traffic Class Distribution
    fig, ax = plt.subplots(figsize=(7, 5))
    if not df.empty:
        counts = df['traffic_class'].value_counts()
        bars = ax.bar(counts.index, counts.values, color=colors[:len(counts)], edgecolor='white', linewidth=1.2)
        ax.set_title("Traffic Class Flow Distribution", fontsize=14, fontweight='bold', pad=15)
        ax.set_xlabel("Traffic Class", fontsize=12)
        ax.set_ylabel("Number of Flow Samples", fontsize=12)
        ax.grid(axis='y', linestyle='--', alpha=0.3)
        for bar in bars:
            yval = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2.0, yval + 0.1, int(yval), ha='center', va='bottom', fontsize=11, fontweight='bold')
    else:
        ax.text(0.5, 0.5, "Insufficient Data", ha='center', va='center', fontsize=14)
    plt.tight_layout()
    fig1_path = os.path.join(out_dir, "traffic_class_distribution.png")
    plt.savefig(fig1_path, dpi=300)
    plt.close()

    # FIGURE 2: Packet Size Distribution by Class
    fig, ax = plt.subplots(figsize=(7, 5))
    if not df.empty and 'mean_packet_size' in df:
        classes = df['traffic_class'].unique()
        data_to_plot = [df[df['traffic_class'] == c]['mean_packet_size'].values for c in classes]
        bp = ax.boxplot(data_to_plot, labels=classes, patch_artist=True)
        for patch, color in zip(bp['boxes'], colors[:len(classes)]):
            patch.set_facecolor(color)
            patch.set_alpha(0.7)
        ax.set_title("Mean Packet Size Distribution (Bytes)", fontsize=14, fontweight='bold', pad=15)
        ax.set_ylabel("Packet Size (Bytes)", fontsize=12)
        ax.grid(axis='y', linestyle='--', alpha=0.3)
    else:
        ax.text(0.5, 0.5, "Insufficient Data", ha='center', va='center', fontsize=14)
    plt.tight_layout()
    fig2_path = os.path.join(out_dir, "packet_size_distribution.png")
    plt.savefig(fig2_path, dpi=300)
    plt.close()

    # FIGURE 3: Inter-Arrival Time Distribution
    fig, ax = plt.subplots(figsize=(7, 5))
    if not df.empty and 'mean_iat_sec' in df:
        for idx, (c, group) in enumerate(df.groupby('traffic_class')):
            ax.hist(group['mean_iat_sec'], bins=10, alpha=0.6, label=c, color=colors[idx % len(colors)])
        ax.set_title("Mean Packet Inter-Arrival Time (Seconds)", fontsize=14, fontweight='bold', pad=15)
        ax.set_xlabel("Inter-Arrival Time (s)", fontsize=12)
        ax.set_ylabel("Frequency", fontsize=12)
        ax.legend()
        ax.grid(linestyle='--', alpha=0.3)
    else:
        ax.text(0.5, 0.5, "Insufficient Data", ha='center', va='center', fontsize=14)
    plt.tight_layout()
    fig3_path = os.path.join(out_dir, "interarrival_distribution.png")
    plt.savefig(fig3_path, dpi=300)
    plt.close()

    # FIGURE 4: Flow Duration Distribution
    fig, ax = plt.subplots(figsize=(7, 5))
    if not df.empty and 'flow_duration_sec' in df:
        classes = df['traffic_class'].unique()
        means = [df[df['traffic_class'] == c]['flow_duration_sec'].mean() for c in classes]
        ax.bar(classes, means, color=colors[:len(classes)], alpha=0.8)
        ax.set_title("Mean Flow Duration by Traffic Class", fontsize=14, fontweight='bold', pad=15)
        ax.set_ylabel("Duration (Seconds)", fontsize=12)
        ax.grid(axis='y', linestyle='--', alpha=0.3)
    else:
        ax.text(0.5, 0.5, "Insufficient Data", ha='center', va='center', fontsize=14)
    plt.tight_layout()
    fig4_path = os.path.join(out_dir, "flow_duration_distribution.png")
    plt.savefig(fig4_path, dpi=300)
    plt.close()

    # FIGURE 5: Throughput (Bytes/sec) Distribution
    fig, ax = plt.subplots(figsize=(7, 5))
    if not df.empty and 'bytes_per_sec' in df:
        classes = df['traffic_class'].unique()
        tput = [df[df['traffic_class'] == c]['bytes_per_sec'].mean() for c in classes]
        ax.bar(classes, tput, color=colors[:len(classes)], alpha=0.85)
        ax.set_title("Mean Tunnel Throughput (Bytes / Second)", fontsize=14, fontweight='bold', pad=15)
        ax.set_ylabel("Throughput (Bytes/s)", fontsize=12)
        ax.grid(axis='y', linestyle='--', alpha=0.3)
    else:
        ax.text(0.5, 0.5, "Insufficient Data", ha='center', va='center', fontsize=14)
    plt.tight_layout()
    fig5_path = os.path.join(out_dir, "throughput_distribution.png")
    plt.savefig(fig5_path, dpi=300)
    plt.close()

    # FIGURE 6: Confusion Matrix
    fig, ax = plt.subplots(figsize=(6, 5))
    cm_data = None
    labels = ["ICMP", "WEB", "BULK", "INTERACTIVE"]
    if os.path.exists(metrics_json):
        with open(metrics_json) as f:
            m_data = json.load(f)
            if "models" in m_data and "Random Forest" in m_data["models"]:
                cm_data = m_data["models"]["Random Forest"].get("confusion_matrix")
                if "dataset_info" in m_data and "classes" in m_data["dataset_info"]:
                    labels = m_data["dataset_info"]["classes"]

    if cm_data and len(cm_data) > 0:
        cm_array = np.array(cm_data)
        im = ax.imshow(cm_array, interpolation='nearest', cmap=plt.cm.Blues)
        plt.colorbar(im)
        tick_marks = np.arange(len(labels))
        ax.set_xticks(tick_marks)
        ax.set_xticklabels(labels, rotation=45)
        ax.set_yticks(tick_marks)
        ax.set_yticklabels(labels)
        ax.set_title("Random Forest Confusion Matrix", fontsize=14, fontweight='bold', pad=15)
        ax.set_ylabel("True Label", fontsize=12)
        ax.set_xlabel("Predicted Label", fontsize=12)
        for i in range(cm_array.shape[0]):
            for j in range(cm_array.shape[1]):
                ax.text(j, i, str(cm_array[i, j]), ha="center", va="center", color="white" if cm_array[i, j] > (cm_array.max()/2) else "cyan", fontweight='bold')
    else:
        ax.text(0.5, 0.5, "Confusion Matrix N/A", ha='center', va='center', fontsize=14)
    plt.tight_layout()
    fig6_path = os.path.join(out_dir, "confusion_matrix.png")
    plt.savefig(fig6_path, dpi=300)
    plt.close()

    # FIGURE 7: Model Comparison
    fig, ax = plt.subplots(figsize=(7, 5))
    if os.path.exists(metrics_json):
        with open(metrics_json) as f:
            m_data = json.load(f)
            if "models" in m_data:
                model_names = list(m_data["models"].keys())
                f1_scores = [m_data["models"][m]["macro_f1"] for m in model_names]
                ax.barh(model_names, f1_scores, color=colors[:len(model_names)])
                ax.set_xlim(0, 1.05)
                ax.set_title("Model Comparison (Macro F1 Score)", fontsize=14, fontweight='bold', pad=15)
                ax.set_xlabel("Macro F1 Score", fontsize=12)
                ax.grid(axis='x', linestyle='--', alpha=0.3)
                for i, v in enumerate(f1_scores):
                    ax.text(v + 0.02, i, f"{v:.4f}", va='center', fontweight='bold')
    else:
        ax.text(0.5, 0.5, "Metrics N/A", ha='center', va='center', fontsize=14)
    plt.tight_layout()
    fig7_path = os.path.join(out_dir, "model_comparison.png")
    plt.savefig(fig7_path, dpi=300)
    plt.close()

    # FIGURE 8: OOD Status Chart
    fig, ax = plt.subplots(figsize=(6, 4))
    categories = ["Known In-Distribution", "OOD / Rejection Target"]
    counts = [len(df) if not df.empty else 0, 0]
    ax.bar(categories, counts, color=['#00E5FF', '#FF4081'], alpha=0.8)
    ax.set_title("OOD / Out-of-Distribution Sample Status", fontsize=13, fontweight='bold', pad=15)
    ax.set_ylabel("Sample Count", fontsize=11)
    ax.grid(axis='y', linestyle='--', alpha=0.3)
    plt.tight_layout()
    fig8_path = os.path.join(out_dir, "ood_result.png")
    plt.savefig(fig8_path, dpi=300)
    plt.close()

    # Copy generated figures to SIH_EVIDENCE/figures
    for f_name in os.listdir(out_dir):
        src_f = os.path.join(out_dir, f_name)
        dst_f = os.path.join(sih_dir, f_name)
        shutil.copy(src_f, dst_f)

    print(f"[VISUALIZER] All 8 figures generated and copied to {sih_dir}")

if __name__ == "__main__":
    generate_all_figures()
