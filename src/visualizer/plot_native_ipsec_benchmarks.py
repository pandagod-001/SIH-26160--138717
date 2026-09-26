import matplotlib.pyplot as plt
import numpy as np
import os
import json

def plot_native_ipsec_benchmarks():
    out_dirs = [
        "results/figures",
        "IPsecTrace_FINAL_MASTER/figures",
        "IPsecTrace_FINAL_MASTER/figures/machine_learning",
        "IPsecTrace_FINAL_MASTER/figures/ablation"
    ]
    for d in out_dirs:
        os.makedirs(d, exist_ok=True)

    # 1. Pipeline Comparison Chart: Baseline (1.0s) vs Enhanced (3.0s + Quantiles)
    models = ['Random Forest', 'XGBoost']
    baseline_f1 = [57.14, 55.96]
    baseline_std = [7.80, 6.93]
    enhanced_f1 = [69.36, 70.53]
    enhanced_std = [7.87, 6.03]

    x = np.arange(len(models))
    width = 0.35

    fig, ax = plt.subplots(figsize=(8, 5))
    rects1 = ax.bar(x - width/2, baseline_f1, width, yerr=baseline_std, label='Baseline (1.0s Window, 9 Summary Stats)', color='#4A90E2', capsize=5)
    rects2 = ax.bar(x + width/2, enhanced_f1, width, yerr=enhanced_std, label='Enhanced (3.0s Window, 14 Features + Quantiles)', color='#50E3C2', capsize=5)

    ax.set_ylabel('Macro-F1 Score (%)', fontsize=12)
    ax.set_title('Pure Native IPsec ESP Benchmark: Baseline vs. Enhanced Feature Pipeline\n(5-Fold GroupKFold, 0% Session Leakage)', fontsize=13, pad=15)
    ax.set_xticks(x)
    ax.set_xticklabels(models, fontsize=11)
    ax.set_ylim(0, 100)
    ax.axhline(25.0, color='red', linestyle='--', linewidth=1.5, label='Random Chance Baseline (4 Classes = 25%)')
    ax.legend(loc='lower right', fontsize=10)
    ax.grid(axis='y', linestyle=':', alpha=0.6)

    for rect in rects1:
        h = rect.get_height()
        ax.annotate(f'{h:.1f}%', xy=(rect.get_x() + rect.get_width() / 2, h), xytext=(0, 3),
                    textcoords="offset points", ha='center', va='bottom', fontweight='bold')
    for rect in rects2:
        h = rect.get_height()
        ax.annotate(f'{h:.1f}%', xy=(rect.get_x() + rect.get_width() / 2, h), xytext=(0, 3),
                    textcoords="offset points", ha='center', va='bottom', fontweight='bold')

    plt.tight_layout()
    for d in out_dirs:
        plt.savefig(os.path.join(d, "native_ipsec_pipeline_comparison.png"), dpi=300)
    plt.close()

    # 2. Per-Class F1 Score Breakdown on Native IPsec ESP
    classes = ['ICMP', 'BULK', 'WEB', 'INTERACTIVE']
    f1_scores = [97.8, 95.5, 57.9, 44.5] # Enhanced pipeline classwise
    colors = ['#2ECC71', '#3498DB', '#E67E22', '#E74C3C']

    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar(classes, f1_scores, color=colors, width=0.55)
    ax.set_ylabel('F1 Score (%)', fontsize=12)
    ax.set_title('Native IPsec ESP Class-Wise Separation (Enhanced Pipeline)\n(Encrypted Tunnel Payload Geometry)', fontsize=13, pad=15)
    ax.set_ylim(0, 110)
    ax.grid(axis='y', linestyle=':', alpha=0.6)

    for bar in bars:
        h = bar.get_height()
        ax.annotate(f'{h:.1f}%', xy=(bar.get_x() + bar.get_width() / 2, h), xytext=(0, 3),
                    textcoords="offset points", ha='center', va='bottom', fontweight='bold', fontsize=11)

    plt.tight_layout()
    for d in out_dirs:
        plt.savefig(os.path.join(d, "native_ipsec_classwise_f1.png"), dpi=300)
    plt.close()

    # 3. Native IPsec Feature Ablation Chart
    subsets = [
        'Set E (No IAT: Size+Rate)',
        'Set C (Throughput Only)',
        'Set D (Packet Size Only)',
        'Set A (All 9 Features)',
        'Set B (Timing Only)',
        'Set F (IAT Only)',
        'Set G (ByteRate Only)'
    ]
    f1_ablation = [59.35, 59.11, 58.15, 57.14, 52.13, 51.60, 42.66]

    fig, ax = plt.subplots(figsize=(9, 5))
    y_pos = np.arange(len(subsets))
    bars = ax.barh(y_pos, f1_ablation, color='#2980B9', height=0.6)
    ax.set_yticks(y_pos)
    ax.set_yticklabels(subsets, fontsize=10)
    ax.invert_yaxis()
    ax.set_xlabel('Macro-F1 Score (%)', fontsize=12)
    ax.set_title('Native IPsec Feature Ablation: Payload Size & Throughput vs. Timing Jitter', fontsize=12, pad=15)
    ax.set_xlim(0, 75)
    ax.grid(axis='x', linestyle=':', alpha=0.6)

    for bar in bars:
        w = bar.get_width()
        ax.annotate(f'{w:.2f}%', xy=(w, bar.get_y() + bar.get_height() / 2), xytext=(5, 0),
                    textcoords="offset points", ha='left', va='center', fontweight='bold')

    plt.tight_layout()
    for d in out_dirs:
        plt.savefig(os.path.join(d, "native_ipsec_feature_ablation.png"), dpi=300)
    plt.close()

    print("[SUCCESS] All 3 Pure Native IPsec ESP Benchmark figures plotted and saved!")

if __name__ == "__main__":
    plot_native_ipsec_benchmarks()
