"""
plot_phase2_charts.py — IPsecTrace Phase 2 Scientific Visualizer
Generates 8 high-resolution publication-quality figures:
1. Leakage Analysis: Random vs Grouped CV Macro-F1 comparison (bar chart)
2. Model Comparison on Combined Benchmark (grouped bar chart)
3. Confusion Matrix / Error Forensics (horizontal bar chart)
4. Feature Ablation Progression (horizontal bar chart)
5. XGBoost Hyperparameter Sensitivity Surface / Heatmap
6. Cross-Dataset Transferability Gap (bar chart)
7. Calibration Curve / Reliability Diagram
8. Out-of-Distribution Rejection Confidence Density / Histogram
Saves all figures to results/figures/phase2_*.png.
"""
import os
import json
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

plt.style.use("seaborn-v0_8-whitegrid" if "seaborn-v0_8-whitegrid" in plt.style.available else "default")
plt.rcParams["font.sans-serif"] = "DejaVu Sans"
plt.rcParams["axes.edgecolor"] = "#cccccc"
plt.rcParams["axes.linewidth"] = 0.8

def generate_all_charts(metrics_path="results/metrics.json", output_dir="results/figures"):
    os.makedirs(output_dir, exist_ok=True)
    
    if not os.path.exists(metrics_path):
        print(f"[PlotCharts] {metrics_path} does not exist yet. Run evaluate_models.py first.")
        return

    with open(metrics_path, "r", encoding="utf-8") as f:
        metrics = json.load(f)
        
    print(f"[PlotCharts] Generating 8 publication-grade charts to {output_dir}...")

    # -------------------------------------------------------------
    # Figure 1: Leakage Analysis (Random vs Grouped CV)
    # -------------------------------------------------------------
    exp1 = metrics.get("exp1_leakage_check", {})
    if exp1:
        rand_scores = exp1.get("random_kfold", {})
        grp_scores = exp1.get("grouped_kfold", {})
        models = list(rand_scores.keys())
        
        x = np.arange(len(models))
        width = 0.35
        
        fig, ax = plt.subplots(figsize=(8, 4.5), dpi=300)
        r_bars = ax.bar(x - width/2, [rand_scores[m] for m in models], width, label="Random 5-Fold CV (Optimistic)", color="#3498db")
        g_bars = ax.bar(x + width/2, [grp_scores[m] for m in models], width, label="Grouped 5-Fold CV (Leakage-Free)", color="#e74c3c")
        
        ax.set_ylabel("Macro-F1 Score", fontsize=11, fontweight="bold")
        ax.set_title("Fig 1: Impact of Data Leakage on Model Validation (Tier 1)", fontsize=12, fontweight="bold", pad=12)
        ax.set_xticks(x)
        ax.set_xticklabels(models, fontsize=10)
        ax.set_ylim(0, 1.1)
        ax.legend(frameon=True, facecolor="white")
        
        for bar in r_bars + g_bars:
            h = bar.get_height()
            ax.annotate(f"{h:.2f}", xy=(bar.get_x() + bar.get_width()/2, h),
                        xytext=(0, 3), textcoords="offset points", ha="center", va="bottom", fontsize=8)
                        
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, "phase2_fig1_leakage_benchmark.png"))
        plt.close()
        print("  [OK] Saved Fig 1: Leakage Benchmark")

    # -------------------------------------------------------------
    # Figure 2: Model Comparison on Combined Benchmark
    # -------------------------------------------------------------
    exp3 = metrics.get("exp3_combined_benchmark", {})
    if exp3:
        models = list(exp3.keys())
        f1_vals = [exp3[m]["macro_f1"] for m in models]
        acc_vals = [exp3[m]["accuracy"] for m in models]
        
        x = np.arange(len(models))
        width = 0.35
        
        fig, ax = plt.subplots(figsize=(8, 4.5), dpi=300)
        b1 = ax.bar(x - width/2, acc_vals, width, label="Accuracy", color="#2ecc71")
        b2 = ax.bar(x + width/2, f1_vals, width, label="Macro-F1", color="#9b59b6")
        
        ax.set_ylabel("Score", fontsize=11, fontweight="bold")
        ax.set_title("Fig 2: Large-Scale Combined Benchmark Performance (18,842 Flows)", fontsize=12, fontweight="bold", pad=12)
        ax.set_xticks(x)
        ax.set_xticklabels(models, fontsize=10)
        ax.set_ylim(0, 1.1)
        ax.legend(frameon=True, facecolor="white")
        
        for bar in b1 + b2:
            h = bar.get_height()
            ax.annotate(f"{h:.2f}", xy=(bar.get_x() + bar.get_width()/2, h),
                        xytext=(0, 3), textcoords="offset points", ha="center", va="bottom", fontsize=8)
                        
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, "phase2_fig2_model_comparison.png"))
        plt.close()
        print("  [OK] Saved Fig 2: Model Comparison")

    # -------------------------------------------------------------
    # Figure 3: Error Forensics / Confusion Matrix
    # -------------------------------------------------------------
    err_path = "results/error_analysis.csv"
    if os.path.exists(err_path):
        err_df = pd.read_csv(err_path)
        top_confusions = err_df.groupby(["traffic_class", "predicted_class"]).size().reset_index(name="count")
        top_confusions = top_confusions.sort_values(by="count", ascending=False).head(8)
        
        fig, ax = plt.subplots(figsize=(8, 4.5), dpi=300)
        labels = [f"{r['traffic_class']} -> {r['predicted_class']}" for _, r in top_confusions.iterrows()]
        counts = top_confusions["count"].values
        
        y_pos = np.arange(len(labels))
        ax.barh(y_pos, counts, color="#e67e22")
        ax.set_yticks(y_pos)
        ax.set_yticklabels(labels, fontsize=10)
        ax.invert_yaxis()
        ax.set_xlabel("Misclassification Count", fontsize=11, fontweight="bold")
        ax.set_title("Fig 3: Dominant Misclassification Pairs in Flow Inference", fontsize=12, fontweight="bold", pad=12)
        
        for i, v in enumerate(counts):
            ax.text(v + max(counts)*0.01, i, f" {v}", va="center", fontsize=9, fontweight="bold")
            
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, "phase2_fig3_error_forensics.png"))
        plt.close()
        print("  [OK] Saved Fig 3: Error Forensics")

    # -------------------------------------------------------------
    # Figure 4: Feature Ablation Progression
    # -------------------------------------------------------------
    exp6 = metrics.get("exp6_feature_ablation", [])
    if exp6:
        fig, ax = plt.subplots(figsize=(9, 4.5), dpi=300)
        sets = [x["feature_set"].replace("Set_", "").replace("_", " ") for x in exp6]
        scores = [x["macro_f1"] for x in exp6]
        
        y_pos = np.arange(len(sets))
        ax.barh(y_pos, scores, color="#1abc9c")
        ax.set_yticks(y_pos)
        ax.set_yticklabels(sets, fontsize=10)
        ax.invert_yaxis()
        ax.set_xlabel("Macro-F1 Score", fontsize=11, fontweight="bold")
        ax.set_title("Fig 4: Feature Ablation Study (Impact on Macro-F1)", fontsize=12, fontweight="bold", pad=12)
        ax.set_xlim(0, 1.1)
        
        for i, v in enumerate(scores):
            ax.text(v + 0.02, i, f"{v:.4f}", va="center", fontsize=9, fontweight="bold")
            
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, "phase2_fig4_feature_ablation.png"))
        plt.close()
        print("  [OK] Saved Fig 4: Feature Ablation")

    # -------------------------------------------------------------
    # Figure 5: Hyperparameter Sensitivity Heatmap
    # -------------------------------------------------------------
    exp5 = metrics.get("exp5_hyperparameter_sensitivity", [])
    if exp5:
        df_hp = pd.DataFrame(exp5)
        sub_hp = df_hp[df_hp["learning_rate"] == 0.1].pivot(index="max_depth", columns="n_estimators", values="mean_macro_f1")
        
        fig, ax = plt.subplots(figsize=(6, 4.5), dpi=300)
        im = ax.imshow(sub_hp.values, cmap="Blues", vmin=sub_hp.values.min()*0.9, vmax=sub_hp.values.max()*1.05)
        
        ax.set_xticks(np.arange(len(sub_hp.columns)))
        ax.set_yticks(np.arange(len(sub_hp.index)))
        ax.set_xticklabels(sub_hp.columns)
        ax.set_yticklabels(sub_hp.index)
        ax.set_xlabel("n_estimators", fontsize=11, fontweight="bold")
        ax.set_ylabel("max_depth", fontsize=11, fontweight="bold")
        ax.set_title("Fig 5: XGBoost Hyperparameter Sensitivity (LR=0.1)", fontsize=12, fontweight="bold", pad=12)
        
        for i in range(len(sub_hp.index)):
            for j in range(len(sub_hp.columns)):
                text = ax.text(j, i, f"{sub_hp.values[i, j]:.3f}", ha="center", va="center", color="black", fontweight="bold")
                
        plt.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, "phase2_fig5_hyperparameter_sensitivity.png"))
        plt.close()
        print("  [OK] Saved Fig 5: Hyperparameter Sensitivity")

    # -------------------------------------------------------------
    # Figure 6: Cross-Dataset Transferability Gap
    # -------------------------------------------------------------
    exp4 = metrics.get("exp4_cross_dataset_transfer", {})
    if exp4:
        fig, ax = plt.subplots(figsize=(7, 4.5), dpi=300)
        scenarios = ["Train T1 -> Test T2\n(Small to Large)", "Train T2 -> Test T1\n(Large to Small)"]
        f1s = [exp4["train_t1_test_t2"]["macro_f1"], exp4["train_t2_test_t1"]["macro_f1"]]
        accs = [exp4["train_t1_test_t2"]["accuracy"], exp4["train_t2_test_t1"]["accuracy"]]
        
        x = np.arange(len(scenarios))
        width = 0.35
        
        b1 = ax.bar(x - width/2, accs, width, label="Accuracy", color="#34495e")
        b2 = ax.bar(x + width/2, f1s, width, label="Macro-F1", color="#e67e22")
        
        ax.set_ylabel("Score", fontsize=11, fontweight="bold")
        ax.set_title("Fig 6: Cross-Dataset Generalization & Transferability Gap", fontsize=12, fontweight="bold", pad=12)
        ax.set_xticks(x)
        ax.set_xticklabels(scenarios, fontsize=10)
        ax.set_ylim(0, 1.1)
        ax.legend(frameon=True, facecolor="white")
        
        for bar in b1 + b2:
            h = bar.get_height()
            ax.annotate(f"{h:.2f}", xy=(bar.get_x() + bar.get_width()/2, h),
                        xytext=(0, 3), textcoords="offset points", ha="center", va="bottom", fontsize=8)
                        
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, "phase2_fig6_cross_dataset_gap.png"))
        plt.close()
        print("  [OK] Saved Fig 6: Cross-Dataset Gap")

    # -------------------------------------------------------------
    # Figure 7: Model Calibration (ECE & Brier Score)
    # -------------------------------------------------------------
    exp8 = metrics.get("exp8_model_calibration", {})
    if exp8:
        fig, ax = plt.subplots(figsize=(7, 4.5), dpi=300)
        models = list(exp8.keys())
        eces = [exp8[m]["expected_calibration_error_ece"] for m in models]
        briers = [exp8[m]["brier_score"] for m in models]
        
        x = np.arange(len(models))
        width = 0.35
        
        b1 = ax.bar(x - width/2, eces, width, label="ECE (Lower is Better)", color="#f39c12")
        b2 = ax.bar(x + width/2, briers, width, label="Brier Score (Lower is Better)", color="#8e44ad")
        
        ax.set_ylabel("Uncertainty Metric", fontsize=11, fontweight="bold")
        ax.set_title("Fig 7: Model Probability Calibration & Reliability", fontsize=12, fontweight="bold", pad=12)
        ax.set_xticks(x)
        ax.set_xticklabels(models, fontsize=10)
        ax.set_ylim(0, max(max(eces), max(briers))*1.3)
        ax.legend(frameon=True, facecolor="white")
        
        for bar in b1 + b2:
            h = bar.get_height()
            ax.annotate(f"{h:.4f}", xy=(bar.get_x() + bar.get_width()/2, h),
                        xytext=(0, 3), textcoords="offset points", ha="center", va="bottom", fontsize=8)
                        
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, "phase2_fig7_calibration_uncertainty.png"))
        plt.close()
        print("  [OK] Saved Fig 7: Calibration & Uncertainty")

    # -------------------------------------------------------------
    # Figure 8: Out-of-Distribution Rejection Confidence
    # -------------------------------------------------------------
    exp7 = metrics.get("exp7_ood_rejection", {})
    if exp7 and "mean_in_dist_confidence" in exp7:
        fig, ax = plt.subplots(figsize=(6.5, 4.5), dpi=300)
        categories = ["In-Distribution\nTraffic Flows", "Held-Out Novel / OOD\nTraffic Flows"]
        confs = [exp7["mean_in_dist_confidence"], exp7["mean_ood_confidence"]]
        colors = ["#27ae60", "#c0392b"]
        
        bars = ax.bar(categories, confs, color=colors, width=0.5)
        ax.axhline(0.5, color="#7f8c8d", linestyle="--", label="Confidence Threshold = 0.5")
        
        ax.set_ylabel("Mean Maximum Mean Maximum Predicted Probability", fontsize=11, fontweight="bold")
        ax.set_title("Fig 8: Out-of-Distribution Novelty Separation", fontsize=12, fontweight="bold", pad=12)
        ax.set_ylim(0, 1.1)
        ax.legend(frameon=True, facecolor="white")
        
        for bar in bars:
            h = bar.get_height()
            ax.annotate(f"{h:.3f}", xy=(bar.get_x() + bar.get_width()/2, h),
                        xytext=(0, 3), textcoords="offset points", ha="center", va="bottom", fontsize=9, fontweight="bold")
                        
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, "phase2_fig8_ood_rejection.png"))
        plt.close()
        print("  [OK] Saved Fig 8: OOD Rejection")

    print("[PlotCharts] All 8 publication figures generated successfully!")

if __name__ == "__main__":
    generate_all_charts()
