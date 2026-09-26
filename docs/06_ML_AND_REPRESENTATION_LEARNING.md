# 06. Machine Learning & Representation Learning

## 1. Multi-Model Architecture Matrix

IPsecTrace benchmarks six distinct model configurations to scientifically evaluate the contribution of each representation:

### Model A: Canonical XGBoost Baseline
- **Input**: 14 aggregate statistical flow properties (durations, byte rates, packet size percentiles, IAT statistics).
- **Architecture**: 100 gradient boosted trees (max depth = 6, learning rate = 0.1).
- **Result**: Accuracy = **66.91% ± 18.66%**, Macro-F1 = **73.91% ± 4.84%**.

### Model B1: Sequence Transformer
- **Input**: Temporal packet sequence $[B, 32, 4]$ (Packet length, Log-IAT, Direction, Position).
- **Architecture**: 2-layer Transformer encoder ($d_{\text{model}}=32$, 2 attention heads, dropout = 0.1).
- **Result**: Accuracy = **69.96% ± 26.40%**, Macro-F1 = **77.66% ± 14.59%**.

### Model B2: Protocol-Aware Sequence Transformer
- **Input**: Packet sequence $[B, 32, 4]$ concatenated with 4 deterministic protocol context markers (`is_esp`, `direction_confidence`, `ike_present`, `packet_density`).
- **Result**: Accuracy = **67.23% ± 22.06%**, Macro-F1 = **70.95% ± 10.62%**.

### Model B3: Self-Supervised Pretrained Sequence Model (SSL)
- **Objective**: Masked Packet Feature Reconstruction (15% random masking of non-padded packet lengths with MSE loss) trained strictly on the train fold.
- **Result**: Accuracy = **72.25% ± 25.73%**, Macro-F1 = **76.18% ± 13.33%** (**+5.35% over baseline**).

### Model C: Hybrid Tabular + Sequence Classifier
- **Architecture**: Fuses 32-dim Tabular Encoder embedding with 32-dim Sequence Transformer embedding into a 64-dim representation with a classification head.
- **Result**: Accuracy = **80.25% ± 13.77%**, Macro-F1 = **81.89% ± 9.15%** (**Top Performer, +13.35% improvement**).

### Model D: Multi-View IPsec Classifier
- **Architecture**: Fuses Tabular (32-dim) + Sequence (32-dim) + Protocol Context (16-dim) = 80-dim representation projected to 48-dim.
- **Result**: Accuracy = **61.33% ± 25.07%**, Macro-F1 = **70.28% ± 9.54%** (Documented negative result due to zero entropy in context markers).
