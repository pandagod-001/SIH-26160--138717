# 04. Dataset & Capture Methodology

## 1. Dataset Overview: `DS1_NATIVE_IPSEC_ENHANCED`

- **Total Windows Analyzed**: **1,829 flow windows**
- **Window Slicing**: 3.0-second non-overlapping windows
- **Physical Capture Files**: **294 distinct PCAP captures**
- **Experiment Groups**: **157 experiment groups**
- **Physical Testbed**: Real native-IPsec Linux / StrongSwan tunnel instances running under various network conditions:
  - `ENV_CLEAN`: Baseline high-bandwidth LAN
  - `ENV_LOSSY`: 2%–5% artificial packet loss
  - `ENV_HIGH`: High-latency satellite / WAN emulation
  - `ENV_LOW`: Low-bandwidth mobile emulation

---

## 2. Traffic Class Distribution

| Traffic Class | Application Profiles | Window Count | Percentage |
| :--- | :--- | :---: | :---: |
| **BULK** | Large file transfers (SCP, SFTP, raw TCP data streams) | 112 | 6.12% |
| **ICMP** | Network reachability sweeps, ping testing, echo requests | 542 | 29.63% |
| **INTERACTIVE** | SSH remote shell keystrokes, CLI sessions, telemetry | 484 | 26.46% |
| **WEB** | HTTPS web browsing, dynamic API polling, HTTP downloads | 691 | 37.78% |
| **Total** | **4 Distinct Application Classes** | **1,829** | **100.0%** |

---

## 3. Strict Zero-Leakage GroupKFold Methodology

To ensure scientifically defensible results, the evaluation enforces **5-Fold `GroupKFold`** grouped strictly on `experiment_group`:
- **Zero PCAP Overlap**: All flow windows belonging to the same physical capture file remain strictly within either the train fold or the test fold (**Train PCAP ∩ Test PCAP = ∅**).
- **Strict Preprocessing Isolation**: `StandardScaler`, log-transform parameters, sequence padding statistics, embedding centroids, and self-supervised pretraining are fitted **exclusively on the training fold**.
