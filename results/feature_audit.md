# IPsecTrace Phase 2 — Feature Lineage & Audit Report
**Generated**: 2026-09-24 01:52:49

## 1. Feature Lineage Matrix
| Feature | Source | Meaning | Cross-Compatible? | Leakage Risk | Status | Unit / Extraction Notes |
|---|---|---|---|---|---|---|
| `flow_duration_sec` | Tier 1 & Tier 2 | Total duration of the flow session in seconds | Yes | None | **ACTIVE (Core Feature)** | Tier 1: seconds directly from PCAP timestamps. Tier 2: converted from microseconds (/1e6). |
| `packets_per_sec` | Tier 1 & Tier 2 | Packet rate (total packets / duration) | Yes | None | **ACTIVE (Core Feature)** | Consistent across both tiers. |
| `bytes_per_sec` | Tier 1 & Tier 2 | Byte throughput rate (total bytes / duration) | Yes | None | **ACTIVE (Core Feature)** | Consistent across both tiers. |
| `mean_iat_sec` | Tier 1 & Tier 2 | Mean inter-arrival time between consecutive packets | Yes | None | **ACTIVE (Core Feature)** | Tier 1: seconds. Tier 2: converted from ISCX mean_flowiat (microseconds / 1e6). |
| `std_iat_sec` | Tier 1 & Tier 2 | Standard deviation of inter-arrival time | Yes | None | **ACTIVE (Core Feature)** | Tier 1: seconds. Tier 2: converted from ISCX std_flowiat (microseconds / 1e6). |
| `mean_packet_size_bytes` | Tier 1 Only | Average packet length in bytes | No | None | **TIER-1 SPECIFIC** | Extracted from raw ESP/IPsec packet lengths. Not available in ISCX FlowMeter ARFF. |
| `std_packet_size_bytes` | Tier 1 Only | Standard deviation of packet length in bytes | No | None | **TIER-1 SPECIFIC** | Extracted from raw ESP/IPsec packet lengths. |
| `min_packet_size_bytes` | Tier 1 Only | Minimum packet length in bytes | No | None | **TIER-1 SPECIFIC** | Extracted from raw ESP/IPsec packet lengths. |
| `max_packet_size_bytes` | Tier 1 Only | Maximum packet length in bytes | No | None | **TIER-1 SPECIFIC** | Extracted from raw ESP/IPsec packet lengths. |
| `ip_proto / port_src / port_dst` | All (Metadata) | IP protocol, Source Port, Destination Port | No | HIGH (Tunnels use fixed ports like 500, 4500, 1194) | **EXCLUDED (Leakage Prevention)** | Excluded from all ML classifiers to prevent shortcut learning. |
| `pcap_file / pcap_source` | All (Metadata) | Source filename | No | HIGH (May encode traffic class in filename) | **EXCLUDED (Leakage Prevention)** | Used only for GroupKFold splitting and provenance tracking. |

## 2. Leakage Mitigation Verification
> [!IMPORTANT]
> 1. **Identifier & Port Exclusion**: All network port numbers (e.g. 500/4500 for IPsec, 1194 for OpenVPN) and IP addresses are completely excluded from model training to prevent classifier shortcuts.
> 2. **Metadata Separation**: Filenames, session IDs, and folder paths are isolated from the feature matrix and strictly used for grouped cross-validation.
> 3. **Statistical Integrity**: All timing features are harmonized to seconds.