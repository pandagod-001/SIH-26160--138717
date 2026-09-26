# IPsecTrace Phase 2 — Data Quality & Integrity Report
**Generated**: 2026-09-24 01:52:48
**Dataset Evaluated**: `data/processed/canonical_vpn_dataset.csv` (18,842 total flow records)

## 1. Executive Summary
- **Total Flow Records**: 18,842
- **Tier 1 (Custom Testbed IPsec)**: 84 flows
- **Tier 2 (ISCX VPN Scenario B)**: 18,758 flows
- **Exact Full-Row Duplicates**: 0
- **Shared Feature Collision / Duplicates**: 752 (3.99%)

## 2. Shared Feature Integrity & Distribution
| Feature | Mean | Std | Median | Min | Max | IQR Outliers (%) |
|---|---|---|---|---|---|---|
| `flow_duration_sec` | 9.7500e+00 | 1.4366e+01 | 1.1006e+01 | 0.0000e+00 | 6.0140e+02 | 1.12% |
| `packets_per_sec` | 2.0747e+03 | 1.9075e+04 | 1.1791e+01 | 0.0000e+00 | 1.0000e+06 | 11.7% |
| `bytes_per_sec` | 4.6183e+05 | 8.8465e+06 | 2.7060e+03 | 0.0000e+00 | 6.1700e+08 | 17.55% |
| `mean_iat_sec` | 4.7485e-01 | 1.4016e+00 | 8.3151e-02 | 0.0000e+00 | 6.0700e+01 | 12.8% |
| `std_iat_sec` | 1.0306e+00 | 3.5268e+00 | 7.3954e-02 | 0.0000e+00 | 1.3600e+02 | 12.67% |

## 3. Class Balance Breakdown
| Traffic Class | Total Flows | Share (%) |
|---|---|---|
| `BULK` | 5,865 | 31.13% |
| `ICMP` | 5,103 | 27.08% |
| `WEB` | 5,022 | 26.65% |
| `INTERACTIVE` | 2,852 | 15.14% |

## 4. Multicollinearity & High Correlation Warnings (|r| > 0.85)
- `mean_iat_sec` ↔ `std_iat_sec`: Pearson r = **0.8744**

## 5. Missing Values & Feature Exclusivity
- **Shared Features** (`flow_duration_sec`, `packets_per_sec`, `bytes_per_sec`, `mean_iat_sec`, `std_iat_sec`): 0 missing values across all 18,842 records.
- **Tier 1 Packet Size Stats** (`mean_packet_size_bytes`, etc.): Present for all 84 Tier 1 records; unpopulated (NaN) for Tier 2 flows as ISCX ARFF files omit packet length distributions.

## 6. Verification Status
> [!IMPORTANT]
> Data quality check passed. Shared features are strictly validated, free of infinite values, and standardized across both provenance tiers.