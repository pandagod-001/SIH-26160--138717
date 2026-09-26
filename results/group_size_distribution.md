# results/group_size_distribution.md — Group-Size Distribution Audit

## 18,842 Canonical Sample Arithmetic Reconciliation
- **DS1_CUSTOM_IPSEC (Primary Native IPsec Testbed)**: `84` samples
- **DS4_ISCX_SCENARIO_B (External Encrypted VPN Time-Windows / ISCX)**: `18,758` samples
  - *ISCX Non-ICMP Traffic (BULK/WEB/INTERACTIVE)*: `13,661` samples
  - *ISCX VOIP/ICMP Traffic*: `5,097` samples
- **Sum Total Verification**: `84 + 18758 = 18,842` (Exact Match: **`True`**)

---

## Group-Size Distribution Statistics
- **Total Unique Experiment Groups**: `90`
- **Minimum Group Size**: `1` samples
- **Maximum Group Size**: `510` samples
- **Median Group Size**: `193.0` samples
- **Mean Group Size**: `209.36` samples

---

## Technical Audit Note on Grouping Boundaries
`GroupKFold` holds out entire `experiment_group` units during cross-validation, guaranteeing zero cross-fold session leakage. Because maximum group size is `510` samples, grouped splitting prevents large session clusters from inflating validation metrics.
