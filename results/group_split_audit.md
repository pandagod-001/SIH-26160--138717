# results/group_split_audit.md — GroupKFold Leakage Audit Report

**Grouping Variable**: `experiment_group` (Session / Capture Run ID)  
**Total Dataset Samples**: `18,842`  
**Total Unique Groups**: `90`  
**Cross-Fold Session Overlap Events**: `0`  
**GroupKFold Audit Status**: `PASSED (Zero Session Leakage)`

---

## 5-Fold GroupKFold Breakdown Table

| Fold # | Train Samples | Validation Samples | Train Groups | Validation Groups | Group Overlap Count | Leakage Audit Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| Fold 1 | 15,073 | 3,769 | 72 | 18 | **0** | `PASSED` |
| Fold 2 | 15,073 | 3,769 | 72 | 18 | **0** | `PASSED` |
| Fold 3 | 15,074 | 3,768 | 72 | 18 | **0** | `PASSED` |
| Fold 4 | 15,074 | 3,768 | 72 | 18 | **0** | `PASSED` |
| Fold 5 | 15,074 | 3,768 | 72 | 18 | **0** | `PASSED` |

---

## Key Technical Finding
By grouping splits strictly on `experiment_group`, entire network capture sessions are assigned exclusively to either training or validation folds. This guarantees **zero cross-fold session correlation**, forcing models to learn genuine application behavioral characteristics rather than session-specific packet lengths or host signatures.
