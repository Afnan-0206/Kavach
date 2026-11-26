# KAVACH-FHIR — Equivalence-Class-Driven Privacy Experiment (Policies D, E, F)

> **Scope & Disclaimer:** Executed offline via [test_k_anonymity_policy.py](file:///C:/Users/hp/devforge/Kavach-FHIR/experiments/test_k_anonymity_policy.py) on isolated copies of `output/kavach-spec-final` against the practice dataset (`Secret-Wards-ToolKit-LF/dev/input` and `dev/attacker/`). All metrics are local diagnostic estimates, not official hidden-evaluation scores. No production code or verified submission outputs were modified.

---

## 1. Experiment Design

- **Equivalence-class key:** `(age_band, gender, district)` across structured CSV/TSV files (`92` total quasi-identifier records).
- **Geography constraint:** No district-to-region lookup exists in the repository; `district` is generalized to `"[REGION]"` without inventing a geography mapping.
- **Policies compared (threshold `k < 3`):**
  - **Baseline:** Existing KAVACH-FHIR output (`5-year` age bands, `district` preserved).
  - **Policy D:** Generalize `district` → `"[REGION]"` for records in classes with `k < 3`.
  - **Policy E:** Apply Policy D, recalculate `k`, then widen `age_band` (`20-year` buckets / `80+`) for remaining classes with `k < 3`.
  - **Policy F:** Apply Policy E, recalculate `k`, then generalize `gender` → `"Unknown"` for remaining classes with `k < 3`.
- **Attack simulator:** `ATTACKS.md`-aligned A3/A4/A5 evaluator enforcing demographic consistency and context-anchored age-band extraction.

---

## 2. Baseline vs. Policy Comparison

| Metric | Baseline | Policy D (`district`) | Policy E (`+ age`) | Policy F (`+ gender`) |
|---|---:|---:|---:|---:|
| **Records Generalized** | `0 / 92` (`0.0%`) | `66 / 92` (`71.74%`) | `66 / 92` (`71.74%`) | `66 / 92` (`71.74%`) |
| **Equivalence Classes** | `51` | `36` | `28` | `27` |
| **`k = 1` Records** | `22` | `10` | `3` | `3` |
| **`k < 3` Records** | `66` | `30` | `9` | `5` |
| **`k < 5` Records** | `81` | `65` | `60` | `60` |
| **Min / Median / Max `k`** | `1 / 2 / 6` | `1 / 2.0 / 6` | `1 / 3.0 / 6` | `1 / 3 / 6` |
| **A3 Mean Risk** | `0.0671` | `0.0558` | `0.0549` | `0.0549` |
| **A4 Re-identification (`≥ 0.5`)** | `0.1667` | `0.1250` | `0.1250` | `0.1250` |
| **A5 True-Target Hits** | **`4 / 14`** | **`4 / 14`** | **`4 / 14`** | **`4 / 14`** |
| **A5 Decoy False Positives** | **`1 / 4`** | `2 / 4` | `2 / 4` | `2 / 4` |
| **Clinical / Preserve Values (`check_dev.py`)** | **`4,855 / 4,855 (100.0%)`** | `4,806 / 4,855 (99.0%)` | `4,806 / 4,855 (99.0%)` | `4,806 / 4,855 (99.0%)` |
| **Output Contract (`validate_output.py`)** | `CONTRACT OK` | `CONTRACT OK` | `CONTRACT OK` | `CONTRACT OK` |

---

## 3. Utility Trade-Off & Why A5 Did Not Improve

1. **Direct Utility Loss (`-49` preserved probes):** `check_dev.py` scores `49` structured `District` cells as utility `preserve` probes. Policy D/E/F generalized `71.74%` (`66/92`) of structured CSV rows, dropping `MEDICAL DATA KEPT` from **`100.0%` (`4,855/4,855`)** to **`99.0%` (`4,806/4,855`)**.
2. **Gender Utility Loss (Policy F):** Policy F additionally erased `gender` → `"Unknown"` on `4` remaining `k < 3` records (`k_lt_3`: `9 → 5`) with **zero** improvement in A3 (`0.0549`), A4 (`0.1250`), or A5 (`4/14`), degrading epidemiological sex-stratification utility for nothing.
3. **Zero A5 Improvement (`4/14` unchanged, decoy FPs worsened `1/4 → 2/4`):** Linked patient profiles also contain `age_band`, `gender`, and `district` inside unstructured `.txt`, `.json`, and FHIR files, so generalizing CSV rows alone does not prevent A5 profile matching—while removing `district` from CSVs actually increased decoy ambiguity (`1/4 → 2/4`).

---

## 4. Validation Summary

- `python -m pytest -v experiments\test_k_anonymity_policy.py`: **5 / 5 passed in 0.32s** (synthetic fixtures verifying `k` calculation, Policy D/E/F transformations, determinism, clinical column preservation, and zero PII in stdout/stderr).

---

## 5. Explicit Recommendation: **KILL**

**KILL** adaptive CSV `(age_band, gender, district)` generalization (Policies D, E, and F) for the current KAVACH-FHIR submission:
- **A5 improvement:** **0** (`4/14` → `4/14`, decoy FPs worsened `1/4` → `2/4`).
- **Clinical/utility cost:** Lost **49** preserved probes (`100.0%` → `99.0%`) and generalized `71.74%` of structured records.
- **Keep Baseline:** The verified KAVACH-FHIR pipeline (`0 / 3,230` PII, `0 / 4` canaries, `4,855 / 4,855` preserved, `1.00` linkage precision, `READY TO SUBMIT`) is strictly superior on utility and A5 decoy resistance.
