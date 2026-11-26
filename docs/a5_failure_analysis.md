# KAVACH-FHIR — A5 Failure Analysis & Selective Quasi-Identifier Generalization Study

> **Historical Snapshot Notice:** This document records an earlier diagnostic study against `output/kavach-spec-final` and isolated experimental copies. Do **not** read these numbers as current release metrics (current release practice results are `78 passed, 1 xfailed`, `0 / 3,230` PII, `4,855 / 4,855` clinical preservation, `1.00` precision, `0.85` recall, `0.97` F0.5, `CONTRACT OK`, `READY TO SUBMIT`). All measurements below are **local diagnostic estimates**, not official hidden-evaluation scores.

---

## 1. Audit of `bench_attacks.py` vs. `ATTACKS.md`

Inspecting `bench_attacks.py` against `../Secret-Wards-ToolKit-LF/docs/ATTACKS.md` identified **four concrete methodology discrepancies**:

1. **Missing Demographic Consistency Check (Primary cause of decoy false positives):**
   - `ATTACKS.md` (§A5) specifies: *"The profile's evidence must also be consistent with that person."*
   - `bench_attacks.py` computed `s *= max(probs.get(rid, 0.05), 0.05)`. When a person was completely filtered out by incompatible `(age, gender, district)` (`probs.get(rid) == 0.0`), the `0.05` floor still produced `8.0 * 0.05 = 0.40 >= 0.30`, falsely flagging demographically impossible decoys.
2. **Permissive Unnormalized Score Threshold (`>= 0.30`):**
   - `bench_attacks.py` thresholded raw unnormalized `s * prob >= 0.30` instead of normalizing confidence across competing candidate profiles (`>= 0.50` posterior confidence).
3. **Noisy Age-Band Extraction in Initial Run:**
   - The initial `AGE_BAND_RE = r"\b(\d{1,3})-(\d{1,3})\b"` matched date fragments (`02-12`, `07-12`) and lab reference ranges (`4-10`, `0-5`), widening profile age intervals to `[0, 97]` and weakening A3/A4/A5 filtering (explicitly warned against in `ATTACKS.md` §Attacker self-checks). Fixing `AGE_BAND_RE` to require age context (`Age:`, `Yrs`, `वर्ष`, `/M`, `/F`) corrected baseline A5 from `3/14` to **`5/14`** and A4 from `14.58%` to **`27.08%`**.
4. **Missing LOS & Global-Shift Recovery:**
   - `bench_attacks.py` did not model length-of-stay (LOS) interval matching or global shift recovery (`≥ 2` profiles at `conf ≥ 0.9` agreeing on one date offset). Note: KAVACH-FHIR uses per-patient HMAC date shifts, so global shift recovery would fail anyway, whereas LOS intervals remain preserved for clinical utility.

---

## 2. Per-Target A5 Diagnostic (14 True Targets)

Measured with clean age-band extraction on `output/kavach-spec-final` (`240`-person `registry.csv`, `14` true targets in `known_facts.jsonl`):

| Target ID (`rid`) | Registry `(Age/Sex/Dist)` | Orig A5 Score (Hit) | Spec-Aligned `p` (Hit) | In Cands (`p_rid`) | Cond Hits | Matched QIs & Root Cause |
|---|---|---:|---:|---|---:|---|
| `UPV0133081` | `65/M/Sitapur` | `4.000` (**True**) | `0.857` (**True**) | Yes (`1.000`) | 56 | `(65-69, M, Sitapur)` is **unique** in `registry.csv` + hospital + condition |
| `UPV4802335` | `49/F/Lucknow` | `4.000` (**True**) | `0.993` (**True**) | Yes (`1.000`) | 82 | `(45-49, F, Lucknow)` is **unique** in `registry.csv` + hospital + condition |
| `UPV5626776` | `40/M/Sitapur` | `8.000` (**True**) | `0.972` (**True**) | Yes (`1.000`) | 0 | `(35-44, M, Sitapur)` is **unique** in `registry.csv` + hospital + date overlap |
| `UPV6780437` | `97/M/Barabanki` | `4.000` (**True**) | `0.892` (**True**) | Yes (`0.500`) | 10 | `(85+, M, Barabanki)` has only `2` registry candidates + condition + hospital |
| `UPV1459499` | `27/F/Barabanki` | `1.000` (**True**) | `0.512` (**True**) | Yes (`0.250`) | 56 | `(25-29, F, Barabanki)` (`4` candidates) + condition + hospital |
| `UPV0850146` | `69/F/Sultanpur` | `0.200` (False) | `0.366` (True*) | **No** (`0.000`) | 38 | Filtered out by wrong-profile `(M, Rae Bareli)`; below `0.5` threshold |
| `UPV1556957` | `72/M/Rae Bareli` | `0.750` (False) | `0.635` (False) | Yes (`0.062`) | 32 | Correct profile lacked unique QIs (`16` cands); matched wrong profile stronger |
| `UPV1902689` | `49/F/Sultanpur` | `0.296` (False) | `0.424` (False) | Yes (`0.074`) | 82 | `13+` registry candidates in cell; below `0.5` confidence |
| `UPV6933414` | `96/M/Bahraich` | `0.600` (False) | `1.000` (False) | **No** (`0.000`) | 5 | Best-scoring profile was `(F, Rae Bareli)` — filtered out by demographic check |
| `UPV5851611` | `72/M/Sultanpur` | `0.200` (False) | `0.479` (False) | **No** (`0.000`) | 30 | Filtered out by `(M, Rae Bareli)` mismatch |
| `UPV4880284` | `21/M/Barabanki` | `0.000` (False) | `0.000` (False) | No (`0.000`) | 0 | No visit date, hospital, or condition match in sanitized profiles |
| `UPV4228021` | `26/M/Sultanpur` | `0.000` (False) | `0.000` (False) | No (`0.000`) | 0 | No visit date, hospital, or condition match in sanitized profiles |
| `UPV0316891` | `31/M/Barabanki` | `0.000` (False) | `0.000` (False) | No (`0.000`) | 0 | No visit date, hospital, or condition match in sanitized profiles |
| `UPV6469260` | `45/F/Unnao` | `0.000` (False) | `0.000` (False) | No (`0.000`) | 0 | No visit date, hospital, or condition match in sanitized profiles |

*\*`UPV0850146` had `spec_p=0.366 < 0.5` and `in_cands=False`, so it is NOT counted as a spec-aligned hit.*

---

## 3. Decoy Analysis (4 Decoys in `known_facts.jsonl`)

| Decoy ID (`rid`) | Registry `(Age/Sex/Dist)` | Orig A5 Score (FP?) | Spec-Aligned `p` (FP?) | In Cands (`p_rid`) | Exact Cause |
|---|---|---:|---:|---|---|
| `UPV4274914` | `42/F/Unnao` | `0.800` (**Yes**) | `0.667` (**Yes**) | Yes (`0.100`) | Coincidentally shares `(35-44, F, Unnao)` with 10 registry people + hospital/date overlap (`p_rid=0.100` but `spec_p=0.667 >= 0.5`) |
| `UPV0922804` | `61/M/Hardoi` | `0.400` (**Yes**) | `0.000` (No) | **No** (`0.000`) | False positive ONLY in `bench_attacks.py` due to `0.05` floor on demographically incompatible `(35-44, M, Sitapur)` profile |
| `UPV2374794` | `80/M/Lucknow` | `0.400` (**Yes**) | `0.000` (No) | **No** (`0.000`) | False positive ONLY in `bench_attacks.py` due to `0.05` floor on demographically incompatible `(20-29, M, Sultanpur)` profile |
| `UPV9848196` | `40/M/Sultanpur` | `0.000` (No) | `0.000` (No) | No (`0.000`) | No matching hospital/date/condition in sanitized output |

**Conclusion on Decoys:** `2/3` of the decoy false positives in `bench_attacks.py` were **simulator bugs** (missing demographic consistency check + permissive `0.3` raw score threshold). Under `ATTACKS.md`-aligned consistency, decoy FPs drop from **`3/4` to `1/4`**.

---

## 4. Policy Simulation Results (Policies A, B, C vs. Baseline)

A generic rare-diagnosis detector (clinical diagnosis/condition phrases appearing in `≤ 2` sanitized files, yielding `16` rare diagnosis strings) was applied on isolated copies of `output/kavach-spec-final`:
- **Baseline:** Current KAVACH-FHIR output (`5-year` age bands, `district` preserved).
- **Policy A:** Coarsen age bands to `20-year` buckets (`0-19`, `20-39`, `40-59`, `60-79`, `80+`) **only** on rare-condition records.
- **Policy B:** Generalize `district` to `[REGION]` **only** on rare-condition records.
- **Policy C:** Apply **both** Policy A and Policy B on rare-condition records.

| Policy | A3 Mean Risk | A4 Re-id (`≥0.5`) | Orig A5 (Decoy FP) | Spec A5 (Decoy FP) | Medical Preserved | Contract |
|---|---:|---:|---:|---:|---:|---|
| **Baseline** | `0.0805` | `0.2708` | `5/14` (`3/4`) | `5/14` (`1/4`) | **4,855 / 4,855 (100%)** | `CONTRACT OK` |
| **Policy A (Age 20yr on rare)** | `0.0782` | `0.2708` | `5/14` (`3/4`) | `5/14` (`1/4`) | **4,855 / 4,855 (100%)** | `CONTRACT OK` |
| **Policy B (District on rare)** | `0.0740` | `0.2500` | `5/14` (`3/4`) | `5/14` (`1/4`) | **4,855 / 4,855 (100%)** | `CONTRACT OK` |
| **Policy C (Age + Dist on rare)** | **`0.0731`** | **`0.2500`** | `5/14` (`3/4`) | `5/14` (`1/4`) | **4,855 / 4,855 (100%)** | `CONTRACT OK` |

*(All 4 policies kept `0 / 3,230` PII leaks.)*

---

## 5. Brutally Honest Decision & Recommendation

**Does selective quasi-identifier generalization preserve 100% of clinical values?**  
**Yes.** Across Policies A, B, and C, `4,855 / 4,855` (100.0%) of medical probes survived and `validate_output.py` remained `CONTRACT OK`.

**Did rare-condition-only generalization (Policies A/B/C) reduce A5 on this dataset?**  
**No — not on the 5 identifiable A5 targets (`5/14` unchanged).** Here is why:
1. **The 5 identifiable A5 targets were NOT identified by `≤ 2`-file rare diagnoses.** They were identified because `(age_band, gender, district)` was *already* `k=1` or `k=2` in the `240`-person `registry.csv` (`UPV0133081`, `UPV4802335`, `UPV5626776`, `UPV6780437`), combined with hospital name and common conditions (`cond_hits` = `10` to `82`).
2. **Coarsening `district` on rare-condition records (Policy B/C) DID reduce A3 (`0.0805` → `0.0731`, `-9.2%`) and A4 (`0.2708` → `0.2500`)** without losing a single clinical value.
3. **Final Recommendation:**
   - **Do NOT rush a complex rare-diagnosis-only heuristic into `main.py` expecting it to magically fix A5**—our measurements prove `5/14` A5 hits come from small `(age_band, district, gender)` cells + hospital names, not just `≤ 2`-file diagnoses.
   - If you want to meaningfully reduce A3/A4/A5 in a future iteration, **generalize `(age_band, district)` for small `(age_band, district, gender)` equivalence classes (e.g., `k < 3` in the exported dataset, or `85+` cells like `97/M/Barabanki`)**, rather than gating only on rare diagnosis string frequency.
   - For the current hackathon submission, keep the verified, stable codebase (`0/3,230` PII, `0/4` canaries, `4,855/4,855` medical values, `1.00` linkage precision, `READY TO SUBMIT`) and present these exact measured findings honestly.
