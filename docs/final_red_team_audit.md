# KAVACH-FHIR — Final Release-Candidate Red-Team Audit

> **Scope & Honesty Note:** This audit was performed offline on Windows 11 (`Python 3.12.10`) using synthetic edge-case fixtures and the truth-hash-matched Secret-Wards practice toolkit (`..\Secret-Wards-ToolKit-LF`). Practice-dataset and local diagnostic numbers are **not** official hidden-evaluator scores, and passing synthetic tests does not prove all possible real-world edge cases are covered.

---

## 1. Repository & Toolkit Versions / Paths Tested

- **Repository:** `C:\Users\hp\devforge\Kavach-FHIR` (branch `master`, base commit `2894112` + uncommitted working-tree changes)
- **Official Practice Toolkit (LF-normalized):** `C:\Users\hp\devforge\Secret-Wards-ToolKit-LF`
  - Practice input: `..\Secret-Wards-ToolKit-LF\dev\input` (`200` files)
  - Truth file: `..\Secret-Wards-ToolKit-LF\dev\truth\truth.json`
- **Preserved Baseline Outputs:** `.\output\kavach-final`, `.\output\kavach-spec-final` (left untouched)
- **Red-Team Verification Output:** `.\output\kavach-redteam-verify`
- **Fresh Virtual Environment:** `%TEMP%\kavach_rt_venv` (`Python 3.12.10`, `pip install -r requirements.txt`)

---

## 2. Benchmark Discrepancy Resolution

Re-checking the earlier A3/A4/A5 reports against `output\kavach-spec-final` explains every difference:

| Metric | `a5_diagnostic.py` (`spec`) | `experiments/test_k_anonymity_policy.py` | Root Cause of Difference |
|---|---:|---:|---|
| **Record Denominator** | `773` | `92` (for k-anon) / `773` (for A3) | `773` = all patient-bearing units across CSV/TSV/JSON/FHIR/TXT in `truth.json`; `92` = structured CSV/TSV rows with `(age_band, gender, district)` QIs (excluding `297` billing `package_code` rows). |
| **A3 Mean Risk** | `0.0805` | `0.0671` | `a5_diagnostic.py` used the full `ATTACKS.md` filter/weight set (`tehsil`, `village`, `pin`, `pin_pre`, given/surname/relative/house weights); `test_k_anonymity_policy.py` used only `(district, gender, age)` + full-name weight. |
| **A4 Re-id Rate (`≥ 0.5`)** | `0.2708` | `0.1667` | Same attacker feature-set difference (`tehsil`/`village`/`pin_pre` + partial-name weights in `a5_diagnostic.py` narrowed more candidates). |
| **A5 True-Target Hits** | `5 / 14` | `4 / 14` | Target `UPV1459499` (`27/F/Barabanki`) fell just below `0.5` confidence when `tehsil`/`village`/partial-name weights were omitted. |

*(Both are local diagnostic approximations of `ATTACKS.md`, not official hidden-evaluation scores.)*

---

## 3. Edge-Case Test Matrix (`tests/test_red_team_matrix.py` + Existing Suite)

| Category | Cases Tested | Status | Notes |
|---|---|---|---|
| **File Parsing** | CSV, TSV, JSON, TXT, FHIR R4, UTF-8 BOM, UTF-16, cp1252, multiline CSV, duplicate headers, empty, invalid UTF-8 (`\x80\x81\xfe\xff`), malformed JSON, >500-deep JSON, `.jpg`/`.xml`/`.bin`, zero-width chars, Devanagari digits | **PASS** | `b"\xff\xfe\x00\x00\x80\x81"` is valid UTF-16 LE BOM; tested invalid bytes without BOM (`b"\x80\x81\xfe\xff\x8d\x90"`). |
| **PII & Side Channels** | Phones, emails, Aadhaar, ABHA, PAN, MRN, Hindi/mixed names, honorifics, kinship, PII filenames, underscore-delimited JSON keys, FHIR extensions, base64 payloads, residual scanner | **PASS** | Fixed 2 confirmed defects (see §4). |
| **Clinical Preservation** | `Dolo 650`, `1-0-1`, vitals, labs, ICD-10 (`E11.9`), eponyms (`Parkinson's disease`), `Dr. Ramesh Sharma` vs patient, `C/O fever` vs `C/O Suresh Kumar` | **PASS** | All clinical probes preserved intact. |
| **Identity Resolution** | Cross-script (`Mohammad Shahid` ↔ `मोहम्मद शाहिद`), family sharing phone (`cannot-link` on gender/name), abstention (`patient: null` when no clues) | **PASS** | Fixed 1 confirmed defect (free-text `DOB:` extraction). |
| **Privacy & Keys** | Intra-release stability, different `RAKSHA_SECRET` unlinkability, determinism, missing/empty/whitespace secret fail-closed, zero secrets/PII in logs/reports | **PASS** | Verified in `tests/test_security.py` & `tests/test_determinism.py`. |
| **FS & Failure Security** | Atomic write temp cleanup on simulated `os.replace` failure, input immutability, symlink handling (best-effort on Windows) | **PASS** | Symlink creation on Windows without Developer Mode falls back gracefully (`try/except OSError`). |
| **Large-file / Linux 2-CPU / 4 GB cgroup** | 50 MB file cap, Linux `resource.getrusage` RSS, offline network-disabled VM | **NOT TESTED** | Local host is Windows 11; Linux container cgroup limits not directly reproduced here. |

---

## 4. Confirmed Defects Found & Minimal Fixes

1. **Cross-line name-token regex bleeding into vitals ([detectors/name_detector.py](file:///C:/Users/hp/devforge/Kavach-FHIR/detectors/name_detector.py)):**
   - *Defect:* `_LABELED_NAME_RE` used `\s+` between name tokens, matching across `\n` into `"BP 120/80"` on the next line; `overlaps_protected()` then rejected the entire match, leaking `"मोहन लाल"`.
   - *Fix:* Replaced `\s+` with `[ \t]+` inside `_LABELED_NAME_RE`.
2. **Underscore-delimited PII in JSON keys ([main.py](file:///C:/Users/hp/devforge/Kavach-FHIR/main.py)):**
   - *Defect:* `_sanitize_json_obj` checked `gazetteer._compiled_full.search(k)` without normalizing `_`/`-` to spaces, missing `"Kavita_Verma_meta"`.
   - *Fix:* Normalized `k_norm = re.sub(r"[_\-]+", " ", k)` and checked `gazetteer.match(k_norm, [])`, `detect_indian_ids(k_norm)`, and `detect_phones(k_norm)`.
3. **Missing `DOB:` clue extraction in free text ([main.py](file:///C:/Users/hp/devforge/Kavach-FHIR/main.py)):**
   - *Defect:* `_extract_clues_from_text` did not parse `DOB:` / `Date of Birth:` / `जन्म तिथि:` lines, preventing cross-script notes with only `Name + Age + DOB` from linking.
   - *Fix:* Added `DOB` extraction via `parse_date_flexible`, which also improved practice-dataset linkage recall from `0.85` to **`0.87`** (`1.00` precision, `0` false merges).

---

## 5. Offline & Resource Assessment

- **Network hygiene:** AST scan across all production `.py` files confirmed **0** imports of `socket`, `urllib`, `http`, `requests`, `httpx`, `aiohttp`, or `ssl`.
- **Fresh-venv runtime:** `12.89s` (`main.py` direct run) and `12.3s` (`check_submission.py` per-run average) on `200` practice files — well within the **15-minute (900s)** limit.
- **Memory disclosure:** `report.json` recorded `peak_rss_mb: 0.0` on Windows 11 (`psapi.GetProcessMemoryInfo` fallback returned `0.0`); on Linux evaluation sandboxes `resource.getrusage(resource.RUSAGE_SELF).ru_maxrss` is used. Exact 2-CPU / 4 GB Linux cgroup enforcement was not reproduced on this Windows host.

---

## 6. Final Official Verification Results (Fresh Venv)

1. **`python -m pytest -v`**: **`51 passed in 6.01s`** (includes `tests/` + `experiments/test_k_anonymity_policy.py`)
2. **`python main.py --input ..\Secret-Wards-ToolKit-LF\dev\input --output .\output\kavach-redteam-verify`** (temp `RAKSHA_SECRET` via env): `files 200 sanitized 193 quarantined 7 records 822`, exit code `0`
3. **`python ..\Secret-Wards-ToolKit-LF\check_dev.py --output .\output\kavach-redteam-verify --truth ..\Secret-Wards-ToolKit-LF\dev\truth\truth.json --show 30`**:
   - **Personal data:** `0 / 3,230` (`0.0%` across all 16 types, all scripts, all hiding places)
   - **Canaries:** `0 / 4`
   - **Medical data kept:** `4,855 / 4,855` (`100.0%`)
   - **Patient linking:** Precision `1.00`, Recall `0.87`, F0.5 `0.97` (`0` false merges)
   - **Raw copies:** `0`
4. **`python ..\Secret-Wards-ToolKit-LF\validate_output.py --input ..\Secret-Wards-ToolKit-LF\dev\input --output .\output\kavach-redteam-verify`**: **`CONTRACT OK`**
5. **`python ..\Secret-Wards-ToolKit-LF\check_submission.py --repo . --run`**: **`READY TO SUBMIT`** (determinism, cross-secret unlinkability, zero secret in outputs/logs, input unchanged).

---

## 7. Remaining Limitations

- Rare-diagnosis targeted re-identification (A5) when an adversary has external `known_facts` + `(age_band, district)` in small registry cells.
- Unlabeled single-token names in free text without structured, honorific, or kinship anchors.
- Windows `peak_rss_mb` reporting (`0.0` in `report.json` on Windows 11) and lack of local Linux 2-CPU / 4 GB cgroup testing.
- Practice-dataset zero leakage does not guarantee zero leakage on unseen hidden evaluation data.
