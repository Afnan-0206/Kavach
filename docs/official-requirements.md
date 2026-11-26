# Official Requirements & Baseline Audit (Phase 0)

This document records the verified requirements, scoring formulas, output contracts, and baseline measurements from the official `Secret-Wards-ToolKit` (`validate_output.py`, `check_dev.py`, `check_submission.py`, `scoring.toml`, `docs/SPEC.md`, `docs/SCORING.md`, `docs/ATTACKS.md`, `docs/DATASET.md`).

---

## 1. Execution & Submission Contract

- **Configuration:** `raksha.toml` at the repository root with `[submission]` (`name`, `setup`, `run` containing `{input}` and `{output}`).
- **Environment:**
  - `RAKSHA_SECRET`: Per-release secret key for HMAC pseudonyms and date shifts. Never log, print, or write to disk.
  - `RAKSHA_INPUT` / `RAKSHA_OUTPUT`: Input (read-only) and output paths.
  - `HF_HUB_OFFLINE=1`, `TRANSFORMERS_OFFLINE=1`: Offline execution, no network during `run`.
  - Limits: Linux, 2 CPUs, 4,096 MB peak RSS, 900s (15 min) timeout.
- **Output Layout (`{output}/`):**
  - `sanitized/`: Mirror of input tree. Preserve relative paths (unless filename contains PII -> rename and record in `report.json`), preserve formats (CSV/TSV delimiter & header unless header has PII; JSON structure & types; valid FHIR R4 Bundle with resolvable references). Write all text as UTF-8.
  - `report.json`: Schema `"raksha-report/1"`, `files` (every input file by `input_sha256`, `output`, `status` in `{"sanitized", "quarantined", "suppressed"}`, `reason` if quarantined), `counts` (`files_total`, `files_sanitized`, `files_quarantined`, `records_processed`, `identifiers_detected`, `records_linked`, `records_generalized`, `records_suppressed`, `records_quarantined`), `timing.seconds`, `resources.peak_rss_mb`. Never leak input filenames or PII.
  - `records.jsonl`: One JSON object per line per exported patient-bearing record: `{"file": "sanitized/...", "loc": "...", "patient": "PSN-..." | null}` (plus optional `"out"` if locator shifted, `"status"`).
    - `loc`: `row:N` (0-based, excluding header) for CSV/TSV; RFC 6901 JSON pointer (e.g. `/visits/3`) for JSON arrays of objects; `doc` for text notes, FHIR Bundles, and single-object JSON.
    - Consistency: `patient` pseudonym must also appear inside the sanitized record itself.
  - `quarantine/` (optional): Not scanned, not part of release.
  - `logs/` (optional): Scanned for PII and `RAKSHA_SECRET`.

---

## 2. Official Scoring Formula (`scoring.toml` & `docs/SCORING.md`)

`total = 100 * sum(weight_c * score_c) - critical_penalties` (not floored at 0).

| Category | Weight | Formula / Components |
|---|---:|---|
| Multilingual PII Detection & Contextual Intelligence | 20% | `F2(P, R)` (`beta = 2.0`). `R = 0.5 * macro(type_weighted) + 0.5 * macro(latin, deva, hinglish)`. `P` = mean over trap groups (`doctor`, `doctor-vs-relative`, `c/o-complaint`, `k/c/o`, `h/o`, `hospital-ward`, `dose`, `1-0-1`, `eponym`, `asha`) + clean token retention. |
| Cross-Document Identity Resolution | 15% | `0.4 * F0.5 + 0.3 * B3_F1 + 0.1 * language_trap + 0.1 * fragmented_trap + 0.1 * homonym_separation`. Ambiguous records excluded from recall, included in precision. |
| Adversarial Privacy & Re-identification | 25% | `(1 - risk) * min(1, utility / 0.40)`. Components: A1 direct exposure (0.20), A2/A3 record linkage vs raw (0.20), A4 profile re-id vs raw (0.20), A5 targeted attack w/ global-shift recovery vs raw (0.20), A6 pseudonym inversion (0.10), A7 cross-release linkability (0.10). |
| Clinical Utility Preservation | 20% | `0.35 * clinical_probes + 0.20 * temporal (0.6*intervals + 0.4*LOS) + 0.10 * generalization + 0.15 * statistics + 0.10 * token_retention + 0.10 * record_retention`. |
| Data Integrity & Secure Export | 10% | `0.15 * format_validity + 0.20 * schema_preservation + 0.15 * fhir_validity + 0.10 * pseudonym_consistency + 0.15 * channel_hygiene + 0.15 * quarantine_handling + 0.10 * report_quality`. |
| CPU Efficiency & Reliability | 10% | `0.30 * reliability + 0.30 * wall_time + 0.20 * peak_memory + 0.20 * determinism` (+ optional scaling). |

### Critical Penalties
- Surviving direct identifier or full patient name: `-1` each (cap `-25`).
- Planted canary found anywhere (content, filenames, report, logs, stdout/stderr, TMPDIR/HOME): `-3` each (cap `-15`).
- Unsupported/malformed PII file copied byte-for-byte into `sanitized/`: `-5` each (cap `-20`).
- False success (exit 0 with missing `report.json` or silently dropped inputs): `-10`.
- Input tampering: `-5`.

---

## 3. Baseline Execution Results (`starter/main.py` on `dev/input`)

Executed with `$env:RAKSHA_SECRET="practice"`:
- **Starter output:** `files 200 sanitized 195 quarantined 5 records 823`
- **Contract validator (`validate_output.py`):** `CONTRACT OK`
- **Practice self-check (`check_dev.py`):**
  - **Personal Data Leaked:** `2718 / 3230` (**84.1% leaked**)
    - `PATIENT_NAME`: 911 / 962 (94.7%)
    - `MRN`: 817 / 850 (96.1%)
    - `RELATIVE_NAME`: 232 / 232 (100.0%)
    - `VILLAGE`: 150 / 150 (100.0%)
    - `HOUSE`: 136 / 136 (100.0%)
    - `PIN`: 136 / 136 (100.0%)
    - `DOB`: 111 / 111 (100.0%)
    - `LOCALITY`: 103 / 103 (100.0%)
    - `LANDMARK`: 64 / 64 (100.0%)
    - `PHONE`: 25 / 308 (8.1%)
    - `AADHAAR_MASKED`: 16 / 16 (100.0%)
    - `INSURANCE_ID`: 15 / 22 (68.2%)
    - `AADHAAR`: 2 / 71 (2.8%)
    - `EMAIL`: 0 / 1 (0.0%)
    - `ABHA_NUMBER`: 0 / 46 (0.0%)
    - `PAN`: 0 / 22 (0.0%)
  - **By Language:** `latin 82.8%`, `deva 100.0%`, `hinglish 100.0%`
  - **By Hiding Place:** `content 83.5%`, `filename 100.0%`, `base64 100.0%`, `metadata 100.0%`, `key 100.0%`, `header 100.0%`
  - **Canaries:** `4 / 4` found in output folder
  - **Medical Data Kept:** `4855 / 4855` (100.0%)
  - **Patient Linking:** precision `0.00`, recall `0.00`, F0.5 `0.00` (0 merged)
  - **Raw Copies:** `0`

---

## 4. Key Edge Cases Observed in `dev/input/`

- **Encodings:** UTF-8, UTF-8 with BOM (`sanjeevani_registration.csv`), UTF-16 (`jeevanjyoti_patients.tsv`), cp1252 (`arogya_legacy_export.csv`), invalid UTF-8 (`corrupt_bytes_note.txt`).
- **Malformed / Unsupported (`misc/`):** `empty_export.csv` (0 bytes), `truncated_opd.json`, `deep_export.json` (1500+ nesting depth), `mislabeled_export.csv` (JSON content with `.csv` extension), `hl7_cda_discharge.xml`, `photo_rx.jpg`, `scanned_discharge.pdf`, `scanned_consent_form.json` (base64 payload), `patient_index.json` (PII in JSON keys).
- **Hidden Channels:** Filenames (`7148988804_report_0047.json`, `Discharge_Summary_Fatima_Bano_SNJ-26-064508.txt`), OPD `_export_meta.source_path`, FHIR `meta.source` / `identifier` / `text.div`, JSON keys, CSV headers, `\u`-escaped Devanagari.
- **Determinism:** `sanitized/` and `records.jsonl` must be byte-identical across runs with the same `RAKSHA_SECRET`, and pseudonyms + date shifts must change with a different `RAKSHA_SECRET`.
