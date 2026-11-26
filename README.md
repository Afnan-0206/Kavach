# KAVACH-FHIR

**Knowledge-Aware Verification and Clinical Anonymization for Healthcare Records**

An offline, CPU-only, LLM-free healthcare privacy firewall for Indian multi-hospital clinical exports (English, Hindi/Devanagari, and Hinglish; CSV, TSV, JSON, FHIR R4 Bundles, and unstructured notes).

---

## 1. Project Overview

Hospitals merging fragmented patient records for public-health research face a dual challenge: removing every direct and indirect personal identifier across heterogeneous formats and scripts while keeping clinical values, clinician attribution, and cross-hospital longitudinal patient links intact.

KAVACH-FHIR implements a deterministic two-pass privacy firewall that:
- Protects clinical entities (`Dr.` attribution, drug dosages, `1-0-1` frequencies, vitals, labs, `C/O <complaint>`, `K/C/O`, `H/O`, disease eponyms, hospital wards) via a **Clinical Shield** before any redaction runs.
- Detects PII across English, Devanagari, and Hinglish using layered rules, semantic column/key classification, cross-script transliteration (`indic-transliteration`), and a per-run **Dynamic Gazetteer**.
- Links records belonging to the same patient conservatively without transitive over-merging, issuing keyed HMAC-SHA256 pseudonyms (`PSN-XXXXXX`).
- Applies deterministic per-patient date shifting, 5-year age banding, and location/PIN generalization.

## 2. Problem Statement

Naive regex or off-the-shelf NER tools fail on Indian healthcare data: they leak Devanagari and Hinglish names, miss PII hidden in filenames, JSON keys, CSV headers, export metadata, and base64 attachments, over-redact clinical values (`Dolo 650`, `1-0-1`, `Dr. Ramesh`), and cannot link a patient across `"Mohammad Shahid"` and `"मोहम्मद शाहिद"` without merging homonyms or family members who share a phone number.

## 3. Architecture

```text
Input Tree (CSV, TSV, JSON, FHIR R4, TXT, Malformed/Unsupported)
   │
   ▼
[1. Resilient Ingestion] ──► Quarantine (unsupported, empty, undecodable, >500-deep JSON, mislabeled)
   │
   ▼
[2. Pass 1: Clue Extraction & Dynamic Gazetteer]
   │  ├── Semantic column/key classifier
   │  ├── Clinical Shield (protected spans)
   │  └── Cross-script transliteration (Latin ↔ Devanagari)
   ▼
[3. Conservative Identity Linker] ──► HKDF + HMAC-SHA256 Pseudonyms (PSN-XXXXXX) or null
   │
   ▼
[4. Pass 2: Sanitization & Privacy Layer]
   │  ├── Layered PII redaction (content, keys, headers, filenames, base64)
   │  ├── Per-patient deterministic date shifting (preserves LOS & intervals)
   │  ├── 5-year age bands & 3-digit PIN prefix generalization
   │  └── Residual Leakage Scanner
   ▼
Atomic UTF-8 Export: sanitized/ + report.json (raksha-report/1) + records.jsonl
```

## 4. Processing Pipeline

1. **Ingestion (`engine/ingestion.py`):** Walks files in sorted deterministic order, computes input SHA-256, decodes UTF-8 BOM, UTF-16, UTF-8, and cp1252, checks JSON nesting depth iteratively (`max_json_depth: 500`), detects JSON disguised as `.csv`, and quarantines malformed/unsupported files without copying raw bytes.
2. **Pass 1 (`main.py`, `detectors/`):** Extracts structured clues and contextual text clues while respecting `ClinicalShield` protected spans, building a per-run `DynamicGazetteer` with Latin–Devanagari transliterations.
3. **Linkage (`engine/identity_linker.py`):** Clusters records using blocking + RapidFuzz phonetic similarity + cluster-wide cannot-link constraints.
4. **Pass 2 (`engine/privacy_engine.py`, `detectors/residual_scanner.py`):** Redacts PII across all channels, inserts pseudonyms inside sanitized records, shifts dates per patient, bands ages, generalizes PINs, and runs a final residual scan before atomic export.

## 5. Detection Methodology

- **Structured IDs (`detectors/indian_ids.py`):** Aadhaar (12-digit & masked `XXXX XXXX 1234`), ABHA (`91-XXXX-XXXX-XXXX` & `@abdm`), PAN, Email, Insurance/PMJAY/Policy IDs, and hospital MRN/UHID/IPD patterns (including underscore-delimited filenames and Devanagari digits).
- **Phones (`detectors/phone_detector.py`):** `+91`, `0`-prefixed, 10-digit mobile, STD landline, masked (`98XXXXXX10`), and labeled callback numbers.
- **Kinship (`detectors/kinship_detector.py`):** `S/o`, `D/o`, `W/o`, `C/O <Name>`, `M/o`, `F/o`, `Guardian`, `पुत्र`, `पुत्री`, `पत्नी`, `पिता`, `माता`.
- **Addresses (`detectors/address_detector.py`):** House/Makan numbers, Mohalla/Ward/Locality, landmarks, villages (`Gram` or pre-Tehsil), and 6-digit PINs.
- **Clinical Shield (`engine/clinical_shield.py`):** Protects `Dr. <Name>`, medical eponyms (`Parkinson's disease`, `Addison's disease`), `C/O <complaint>`, `K/C/O`, `H/O`, hospital names, dosages, `1-0-1` frequencies, vitals, and lab values.

## 6. Multilingual Support

`engine/normalization.py` performs NFKC normalization, zero-width character removal, Cyrillic/Greek homoglyph folding, Devanagari-to-ASCII digit conversion, and `indic-transliteration` (Devanagari ↔ ITRANS) paired with Indian phonetic normalization (`Mohammad`/`Mohd`/`Md.`/`मोहम्मद`).

## 7. Identity Linkage

Records are blocked by strong identifiers (`AADHAAR`, `ABHA`, `PAN`, `EMAIL`, `MRN`), shared phone numbers, and phonetic name tokens.
- Shared phone numbers **never** link two records alone; they require corroboration by name, DOB, or relative.
- Name matches require at least two independent corroborating points (DOB, relative name, or village/district + age + gender).
- Every merge runs a cluster-wide **cannot-link** check (gender mismatch, age difference > 3, conflicting Aadhaar/ABHA/PAN, same-hospital MRN conflict, district conflict, or low full-name similarity) to prevent transitive over-merging. Ambiguous records receive `patient: null`.

## 8. Pseudonymization

`engine/security.py` derives domain-separated 256-bit keys from `RAKSHA_SECRET` using **HKDF-SHA256** (`kavach-fhir:pseudonym:v1`, `kavach-fhir:date-shift:v1`, `kavach-fhir:filename:v1`, `kavach-fhir:temp-aesgcm:v1`). Patient pseudonyms use HMAC-SHA256 encoded in Crockford Base32 (`PSN-XXXXXX`) with collision checking.

## 9. Privacy Policy

Configured via `config/policy.yaml`:
- `age_band_years: 5` (truthful 5-year bands containing true age; `85+` top-coding)
- `date_shift_max_days: 180` (per-patient secret non-zero offset preserving length of stay and visit intervals)
- `pin_prefix_digits: 3` (`229073` → `229***`)
- Village, house, locality, and landmark strings are suppressed.

## 10. Security Model

- No LLMs, no generative models, no pretrained transformers, and no network calls during execution.
- `RAKSHA_SECRET` is read solely from the environment and never logged, printed, or written to disk.
- Raw input data and intermediate structures (`IngestedFile`, `RecordUnit`, `clues`, `DynamicGazetteer`) are held strictly in memory and never written to disk; only already-sanitized outputs, `records.jsonl`, and `report.json` are written atomically via `tempfile.mkstemp` + `os.replace`.
- `KeyRing` includes unit-tested AES-256-GCM helpers (`encrypt_bytes` / `decrypt_bytes`) for any future encrypted temp-file needs, though no disk intermediates are created in the current pipeline.
- Unprocessable or malformed files are quarantined (`output/report.json` lists SHA-256 + reason) and never copied raw into `sanitized/`.

## 11. Installation

```bash
pip install -r requirements.txt
```

Dependencies: `cryptography`, `PyYAML`, `rapidfuzz`, `indic-transliteration`, `pytest`.

## 12. Execution

`RAKSHA_SECRET` is **required** (non-empty, non-whitespace) and fails closed before creating any output directory if unset or blank.

**PowerShell (Windows):**
```powershell
$env:RAKSHA_SECRET="your-secret-key"
python main.py --input ..\Secret-Wards-ToolKit-LF\dev\input --output .\output\kavach-final
```

**Bash (Linux/macOS):**
```bash
export RAKSHA_SECRET="your-secret-key"
python main.py --input /path/to/input --output /path/to/output
```

## 13. Testing

```powershell
python -m pytest -v tests\
```

## 14. Measured Performance (Practice Dataset)

Measured on the supplied practice/development dataset (`Secret-Wards-ToolKit-LF/dev/input`: **200 files**, **193 sanitized**, **7 quarantined**, **822 exported records**). These are practice-dataset measurements, **not** hidden-evaluation scores, and zero leakage on practice data does not guarantee zero leakage on arbitrary real-world datasets.

| Metric | Result |
|---|---:|
| PII leakage (`check_dev.py`) | **0 / 3,230** |
| Canaries leaked | **0 / 4** |
| Clinical preservation | **4,855 / 4,855** (100.0%) |
| Linkage precision | **1.00** |
| Linkage recall | **0.85** |
| Linkage F0.5 | **0.97** |
| False merges | **0** |
| Raw unsupported copies | **0** |
| Output contract (`validate_output.py`) | **`CONTRACT OK`** (193 sanitized, 7 quarantined) |
| Runtime (CPU) | **~8.5–10.2 seconds** |

**Conservative Linkage Trade-off:** KAVACH-FHIR enforces cluster-wide cannot-link constraints and requires multi-point corroboration when strong IDs are absent. This yields **1.00 precision** and **0 false merges** at the cost of **0.85 recall** (leaving genuinely ambiguous or sparsely corroborated records unlinked as `patient: null`).

## 15. Limitations

- Rare-diagnosis population-level privacy: k-anonymity suppression is not dynamically coupled to external population registries, so an attacker with exact rare-disease + district + age-band knowledge can still narrow down small equivalence classes.
- Unlabeled names: unlabeled single-token names in free text that do not appear in any structured record, honorific, or kinship pattern may escape the per-run gazetteer.
- Windows Git CRLF checkout alters line endings vs. Linux LF SHA-256 hashes in `dev/truth/truth.json`; on Linux evaluation sandboxes, SHA-256 hashes match natively.
