# KAVACH-FHIR — Security Findings Remediation Report

> **Scope:** Remediation of all confirmed P0, P1, P2, and cryptographic hardening findings from the white-box security review of `KAVACH-FHIR`. All fixes use deterministic offline CPU-only logic and synthetic regression tests; no official toolkit scripts or verified output directories were modified.

---

## P0 — Release Blockers

### 1. Clean-Directory Privacy Bypass (`clean/`)
- **Original Finding**: Files placed under an input subdirectory named `clean/` bypassed filename checks, clue extraction, CSV/JSON/TXT redaction, date shifting, and residual scanning, and were copied verbatim into `output/sanitized/clean/`.
- **Root Cause**: `is_clean_ref = rel_path.startswith("clean/")` short-circuited `_selective_out_rel`, Pass 1 clue extraction, and Pass 2 sanitization in [main.py](../main.py).
- **Files Modified**: [main.py](../main.py), [detectors/name_detector.py](../detectors/name_detector.py) (added bare `Patient:` label support while excluding `PSN-` pseudonyms).
- **Remediation**: Removed all `is_clean_ref` exemptions so every input file undergoes full inspection and sanitization. Legitimate PII-free reference files naturally retain their relative paths and clinical content without gaining synthetic `Patient: PSN-...` headers.
- **Regression Test**: `test_p0_clean_directory_bypass_removed` in [tests/test_security_remediation.py](../tests/test_security_remediation.py).
- **Remaining Risk**: Low — unlabelled free-text names without contextual anchors remain a documented limitation.
- **Status**: **Resolved**.

### 2. `ClinicalShield` Over-Protection / PII Smuggling
- **Original Finding**: Clinical complaint/history clauses (`C/O fever ...`, `K/C/O ...`) protected unbounded trailing text on the same line, allowing patient names, phone numbers, and Aadhaar numbers to evade both `detect_all_spans` and `scan_and_scrub_residual`.
- **Root Cause**: `_CO_COMPLAINT_RE` and `_CLINICAL_PREFIX_RE` in [engine/clinical_shield.py](../engine/clinical_shield.py) matched broad trailing clauses, and [engine/pii_detector.py](../engine/pii_detector.py) / [detectors/residual_scanner.py](../detectors/residual_scanner.py) suppressed structured IDs overlapping protected spans.
- **Files Modified**: [engine/clinical_shield.py](../engine/clinical_shield.py), [engine/pii_detector.py](../engine/pii_detector.py), [detectors/residual_scanner.py](../detectors/residual_scanner.py).
- **Remediation**: Narrowed `_CO_COMPLAINT_RE` and `_CLINICAL_PREFIX_RE` to protect only the prefix and immediate clinical keyword/duration, and removed `overlaps_protected` gating for high-confidence structured identifiers (`AADHAAR`, `ABHA_*`, `PAN`, `EMAIL`, `INSURANCE_ID`, `PHONE`, `MRN`).
- **Regression Test**: `test_p0_clinical_shield_does_not_smuggle_pii` in [tests/test_security_remediation.py](../tests/test_security_remediation.py); existing `tests/test_clinical.py` continues to pass.
- **Remaining Risk**: Low — an unlabelled person name immediately following a clinical acronym without separation could still require gazetteer or structural anchoring.
- **Status**: **Resolved**.

### 3. Unicode Normalization Offset-Fallback Bypass
- **Original Finding**: Inserting a single zero-width character (`\u200b`) or NFKC-expanding character anywhere in a text caused `len(normalize_text(text)) != len(text)`, forcing detectors to fall back to scanning the unnormalized raw string and letting homoglyph/Devanagari/zero-width-split PII leak.
- **Root Cause**: `target = norm if len(norm) == len(text) else text` in `indian_ids.py`, `phone_detector.py`, and `address_detector.py`; missing zero-width/NFKC normalization in `kinship_detector.py`, `name_detector.py`, and `DynamicGazetteer`.
- **Files Modified**: [engine/normalization.py](../engine/normalization.py) (`normalize_with_map`, `map_norm_span`), [detectors/indian_ids.py](../detectors/indian_ids.py), [detectors/phone_detector.py](../detectors/phone_detector.py), [detectors/address_detector.py](../detectors/address_detector.py), [detectors/kinship_detector.py](../detectors/kinship_detector.py), [detectors/name_detector.py](../detectors/name_detector.py).
- **Remediation**: Replaced the equal-length heuristic with `normalize_with_map()` and `map_norm_span()`, mapping normalized match indices back to exact character offsets in the original text across all five detectors and `DynamicGazetteer`.
- **Regression Test**: `test_p0_unicode_zero_width_and_homoglyph_offset_mapping` in [tests/test_security_remediation.py](../tests/test_security_remediation.py).
- **Remaining Risk**: Low — only homoglyphs in `_HOMOGLYPHS` (Cyrillic/Greek lookalikes) and NFKC-canonical equivalents are folded; exotic Unicode script confusables outside that table remain out of scope.
- **Status**: **Resolved**.

---

## P1 — High-Priority Security

### 4. Symlink & Reparse-Point Ingestion Escapes
- **Original Finding**: `ingest_directory` used `input_dir.rglob("*")` and `Path.is_file()`, which follows symlinks and Windows reparse points outside the permitted input root.
- **Root Cause**: Missing symlink/reparse-point and resolved-path containment checks in [engine/ingestion.py](../engine/ingestion.py).
- **Files Modified**: [engine/ingestion.py](../engine/ingestion.py).
- **Remediation**: Replaced `rglob` with `os.walk(..., followlinks=False)` plus `_is_reparse_or_symlink` (checking `is_symlink()`, `S_ISLNK`, and Windows `FILE_ATTRIBUTE_REPARSE_POINT`) and `resolve(strict=True).is_relative_to(input_root)`. Unsafe paths are quarantined as `symlink_or_path_escape` without reading target bytes.
- **Regression Test**: `test_p1_symlink_ingestion_quarantined` in [tests/test_security_remediation.py](../tests/test_security_remediation.py).
- **Remaining Risk**: Low — non-privileged Windows accounts without Developer Mode cannot create symlinks (test skips gracefully in that case, while reparse-point logic is active).
- **Status**: **Resolved**.

### 5. Policy Configuration Reconciliation & String-Valued JSON Ages
- **Original Finding**: Seven `config/policy.yaml` settings (`min_group_size`, `suppress_rare_pin`, `suppress_village`, `preserve_clinician_names`, `preserve_clinical_values`, `linkage_auto_merge_threshold`, `linkage_min_independent_clues`) were unread, and string-valued JSON/FHIR ages (`"age": "48"`) were left unbanded.
- **Root Cause**: Hardcoded behavior in [main.py](../main.py) and [engine/identity_linker.py](../engine/identity_linker.py); `isinstance(v, int)` gate on JSON `AGE` fields.
- **Files Modified**: [main.py](../main.py), [engine/identity_linker.py](../engine/identity_linker.py), [engine/pii_detector.py](../engine/pii_detector.py), [config/policy.yaml](../config/policy.yaml).
- **Remediation**: Wired `suppress_rare_pin`, `suppress_village`, `preserve_clinician_names`, `preserve_clinical_values`, `linkage_auto_merge_threshold`, and `linkage_min_independent_clues` into `run_pipeline`, `_sanitize_json_obj`, `redact_text`, and `link_records`. Removed the unsupported `min_group_size` key from `policy.yaml` with an explicit reference to [docs/k_anonymity_experiment.md](../docs/k_anonymity_experiment.md). Updated `_sanitize_json_obj` to band string-valued `AGE` fields (`"48"`, `"48 Y / M"`).
- **Regression Test**: `test_p1_json_string_age_keys_metadata_dates_and_mrn_residual` in [tests/test_security_remediation.py](../tests/test_security_remediation.py).
- **Remaining Risk**: Medium (accepted) — rare quasi-identifier combinations (A5 external-knowledge linking) remain an architectural trade-off documented in `docs/k_anonymity_experiment.md`.
- **Status**: **Resolved**.

### 6. JSON Key Sanitization, Metadata Date Shifting & MRN Residual Scanning
- **Original Finding**: Dates embedded in JSON keys (`"dob_1990-05-12"`) were not shifted, top-level metadata dates in multi-record JSON files bypassed `choose_collision_safe_shift`, and `scan_and_scrub_residual` excluded `MRN`.
- **Root Cause**: `k_has_id` gating in `_sanitize_json_obj` (and `_` replacement destroying ISO `-` separators), direct `get_shift_for_record` call for top-level JSON metadata, and `MRN` omission in `residual_scanner.py`.
- **Files Modified**: [main.py](../main.py), [detectors/residual_scanner.py](../detectors/residual_scanner.py).
- **Remediation**: Added `_sanitize_json_key` (preserving ISO hyphens while scanning `_`-separated tokens for dates and PII), routed multi-record JSON top-level metadata dates through `safe_shifts`, and added `MRN` to `scan_and_scrub_residual`.
- **Regression Test**: `test_p1_json_string_age_keys_metadata_dates_and_mrn_residual` in [tests/test_security_remediation.py](../tests/test_security_remediation.py).
- **Remaining Risk**: Low — single-token names in `DynamicGazetteer` remain excluded from `scan_and_scrub_residual` to avoid false positives on clinical words.
- **Status**: **Resolved**.

---

## P2 — Additional Security & Crypto Hardening

### 7. Cross-Hospital Generic MRN Prefix Linkage Split
- **Original Finding**: Disjoint MRNs sharing generic prefixes (`UHID-001` vs `UHID-999`) blocked linkage of the same patient even when verified government IDs (`aadhaar`, `abha`, `pan`) matched.
- **Root Cause**: `_cannot_link` in [engine/identity_linker.py](../engine/identity_linker.py) treated all alphabetic MRN prefixes as single-facility identifiers.
- **Files Modified**: [engine/identity_linker.py](../engine/identity_linker.py).
- **Remediation**: Excluded generic prefixes (`UHID`, `MRN`, `PAT`, `REG`, `IPD`, `OPD`, `ADM`, `IP`, `SMP`, `LAB`) from same-prefix cannot-link rejection and allowed matching verified government IDs (`aadhaar`, `abha`, `pan`) to override facility-prefix conflicts.
- **Regression Test**: `test_p2_cross_hospital_generic_mrn_prefix_links_on_gov_id` in [tests/test_security_remediation.py](../tests/test_security_remediation.py).
- **Remaining Risk**: Low — two hospitals sharing an unlisted custom prefix without a matching government ID would still be conservatively separated.
- **Status**: **Resolved**.

### 8. Localhost Dashboard Host, Origin, CSRF & Inline Event Hardening
- **Original Finding**: `POST /api/run` and `POST /api/evaluate` accepted cross-origin requests without `Origin`/`Host` validation or a CSRF token, and file/folder buttons interpolated names into inline `onclick` attributes.
- **Root Cause**: Missing `Host`/`Origin`/CSRF checks in `DashboardHandler` and inline `onclick` template strings in [dashboard.py](../dashboard.py).
- **Files Modified**: [dashboard.py](../dashboard.py), [tests/test_dashboard.py](../tests/test_dashboard.py).
- **Remediation**: Added `_is_valid_host` (`127.0.0.1` / `localhost`), `_is_valid_origin` (`Origin`/`Referer` scheme, host, and port check), and per-server `secrets.token_urlsafe(32)` `X-Kavach-CSRF` validation using `hmac.compare_digest` on all `POST` endpoints. Replaced inline `onclick` filename/folder interpolation with `data-*` attributes and delegated `addEventListener` handlers.
- **Regression Test**: `test_dashboard_csrf_origin_host_and_no_inline_onclick` in [tests/test_dashboard.py](../tests/test_dashboard.py) (proves cross-origin `POST`, foreign `Host`, and missing CSRF requests are rejected with HTTP `403`).
- **Remaining Risk**: Low — localhost-only single-operator model; CSP retains `'unsafe-inline'` for the self-contained single-file HTML/JS UI.
- **Status**: **Resolved**.

### 9. Cryptographic Review (`KeyRing` & Date-Shift Bounds)
- **Original Finding**: `KeyRing` accepted arbitrarily short secrets silently, `PSN-XXXXXX` uses 30-bit Crockford Base32 (per-run collision-checked), and `choose_collision_safe_shift` could expand its fallback sweep to `±365` days beyond `date_shift_max_days` (`180`).
- **Files Modified**: [engine/security.py](../engine/security.py), [engine/privacy_engine.py](../engine/privacy_engine.py).
- **Remediation**: Added a `UserWarning` in `KeyRing.__init__` when `RAKSHA_SECRET` is shorter than 16 bytes (128 bits), and constrained `choose_collision_safe_shift`'s deterministic fallback sweep strictly to `[-max_days, +max_days]` so it fails closed (`ValueError`) rather than exceeding the configured policy bound.
- **Regression Test**: `test_crypto_weak_secret_warns_and_shift_bounds` in [tests/test_security_remediation.py](../tests/test_security_remediation.py).
- **Remaining Risk**: Low — `PSN-XXXXXX` (30 bits) remains collision-checked per run; cross-run collisions remain theoretically possible at large population scales (`~38k+` distinct patients).
- **Status**: **Resolved**.

---

## Clinical Preservation Recovery (72 / 72 Probes Restored)

Following the initial security remediation, practice evaluation showed `4,783 / 4,855` medical values preserved (`72` lost) while PII leakage remained `0 / 3,230`. Three targeted corrections restored full `4,855 / 4,855` (`100.0%`) clinical preservation without weakening any security control:

1. **Clinical History & Kinship Disambiguation** ([detectors/kinship_detector.py](../detectors/kinship_detector.py), [engine/clinical_shield.py](../engine/clinical_shield.py)):
   - Added `(?<![A-Za-z]/)` negative lookbehind to `_LATIN_KINSHIP_RE` so `K/C/O`, `F/H/O`, and `P/H/O` do not match `C/O` or `H/o`.
   - Protected the `K/C/O|H/O|F/H/O|P/H/O` markers in `_CLINICAL_PREFIX_RE` and checked full-match overlap (`m.start(0)` to `end`) in `detect_kinship`, preserving Title-Cased clinical conditions while keeping trailing names, phones, and Aadhaar numbers fully redactable.
2. **Context-Aware `ward` Field Handling** ([engine/pii_detector.py](../engine/pii_detector.py), [main.py](../main.py)):
   - Removed the blanket `k == "ward"` → `"ADDRESS"` classification in `classify_field_name`, and handled JSON `"ward"` fields contextually in `_sanitize_json_obj` so standalone hospital ward labels (without residential keywords or PII/address sibling keys) are preserved while residential `"Ward No. ..."` / `"Mohalla ..."` values are redacted.
3. **PIN Range Guard** ([detectors/address_detector.py](../detectors/address_detector.py)):
   - Guarded `_PIN_RE`'s hyphen branch with `(?<![\d.])-\s*([1-8]\d{5})\b` so numeric/decimal lab ranges (`150000-410000`, `12.5-150000`) are not misclassified as postal PINs.

### Final Verification Results (`output/kavach-clinical-recovery-verify`)
- **`python -m pytest -q`**: **`78 passed, 1 xfailed`** (includes `test_clinical_recovery_history_markers_and_trailing_pii`, `test_clinical_recovery_ward_hospital_vs_residential`, `test_clinical_recovery_pin_vs_numeric_and_decimal_ranges`, and all P0/P1/P2 tests).
- **`validate_output.py`**: **`CONTRACT OK`** (`files 200 sanitized 193 quarantined 7 records 822`).
- **`check_dev.py`**:
  - Personal data leaked: **`0 / 3,230` (`0.0%`)**
  - Canaries leaked: **`0 / 4`**
  - Medical data kept: **`4,855 / 4,855` (`100.0%`)**
  - Patient linking: **`precision 1.00, recall 0.85, F0.5 0.97`** (`0` false merges)
  - Raw copies: **`0`**
- **`check_submission.py --repo . --run`**: **`READY TO SUBMIT`**
