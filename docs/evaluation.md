# KAVACH-FHIR Evaluation Summary (Practice Dataset)

Measured on the supplied truth-hash-matched Secret-Wards practice/development dataset (`Secret-Wards-ToolKit-LF/dev/input`: **200 files**, **193 sanitized**, **7 quarantined**, **822 records**).

> **Note:** These are results on the supplied practice/development dataset, **not** the official hidden-evaluation score. Zero leakage on the practice dataset does not guarantee zero leakage on arbitrary real-world datasets.

| Metric | Starter Baseline | KAVACH-FHIR |
|---|---:|---:|
| Unit & Security Tests (`pytest`) | — | **78 passed, 1 xfailed** |
| PII Leakage (`check_dev.py`) | 83.5%+ | **0 / 3,230** |
| Canaries Leaked | 4 / 4 | **0 / 4** |
| Clinical Preservation | 100.0% | **4,855 / 4,855** (100.0%) |
| Linkage Precision | 0.00 | **1.00** |
| Linkage Recall | 0.00 | **0.85** |
| Linkage F0.5 | 0.00 | **0.97** |
| False Merges | 0 | **0** |
| Raw Unsupported Copies | 0 | **0** |
| Practice Dataset Files | 200 | **200** (193 sanitized, 7 quarantined) |
| Exported Records | — | **822** |
| Contract Validation | `CONTRACT OK` | **`CONTRACT OK`** |
| Full Submission Checker | — | **`READY TO SUBMIT`** |

## Conservative Linkage Trade-Off

KAVACH-FHIR prioritizes precision over aggressive recall: shared phone numbers never link alone, name matches require multi-point corroboration, and every candidate merge passes cluster-wide cannot-link checks. This achieves **1.00 precision** and **0 false merges** while leaving ambiguous records unlinked (`0.85` recall, `0.97` F0.5).

## Known Limitations

- **Rare-diagnosis population-level privacy:** Quasi-identifier generalization (`5-year` age bands, `3-digit` PIN prefixes) is not coupled to external population registries; an adversary with exact rare-disease + district + age-band knowledge may still isolate small equivalence classes.
- **Unlabeled names:** Single-token or unlabeled names in free text without structured, honorific, or kinship anchors may not be captured by the per-run gazetteer.
