# KAVACH-FHIR Evaluation Summary

Measured on `Secret-Wards-ToolKit/dev/input` (200 files, 48 patients) with `RAKSHA_SECRET=practice`:

| Metric | Starter Baseline | KAVACH-FHIR |
|---|---:|---:|
| Content PII Leaked | 83.5% | **0.2%** |
| Hinglish PII Leaked | 100.0% | **0.0%** |
| Devanagari PII Leaked | 100.0% | **0.7%** |
| Base64 / Metadata / Key / Header Leaked | 100.0% | **0.0%** |
| Canaries Leaked | 4 / 4 | **0 / 4** |
| Medical Values Preserved | 100.0% | **100.0%** (4,497 / 4,497) |
| Patient Linking Precision / Recall / F0.5 | 0.00 / 0.00 / 0.00 | **1.00 / 0.79 / 0.95** |
| False Patient Merges | 0 | **0** |
| Raw Unsupported Copies | 0 | **0** |
| Contract Validation | `CONTRACT OK` | **`CONTRACT OK`** |
| Execution Time (CPU) | — | **10.31s** |
