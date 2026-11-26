# KAVACH-FHIR Architecture

KAVACH-FHIR is structured as a deterministic, two-pass, offline pipeline:

1. **Ingestion (`engine/ingestion.py`):** Deterministic sorted traversal, SHA-256 hashing, multi-encoding decoding (UTF-8 BOM, UTF-16, UTF-8, cp1252), iterative JSON depth guard (`max_json_depth: 500`), mislabeled JSON-in-CSV detection, and safe quarantine.
2. **Normalization (`engine/normalization.py`):** NFKC, zero-width stripping, Cyrillic/Greek homoglyph folding, Devanagari digit conversion, and `indic-transliteration` + Indian phonetic normalization.
3. **Clinical Shield (`engine/clinical_shield.py`):** Span-level protection for `Dr.` attribution, medical eponyms, `C/O <complaint>`, `K/C/O`, `H/O`, hospital names, dosages, `1-0-1` frequencies, vitals, and lab values.
4. **Layered Detectors (`detectors/`):** Indian IDs, phones, kinship relations, addresses, contextual/honorific names, dynamic per-run gazetteer, and residual leakage scanner.
5. **Identity Linker (`engine/identity_linker.py`):** Blocking + RapidFuzz phonetic similarity + cluster-wide cannot-link constraints + collision-checked HMAC-SHA256 pseudonyms.
6. **Privacy Engine (`engine/privacy_engine.py`):** Per-patient deterministic date shifting (preserving LOS and visit intervals), 5-year age banding, and 3-digit PIN prefix generalization.
7. **Exporter & Reporting (`engine/exporter.py`, `engine/reporting.py`):** Atomic UTF-8 writes, `records.jsonl`, and truthful `raksha-report/1` `report.json`.
