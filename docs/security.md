# KAVACH-FHIR Security Model

1. **Key Derivation (`engine/security.py`):** `RAKSHA_SECRET` is never stored or logged. HKDF-SHA256 derives independent 256-bit keys for pseudonyms, date shifts, filename tokens, and AES-256-GCM temporary encryption.
2. **Pseudonym Inversion Resistance:** HMAC-SHA256 keyed with the derived pseudonym key prevents dictionary/rainbow-table inversion of `PSN-XXXXXX` identifiers, and different `RAKSHA_SECRET` values produce unlinkable pseudonyms and date shifts.
3. **Side-Channel Hygiene:** `stdout` prints only aggregate counts (`files ... sanitized ... quarantined ... records ...`). `report.json` identifies files solely by input SHA-256 and never records raw filenames or PII.
4. **Fail-Safe Quarantine:** Unsupported formats (`.pdf`, `.jpg`, `.xml`), empty files, undecodable byte sequences, truncated JSON, and excessively deep JSON (`>500` levels) are quarantined and never copied raw into `sanitized/`.
5. **Atomic Writes:** Sanitized outputs, `records.jsonl`, and `report.json` are written to temporary files and atomically swapped via `os.replace`.
