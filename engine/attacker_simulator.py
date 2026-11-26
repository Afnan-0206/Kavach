"""Local re-identification risk simulator (Sweeney-style equivalence class & attacker check)."""
from __future__ import annotations

import csv
import io
import json
from collections import Counter
from pathlib import Path


def estimate_equivalence_risk(sanitized_dir: Path) -> dict[str, float | int]:
    """Measure k-anonymity equivalence class sizes on (age_band, district, gender) in sanitized CSVs."""
    classes: Counter[tuple[str, str, str]] = Counter()
    total_records = 0

    for p in sorted(sanitized_dir.rglob("*.csv")) + sorted(sanitized_dir.rglob("*.tsv")):
        delim = "\t" if p.suffix.lower() == ".tsv" else ","
        try:
            rows = list(csv.reader(io.StringIO(p.read_text(encoding="utf-8"), newline=""), delimiter=delim))
        except (OSError, csv.Error):
            continue
        if len(rows) < 2:
            continue
        headers = [h.lower() for h in rows[0]]
        age_idx = next((i for i, h in enumerate(headers) if "age" in h or "umar" in h), None)
        dist_idx = next((i for i, h in enumerate(headers) if "district" in h or "jila" in h), None)
        sex_idx = next((i for i, h in enumerate(headers) if h in ("sex", "gender", "ling")), None)
        if age_idx is None and dist_idx is None:
            continue
        for row in rows[1:]:
            age_b = row[age_idx].strip() if age_idx is not None and age_idx < len(row) else ""
            dist = row[dist_idx].strip() if dist_idx is not None and dist_idx < len(row) else ""
            sex = row[sex_idx].strip() if sex_idx is not None and sex_idx < len(row) else ""
            if age_b or dist:
                classes[(age_b, dist, sex)] += 1
                total_records += 1

    unique_records = sum(c for c in classes.values() if c == 1)
    lt5_records = sum(c for c in classes.values() if c < 5)
    return {
        "total_quasi_records": total_records,
        "equivalence_classes": len(classes),
        "unique_k1_records": unique_records,
        "lt5_records": lt5_records,
        "k1_rate": round(unique_records / total_records, 4) if total_records else 0.0,
    }
