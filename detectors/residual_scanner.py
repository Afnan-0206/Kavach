"""Final residual leakage scanner for sanitized outputs and side channels."""
from __future__ import annotations

import re

from detectors.indian_ids import detect_indian_ids
from detectors.name_detector import DynamicGazetteer
from detectors.phone_detector import detect_phones
from engine.clinical_shield import find_protected_spans, overlaps_protected
from engine.pii_detector import resolve_overlaps
from engine.record_model import EntitySpan


def scan_and_scrub_residual(
    text: str,
    gazetteer: DynamicGazetteer | None = None,
) -> tuple[str, int]:
    """Scan output text for any surviving direct IDs or known patient names and scrub them."""
    if not text:
        return text, 0
    protected = find_protected_spans(text)
    hits: list[EntitySpan] = []

    for s in detect_indian_ids(text):
        if s.entity_type in ("AADHAAR", "ABHA_NUMBER", "ABHA_ADDRESS", "PAN", "EMAIL", "INSURANCE_ID", "AADHAAR_MASKED"):
            if not overlaps_protected(s.start, s.end, protected):
                hits.append(s)

    for s in detect_phones(text):
        if not overlaps_protected(s.start, s.end, protected):
            hits.append(s)

    if gazetteer is not None and gazetteer._compiled_full is not None:
        for m in gazetteer._compiled_full.finditer(text):
            if not overlaps_protected(m.start(), m.end(), protected):
                hits.append(EntitySpan(m.start(), m.end(), "PATIENT_NAME", m.group(0)))

    resolved = resolve_overlaps(hits)
    if not resolved:
        return text, 0

    out: list[str] = []
    cur = 0
    for sp in resolved:
        out.append(text[cur:sp.start])
        out.append(f"[{sp.entity_type}]")
        cur = sp.end
    out.append(text[cur:])
    return "".join(out), len(resolved)
