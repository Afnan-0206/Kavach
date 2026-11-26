"""Detection of Indian structured identifiers: Aadhaar, ABHA, PAN, MRN/UHID, Insurance, Email."""
from __future__ import annotations

import re

from engine.normalization import map_norm_span, normalize_with_map
from engine.record_model import EntitySpan

# Note: patterns run on normalized text (Indic digits -> ASCII) or original text with Devanagari digits
_AADHAAR_RE = re.compile(r"(?<!\d)(?:\d{4}[\s\-]?\d{4}[\s\-]?\d{4})(?!\d)")
_AADHAAR_MASKED_RE = re.compile(r"(?i)(?<![A-Za-z0-9])[X*#]{4}[\s\-]?[X*#]{4}[\s\-]?\d{4}(?!\d)")
_ABHA_NUM_RE = re.compile(r"(?<!\d)\d{2}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}(?!\d)")
_ABHA_ADDR_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@(?:abdm|ndhm|sbx)\b", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_PAN_RE = re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")

# Hospital MRN / UHID / IPD / OPD / Sample / Bill / Insurance IDs
# Covers: SNJ/26/064127, SNJ-26-064508, UHID-010607, JJH-0077132, ADM000162, DHH-IPD-00591,
# IP-26-00130, OPD/26/02/00085, BL/26/000235, and general unseen hospital prefix-year-seq IDs.
_MRN_PREFIXED_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:UHID|MRN|IPD|OPD|ADM|SNJ|JJH|DHH|ARG|BL|REG|IP|SMP|LAB|PAT)"
    r"(?:[/\-]\d{2,4}){1,3}(?:[/\-][A-Z0-9]{2,10})?(?![A-Za-z0-9])"
    r"|(?<![A-Za-z0-9])(?:UHID|MRN|IPD|ADM|SNJ|JJH|DHH|REG)[\-/]?\d{4,10}(?![A-Za-z0-9])"
    r"|(?<![A-Za-z0-9])[A-Z]{2,4}[/\-]\d{2,4}[/\-]\d{4,8}(?![A-Za-z0-9])",
    re.IGNORECASE,
)

# Insurance / PMJAY / Policy IDs
_INSURANCE_RE = re.compile(
    r"\b(?:PMJAY|AB\-?PMJAY|POL|POLICY|INS|TPA|CGHS|ESIC)[\-/][A-Z0-9]{1,6}(?:[\-/][A-Z0-9]{2,12}){1,3}\b",
    re.IGNORECASE,
)

# Context-anchored generic ID (e.g., "Reg No: 123456", "ID: X9982")
_LABELED_ID_RE = re.compile(
    r"(?i)(?:UHID|MRN|Reg(?:istration)?\s*(?:No\.?|ID)?|Patient\s*ID|IPD\s*No\.?|Sample\s*ID|"
    r"पंजीकरण\s*(?:सं\.?|संख्या)?|यूएचआईडी)\s*[:#\-]\s*([A-Z0-9][A-Z0-9/\-]{3,20})"
)


def detect_indian_ids(text: str) -> list[EntitySpan]:
    """Detect structured Indian IDs, emails, MRNs, and insurance IDs."""
    target, idx_map = normalize_with_map(text)
    if not target:
        return []
    spans: list[EntitySpan] = []

    def _add(ns: int, ne: int, etype: str, val: str) -> None:
        os_, oe_ = map_norm_span(idx_map, ns, ne)
        if oe_ > os_:
            spans.append(EntitySpan(os_, oe_, etype, val))

    for m in _ABHA_ADDR_RE.finditer(target):
        _add(m.start(), m.end(), "ABHA_ADDRESS", m.group(0))

    for m in _EMAIL_RE.finditer(target):
        if not m.group(0).lower().endswith(("@abdm", "@ndhm", "@sbx")):
            _add(m.start(), m.end(), "EMAIL", m.group(0))

    for m in _PAN_RE.finditer(target):
        _add(m.start(), m.end(), "PAN", m.group(0))

    for m in _ABHA_NUM_RE.finditer(target):
        digits = re.sub(r"\D", "", m.group(0))
        if len(digits) == 14:
            _add(m.start(), m.end(), "ABHA_NUMBER", m.group(0))

    for m in _AADHAAR_MASKED_RE.finditer(target):
        _add(m.start(), m.end(), "AADHAAR_MASKED", m.group(0))

    for m in _AADHAAR_RE.finditer(target):
        digits = re.sub(r"\D", "", m.group(0))
        # Avoid matching 12-digit substrings of 14-digit ABHA numbers
        if len(digits) == 12:
            _add(m.start(), m.end(), "AADHAAR", m.group(0))

    for m in _INSURANCE_RE.finditer(target):
        _add(m.start(), m.end(), "INSURANCE_ID", m.group(0))

    for m in _MRN_PREFIXED_RE.finditer(target):
        _add(m.start(), m.end(), "MRN", m.group(0))

    for m in _LABELED_ID_RE.finditer(target):
        _add(m.start(1), m.end(1), "MRN", m.group(1))

    return spans
