"""Detection of Indian addresses: House No, Locality/Mohalla, Landmark, Village, PIN."""
from __future__ import annotations

import re

from engine.normalization import map_norm_span, normalize_with_map
from engine.record_model import EntitySpan

_HOUSE_RE = re.compile(
    r"\b(?:H\.?\s*No\.?|House(?:\s+No\.?)?|Makan(?:\s+No\.?)?|Flat(?:\s+No\.?)?|Plot(?:\s+No\.?)?|मकान\s*(?:नं\.?|संख्या)?)\s*[:#\-]?\s*[A-Z0-9\-\/]{1,12}\b",
    re.IGNORECASE,
)

_LOCALITY_RE = re.compile(
    r"\b(?:Mohalla|Colony|Nagar|Vihar|Sector|Gali|Street|Lane|Road|मोहल्ला|कॉलोनी|नगर)\s+[A-Z\u0900-\u097F][A-Za-z\u0900-\u097F0-9\s\-]{1,35}?(?=[,\n;]|$|\s+(?:near|opp|Tehsil|Distt|District|PIN))",
    re.IGNORECASE,
)

_WARD_LOCALITY_RE = re.compile(
    r"\bWard\s+(?:No\.?\s*)?\d+\b(?!\s*\((?:Medicine|Surgery|Pediatrics|Gynae|Ortho|ICU|ENT|Eye)\))",
    re.IGNORECASE,
)

_LANDMARK_RE = re.compile(
    r"\b(?:near|opp\.?|opposite|behind|beside|in\s+front\s+of|के\s+पास|के\s+सामने)\s+[A-Z\u0900-\u097F][A-Za-z\u0900-\u097F0-9\s\-]{2,35}?(?=[,\n;]|$|\s+(?:Tehsil|Distt|District|Gram|Village|PIN))"
    r"|([\u0900-\u097F0-9]{2,}(?:\s+[\u0900-\u097F0-9]{2,}){0,4}\s+(?:के\s+पास|के\s+सामने|के\s+पीछे))",
    re.IGNORECASE,
)

_VILLAGE_RE = re.compile(
    r"\b(?:Gram|Village|Vill\.?|Post|P\.?O\.?|ग्राम|गांव|गाँव)\s*[:\-]?\s*([A-Z\u0900-\u097F][A-Za-z\u0900-\u097F\s\-]{2,30}?)(?=[,\n;]|$|\s+(?:Tehsil|Distt|District|Block|PIN))"
    r"|,\s*([A-Z][A-Za-z\s\-]{2,30}?)(?=,\s*(?:Tehsil|Taluka|Block|Distt|District)\b)",
    re.IGNORECASE,
)

_PIN_RE = re.compile(
    r"(?:(?:PIN|Pin\s*Code|Zip|पिन)\s*[:\-]?\s*|,\s*|(?<![\d.])-\s*)([1-8]\d{5})\b",
    re.IGNORECASE,
)


def detect_addresses(text: str) -> list[EntitySpan]:
    """Detect house numbers, localities, landmarks, villages, and PIN codes."""
    target, idx_map = normalize_with_map(text)
    if not target:
        return []
    spans: list[EntitySpan] = []

    def _add(ns: int, ne: int, etype: str, val: str) -> None:
        os_, oe_ = map_norm_span(idx_map, ns, ne)
        if oe_ > os_:
            spans.append(EntitySpan(os_, oe_, etype, val))

    for m in _HOUSE_RE.finditer(target):
        _add(m.start(), m.end(), "HOUSE", m.group(0))

    for m in _LOCALITY_RE.finditer(target):
        raw_g = m.group(0)
        val = raw_g.strip()
        lead = len(raw_g) - len(raw_g.lstrip())
        _add(m.start() + lead, m.start() + lead + len(val), "LOCALITY", val)

    for m in _WARD_LOCALITY_RE.finditer(target):
        _add(m.start(), m.end(), "LOCALITY", m.group(0))

    for m in _LANDMARK_RE.finditer(target):
        raw_g = m.group(0)
        val = raw_g.strip()
        lead = len(raw_g) - len(raw_g.lstrip())
        _add(m.start() + lead, m.start() + lead + len(val), "LANDMARK", val)

    for m in _VILLAGE_RE.finditer(target):
        grp = 1 if m.group(1) is not None else 2
        raw_g = m.group(grp)
        val = raw_g.strip()
        if not any(w in val.lower() for w in ("mohalla", "ward", "near ", "opp", "house", "makan", "h.no")):
            lead = len(raw_g) - len(raw_g.lstrip())
            _add(m.start(grp) + lead, m.start(grp) + lead + len(val), "VILLAGE", val)

    for m in _PIN_RE.finditer(target):
        _add(m.start(1), m.end(1), "PIN", m.group(1))

    return spans
