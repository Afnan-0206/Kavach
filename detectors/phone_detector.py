"""Detection of Indian phone numbers (mobile, landline, masked, Devanagari)."""
from __future__ import annotations

import re

from engine.normalization import map_norm_span, normalize_with_map
from engine.record_model import EntitySpan

# +91 72864 90658, +91-7286490658, 072864-90658, 7286490658
_PHONE_RE = re.compile(
    r"(?<!\d)(?:(?:\+?91|0)[\s\-]?)?[6-9]\d{4}[\s\-]?\d{5}(?!\d)"
)
# STD landline: 0522-2234567, 011-23456789
_LANDLINE_RE = re.compile(r"(?<!\d)0\d{2,4}[\-]\d{6,8}(?!\d)")
# Masked phone: 98XXXXXX10, XXXXXX9010
_MASKED_PHONE_RE = re.compile(r"(?i)(?<![A-Za-z0-9])(?:\d{2}[X*]{6}\d{2}|[X*]{6}\d{4})(?!\d)")
# Labeled phone that might start with non-6-9 or have spaces
_LABELED_PHONE_RE = re.compile(
    r"(?i)(?:Mobile|Mob|Phone|Ph|Contact|Callback|Tel|फ़ोन|मोबाइल|संपर्क)\s*(?:No\.?|Number|#)?\s*[:\-]\s*([\+\d\-\s]{8,16})"
)


def detect_phones(text: str) -> list[EntitySpan]:
    """Detect Indian phone numbers and masked phone numbers."""
    target, idx_map = normalize_with_map(text)
    if not target:
        return []
    spans: list[EntitySpan] = []

    def _add(ns: int, ne: int, val: str) -> None:
        os_, oe_ = map_norm_span(idx_map, ns, ne)
        if oe_ > os_:
            spans.append(EntitySpan(os_, oe_, "PHONE", val))

    for m in _PHONE_RE.finditer(target):
        _add(m.start(), m.end(), m.group(0))

    for m in _LANDLINE_RE.finditer(target):
        _add(m.start(), m.end(), m.group(0))

    for m in _MASKED_PHONE_RE.finditer(target):
        _add(m.start(), m.end(), m.group(0))

    for m in _LABELED_PHONE_RE.finditer(target):
        val = m.group(1).strip()
        digits = re.sub(r"\D", "", val)
        if 8 <= len(digits) <= 13:
            lead = len(m.group(1)) - len(m.group(1).lstrip())
            ns = m.start(1) + lead
            _add(ns, ns + len(val), val)

    return spans
