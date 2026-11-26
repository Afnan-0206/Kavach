"""Detection of relative/kinship names (S/o, D/o, W/o, C/O, Devanagari relations)."""
from __future__ import annotations

import re

from engine.clinical_shield import overlaps_protected
from engine.record_model import EntitySpan

# Latin kinship markers: prefix is case-insensitive, name MUST start with uppercase [A-Z]
_LATIN_KINSHIP_RE = re.compile(
    r"(?i:\b(?:S/o|D/o|W/o|C/O|M/o|F/o|H/o|Guardian|Relative(?:\s+Name)?|Father(?:'s)?(?:\s+Name)?|"
    r"Husband(?:'s)?(?:\s+Name)?|Mother(?:'s)?(?:\s+Name)?|Pita/Pati\s+ka\s+Naam)\s*[:\-]?\s*"
    r"(?:Late\s+|Shri\s+|Smt\.?\s+|Mr\.?\s+|Mrs\.?\s+)?)"
    r"([A-Z][a-zA-Z\.']+(?:\s+[A-Z][a-zA-Z\.']+){0,3})"
)

# Devanagari kinship markers: पुत्र, पुत्री, पत्नी, पिता, माता, पति, अभिभावक
_DEVA_KINSHIP_RE = re.compile(
    r"(?:पुत्र|पुत्री|पत्नी|पिता|माता|पति|अभिभावक|संरक्षक)\s*[:\-]?\s*"
    r"(?:श्री\s+|श्रीमती\s+|स्व\.?\s+)?"
    r"([\u0900-\u097F]+(?:\s+[\u0900-\u097F]+){0,2})"
)

# Trailing relation in Hindi: "<Name> के पुत्र/पत्नी" or "<Name> की पत्नी"
_DEVA_PRE_KINSHIP_RE = re.compile(
    r"([\u0900-\u097F]{2,}(?:\s+[\u0900-\u097F]{2,}){0,2})\s+(?:के|की|का)\s+(?:पुत्र|पुत्री|पत्नी|पिता|माता|पति)"
)

_NON_NAME_TAIL = {"age", "dob", "uhid", "ipd", "mobile", "phone", "address", "ward", "bed", "informed", "about", "diet"}


def detect_kinship(text: str, protected: list[tuple[int, int, str]]) -> list[EntitySpan]:
    """Detect relative names anchored by kinship markers, respecting ClinicalShield."""
    spans: list[EntitySpan] = []

    for rx in (_LATIN_KINSHIP_RE, _DEVA_KINSHIP_RE, _DEVA_PRE_KINSHIP_RE):
        for m in rx.finditer(text):
            start, end = m.start(1), m.end(1)
            if overlaps_protected(start, end, protected):
                continue
            name = m.group(1).strip(" .,;:")
            parts = name.split()
            while parts and parts[-1].lower() in _NON_NAME_TAIL:
                parts.pop()
            if not parts:
                continue
            clean_name = " ".join(parts)
            spans.append(EntitySpan(
                start=start,
                end=start + len(clean_name),
                entity_type="RELATIVE_NAME",
                text=clean_name,
                role="relative",
            ))

    return spans
