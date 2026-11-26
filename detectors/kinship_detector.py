"""Detection of relative/kinship names (S/o, D/o, W/o, C/O, Devanagari relations)."""
from __future__ import annotations

import re

from engine.clinical_shield import overlaps_protected
from engine.normalization import map_norm_span, normalize_with_map
from engine.record_model import EntitySpan

# Latin kinship markers: prefix is case-insensitive, name MUST start with uppercase [A-Z]
_LATIN_KINSHIP_RE = re.compile(
    r"(?<![A-Za-z]/)(?i:\b(?:S/o|D/o|W/o|C/O|M/o|F/o|H/o|Guardian|Relative(?:[ \t]+Name)?|"
    r"Attendant(?:[ \t]+Name)?|Attender|Next[ \t]+of[ \t]+Kin|Caregiver|Contact[ \t]+Person|"
    r"Father(?:'s)?(?:[ \t]+Name)?|Husband(?:'s)?(?:[ \t]+Name)?|Mother(?:'s)?(?:[ \t]+Name)?|"
    r"Wife(?:'s)?(?:[ \t]+Name)?|Pita/Pati[ \t]+ka[ \t]+Naam)[ \t]*[:\-]?[ \t]*"
    r"(?:Late[ \t]+|Shri[ \t]+|Smt\.?[ \t]+|Mr\.?[ \t]+|Mrs\.?[ \t]+)?)"
    r"([A-Z][a-zA-Z\.']+(?:[ \t]+[A-Z][a-zA-Z\.']+){0,3})"
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
    scan_text, idx_map = normalize_with_map(text)
    if not scan_text:
        return []
    spans: list[EntitySpan] = []

    for rx in (_LATIN_KINSHIP_RE, _DEVA_KINSHIP_RE, _DEVA_PRE_KINSHIP_RE):
        for m in rx.finditer(scan_text):
            raw_g = m.group(1)
            name = raw_g.strip(" .,;:")
            parts = name.split()
            while parts and parts[-1].lower() in _NON_NAME_TAIL:
                parts.pop()
            if not parts:
                continue
            clean_name = " ".join(parts)
            lead = len(raw_g) - len(raw_g.lstrip(" .,;:"))
            ns = m.start(1) + lead
            ne = ns + len(clean_name)
            start, end = map_norm_span(idx_map, ns, ne)
            full_start, _ = map_norm_span(idx_map, m.start(0), ne)
            if end <= start or overlaps_protected(full_start, end, protected):
                continue
            spans.append(EntitySpan(
                start=start,
                end=end,
                entity_type="RELATIVE_NAME",
                text=clean_name,
                role="relative",
            ))

    return spans
