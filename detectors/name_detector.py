"""Multilingual name detection: labeled names, honorifics, and dynamic gazetteer propagation."""
from __future__ import annotations

import re

from engine.clinical_shield import overlaps_protected
from engine.normalization import map_norm_span, normalize_text, normalize_with_map
from engine.record_model import EntitySpan

# Labeled names in English, Hinglish, and Hindi
_LABELED_NAME_RE = re.compile(
    r"(?i:(?:Patient(?:'s)?(?:[ \t]+Name)?|Pt\.?[ \t]+Name|Full[ \t]+Name|Name|Naam|नाम|मरीज़(?:[ \t]+का[ \t]+नाम)?|रोगी(?:[ \t]+का[ \t]+नाम)?|"
    r"Witnessed[ \t]+by|Raised[ \t]+by|Attendant(?:[ \t]+Name)?)[ \t]*[:\-][ \t]*"
    r"(?:Shri[ \t]+|Smt\.?[ \t]+|Mr\.?[ \t]+|Mrs\.?[ \t]+|Ms\.?[ \t]+|श्री[ \t]+|श्रीमती[ \t]+)?)"
    r"([A-Z\u0900-\u097F][A-Za-z\u0900-\u097F\.']+(?:[ \t]+[A-Z\u0900-\u097F][A-Za-z\u0900-\u097F\.']+){0,3})"
)

# Honorific-anchored names: "Shahid sahab", "Asha ji", "मोहम्मद शाहिद जी", "श्री रामेश"
_LATIN_HONORIFIC_RE = re.compile(
    r"\b([A-Z][a-z]{2,20}(?:\s+[A-Z][a-z]{2,20})?)\s+(?i:ji|sahab|saheb|didi|behenji|bhai|babu)\b"
)
_DEVA_HONORIFIC_RE = re.compile(
    r"([\u0900-\u097F]{2,20}(?:\s+[\u0900-\u097F]{2,20})?)\s+(?:जी|साहब|साहिब|दीदी|भाई)(?=\s|$|[.,।])"
)
_DEVA_PREFIX_HON_RE = re.compile(
    r"(?:श्री|श्रीमती|कुमारी)\s+([\u0900-\u097F]{2,20}(?:\s+[\u0900-\u097F]{2,20})?)"
)

# Hindi sentence subject: "<Name> को <N> दिन से" or "<Name> की उम्र"
_DEVA_CONTEXT_RE = re.compile(
    r"([\u0900-\u097F]{2,20}\s+[\u0900-\u097F]{2,20})\s+(?:को|की|का|ने)\s+(?:\d+|बुखार|दर्द|उम्र|आयु|तारीख|जांच)"
)

# Age/Sex inline pattern: "Asha ji 48 Y / F" or "Mahesh 48/M"
_INLINE_AGE_NAME_RE = re.compile(
    r"\b([A-Z][a-z]{2,20}(?:\s+[A-Z][a-z]{2,20}){0,2})\s+(?:\d{1,3}\s*(?:Y|Yrs?|Years?)\s*/\s*[MF]|\d{1,3}\s*/\s*[MF])\b"
)

# Role-parenthetical or action-phrase names: "Zorawar Qadri (attendant, ...)", "called by Kaveri Nambiar 94054-71434"
_ROLE_PAREN_NAME_RE = re.compile(
    r"\b([A-Z][a-z]{2,20}(?:\s+[A-Z][a-z]{2,20}){1,2})\s*\(\s*(?i:attendant|relative|patient|visitor|spouse|son|daughter|wife|husband|father|mother)\b"
)
_ACTION_NAME_RE = re.compile(
    r"(?i:\b(?:called\s+by|brought\s+by|informed\s+by|accompanied\s+by|signed\s+by|witnessed\s+by|received\s+by|contacted)\s+)"
    r"([A-Z][a-z]{2,20}(?:\s+[A-Z][a-z]{2,20}){1,2})"
)
_NAME_BEFORE_PHONE_RE = re.compile(
    r"\b([A-Z][a-z]{2,20}\s+[A-Z][a-z]{2,20})\s+(?=(?:\+?91[\s\-]?)?[6-9]\d{4}[\s\-]?\d{5}\b)"
)

_STOP_WORDS = {
    "patient", "male", "female", "age", "sex", "dob", "ward", "bed", "date",
    "fever", "pain", "cough", "tablet", "tab", "cap", "inj", "syrup",
    "hospital", "clinic", "doctor", "nurse", "normal", "positive", "negative",
    "मरीज", "रोगी", "आयु", "उम्र", "तारीख", "ग्राम", "पता", "जिला", "दवा",
}


def detect_contextual_names(text: str, protected: list[tuple[int, int, str]]) -> list[EntitySpan]:
    """Detect person names using labels, honorifics, roles, and Hindi/Hinglish syntactic cues."""
    spans: list[EntitySpan] = []
    scan_text, idx_map = normalize_with_map(text)
    if not scan_text:
        return spans

    for rx in (
        _LABELED_NAME_RE,
        _LATIN_HONORIFIC_RE,
        _DEVA_HONORIFIC_RE,
        _DEVA_PREFIX_HON_RE,
        _DEVA_CONTEXT_RE,
        _INLINE_AGE_NAME_RE,
        _ROLE_PAREN_NAME_RE,
        _ACTION_NAME_RE,
        _NAME_BEFORE_PHONE_RE,
    ):
        for m in rx.finditer(scan_text):
            raw_g = m.group(1)
            name = raw_g.strip(" .,;:-")
            if not name or name.lower() in _STOP_WORDS:
                continue
            parts = name.split()
            while parts and parts[-1].lower() in _STOP_WORDS:
                parts.pop()
            if not parts:
                continue
            clean = " ".join(parts)
            if clean.upper().startswith("PSN"):
                continue
            lead = len(raw_g) - len(raw_g.lstrip(" .,;:-"))
            ns = m.start(1) + lead
            ne = ns + len(clean)
            start, end = map_norm_span(idx_map, ns, ne)
            if end <= start or overlaps_protected(start, end, protected):
                continue
            spans.append(EntitySpan(
                start=start,
                end=end,
                entity_type="PATIENT_NAME",
                text=clean,
                role="patient",
            ))

    return spans


class DynamicGazetteer:
    """Per-run gazetteer built from structured records & high-confidence detections."""

    def __init__(self) -> None:
        self.full_names: set[str] = set()
        self.tokens: set[str] = set()
        self._compiled_full: re.Pattern | None = None
        self._compiled_tok: re.Pattern | None = None

    def add_name(self, name: str) -> None:
        norm = normalize_text(name).strip()
        if not norm or len(norm) < 3:
            return
        if norm.lower() in _STOP_WORDS:
            return
        self.full_names.add(norm)
        for tok in norm.split():
            tok_clean = tok.strip(".,;:'\"")
            if len(tok_clean) >= 4 and tok_clean.lower() not in _STOP_WORDS:
                self.tokens.add(tok_clean)

    def build(self) -> None:
        if self.full_names:
            escaped = [re.escape(n) for n in sorted(self.full_names, key=len, reverse=True)]
            self._compiled_full = re.compile(
                r"(?<![A-Za-z\u0900-\u097F])(?:" + "|".join(escaped) + r")(?![A-Za-z\u0900-\u097F])",
                re.IGNORECASE,
            )
        if self.tokens:
            escaped_t = [re.escape(t) for t in sorted(self.tokens, key=len, reverse=True)]
            self._compiled_tok = re.compile(
                r"(?<![A-Za-z\u0900-\u097F])(?:" + "|".join(escaped_t) + r")(?![A-Za-z\u0900-\u097F])",
                re.IGNORECASE,
            )

    def _match_rx(self, text: str, rx: re.Pattern | None, protected: list[tuple[int, int, str]]) -> list[EntitySpan]:
        if rx is None or not text:
            return []
        scan_text, idx_map = normalize_with_map(text)
        if not scan_text:
            return []
        spans: list[EntitySpan] = []
        for m in rx.finditer(scan_text):
            start, end = map_norm_span(idx_map, m.start(), m.end())
            if end > start and not overlaps_protected(start, end, protected):
                spans.append(EntitySpan(
                    start=start,
                    end=end,
                    entity_type="PATIENT_NAME",
                    text=m.group(0),
                    role="patient",
                ))
        return spans

    def match(self, text: str, protected: list[tuple[int, int, str]]) -> list[EntitySpan]:
        spans = self._match_rx(text, self._compiled_full, protected)
        spans.extend(self._match_rx(text, self._compiled_tok, protected))
        return spans

    def match_full_only(self, text: str, protected: list[tuple[int, int, str]]) -> list[EntitySpan]:
        return self._match_rx(text, self._compiled_full, protected)
