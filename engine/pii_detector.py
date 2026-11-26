"""Layered multilingual PII detection, overlap resolution, and channel sanitization."""
from __future__ import annotations

import base64
import binascii
import re

from detectors.address_detector import detect_addresses
from detectors.indian_ids import detect_indian_ids
from detectors.kinship_detector import detect_kinship
from detectors.name_detector import DynamicGazetteer, detect_contextual_names
from detectors.phone_detector import detect_phones
from engine.clinical_shield import find_protected_spans, overlaps_protected
from engine.normalization import normalize_text
from engine.record_model import EntitySpan, PipelineStats

_B64_RE = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")

# Priority order when resolving overlapping spans (higher wins)
_TYPE_PRIORITY = {
    "ABHA_NUMBER": 100,
    "ABHA_ADDRESS": 98,
    "AADHAAR": 95,
    "AADHAAR_MASKED": 92,
    "PAN": 90,
    "EMAIL": 88,
    "INSURANCE_ID": 85,
    "PHONE": 82,
    "MRN": 80,
    "RELATIVE_NAME": 75,
    "PATIENT_NAME": 70,
    "DOB": 65,
    "HOUSE": 60,
    "LOCALITY": 55,
    "LANDMARK": 50,
    "VILLAGE": 48,
    "PIN": 45,
}


def resolve_overlaps(spans: list[EntitySpan]) -> list[EntitySpan]:
    """Keep non-overlapping spans, preferring longer and higher-priority detections."""
    ordered = sorted(
        spans,
        key=lambda s: (-(s.end - s.start), -_TYPE_PRIORITY.get(s.entity_type, 0), s.start),
    )
    kept: list[EntitySpan] = []
    for cand in ordered:
        if cand.end <= cand.start:
            continue
        if any(cand.start < k.end and cand.end > k.start for k in kept):
            continue
        kept.append(cand)
    kept.sort(key=lambda s: s.start)
    return kept


def classify_field_name(field_name: str) -> str | None:
    """Semantically classify a CSV header or JSON key into a PII/quasi-ID category."""
    k = re.sub(r"[^a-z0-9/\s]", " ", normalize_text(field_name).lower()).strip()
    tokens = set(k.split())

    # Clinician attribution must be preserved
    if any(w in tokens for w in ("doctor", "doc", "ref_doctor", "referred", "consultant", "physician", "surgeon")):
        return "CLINICIAN"
    if "ref" in tokens and "doctor" in k:
        return "CLINICIAN"

    if any(w in k for w in ("aadhaar", "aadhar", "uidai")):
        return "AADHAAR"
    if "abha" in k:
        return "ABHA_NUMBER"
    if "pan" in tokens or "payer pan" in k:
        return "PAN"
    if any(w in k for w in ("pmjay", "policy", "insurance")):
        return "INSURANCE_ID"
    if any(w in k for w in ("email", "e mail")):
        return "EMAIL"
    if any(w in k for w in ("phone", "mobile", "mob", "contact", "callback", "tel")):
        return "PHONE"
    if any(w in k for w in ("uhid", "mrn", "reg no", "reg_no", "patient id", "patientid", "patient ref", "hospital uhid", "ipd", "sample id", "bill no", "visit id")):
        return "MRN"
    if any(w in k for w in ("pita", "pati", "guardian", "relative", "father", "mother", "husband", "spouse")):
        return "RELATIVE_NAME"
    if any(w in k for w in ("patient name", "patient_name", "naam", "first name", "firstname", "last name", "lastname", "full name", "raised by")) or k == "name":
        return "PATIENT_NAME"
    if any(w in k for w in ("dob", "janm tithi", "birth date", "birthdate", "birth")):
        return "DOB"
    if k in ("age", "umar", "age sex", "age_sex"):
        return "AGE"
    if k in ("sex", "gender", "ling"):
        return "GENDER"
    if any(w in k for w in ("village", "gaon", "gram", "city")):
        return "VILLAGE"
    if any(w in k for w in ("district", "jila", "distt")):
        return "DISTRICT"
    if any(w in k for w in ("tehsil", "taluka", "block")):
        return "TEHSIL"
    if any(w in k for w in ("pin", "zip", "postal")):
        return "PIN"
    if any(w in k for w in ("address", "pata", "street", "house", "mohalla", "locality", "landmark")) or k == "ward":
        return "ADDRESS"
    if any(w in k for w in ("source path", "source_path", "filepath", "file_path")):
        return "METADATA_PATH"
    if any(w in k for w in ("date", "registered", "collected", "reported", "recordeddate", "authoredon", "effectivedatetime", "performeddatetime")):
        return "DATE"
    return None


def detect_all_spans(
    text: str,
    gazetteer: DynamicGazetteer | None = None,
) -> list[EntitySpan]:
    """Run all layered detectors on text, respecting ClinicalShield."""
    if not text:
        return []
    protected = find_protected_spans(text)
    raw_spans: list[EntitySpan] = []

    for s in detect_indian_ids(text):
        if not overlaps_protected(s.start, s.end, protected):
            raw_spans.append(s)

    for s in detect_phones(text):
        if not overlaps_protected(s.start, s.end, protected):
            raw_spans.append(s)

    raw_spans.extend(detect_kinship(text, protected))

    for s in detect_addresses(text):
        if not overlaps_protected(s.start, s.end, protected):
            raw_spans.append(s)

    raw_spans.extend(detect_contextual_names(text, protected))

    if gazetteer is not None:
        raw_spans.extend(gazetteer.match(text, protected))

    return resolve_overlaps(raw_spans)


def redact_text(
    text: str,
    gazetteer: DynamicGazetteer | None = None,
    stats: PipelineStats | None = None,
    pseudonym: str | None = None,
) -> str:
    """Detect and replace PII spans in text, plus sanitize embedded base64 payloads."""
    if not text:
        return text

    # Handle base64-encoded text attachments first
    def _clean_b64(m: re.Match) -> str:
        tok = m.group(0)
        try:
            decoded = base64.b64decode(tok + "=" * (-len(tok) % 4)).decode("utf-8", errors="strict")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            return tok
        # Only treat as text attachment if mostly printable
        if not decoded or sum(ch.isprintable() or ch in "\r\n\t" for ch in decoded) / len(decoded) < 0.85:
            return tok
        cleaned_inner = redact_text(decoded, gazetteer=gazetteer, stats=stats, pseudonym=pseudonym)
        return base64.b64encode(cleaned_inner.encode("utf-8")).decode("ascii")

    text = _B64_RE.sub(_clean_b64, text)

    spans = detect_all_spans(text, gazetteer=gazetteer)
    if not spans:
        return text

    out_parts: list[str] = []
    cursor = 0
    for sp in spans:
        out_parts.append(text[cursor:sp.start])
        if sp.entity_type == "PIN" and len(sp.text) == 6 and sp.text.isdigit():
            replacement = f"{sp.text[:3]}***"
        elif sp.entity_type == "PATIENT_NAME" and pseudonym:
            replacement = pseudonym
        else:
            replacement = f"[{sp.entity_type}]"
        out_parts.append(replacement)
        cursor = sp.end
        if stats is not None:
            stats.add_entity(sp.entity_type)
    out_parts.append(text[cursor:])
    return "".join(out_parts)
