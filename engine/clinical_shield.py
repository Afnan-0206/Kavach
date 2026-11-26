"""Clinical Shield: protects medical values, clinician attribution, and meaning traps."""
from __future__ import annotations

import re

# Clinician attribution: Dr. Ramesh, Dr Ramesh Srivastava, डॉ. रमेश, Consultant: Dr. ...
_CLINICIAN_RE = re.compile(
    r"(?:"
    r"(?:Consultant|Referred\s+by|Ref\.?\s*Dr|Treating\s+Doctor|Physician|Surgeon)\s*[:\-]\s*"
    r")?"
    r"(?:Dr\.?|डॉ\.?)\s+[A-Z\u0900-\u097F][A-Za-z\u0900-\u097F\.\-]*"
    r"(?:\s+[A-Z\u0900-\u097F][A-Za-z\u0900-\u097F\.\-]*){0,3}",
    re.UNICODE,
)

# Medical eponyms that contain proper-looking names
_EPONYM_RE = re.compile(
    r"\b(?:Parkinson(?:'s)?|Addison(?:'s)?|Alzheimer(?:'s)?|Cushing(?:'s)?|Graves(?:'|s)?|"
    r"Hodgkin(?:'s)?|Non-Hodgkin(?:'s)?|Crohn(?:'s)?|Bell(?:'s)?|Hashimoto(?:'s)?|"
    r"Hansen(?:'s)?|Wilson(?:'s)?|Down(?:'s)?|Turner(?:'s)?|Marfan(?:'s)?|Guillain-Barr[eé]|"
    r"Raynaud(?:'s)?|Sj[oö]gren(?:'s)?|Kawasaki|Takayasu|Pott(?:'s)?|Paget(?:'s)?|"
    r"Huntington(?:'s)?|Men[iè]re(?:'s)?|Burkitt(?:'s)?|Ewing(?:'s)?|Kaposi(?:'s)?|"
    r"Stevens-Johnson|Wernicke|Korsakoff|Barrett(?:'s)?|Mallory-Weiss|Meckel(?:'s)?|"
    r"Brugada|Wolff-Parkinson-White|Hirschsprung(?:'s)?|Duchenne)\s*"
    r"(?:disease|syndrome|lymphoma|palsy|thyroiditis|triad|lesion|esophagus|ulcer|anemia)?\b",
    re.IGNORECASE,
)

# Clinical complaint / history prefixes: K/C/O, H/O, F/H/O, P/H/O
# Protect the history marker itself so it is never misparsed as a kinship prefix (H/o, C/O),
# while allowing PII (names, phones, IDs) following a clinical condition to be redacted.
_CLINICAL_PREFIX_RE = re.compile(
    r"\b(?:K/C/O|H/O|F/H/O|P/H/O)\b",
    re.IGNORECASE,
)

# C/O followed by clinical symptom words (NOT a person name) — protect only the C/O + symptom phrase
_CLINICAL_COMPLAINTS = (
    "fever|bukhar|pain|dard|cough|khansi|cold|breathlessness|dyspnea|dyspnoea|"
    "vomiting|nausea|diarrhoea|diarrhea|loose\\s+motions|weakness|kamzori|fatigue|"
    "headache|chest\\s+pain|abdominal\\s+pain|back\\s+pain|joint\\s+pain|swelling|"
    "edema|oedema|rash|itching|bleeding|dizziness|vertigo|syncope|palpitations|"
    "burning\\s+micturition|dysuria|constipation|anorexia|weight\\s+loss|chills|"
    "rigors|hemoptysis|hematuria|jaundice|seizures|fits|unconsciousness|trauma|"
    "injury|fracture|burn|ulcer|discharge|sore\\s+throat|wheezing|orthopnea|"
    "बुखार|दर्द|खांसी|उल्टी|दस्त|कमजोरी|चक्कर|सूजन|सांस"
)
_CO_COMPLAINT_RE = re.compile(
    rf"\bC/O\s*[:\-]?\s*(?:{_CLINICAL_COMPLAINTS})\b(?:\s+x\s+\d+\s*(?:days?|wks?|weeks?|months?|d|w|m))?",
    re.IGNORECASE,
)

# Hospital / organization / ASHA worker phrases
_ORG_RE = re.compile(
    r"(?:\b(?:[A-Z][A-Za-z]+\s+){1,4}(?:Multispeciality\s+)?(?:Charitable\s+)?"
    r"(?:Hospital|Clinic|Seva\s+Sadan|Nursing\s+Home|Medical\s+Centre|Diagnostics)\b"
    r"|\bASHA\s+(?:workers?|didi|didiji)\b)",
)

# Dosages, frequencies, vitals, lab values, wards
_DOSE_VITAL_LAB_RE = re.compile(
    r"(?:"
    r"\b\d+(?:\.\d+)?\s*(?:mg|mcg|ug|g|gm|ml|mL|L|IU|units?|%|mmHg|bpm|/min|/uL|/cumm|mg/dL|g/dL|mmol/L|U/L|IU/L|ng/mL|pg/mL|mEq/L|fL|pg|K/uL)\b"
    r"|\b[01]-[01]-[01](?:-[01])?\b"
    r"|\b(?:OD|BD|TDS|QID|HS|SOS|STAT|PRN)\s*(?:x\s*\d+\s*(?:days?|wks?|weeks?|months?|d|w|m))?\b"
    r"|\b(?:BP|HR|PR|RR|SpO2|Temp|RBS|FBS|PPBS|Hb|WBC|RBC|PLT|ESR|CRP|TSH|HbA1c)\s*[:=]?\s*\d+(?:\.\d+)?(?:/\d+(?:\.\d+)?)?\s*%?"
    r"|\bWard\s+\d+\s*\([^)]+\)"
    r"|\bBed\s+(?:No\.?\s*)?\d+\b"
    r"|\b(?:ICD-?10|LOINC)\s*[:#]?\s*[A-Z0-9.\-]+\b"
    r")",
    re.IGNORECASE,
)


def find_protected_spans(text: str) -> list[tuple[int, int, str]]:
    """Return sorted list of (start, end, reason) spans that must NOT be redacted as PII."""
    spans: list[tuple[int, int, str]] = []
    for rx, tag in (
        (_CLINICIAN_RE, "clinician"),
        (_EPONYM_RE, "eponym"),
        (_CLINICAL_PREFIX_RE, "clinical_history"),
        (_CO_COMPLAINT_RE, "clinical_complaint"),
        (_ORG_RE, "organization"),
        (_DOSE_VITAL_LAB_RE, "clinical_value"),
    ):
        for m in rx.finditer(text):
            spans.append((m.start(), m.end(), tag))
    spans.sort(key=lambda x: (x[0], -(x[1] - x[0])))
    return spans


def overlaps_protected(start: int, end: int, protected: list[tuple[int, int, str]]) -> bool:
    """Return True if [start, end) overlaps any protected clinical span."""
    for ps, pe, _ in protected:
        if ps >= end:
            break
        if start < pe and end > ps:
            return True
    return False
