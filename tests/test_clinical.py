"""Tests for Clinical Shield: preserving medical values and clinician attribution."""
from __future__ import annotations

from detectors.name_detector import DynamicGazetteer
from engine.pii_detector import redact_text


def test_preserve_clinician_and_redact_relative():
    gaz = DynamicGazetteer()
    gaz.add_name("Ramesh")
    gaz.build()
    txt = "Consultant: Dr. Ramesh Srivastava (MD Medicine). Attendant S/o Ramesh informed."
    out = redact_text(txt, gazetteer=gaz)
    assert "Dr. Ramesh Srivastava" in out
    assert "S/o [RELATIVE_NAME]" in out


def test_preserve_clinical_traps():
    txt = (
        "C/O: fever x 7 days, body ache. K/C/O addison's disease, Parkinson's disease.\n"
        "1. Tab Paracetamol 650mg 1-1-1 x 5 days\n"
        "2. Tab Ramipril 5 mg 0-0-1 x 1 month\n"
        "BP 150/90, SpO2 98%, RBS 145 mg/dL, Ward 8 (Medicine) / Bed 2."
    )
    out = redact_text(txt)
    for must_keep in (
        "C/O: fever x 7 days",
        "addison's disease",
        "Parkinson's disease",
        "Paracetamol 650mg 1-1-1 x 5 days",
        "Ramipril 5 mg 0-0-1 x 1 month",
        "BP 150/90",
        "SpO2 98%",
        "RBS 145 mg/dL",
        "Ward 8 (Medicine)",
    ):
        assert must_keep in out
