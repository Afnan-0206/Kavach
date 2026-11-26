"""Tests for multilingual PII detection, homoglyphs, zero-width chars, and canaries."""
from __future__ import annotations

from detectors.name_detector import DynamicGazetteer
from engine.normalization import normalize_text
from engine.pii_detector import redact_text


def test_indian_ids_and_phones():
    txt = "Aadhaar: 3972 0583 9628, ABHA: 91-7938-3729-8403, PAN: ABCDE1234F, Mob: +91 72864 90658"
    out = redact_text(txt)
    assert "3972 0583 9628" not in out
    assert "91-7938-3729-8403" not in out
    assert "ABCDE1234F" not in out
    assert "72864 90658" not in out


def test_devanagari_and_hinglish_names():
    txt = "नाम: मोहम्मद शाहिद   आयु: 39 वर्ष\nShahid sahab ka BP 117/82."
    gaz = DynamicGazetteer()
    gaz.add_name("मोहम्मद शाहिद")
    gaz.add_name("Shahid")
    gaz.build()
    out = redact_text(txt, gazetteer=gaz)
    assert "मोहम्मद शाहिद" not in out
    assert "Shahid" not in out
    assert "117/82" in out


def test_unicode_homoglyphs_and_zero_width():
    # Cyrillic 'а' and zero-width space inside Aadhaar
    s = "Aаdhaar: 3972\u200b0583\u200b9628"
    norm = normalize_text(s)
    assert "Aadhaar: 397205839628" == norm
    # Devanagari digits
    assert normalize_text("९८७६५४३२१०") == "9876543210"


def test_action_and_role_canary_patterns():
    txt = "18:40 - Zorawar Qadri (attendant, bed 12), mob 6910522119\ncalled by Kaveri Nambiar 94054-71434"
    out = redact_text(txt)
    assert "Zorawar Qadri" not in out
    assert "Kaveri Nambiar" not in out
    assert "6910522119" not in out
    assert "94054-71434" not in out
