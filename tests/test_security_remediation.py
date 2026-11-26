"""Regression tests for KAVACH-FHIR security remediation (P0, P1, P2, and crypto)."""
from __future__ import annotations

import datetime as dt
import json
import os
from pathlib import Path

import pytest

from detectors.name_detector import DynamicGazetteer
from detectors.residual_scanner import scan_and_scrub_residual
from engine.identity_linker import link_records
from engine.ingestion import ingest_directory
from engine.pii_detector import redact_text
from engine.privacy_engine import choose_collision_safe_shift
from engine.record_model import PipelineStats, RecordUnit
from engine.security import KeyRing
from main import _sanitize_json_obj, run_pipeline


def _policy_path() -> Path:
    return Path(__file__).resolve().parents[1] / "config" / "policy.yaml"


def test_p0_clean_directory_bypass_removed(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("RAKSHA_SECRET", "remediation-test-secret-0123456789")
    inp = tmp_path / "in"
    out = tmp_path / "out"
    (inp / "clean").mkdir(parents=True)
    (inp / "clean" / "leak.txt").write_text(
        "Patient: Ramesh Kumar, Aadhaar: 9876 5432 1012, Phone: 9876543210\n",
        encoding="utf-8",
    )
    (inp / "clean" / "ref.txt").write_text("C/O: fever, BP 120/80 mmHg\n", encoding="utf-8")

    assert run_pipeline(inp, out, _policy_path()) == 0
    leaked_san = (out / "sanitized" / "clean" / "leak.txt").read_text(encoding="utf-8")
    assert "Ramesh Kumar" not in leaked_san
    assert "9876 5432 1012" not in leaked_san
    assert "9876543210" not in leaked_san
    assert "[AADHAAR]" in leaked_san
    assert "[PHONE]" in leaked_san

    ref_san = (out / "sanitized" / "clean" / "ref.txt").read_text(encoding="utf-8")
    assert "C/O: fever, BP 120/80 mmHg" in ref_san
    assert "Patient:" not in ref_san


def test_p0_clinical_shield_does_not_smuggle_pii():
    gaz = DynamicGazetteer()
    gaz.add_name("Ramesh Kumar")
    gaz.build()
    txt = "C/O fever Ramesh Kumar 9876543210 Aadhaar 9876 5432 1012"
    out = redact_text(txt, gazetteer=gaz)
    out, hits = scan_and_scrub_residual(out, gazetteer=gaz)
    assert "C/O fever" in out
    assert "Ramesh Kumar" not in out
    assert "9876543210" not in out
    assert "9876 5432 1012" not in out
    assert "[PHONE]" in out
    assert "[AADHAAR]" in out
    assert hits == 0


def test_p0_unicode_zero_width_and_homoglyph_offset_mapping():
    gaz = DynamicGazetteer()
    gaz.add_name("Ramesh Kumar")
    gaz.build()
    # Cyrillic АВС + zero-width space \u200b inside phone & before Devanagari Aadhaar
    txt = (
        "Aadhaar: \u200b९८७६ ५४३२ १०१२, "
        "Phone: 98765\u200b43210, "
        "PAN: АВСDE1234F, "
        "S/o M\u200bohan Lal, "
        "Name: R\u200bamesh Kumar"
    )
    out = redact_text(txt, gazetteer=gaz)
    assert "९८७६" not in out
    assert "43210" not in out
    assert "АВСDE1234F" not in out
    assert "ohan Lal" not in out
    assert "amesh Kumar" not in out
    assert "[AADHAAR]" in out
    assert "[PHONE]" in out
    assert "[PAN]" in out
    assert "[RELATIVE_NAME]" in out
    assert "[PATIENT_NAME]" in out


def test_p1_symlink_ingestion_quarantined(tmp_path: Path):
    inp = tmp_path / "in"
    inp.mkdir()
    outside = tmp_path / "outside_secret.txt"
    outside.write_text("TOP_SECRET_EXTERNAL_DATA", encoding="utf-8")
    link = inp / "link.txt"
    try:
        os.symlink(outside, link)
    except OSError:
        pytest.skip("Symlink creation requires elevated privileges on this Windows host")

    items = {x.rel_path: x for x in ingest_directory(inp)}
    assert "link.txt" in items
    assert items["link.txt"].status == "quarantined"
    assert items["link.txt"].quarantine_reason == "symlink_or_path_escape"


def test_p1_json_string_age_keys_metadata_dates_and_mrn_residual(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("RAKSHA_SECRET", "remediation-test-secret-0123456789")
    gaz = DynamicGazetteer()
    gaz.add_name("Ramesh Kumar")
    gaz.build()
    stats = PipelineStats()
    obj = {
        "age": "48",
        "age_sex": "48 Y / M",
        "dob_1990-05-12": "ok",
        "mrn": "SNJ/26/064127",
    }
    san = _sanitize_json_obj(obj, gaz, stats, "PSN-AAAAAA", 10, 5, 3)
    assert san["age"] == "45-49"
    assert san["age_sex"] == "45-49 Y / M"
    assert "1990-05-12" not in json.dumps(san)

    res_txt, n_res = scan_and_scrub_residual("Ref: SNJ/26/064127", gazetteer=gaz)
    assert "SNJ/26/064127" not in res_txt
    assert "[MRN]" in res_txt and n_res == 1

    # Multi-record JSON top-level metadata date avoids protected_dobs
    inp = tmp_path / "in"
    out = tmp_path / "out"
    inp.mkdir()
    payload = {
        "export_date": "2026-01-10",
        "patients": [{"name": "Ramesh Kumar", "birthDate": "1990-05-12"}],
    }
    (inp / "multi.json").write_text(json.dumps(payload), encoding="utf-8")
    assert run_pipeline(inp, out, _policy_path()) == 0
    san_multi = json.loads((out / "sanitized" / "multi.json").read_text(encoding="utf-8"))
    assert san_multi["export_date"] != "2026-01-10"


def test_p2_cross_hospital_generic_mrn_prefix_links_on_gov_id(monkeypatch):
    monkeypatch.setenv("RAKSHA_SECRET", "remediation-test-secret-0123456789")
    kr = KeyRing.from_env()
    u1 = RecordUnit("a.csv", "a.csv", "row:0", "", clues={
        "aadhaar": "123456789012", "name": "Ramesh Kumar", "dob": "1985-05-10", "mrns": ["UHID-001"],
    })
    u2 = RecordUnit("b.csv", "b.csv", "row:0", "", clues={
        "aadhaar": "123456789012", "name": "Ramesh Kumar", "dob": "1985-05-10", "mrns": ["UHID-999"],
    })
    link_records([u1, u2], kr)
    assert u1.pseudonym is not None
    assert u1.pseudonym == u2.pseudonym


def test_crypto_weak_secret_warns_and_shift_bounds():
    with pytest.warns(UserWarning, match="shorter than 16 bytes"):
        kr = KeyRing(b"short")
    base = dt.date(2026, 1, 10)
    # Block every offset in [-5, +5] -> must fail closed rather than exceed max_days
    blocked = {base + dt.timedelta(days=d) for d in range(-5, 6) if d != 0}
    with pytest.raises(ValueError, match="collision-safe date shift"):
        choose_collision_safe_shift(kr, "pt-1", {base}, blocked, max_days=5)


def test_clinical_recovery_history_markers_and_trailing_pii():
    gaz = DynamicGazetteer()
    gaz.add_name("Ramesh Kumar")
    gaz.build()

    # All four history marker variants with Title-Cased clinical conditions
    hist = (
        "K/C/O Pulmonary Tuberculosis; "
        "H/O Type 2 Diabetes Mellitus; "
        "F/H/O Coronary Artery Disease; "
        "P/H/O Bronchial Asthma"
    )
    out_hist = redact_text(hist, gazetteer=gaz)
    for expected in (
        "K/C/O Pulmonary Tuberculosis",
        "H/O Type 2 Diabetes Mellitus",
        "F/H/O Coronary Artery Disease",
        "P/H/O Bronchial Asthma",
    ):
        assert expected in out_hist

    # Patient name, phone, and Aadhaar immediately after history phrase must still redact
    smuggled = "K/C/O Hypertension Ramesh Kumar 9876543210 Aadhaar 9876 5432 1012"
    out_smuggled = redact_text(smuggled, gazetteer=gaz)
    assert "K/C/O Hypertension" in out_smuggled
    assert "Ramesh Kumar" not in out_smuggled
    assert "9876543210" not in out_smuggled
    assert "9876 5432 1012" not in out_smuggled
    assert "[PHONE]" in out_smuggled
    assert "[AADHAAR]" in out_smuggled


def test_clinical_recovery_ward_hospital_vs_residential():
    gaz = DynamicGazetteer()
    stats = PipelineStats()
    obj = {
        "hospital_ward": {"ward": "Ward 8 (Medicine)", "unit": "ICU"},
        "general_ward": {"ward": "General Medicine"},
        "res_ward": {"ward": "Ward No. 14, Mohalla Azad Nagar, PIN 226001"},
    }
    san = _sanitize_json_obj(obj, gaz, stats, "PSN-AAAAAA", 10, 5, 3)
    assert san["hospital_ward"]["ward"] == "Ward 8 (Medicine)"
    assert san["general_ward"]["ward"] == "General Medicine"
    assert "Ward No. 14" not in san["res_ward"]["ward"]
    assert "Mohalla Azad Nagar" not in san["res_ward"]["ward"]
    assert "226001" not in san["res_ward"]["ward"]
    assert "226***" in san["res_ward"]["ward"]


def test_clinical_recovery_pin_vs_numeric_and_decimal_ranges():
    # Lab numeric and decimal ranges must not be generalized as PIN codes
    ranges_txt = "Platelets: 150000-410000 /cumm; Ref: 12.5-150000"
    assert redact_text(ranges_txt) == ranges_txt

    # Valid PINs in address contexts (with label, comma, or hyphen after text) must still generalize
    addr_txt = "Mohalla Azad Nagar, Lucknow - 226001, UP-226010, PIN: 226016, Gomti Nagar, 226020"
    out_addr = redact_text(addr_txt)
    for raw_pin, masked in (("226001", "226***"), ("226010", "226***"), ("226016", "226***"), ("226020", "226***")):
        assert raw_pin not in out_addr
        assert masked in out_addr
