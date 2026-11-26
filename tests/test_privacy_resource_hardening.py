"""Tests for risk-aware QI generalization, 80-bit HMAC pseudonyms, and cross-platform RSS reporting."""
from __future__ import annotations

import csv
import io
import json
import re
from pathlib import Path

import pytest

from engine.reporting import peak_rss_mb
from engine.security import KeyRing
from main import run_pipeline


def _default_policy() -> Path:
    return Path(__file__).resolve().parents[1] / "config" / "policy.yaml"


def test_task1_small_group_qi_widening_and_large_group_preservation(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("RAKSHA_SECRET", "qi-hardening-test-secret-0123456789")
    inp = tmp_path / "in"
    out = tmp_path / "out"
    inp.mkdir()

    # 5 distinct patients in (30-34, F, Lucknow) -> k=5 (keeps 5-yr band + 3-digit PIN)
    # 1 unique patient in (48 -> 45-49, M, Sitapur) -> k=1 < 5 (widens to 40-59 + 2-digit PIN)
    rows = [
        ["MRN", "Patient Name", "Age", "Gender", "District", "PIN", "Notes"],
    ]
    for i in range(5):
        rows.append([f"SNJ-{100+i}", f"Asha Devi {i}", "32", "F", "Lucknow", "226001", "Tab Paracetamol 650mg 1-0-1"])
    rows.append(["SNJ-999", "Ramesh Verma", "48", "M", "Sitapur", "261001", "BP 130/80, Tab Ramipril 5 mg"])
    buf = io.StringIO()
    csv.writer(buf, lineterminator="\n").writerows(rows)
    (inp / "cohort.csv").write_text(buf.getvalue(), encoding="utf-8")

    # Also add a second file for Ramesh Verma to verify cross-file QI consistency
    (inp / "follow_up_note.txt").write_text(
        "Patient Name: Ramesh Verma\nMRN: SNJ-999\nAge: 48 Y / M\nDistrict: Sitapur\nPIN: 261001\nBP 130/80\n",
        encoding="utf-8",
    )

    assert run_pipeline(inp, out, _default_policy()) == 0
    san_rows = list(csv.reader(io.StringIO((out / "sanitized" / "cohort.csv").read_text(encoding="utf-8"))))
    # Large group (k=5): 30-34 and 226***
    assert san_rows[1][2] == "30-34"
    assert san_rows[1][5] == "226***"
    # Small group (k=1): widened to 40-59 and PIN suppressed to [PIN]
    assert san_rows[6][2] == "40-59"
    assert san_rows[6][5] == "[PIN]"
    # Clinical values preserved
    assert "Ramipril 5 mg" in san_rows[6][6]
    assert "BP 130/80" in san_rows[6][6]

    # Cross-file consistency for Ramesh Verma
    note_txt = (out / "sanitized" / "follow_up_note.txt").read_text(encoding="utf-8")
    assert "40-59" in note_txt
    assert "[PIN]" in note_txt
    assert "BP 130/80" in note_txt


def test_task1_strict_policy_generalizes_district_and_rare_diagnosis_preserving_meds(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("RAKSHA_SECRET", "qi-strict-test-secret-0123456789")
    inp = tmp_path / "in"
    out = tmp_path / "out"
    inp.mkdir()
    policy = tmp_path / "strict_policy.yaml"
    policy.write_text(
        "age_band_years: 5\ndate_shift_max_days: 180\nmin_group_size: 5\n"
        "qi_generalization_enabled: true\nqi_widen_pin: true\nqi_widen_age_band: true\n"
        "qi_generalize_rare_district: true\nqi_generalize_rare_diagnosis: true\n"
        "pin_prefix_digits: 3\nsuppress_rare_pin: true\nsuppress_village: true\n"
        "preserve_clinician_names: true\npreserve_clinical_values: true\n",
        encoding="utf-8",
    )
    (inp / "rare.csv").write_text(
        "MRN,Patient Name,Age,Gender,District,Notes\n"
        "JJH-101,Meena Kumari,47,F,Bahraich,\"Dengue fever; Tab Paracetamol 650mg 1-1-1, BP 110/70\"\n",
        encoding="utf-8",
    )

    assert run_pipeline(inp, out, policy) == 0
    san_rows = list(csv.reader(io.StringIO((out / "sanitized" / "rare.csv").read_text(encoding="utf-8"))))
    assert san_rows[1][2] == "40-59"
    assert san_rows[1][4] == "[REGION]"
    assert "Dengue" not in san_rows[1][5]
    assert "Infectious Disease" in san_rows[1][5]
    assert "Paracetamol 650mg 1-1-1" in san_rows[1][5]
    assert "BP 110/70" in san_rows[1][5]


def test_task2_80bit_pseudonym_entropy_determinism_unlinkability_and_scale():
    k1 = KeyRing(b"0123456789abcdef0123456789abcdef")
    k2 = KeyRing(b"fedcba9876543210fedcba9876543210")

    p1 = k1.pseudonym("aadhaar:123456789012")
    p2 = k1.pseudonym("aadhaar:123456789012")
    p_other = k2.pseudonym("aadhaar:123456789012")

    assert re.fullmatch(r"PSN-[0-9A-HJKMNP-TV-Z]{16}", p1)
    assert p1 == p2
    assert p1 != p_other
    assert p1 != k1.pseudonym("aadhaar:123456789012", collision_salt=1)

    with pytest.raises(RuntimeError, match="collision"):
        k1.pseudonym("aadhaar:123456789012", collision_salt=1001)

    # 10,000 synthetic patients -> zero collisions
    seen = {k1.pseudonym(f"synthetic-patient-{i}") for i in range(10000)}
    assert len(seen) == 10000


def test_task3_cross_platform_peak_rss_positive_and_reported(tmp_path: Path, monkeypatch):
    rss, status = peak_rss_mb()
    assert status == "measured"
    assert isinstance(rss, float) and rss > 0.0

    monkeypatch.setenv("RAKSHA_SECRET", "rss-report-test-secret-0123456789")
    inp = tmp_path / "in"
    out = tmp_path / "out"
    inp.mkdir()
    (inp / "note.txt").write_text("C/O: fever\nBP 120/80\n", encoding="utf-8")
    assert run_pipeline(inp, out, _default_policy()) == 0
    rep = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert rep["resources"]["measurement_status"] == "measured"
    assert isinstance(rep["resources"]["peak_rss_mb"], float)
    assert rep["resources"]["peak_rss_mb"] > 0.0
