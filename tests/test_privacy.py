"""Tests for date shifting, age banding, and PIN generalization."""
from __future__ import annotations

from pathlib import Path
from engine.privacy_engine import age_to_band, generalize_pin, parse_date_flexible, shift_date_str
from engine.security import KeyRing


def test_age_bands_contain_true_age():
    for age in (0, 4, 5, 46, 48, 84, 85, 97):
        band = age_to_band(age, 5)
        if band == "85+":
            assert age >= 85
        else:
            lo, hi = (int(x) for x in band.split("-"))
            assert lo <= age <= hi


def test_date_shift_preserves_length_of_stay():
    kr = KeyRing(b"test-secret")
    shift = kr.date_shift_days("patient-1", 180)
    adm = shift_date_str("02/01/2026", shift, month_first=False)
    dis = shift_date_str("11/01/2026", shift, month_first=False)
    # Both shifted by exact same offset -> 9-day gap preserved
    from engine.privacy_engine import parse_date_flexible
    d1 = parse_date_flexible(adm, month_first=False)
    d2 = parse_date_flexible(dis, month_first=False)
    assert d1 is not None and d2 is not None
    assert (d2 - d1).days == 9


def test_month_first_date_shift():
    assert shift_date_str("04/20/1979", 10, month_first=True) == "04/30/1979"


def test_pin_generalization():
    assert generalize_pin("229073", 3) == "229***"


def test_collision_safe_date_shift_avoids_protected_dobs(tmp_path: Path, monkeypatch):
    import csv, io
    from main import run_pipeline

    # Construct a synthetic dataset where Patient B's shifted RegDate would collide with Patient A's DOB
    # under the base HMAC shift, forcing deterministic alternative offset selection.
    kr = KeyRing(b"collision-secret")
    dob_a = "15-06-2024"
    reg_b = "10-01-2024"
    # Find a patient_key for B whose base shift maps 2024-01-10 -> 2024-06-15 (+157 days)
    import datetime as dt
    target_diff = (dt.date(2024, 6, 15) - dt.date(2024, 1, 10)).days
    colliding_id = None
    for idx in range(5000):
        cand_id = f"UHID-SYN-{idx:04d}"
        if kr.date_shift_days(f"mrn:{cand_id.lower().replace('-', '')}", 180) == target_diff:
            colliding_id = cand_id
            break
    assert colliding_id is not None

    inp = tmp_path / "in"
    inp.mkdir()
    csv_path = inp / "patients.csv"
    csv_path.write_text(
        f"UHID,Patient Name,DOB,Admission Date,Discharge Date,Registration Date\n"
        f"UHID-SYN-A,Alpha Patient,{dob_a},01-03-2024,06-03-2024,01-03-2024\n"
        f"{colliding_id},Beta Patient,05-02-1990,05-01-2024,12-01-2024,{reg_b}\n",
        encoding="utf-8",
    )

    policy = Path(__file__).resolve().parents[1] / "config" / "policy.yaml"
    monkeypatch.setenv("RAKSHA_SECRET", "collision-secret")

    out1 = tmp_path / "out1"
    run_pipeline(inp, out1, policy)
    out2 = tmp_path / "out2"
    run_pipeline(inp, out2, policy)

    san_csvs_1 = list((out1 / "sanitized").glob("*.csv"))
    san_csvs_2 = list((out2 / "sanitized").glob("*.csv"))
    assert len(san_csvs_1) == 1
    txt1 = san_csvs_1[0].read_text(encoding="utf-8")
    txt2 = san_csvs_2[0].read_text(encoding="utf-8")

    # 1. Original protected DOBs must never appear anywhere in sanitized output
    assert dob_a not in txt1
    assert "05-02-1990" not in txt1

    # 2. Deterministic repeat run with same secret
    assert txt1 == txt2

    # 3. Length-of-stay intervals preserved (5 days for Alpha, 7 days for Beta)
    rows = list(csv.reader(io.StringIO(txt1, newline="")))
    for r in rows[1:]:
        adm = parse_date_flexible(r[3])
        dis = parse_date_flexible(r[4])
        assert adm is not None and dis is not None
        assert (dis - adm).days in (5, 7)

    # 4. Different secret produces different output
    monkeypatch.setenv("RAKSHA_SECRET", "other-secret")
    out3 = tmp_path / "out3"
    run_pipeline(inp, out3, policy)
    san_csvs_3 = list((out3 / "sanitized").glob("*.csv"))
    assert san_csvs_3[0].read_text(encoding="utf-8") != txt1
