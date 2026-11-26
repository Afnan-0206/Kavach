"""Adversarial Attack Arena (A1-A7) remediation tests covering all 8 required scenarios."""
from __future__ import annotations

import csv
import datetime as dt
import io
import json
import re
from pathlib import Path

from engine.privacy_engine import extract_dates_in_text
from main import run_pipeline


def _write_strict_policy(path: Path) -> Path:
    path.write_text(
        "age_band_years: 5\ndate_shift_max_days: 180\nmin_group_size: 5\n"
        "qi_generalization_enabled: true\nqi_widen_pin: true\nqi_suppress_k1_pin: true\n"
        "qi_widen_age_band: true\nqi_suppress_small_tehsil: true\nqi_jitter_high_risk_los: true\n"
        "qi_generalize_rare_district: true\nqi_generalize_rare_hospital: true\n"
        "qi_generalize_rare_diagnosis: true\nqi_rare_condition_max_profiles: 3\n"
        "pin_prefix_digits: 3\nsuppress_rare_pin: true\nsuppress_village: true\n"
        "preserve_clinician_names: true\npreserve_clinical_values: true\n",
        encoding="utf-8",
    )
    return path


def test_a5_unique_older_patient_rare_diagnosis_and_hospital(tmp_path: Path, monkeypatch):
    """Scenarios 1 & 8: Unique 97/M patient with rare condition & named hospital."""
    monkeypatch.setenv("RAKSHA_SECRET", "arena-test-secret-0123456789abcdef")
    inp, out = tmp_path / "in", tmp_path / "out"
    inp.mkdir()
    policy = _write_strict_policy(tmp_path / "strict.yaml")

    (inp / "trap.txt").write_text(
        "Patient Name: Harihar Singh\nMRN: JJH-901\nAge: 97 Y / M\n"
        "District: Barabanki, Tehsil Nawabganj, PIN 225001\n"
        "Admitted at Jeevan Jyoti Hospital on 2026-01-10, discharged 2026-01-19.\n"
        "Diagnosis: Brugada syndrome. Tab Metoprolol 25mg 1-0-1, BP 130/80.\n",
        encoding="utf-8",
    )
    assert run_pipeline(inp, out, policy) == 0
    san = (out / "sanitized" / "trap.txt").read_text(encoding="utf-8")
    assert "Harihar Singh" not in san
    assert "80+" in san
    assert "[REGION]" in san or "Barabanki" not in san
    assert "[TEHSIL]" in san
    assert "[PIN]" in san
    assert "Jeevan Jyoti Hospital" not in san
    assert "Hospital" in san
    assert "Brugada" not in san
    assert "Cardiovascular Condition" in san
    assert "Metoprolol 25mg 1-0-1" in san
    assert "BP 130/80" in san


def test_a5_rare_vs_common_conditions_and_multilingual_variants(tmp_path: Path, monkeypatch):
    """Scenarios 2, 3 & 6: <=3 profile rare conditions (EN/HI/Hinglish) broadened; >3 common conditions kept."""
    monkeypatch.setenv("RAKSHA_SECRET", "arena-test-secret-0123456789abcdef")
    inp, out = tmp_path / "in", tmp_path / "out"
    inp.mkdir()
    policy = _write_strict_policy(tmp_path / "strict.yaml")

    rows = [["MRN", "Patient Name", "Age", "Gender", "District", "Notes"]]
    # 4 distinct profiles share 'Asthma' (common > 3)
    for i in range(4):
        rows.append([f"SNJ-{10+i}", f"Patient Common {i}", "32", "F", "Lucknow", "Asthma; Tab Salbutamol 4mg"])
    # 2 distinct profiles share rare 'डेंगू' / 'Dengue' (<= 3) and 1 shares 'मिर्गी' (<= 3)
    rows.append(["SNJ-50", "Rare Hindi One", "47", "F", "Unnao", "डेंगू बुखार; Tab Paracetamol 650mg"])
    rows.append(["SNJ-51", "Rare English Two", "67", "M", "Hardoi", "Dengue; BP 110/70"])
    rows.append(["SNJ-52", "Rare Neuro Three", "71", "M", "Sitapur", "मिर्गी (epilepsy); Tab Levetiracetam 500mg"])

    buf = io.StringIO()
    csv.writer(buf, lineterminator="\n").writerows(rows)
    (inp / "cohort.csv").write_text(buf.getvalue(), encoding="utf-8")

    assert run_pipeline(inp, out, policy) == 0
    san_rows = list(csv.reader(io.StringIO((out / "sanitized" / "cohort.csv").read_text(encoding="utf-8"))))
    # Common (>3 profiles) preserved unchanged
    assert "Asthma" in san_rows[1][5]
    assert "Salbutamol 4mg" in san_rows[1][5]
    # Rare (<=3 profiles, Hindi/English) broadened while keeping meds/vitals
    assert "डेंगू" not in san_rows[5][5]
    assert "Infectious Disease" in san_rows[5][5]
    assert "Paracetamol 650mg" in san_rows[5][5]
    assert "Dengue" not in san_rows[6][5]
    assert "Infectious Disease" in san_rows[6][5]
    assert "BP 110/70" in san_rows[6][5]
    assert "मिर्गी" not in san_rows[7][5]
    assert "Neurological Condition" in san_rows[7][5]
    assert "Levetiracetam 500mg" in san_rows[7][5]


def test_a4_profile_aggregation_and_a5_los_jitter(tmp_path: Path, monkeypatch):
    """Scenarios 4, 5 & 7: Pooled pseudonym encounters, no raw refs, LOS jitter preserves order, tehsil/PIN suppressed."""
    monkeypatch.setenv("RAKSHA_SECRET", "arena-test-secret-0123456789abcdef")
    inp, out = tmp_path / "in", tmp_path / "out"
    inp.mkdir()
    policy = _write_strict_policy(tmp_path / "strict.yaml")

    (inp / "enc1.json").write_text(
        json.dumps({
            "patient_ref": "SNJ-888",
            "patient_name": "Kiran Rao",
            "age": "46",
            "gender": "F",
            "district": "Bahraich",
            "tehsil": "Nanpara",
            "pin": "271865",
            "admission_note": "Admitted 2026-02-01, discharged 2026-02-10. Tab Dolo 650mg.",
        }),
        encoding="utf-8",
    )
    (inp / "enc2.txt").write_text(
        "Patient Name: Kiran Rao\nMRN: SNJ-888\nAge: 46 Y / F\n"
        "District: Bahraich, Tehsil Nanpara, PIN 271865\n"
        "Admitted 2026-02-01, Discharged 2026-02-10. BP 118/76.\n",
        encoding="utf-8",
    )

    assert run_pipeline(inp, out, policy) == 0
    recs = [json.loads(l) for l in (out / "records.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    psns = {r["patient"] for r in recs}
    assert len(psns) == 1
    psn = next(iter(psns))
    assert re.fullmatch(r"PSN-[0-9A-HJKMNP-TV-Z]{16}", psn)

    j_out = json.loads((out / "sanitized" / "enc1.json").read_text(encoding="utf-8"))
    t_out = (out / "sanitized" / "enc2.txt").read_text(encoding="utf-8")

    # Raw references & geographic QIs removed
    assert j_out["patient_ref"] == psn
    assert "SNJ-888" not in json.dumps(j_out) and "SNJ-888" not in t_out
    assert j_out["tehsil"] == "[TEHSIL]" and "[TEHSIL]" in t_out
    assert j_out["pin"] == "[PIN]" and "[PIN]" in t_out
    assert j_out["age"] == "40-59" and "40-59" in t_out

    # LOS jitter: chronological order preserved (d1 < d2), exact 9-day LOS obscured (delta != 9)
    dates = sorted(extract_dates_in_text(t_out))
    assert len(dates) == 2
    assert dates[0] < dates[1]
    assert (dates[1] - dates[0]).days != 9
