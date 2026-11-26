"""Regression tests for filename privacy, FHIR relative names, MRN families, and PII-free logs."""
from __future__ import annotations

import json
from pathlib import Path

from detectors.indian_ids import detect_indian_ids
from engine.pii_detector import redact_text
from main import run_pipeline


def test_opaque_filenames_and_no_original_names_in_outputs(tmp_path: Path, monkeypatch, capsys):
    inp = tmp_path / "in"
    (inp / "discharge").mkdir(parents=True)
    (inp / "notes").mkdir(parents=True)
    (inp / "7585697553_folder").mkdir(parents=True)

    (inp / "discharge" / "Discharge_Summary_Reena_Nishad_JJH-0076928.txt").write_text(
        "Patient Name: Reena Nishad\nUHID: JJH-0076928\nBP 120/80", encoding="utf-8"
    )
    (inp / "notes" / "nursing_adm000161.txt").write_text(
        "Patient Name: Shahid\nBP 118/78", encoding="utf-8"
    )
    (inp / "7585697553_folder" / "report.txt").write_text(
        "C/O: fever x 3 days", encoding="utf-8"
    )

    policy = Path(__file__).resolve().parents[1] / "config" / "policy.yaml"
    monkeypatch.setenv("RAKSHA_SECRET", "secret-one")
    out1 = tmp_path / "out1"
    run_pipeline(inp, out1, policy)
    captured = capsys.readouterr()

    # 1. No raw PII or original filenames in stdout/stderr
    for forbidden in ("Reena_Nishad", "Reena Nishad", "JJH-0076928", "adm000161", "7585697553", "Shahid"):
        assert forbidden not in captured.out
        assert forbidden not in captured.err

    # 2. Selective output path compliance:
    # - PII-bearing filenames & directories are renamed to opaque keyed tokens
    # - Safe filenames (report.txt) are preserved inside renamed/safe directories
    # - Original PII-bearing names never appear in sanitized/, records.jsonl, or report.json
    san_files = sorted(p.relative_to(out1 / "sanitized").as_posix() for p in (out1 / "sanitized").rglob("*") if p.is_file())
    assert len(san_files) == 3
    for sf in san_files:
        assert "Reena_Nishad" not in sf
        assert "nursing_adm000161" not in sf
        assert "7585697553" not in sf

    assert any(sf.startswith("discharge/doc_") and sf.endswith(".txt") for sf in san_files)
    assert any(sf.startswith("notes/doc_") and sf.endswith(".txt") for sf in san_files)
    assert any(sf.startswith("dir_") and sf.endswith("/report.txt") for sf in san_files)

    records_txt = (out1 / "records.jsonl").read_text(encoding="utf-8")
    report_txt = (out1 / "report.json").read_text(encoding="utf-8")
    for forbidden in ("Reena_Nishad", "nursing_adm000161", "7585697553_folder", "JJH-0076928"):
        assert forbidden not in records_txt
        assert forbidden not in report_txt

    # 3. Deterministic opaque names with same secret
    out2 = tmp_path / "out2"
    run_pipeline(inp, out2, policy)
    san_files_2 = sorted(p.relative_to(out2 / "sanitized").as_posix() for p in (out2 / "sanitized").rglob("*") if p.is_file())
    assert san_files == san_files_2

    # 4. Different opaque names with different secret
    monkeypatch.setenv("RAKSHA_SECRET", "secret-two")
    out3 = tmp_path / "out3"
    run_pipeline(inp, out3, policy)
    san_files_3 = sorted(p.relative_to(out3 / "sanitized").as_posix() for p in (out3 / "sanitized").rglob("*") if p.is_file())
    assert san_files != san_files_3


def test_selective_output_paths_preserve_safe_and_avoid_collisions(tmp_path: Path, monkeypatch):
    inp = tmp_path / "in"
    (inp / "billing").mkdir(parents=True)
    (inp / "clean").mkdir(parents=True)
    (inp / "notes").mkdir(parents=True)

    # Safe filenames and directories must be preserved verbatim
    (inp / "billing" / "arogya_claims.csv").write_text("claim_id,amount\nC1,500\n", encoding="utf-8")
    (inp / "clean" / "drug_formulary.csv").write_text("drug,dose\nDolo,650mg\n", encoding="utf-8")
    (inp / "notes" / "ward_summary.txt").write_text("C/O: fever x 2 days\nBP 120/80\n", encoding="utf-8")

    # PII-bearing filename must be renamed while preserving directory and extension
    (inp / "notes" / "Ramesh_Kumar_UHID-1001.txt").write_text("Patient Name: Ramesh Kumar\n", encoding="utf-8")

    policy = Path(__file__).resolve().parents[1] / "config" / "policy.yaml"
    monkeypatch.setenv("RAKSHA_SECRET", "path-secret-1")
    out1 = tmp_path / "out1"
    run_pipeline(inp, out1, policy)

    san = out1 / "sanitized"
    assert (san / "billing" / "arogya_claims.csv").is_file()
    assert (san / "clean" / "drug_formulary.csv").is_file()
    assert (san / "notes" / "ward_summary.txt").is_file()

    renamed_notes = [p.name for p in (san / "notes").iterdir() if p.name != "ward_summary.txt"]
    assert len(renamed_notes) == 1
    assert renamed_notes[0].startswith("doc_") and renamed_notes[0].endswith(".txt")

    # No collisions & report.json / records.jsonl match actual sanitized paths
    all_san = {f"sanitized/{p.relative_to(san).as_posix()}" for p in san.rglob("*") if p.is_file()}
    assert len(all_san) == 4
    report = json.loads((out1 / "report.json").read_text(encoding="utf-8"))
    reported_paths = {f["output"] for f in report["files"] if f["status"] == "sanitized"}
    assert reported_paths == all_san
    for line in (out1 / "records.jsonl").read_text(encoding="utf-8").splitlines():
        rec = json.loads(line)
        assert rec["file"] in all_san


def test_no_filename_collisions_for_identical_basenames(tmp_path: Path, monkeypatch):
    inp = tmp_path / "in"
    (inp / "a").mkdir(parents=True)
    (inp / "b").mkdir(parents=True)
    (inp / "a" / "same.txt").write_text("C/O: fever", encoding="utf-8")
    (inp / "b" / "same.txt").write_text("C/O: cough", encoding="utf-8")
    (inp / "a" / "Ramesh_Kumar_UHID-1001.txt").write_text("Patient Name: Ramesh Kumar\n", encoding="utf-8")
    (inp / "b" / "Ramesh_Kumar_UHID-1001.txt").write_text("Patient Name: Ramesh Kumar\n", encoding="utf-8")

    policy = Path(__file__).resolve().parents[1] / "config" / "policy.yaml"
    monkeypatch.setenv("RAKSHA_SECRET", "collision-test")
    out = tmp_path / "out"
    run_pipeline(inp, out, policy)

    san = out / "sanitized"
    san_files = [p for p in san.rglob("*") if p.is_file()]
    assert len(san_files) == 4
    assert (san / "a" / "same.txt").is_file()
    assert (san / "b" / "same.txt").is_file()
    renamed = [p for p in san_files if p.name != "same.txt"]
    assert len(renamed) == 2
    assert renamed[0].name != renamed[1].name


def test_fhir_relative_extension_and_clinician_preservation(tmp_path: Path, monkeypatch):
    bundle = {
        "resourceType": "Bundle",
        "id": "b1",
        "type": "document",
        "entry": [
            {
                "fullUrl": "urn:uuid:p1",
                "resource": {
                    "resourceType": "Patient",
                    "id": "p1",
                    "text": {"status": "generated", "div": "<div xmlns=\"http://www.w3.org/1999/xhtml\">Salma Ansari</div>"},
                    "name": [{"text": "Salma Ansari"}],
                    "gender": "female",
                    "extension": [
                        {
                            "url": "http://hl7.org/fhir/StructureDefinition/patient-mothersMaidenName",
                            "valueString": "Ayesha Devi",
                        }
                    ],
                },
            },
            {
                "fullUrl": "urn:uuid:pr1",
                "resource": {
                    "resourceType": "Practitioner",
                    "id": "pr1",
                    "name": [{"text": "Dr. Ramesh Srivastava"}],
                },
            },
        ],
    }
    inp = tmp_path / "in"
    (inp / "fhir").mkdir(parents=True)
    (inp / "fhir" / "bundle_test.json").write_text(json.dumps(bundle), encoding="utf-8")

    policy = Path(__file__).resolve().parents[1] / "config" / "policy.yaml"
    monkeypatch.setenv("RAKSHA_SECRET", "fhir-test")
    out = tmp_path / "out"
    run_pipeline(inp, out, policy)

    san_files = list((out / "sanitized" / "fhir").glob("*.json"))
    assert len(san_files) == 1
    out_txt = san_files[0].read_text(encoding="utf-8")
    assert "Ayesha Devi" not in out_txt
    assert "Salma Ansari" not in out_txt
    assert "Dr. Ramesh Srivastava" in out_txt
    parsed = json.loads(out_txt)
    assert parsed["resourceType"] == "Bundle"


def test_mrn_patterns_positive_and_negative():
    positives = [
        "JJH-0076928",
        "IPD-2026-00454",
        "IP-26-00130",
        "adm000161",
        "UHID-010660",
        "SNJ-26-064279",
    ]
    for mrn in positives:
        found = [s.entity_type for s in detect_indian_ids(f"ID: {mrn}")]
        assert "MRN" in found, f"Failed to detect MRN: {mrn}"

    # Negative: clinical codes, doses, dates must NOT be flagged as MRN
    negatives = "ICD-10 E11.9, LOINC 718-7, Tab Dolo 650mg 1-0-1, Date 2026-02-15"
    assert detect_indian_ids(negatives) == []


def test_hindi_postposition_landmark_redaction():
    txt = "पता: पंचायत भवन के पास, ग्राम मोहनगंज, BP 130/80"
    out = redact_text(txt)
    assert "पंचायत भवन के पास" not in out
    assert "BP 130/80" in out


def test_nursing_note_relative_after_kco_and_edge_cases():
    # 1. One-word & multi-word relative names inside Attendant (S/o ...) / (W/o ...) after K/C/O diagnosis
    note1 = "14:00 - Patient A - K/C/O addison's disease. Attendant (S/o Farhan) informed about diet."
    out1 = redact_text(note1)
    assert "Farhan" not in out1
    assert "K/C/O addison's disease" in out1
    assert "informed about diet" in out1

    note2 = "14:00 - Patient B - K/C/O bell's palsy. Attendant (W/o Deepak Verma) informed about diet."
    out2 = redact_text(note2)
    assert "Deepak Verma" not in out2
    assert "K/C/O bell's palsy" in out2

    # 2. Various relationship labels & whitespace/punctuation variations
    note3 = "Next of kin:   Meena Kumari;\nCaregiver - Rakesh\nAttender: S. K. Nair"
    out3 = redact_text(note3)
    assert "Meena Kumari" not in out3
    assert "Rakesh" not in out3
    assert "Nair" not in out3

    # 3. Clinician attribution & person-like medical terms preserved; no false positive without relative field
    note4 = (
        "10:00 - Dr. Arvind Mehta reviewed Parkinson's disease and Crohn's disease.\n"
        "C/O: fever x 4 days. Tab Dolo 650mg 1-1-1 x 5 days. BP 120/80."
    )
    out4 = redact_text(note4)
    assert out4 == note4


def test_hindi_shri_honorific_and_age_gender_cells(tmp_path: Path, monkeypatch):
    out_txt = redact_text("Patient Name: श्री राम\nBP 120/80")
    assert "राम" not in out_txt
    assert "BP 120/80" in out_txt

    inp = tmp_path / "in"
    inp.mkdir()
    (inp / "hindi_ages.csv").write_text(
        "Patient Name,Age,Diagnosis\n"
        "Asha,47 वर्ष / महिला,Asthma\n"
        "Ramesh,52 वर्ष / पुरुष,Fever\n"
        "Mohan,63 वर्ष,Diabetes\n",
        encoding="utf-8",
    )
    out = tmp_path / "out"
    policy = Path(__file__).resolve().parents[1] / "config" / "policy.yaml"
    monkeypatch.setenv("RAKSHA_SECRET", "hindi-age-sec")
    run_pipeline(inp, out, policy)
    san_csv = (out / "sanitized" / "hindi_ages.csv").read_text(encoding="utf-8")
    assert "45-49 वर्ष / महिला" in san_csv
    assert "50-54 वर्ष / पुरुष" in san_csv
    assert "60-64 वर्ष" in san_csv


def test_multiword_district_extraction_stops_before_subsequent_fields():
    from detectors.name_detector import DynamicGazetteer
    from main import _extract_clues_from_text

    cases = [
        ("District: Rae Bareli Age: 48/M", "Rae Bareli"),
        ("District: Ambedkar Nagar PIN: 224122", "Ambedkar Nagar"),
        ("District: Gautam Buddha Nagar, State: UP", "Gautam Buddha Nagar"),
        ("जिला: बाराबंकी आयु: 45", "बाराबंकी"),
    ]
    for text, expected in cases:
        clues: dict = {}
        _extract_clues_from_text(text, clues, DynamicGazetteer())
        assert clues.get("district") == expected


def test_date_shift_collision_exhaustion_fails_closed():
    import datetime as dt
    import pytest
    from engine.privacy_engine import choose_collision_safe_shift
    from engine.security import KeyRing

    kr = KeyRing(b"exhaust-secret")
    anchor = dt.date(2025, 6, 1)
    all_candidates = {anchor + dt.timedelta(days=d) for d in range(-365, 366)}
    with pytest.raises(ValueError, match="collision-safe date shift"):
        choose_collision_safe_shift(kr, "pt-exhaust", {anchor}, all_candidates, max_days=180)
    # Deterministic failure on repeat call
    with pytest.raises(ValueError, match="collision-safe date shift"):
        choose_collision_safe_shift(kr, "pt-exhaust", {anchor}, all_candidates, max_days=180)


def test_landmark_detection_english_and_hindi():
    from detectors.address_detector import detect_addresses

    en = "Address: near City Hospital, opp. Primary School, PIN: 226001"
    en_landmarks = [s.text for s in detect_addresses(en) if s.entity_type == "LANDMARK"]
    assert any("near City Hospital" in x for x in en_landmarks)
    assert any("opp. Primary School" in x for x in en_landmarks)

    hi = "पता: पावर हाउस के पास, मंदिर के सामने, जिला लखनऊ"
    hi_landmarks = [s.text for s in detect_addresses(hi) if s.entity_type == "LANDMARK"]
    assert any("पावर हाउस के पास" in x for x in hi_landmarks)
    assert any("मंदिर के सामने" in x for x in hi_landmarks)
