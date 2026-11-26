"""Tiered synthetic edge-case & adversarial test suite (Easy, Medium, Most Difficult)."""
from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from main import run_pipeline


def _run(tmp_path: Path, monkeypatch, files: dict[str, bytes | str], secret: str = "tier-test-sec") -> tuple[Path, Path]:
    inp = tmp_path / "in"
    out = tmp_path / "out"
    for rel, content in files.items():
        dest = inp / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            dest.write_bytes(content)
        else:
            dest.write_text(content, encoding="utf-8")
    policy = Path(__file__).resolve().parents[1] / "config" / "policy.yaml"
    monkeypatch.setenv("RAKSHA_SECRET", secret)
    rc = run_pipeline(inp, out, policy)
    assert rc == 0
    return inp, out


def _all_sanitized_text(out: Path) -> str:
    return "\n".join(p.read_text(encoding="utf-8") for p in (out / "sanitized").rglob("*") if p.is_file())


# ===========================================================================
# TIER 1: EASY — Basic formats, encodings, quarantine hygiene
# ===========================================================================

def test_easy_formats_encodings_and_quarantine(tmp_path: Path, monkeypatch):
    _, out = _run(tmp_path, monkeypatch, {
        "opd.csv": "Patient Name,Phone,Aadhaar,Diagnosis,Dose\nKaran Malhotra,9811100022,2345 6789 0123,Malaria,Paracetamol 500 mg\n",
        "lab.tsv": "\ufeffPatient Name\tEmail\tPAN\tTest\nNeha Joshi\tneha.j@example.in\tBCDEA1234F\tHb 13.2 g/dL\n".encode("utf-8"),
        "note_u16.txt": "Patient Name: Deepak Rao\nVitals: BP 118/76 mmHg, SpO2 99%\n".encode("utf-16"),
        "note_cp.txt": "Patient Name: Pooja Sen\nTemp 98.6\xb0F\n".encode("cp1252"),
        "empty.txt": b"",
        "img.jpg": b"\xff\xd8\xff\xe0RAW_KARAN_MALHOTRA",
        "disguised.csv": '{"patient": "Karan Malhotra"}',
    })
    rep = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert rep["counts"]["files_sanitized"] == 4
    assert rep["counts"]["files_quarantined"] == 3
    san = _all_sanitized_text(out)
    for pii in ("Karan Malhotra", "9811100022", "2345 6789 0123", "Neha Joshi", "neha.j@example.in", "BCDEA1234F", "Deepak Rao", "Pooja Sen"):
        assert pii not in san
    for med in ("Malaria", "Paracetamol 500 mg", "Hb 13.2 g/dL", "118/76", "99%"):
        assert med in san


# ===========================================================================
# TIER 2: MEDIUM — Multilingual, Clinical Shield traps, side channels
# ===========================================================================

def test_medium_multilingual_clinical_shield_and_side_channels(tmp_path: Path, monkeypatch):
    b64_unpadded = base64.b64encode(b"Patient Name: Vikram Mehta\nPhone: 9812345678").decode().rstrip("=")
    note = (
        "मरीज़ का नाम: प्रीति शर्मा\n"
        "फोन: +९१ ९८१२३-४५६७८\n"
        "आधार: ५४३२ ६७८९ १२३४\n"
        "Attending: Dr. Priya Nair, डॉ. राजेश गुप्ता\n"
        "K/C/O: Parkinson's disease, Addison's disease\n"
        "C/O: chest pain x 2 days\n"
        "Rx: Tab Azithromycin 500 mg 1-0-0, Inj Ceftriaxone 1 g IV BD\n"
        "Attendant: Anwar sahab (C/O Vikram Mehta)\n"
    )
    fhir = {
        "resourceType": "Bundle",
        "type": "collection",
        "entry": [
            {
                "resource": {
                    "resourceType": "Patient",
                    "id": "pt1",
                    "name": [{"text": "Vikram Mehta"}],
                    "extension": [{"url": "http://example.org/StructureDefinition/motherName", "valueString": "Kamla Mehta"}],
                }
            },
            {"resource": {"resourceType": "Practitioner", "id": "doc1", "name": [{"text": "Dr. S. K. Deshmukh"}]}},
        ],
    }
    json_side = {
        "Vikram_Mehta_meta": "internal",
        "payload": b64_unpadded,
    }
    _, out = _run(tmp_path, monkeypatch, {
        "patients/9812345678_Vikram_Mehta/note_BCDEA1234F.txt": note,
        "bundle.json": json.dumps(fhir),
        "side.json": json.dumps(json_side),
        "hdr.csv": "Patient_Vikram_Mehta_Phone,Diagnosis\n9812345678,Enteric Fever\n",
    })
    san_paths = [p.relative_to(out / "sanitized").as_posix() for p in (out / "sanitized").rglob("*") if p.is_file()]
    for sp in san_paths:
        assert "9812345678" not in sp
        assert "Vikram_Mehta" not in sp
        assert "BCDEA1234F" not in sp

    san = _all_sanitized_text(out)
    for pii in ("प्रीति शर्मा", "९८१२३", "५४३२", "Anwar", "Vikram Mehta", "Kamla Mehta", "9812345678", b64_unpadded):
        assert pii not in san
    for keep in ("Dr. Priya Nair", "Dr. S. K. Deshmukh", "Parkinson's disease", "Addison's disease", "chest pain", "Azithromycin 500 mg", "1-0-0", "Enteric Fever"):
        assert keep in san


# ===========================================================================
# TIER 3: MOST DIFFICULT — Homoglyphs, linkage traps, DOB collisions, unlabeled names
# ===========================================================================

def test_hard_cyrillic_homoglyph_spoofing_in_name_pan_and_phone(tmp_path: Path, monkeypatch):
    # Uses Cyrillic а (\u0430), е (\u0435), З (\u0417), А (\u0410), В (\u0412), С (\u0421), Е (\u0415)
    spoof = (
        "Patient Name: R\u0430m\u0435sh Kum\u0430r\n"
        "PAN: \u0410\u0412\u0421D\u04151234F\n"
        "Phone: 9812\u041745678\n"
        "Diagnosis: Acute Bronchitis\n"
    )
    _, out = _run(tmp_path, monkeypatch, {"spoof.txt": spoof})
    san = _all_sanitized_text(out)
    assert "R\u0430m\u0435sh" not in san
    assert "Ramesh" not in san
    assert "\u0410\u0412\u0421D\u04151234F" not in san
    assert "1234F" not in san
    assert "9812\u041745678" not in san
    assert "Acute Bronchitis" in san


def test_hard_twins_and_homonyms_cannot_link_vs_cross_script_drift(tmp_path: Path, monkeypatch):
    # Twins sharing phone, DOB, address, but different first name & gender -> MUST NOT merge
    twin1 = "Patient Name: Aarav Verma\nAge: 24/M\nDOB: 05/06/2002\nPhone: 9899001122\nDistrict: Lucknow\n"
    twin2 = "Patient Name: Ananya Verma\nAge: 24/F\nDOB: 05/06/2002\nPhone: 9899001122\nDistrict: Lucknow\n"
    # Homonyms in different districts -> MUST NOT merge
    hom1 = "Patient Name: Sunil Sharma\nAge: 45/M\nDistrict: Lucknow\n"
    hom2 = "Patient Name: Sunil Sharma\nAge: 45/M\nDistrict: Varanasi\n"
    # Cross-script + prefix alias (Mohammad Irfan <-> मोहम्मद इरफ़ान <-> Md. Irfan) with DOB -> MUST link
    c1 = "Patient Name: Mohammad Irfan\nAge: 46/M\nDOB: 15/08/1980\n"
    c2 = "Patient Name: मोहम्मद इरफान\nAge: 46/M\nDOB: 15/08/1980\n"
    c3 = "Patient Name: Md. Irfan\nAge: 46/M\nDOB: 15/08/1980\n"

    _, out = _run(tmp_path, monkeypatch, {
        "t1.txt": twin1, "t2.txt": twin2,
        "h1.txt": hom1, "h2.txt": hom2,
        "c1.txt": c1, "c2.txt": c2, "c3.txt": c3,
    })
    recs = {Path(r["file"]).name: r["patient"] for r in (json.loads(l) for l in (out / "records.jsonl").read_text(encoding="utf-8").splitlines() if l.strip())}
    assert recs["t1.txt"] != recs["t2.txt"]
    assert recs["h1.txt"] != recs["h2.txt"]
    assert recs["c1.txt"] is not None
    assert recs["c1.txt"] == recs["c2.txt"] == recs["c3.txt"]


def test_hard_dob_collision_prevention_and_unicode_filename(tmp_path: Path, monkeypatch):
    # Patient A DOB = 14/02/1985; Patient B Visit Date = 15/02/1985 (must never shift onto 14/02/1985)
    csv_data = (
        "Patient Name,DOB,Visit Date,Diagnosis\n"
        "Asha Gupta,14/02/1985,10/01/2026,Hypertension\n"
        "Rohit Nair,20/09/1990,15/02/1985,Asthma\n"
    )
    # Unicode filename containing patient name in Devanagari
    deva_note = "Patient Name: रमेश यादव\nBP 120/80\n"
    _, out = _run(tmp_path, monkeypatch, {
        "reg.csv": csv_data,
        "रमेश_यादव_note.txt": deva_note,
    })
    san_files = [p.name for p in (out / "sanitized").rglob("*") if p.is_file()]
    assert all("रमेश" not in fn and "यादव" not in fn for fn in san_files)

    reg_out = (out / "sanitized" / "reg.csv").read_text(encoding="utf-8")
    assert "14/02/1985" not in reg_out
    assert "20/09/1990" not in reg_out


@pytest.mark.xfail(
    strict=True,
    reason="Known LLM-free/no-NER limitation: unlabeled mid-sentence free-text names without structured, honorific, or kinship anchors are not redacted.",
)
def test_hard_unlabeled_mid_sentence_free_text_name_probe(tmp_path: Path, monkeypatch):
    # Brutal honesty test: completely unlabeled 2-word name in free text with zero structured anchor
    note = "The patient Anirudh Kulkarni was admitted with dengue fever and given Dolo 650.\n"
    _, out = _run(tmp_path, monkeypatch, {"free.txt": note})
    san = _all_sanitized_text(out)
    assert "Anirudh Kulkarni" not in san
