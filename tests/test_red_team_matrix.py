"""Final release-candidate red-team edge-case test matrix (synthetic fixtures only)."""
from __future__ import annotations

import base64
import csv
import io
import json
import os
from pathlib import Path

import pytest

from engine.exporter import atomic_write_text
from main import run_pipeline


def _run(tmp_path: Path, monkeypatch, files: dict[str, bytes | str], secret: str = "rt-secret-1") -> tuple[Path, Path]:
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


# ---------------------------------------------------------------------------
# 1. File parsing edge cases
# ---------------------------------------------------------------------------

def test_parsing_encodings_formats_multiline_and_duplicate_headers(tmp_path: Path, monkeypatch):
    csv_multiline = (
        "Patient Name,Notes,Age,District,District\n"
        '"Ramesh Kumar","Line1 fever\nLine2 cough",48,Sitapur,Sitapur\n'
    )
    tsv_bom = "\ufeffPatient Name\tPhone\tDiagnosis\nSita Devi\t9876543210\tDengue\n".encode("utf-8")
    txt_utf16 = "Patient Name: मोहन लाल\nBP 120/80\n".encode("utf-16")
    txt_cp1252 = "Patient Name: Asha Devi\nTemp 99\xb0F\n".encode("cp1252")
    fhir_bundle = json.dumps({
        "resourceType": "Bundle",
        "type": "collection",
        "entry": [
            {"resource": {"resourceType": "Patient", "id": "p1", "name": [{"text": "Ramesh Kumar"}], "gender": "male", "birthDate": "1978-03-10"}},
            {"resource": {"resourceType": "Practitioner", "id": "pr1", "name": [{"text": "Dr. Arvind Mehta"}]}},
            {"resource": {"resourceType": "Condition", "subject": {"reference": "Patient/p1"}, "code": {"text": "Type 2 Diabetes"}}},
        ],
    })

    _, out = _run(tmp_path, monkeypatch, {
        "a.csv": csv_multiline,
        "b.tsv": tsv_bom,
        "c.txt": txt_utf16,
        "d.txt": txt_cp1252,
        "e.json": fhir_bundle,
    })
    rep = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert rep["counts"]["files_sanitized"] == 5
    assert rep["counts"]["files_quarantined"] == 0

    san_all = "\n".join(p.read_text(encoding="utf-8") for p in (out / "sanitized").rglob("*") if p.is_file())
    for pii in ("Ramesh Kumar", "Sita Devi", "9876543210", "मोहन लाल", "Asha Devi", "1978-03-10"):
        assert pii not in san_all
    assert "Dr. Arvind Mehta" in san_all
    assert "Type 2 Diabetes" in san_all


@pytest.mark.parametrize("rel,payload", [
    ("empty.txt", b""),
    ("bad_utf8.txt", b"\x80\x81\xfe\xff\x8d\x90"),
    ("trunc.json", "{bad json"),
    ("photo.jpg", b"\xff\xd8\xff\xe0RAW_PII_RAMESH_9876543210"),
    ("legacy.xml", "<patient><name>Ramesh Kumar</name></patient>"),
    ("weird.bin", b"\x00\x01\x02Ramesh Kumar"),
])
def test_quarantined_formats_never_copied_raw(tmp_path: Path, monkeypatch, rel: str, payload: bytes | str):
    _, out = _run(tmp_path, monkeypatch, {rel: payload})
    assert list((out / "sanitized").rglob("*")) == []
    rep = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert rep["counts"]["files_quarantined"] == 1
    assert "Ramesh" not in json.dumps(rep)


def test_deep_json_quarantined_and_unicode_deva_digits(tmp_path: Path, monkeypatch):
    deep = "{}"
    for _ in range(550):
        deep = f'{{"a":{deep}}}'
    note = "Patient Name: सुरे\u200bश वर्मा\nPhone: ९८७६५४३२१०\nBP १२०/८०\n"
    _, out = _run(tmp_path, monkeypatch, {"deep.json": deep, "note.txt": note})
    rep = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert rep["counts"]["files_quarantined"] == 1
    assert rep["counts"]["files_sanitized"] == 1
    san = next((out / "sanitized").rglob("*.txt")).read_text(encoding="utf-8")
    assert "सुरेश" not in san
    assert "९८७६५४३२१०" not in san
    assert "9876543210" not in san


# ---------------------------------------------------------------------------
# 2. PII detection, side channels & base64
# ---------------------------------------------------------------------------

def test_side_channels_json_keys_base64_and_identifiers(tmp_path: Path, monkeypatch):
    b64_payload = base64.b64encode(b"Patient Name: Kavita Verma\nAadhaar: 4123 5678 9012\nPhone: +91 9811122233").decode()
    doc = {
        "patient_name": "Kavita Verma",
        "Kavita_Verma_meta": "internal",
        "aadhaar": "4123-5678-9012",
        "abha": "91-1234-5678-9012",
        "pan": "ABCDE1234F",
        "email": "kavita.verma@example.org",
        "attachment_b64": b64_payload,
    }
    _, out = _run(tmp_path, monkeypatch, {"Kavita_Verma_9811122233.json": json.dumps(doc)})
    san_files = list((out / "sanitized").rglob("*"))
    assert len(san_files) == 1
    assert "Kavita" not in san_files[0].name
    assert "9811122233" not in san_files[0].name
    san_txt = san_files[0].read_text(encoding="utf-8")
    for leak in ("Kavita", "Verma", "4123", "9012", "ABCDE1234F", "kavita.verma@example.org", "9811122233", b64_payload):
        assert leak not in san_txt


# ---------------------------------------------------------------------------
# 3. Clinical preservation
# ---------------------------------------------------------------------------

def test_clinical_preservation_traps_and_icd_codes(tmp_path: Path, monkeypatch):
    note = (
        "Patient Name: Ramesh Kumar\n"
        "Attending: Dr. Ramesh Sharma\n"
        "C/O: fever x 3 days, productive cough\n"
        "K/C/O: Type 2 Diabetes (ICD-10: E11.9), Parkinson's disease\n"
        "Rx: Tab Dolo 650 mg 1-0-1 x 5 days\n"
        "Vitals: BP 128/82 mmHg, SpO2 98%, HbA1c 7.4%\n"
        "Attendant: C/O Suresh Kumar (9876501234)\n"
    )
    _, out = _run(tmp_path, monkeypatch, {"ward_note.txt": note})
    san = (out / "sanitized" / "ward_note.txt").read_text(encoding="utf-8")
    assert "Ramesh Kumar" not in san
    assert "Suresh Kumar" not in san
    assert "9876501234" not in san
    for keep in ("Dr. Ramesh Sharma", "fever", "E11.9", "Parkinson's disease", "Dolo 650", "1-0-1", "128/82", "98%", "7.4%"):
        assert keep in san


# ---------------------------------------------------------------------------
# 4. Identity resolution (cross-script, family phone, cannot-link, abstention)
# ---------------------------------------------------------------------------

def test_identity_resolution_cross_script_and_family_cannot_link(tmp_path: Path, monkeypatch):
    f1 = "Patient Name: Mohammad Shahid\nAge: 48/M\nDOB: 10/05/1978\nPhone: 9810011223\n"
    f2 = "Patient Name: मोहम्मद शाहिद\nAge: 48/M\nDOB: 10/05/1978\n"
    f3 = "Patient Name: Fatima Begum\nAge: 44/F\nPhone: 9810011223\n"  # shares phone, different gender/name -> MUST NOT merge
    f4 = "C/O: fever x 2 days\nBP 120/80\n"  # no identity clues -> abstention (patient: null)
    _, out = _run(tmp_path, monkeypatch, {"n1.txt": f1, "n2.txt": f2, "n3.txt": f3, "n4.txt": f4})

    recs = [json.loads(l) for l in (out / "records.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    by_file = {Path(r["file"]).name: r["patient"] for r in recs}
    assert by_file["n1.txt"] is not None
    assert by_file["n1.txt"] == by_file["n2.txt"]
    assert by_file["n3.txt"] != by_file["n1.txt"]
    assert by_file["n4.txt"] is None


# ---------------------------------------------------------------------------
# 5. File-system & failure security (atomic cleanup, input immutability, traversal)
# ---------------------------------------------------------------------------

def test_atomic_write_cleans_up_temp_on_failure(tmp_path: Path, monkeypatch):
    dest = tmp_path / "sanitized" / "out.txt"

    def _boom(*args, **kwargs):
        raise OSError("simulated disk error")

    monkeypatch.setattr(os, "replace", _boom)
    with pytest.raises(OSError, match="simulated disk error"):
        atomic_write_text(dest, "sanitized content")
    assert not dest.exists()
    assert list(dest.parent.glob(".kavach_*.tmp")) == []


def test_input_files_never_modified_and_symlinks_handled(tmp_path: Path, monkeypatch):
    inp = tmp_path / "in"
    inp.mkdir()
    orig = inp / "note.txt"
    orig.write_text("Patient Name: Meena Devi\nBP 120/80\n", encoding="utf-8")
    before_bytes = orig.read_bytes()

    outside = tmp_path / "secret_outside.txt"
    outside.write_text("OUTSIDE_SECRET", encoding="utf-8")
    link = inp / "link.txt"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pass  # Windows without Developer Mode may disallow symlinks

    out = tmp_path / "out"
    policy = Path(__file__).resolve().parents[1] / "config" / "policy.yaml"
    monkeypatch.setenv("RAKSHA_SECRET", "fs-secret")
    run_pipeline(inp, out, policy)

    assert orig.read_bytes() == before_bytes
    assert outside.read_text(encoding="utf-8") == "OUTSIDE_SECRET"
