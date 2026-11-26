"""Tests for resilient ingestion and quarantine behavior."""
from __future__ import annotations

from pathlib import Path
from engine.ingestion import decode_bytes, ingest_directory


def test_decode_utf8_bom_utf16_cp1252():
    assert decode_bytes(b"\xef\xbb\xbfhello")[0] == "hello"
    assert decode_bytes("नमस्ते".encode("utf-16"))[0] == "नमस्ते"
    assert decode_bytes("café".encode("cp1252"))[0] == "café"
    assert decode_bytes(b"\xff\xfe\x00")[0] is None


def test_quarantine_edge_cases(tmp_path: Path):
    (tmp_path / "empty.csv").write_bytes(b"")
    (tmp_path / "bad.pdf").write_bytes(b"%PDF-1.4")
    (tmp_path / "mislabeled.csv").write_text('{"patient": "Test"}', encoding="utf-8")
    (tmp_path / "trunc.json").write_text('{"a": [1, 2', encoding="utf-8")
    (tmp_path / "good.txt").write_text("C/O fever", encoding="utf-8")

    # Deep JSON (> 500 levels)
    deep = "{" + '"a":' * 520 + "1" + "}" * 520
    (tmp_path / "deep.json").write_text(deep, encoding="utf-8")

    items = {x.rel_path: x for x in ingest_directory(tmp_path, max_json_depth=500)}
    assert items["empty.csv"].status == "quarantined"
    assert items["bad.pdf"].status == "quarantined"
    assert items["mislabeled.csv"].status == "quarantined"
    assert items["trunc.json"].status == "quarantined"
    assert items["deep.json"].status == "quarantined"
    assert items["good.txt"].status == "sanitized"
