"""Tests for repeat-run determinism and secret unlinkability."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
from main import run_pipeline


def _tree_digest(root: Path) -> str:
    h = hashlib.sha256()
    for sub in ("sanitized", "records.jsonl"):
        p = root / sub
        items = sorted(p.rglob("*")) if p.is_dir() else [p]
        for f in items:
            if f.is_file():
                h.update(f.relative_to(root).as_posix().encode() + b"\0" + f.read_bytes())
    return h.hexdigest()


def test_determinism_and_secret_unlinkability(tmp_path: Path, monkeypatch):
    inp = tmp_path / "in"
    inp.mkdir()
    (inp / "note.txt").write_text("Name: Ramesh Kumar\nDate: 12/04/2026\nBP 120/80", encoding="utf-8")

    policy = Path(__file__).resolve().parents[1] / "config" / "policy.yaml"

    monkeypatch.setenv("RAKSHA_SECRET", "sec-1")
    out1 = tmp_path / "out1"
    run_pipeline(inp, out1, policy)

    out2 = tmp_path / "out2"
    run_pipeline(inp, out2, policy)

    monkeypatch.setenv("RAKSHA_SECRET", "sec-2")
    out3 = tmp_path / "out3"
    run_pipeline(inp, out3, policy)

    assert _tree_digest(out1) == _tree_digest(out2)
    assert _tree_digest(out1) != _tree_digest(out3)
