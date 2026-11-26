"""Atomic UTF-8 exporter for sanitized files and records.jsonl."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path


def atomic_write_text(dest: Path, content: str) -> None:
    """Write UTF-8 text atomically via a temporary file in the destination directory."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=".kavach_", suffix=".tmp", dir=str(dest.parent))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
            f.write(content)
        os.replace(tmp_path, dest)
    except Exception:
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)
        raise


def write_records_jsonl(output_dir: Path, records: list[dict]) -> None:
    """Write records.jsonl deterministically."""
    lines = [json.dumps(r, ensure_ascii=False, sort_keys=True) for r in records]
    content = ("\n".join(lines) + "\n") if lines else ""
    atomic_write_text(output_dir / "records.jsonl", content)
