"""Resilient, deterministic file ingestion with encoding detection and safe quarantine."""
from __future__ import annotations

import csv
import hashlib
import io
import json
from pathlib import Path
from typing import Any

from engine.record_model import IngestedFile

SUPPORTED_EXTS = {".csv", ".tsv", ".json", ".txt"}


def decode_bytes(raw: bytes) -> tuple[str | None, str]:
    """Decode raw bytes into text, supporting UTF-8 BOM, UTF-16, UTF-8, and cp1252."""
    if raw.startswith(b"\xef\xbb\xbf"):
        try:
            return raw[3:].decode("utf-8", errors="strict"), "utf-8-sig"
        except UnicodeDecodeError:
            return None, "undecodable"
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return raw.decode("utf-16", errors="strict"), "utf-16"
        except UnicodeDecodeError:
            return None, "undecodable"
    for enc in ("utf-8", "cp1252"):
        try:
            return raw.decode(enc, errors="strict"), enc
        except UnicodeDecodeError:
            continue
    return None, "undecodable"


def _json_depth(obj: Any, max_depth: int) -> int:
    """Iterative depth check to avoid RecursionError on deeply nested JSON."""
    stack: list[tuple[Any, int]] = [(obj, 1)]
    deepest = 0
    while stack:
        cur, depth = stack.pop()
        if depth > deepest:
            deepest = depth
        if deepest > max_depth:
            return deepest
        if isinstance(cur, dict):
            for v in cur.values():
                if isinstance(v, (dict, list)):
                    stack.append((v, depth + 1))
        elif isinstance(cur, list):
            for v in cur:
                if isinstance(v, (dict, list)):
                    stack.append((v, depth + 1))
    return deepest


def _looks_like_json(text: str) -> bool:
    stripped = text.lstrip()
    if not stripped or stripped[0] not in "{[":
        return False
    try:
        json.loads(stripped)
        return True
    except ValueError:
        return False


def ingest_directory(
    input_dir: Path,
    max_json_depth: int = 500,
    max_file_size_mb: int = 50,
) -> list[IngestedFile]:
    """Walk input_dir in deterministic sorted order and parse or quarantine each file."""
    results: list[IngestedFile] = []
    max_bytes = max_file_size_mb * 1024 * 1024

    all_paths = sorted(p for p in input_dir.rglob("*") if p.is_file())
    for path in all_paths:
        rel = path.relative_to(input_dir).as_posix()
        raw = path.read_bytes()
        sha = hashlib.sha256(raw).hexdigest()
        ext = path.suffix.lower()

        if len(raw) > max_bytes:
            results.append(IngestedFile(
                rel_path=rel, out_rel=rel, sha256=sha, ext=ext, fmt="quarantined",
                status="quarantined", quarantine_reason="file_too_large",
            ))
            continue

        if ext not in SUPPORTED_EXTS:
            results.append(IngestedFile(
                rel_path=rel, out_rel=rel, sha256=sha, ext=ext, fmt="quarantined",
                status="quarantined", quarantine_reason="unsupported_format",
            ))
            continue

        if not raw.strip():
            results.append(IngestedFile(
                rel_path=rel, out_rel=rel, sha256=sha, ext=ext, fmt="quarantined",
                status="quarantined", quarantine_reason="empty_file",
            ))
            continue

        text, enc = decode_bytes(raw)
        if text is None:
            results.append(IngestedFile(
                rel_path=rel, out_rel=rel, sha256=sha, ext=ext, fmt="quarantined",
                status="quarantined", quarantine_reason="undecodable_text",
            ))
            continue

        if ext in (".csv", ".tsv"):
            if _looks_like_json(text):
                results.append(IngestedFile(
                    rel_path=rel, out_rel=rel, sha256=sha, ext=ext, fmt="quarantined",
                    status="quarantined", quarantine_reason="mislabeled_json_in_csv",
                ))
                continue
            delim = "\t" if ext == ".tsv" else ","
            try:
                rows = list(csv.reader(io.StringIO(text, newline=""), delimiter=delim))
                if not rows:
                    raise ValueError("empty_csv")
                results.append(IngestedFile(
                    rel_path=rel, out_rel=rel, sha256=sha, ext=ext,
                    fmt="tsv" if ext == ".tsv" else "csv",
                    encoding=enc, delimiter=delim, text=text, csv_rows=rows,
                ))
            except (csv.Error, ValueError):
                results.append(IngestedFile(
                    rel_path=rel, out_rel=rel, sha256=sha, ext=ext, fmt="quarantined",
                    status="quarantined", quarantine_reason="malformed_csv",
                ))

        elif ext == ".json":
            try:
                parsed = json.loads(text)
            except (ValueError, RecursionError):
                results.append(IngestedFile(
                    rel_path=rel, out_rel=rel, sha256=sha, ext=ext, fmt="quarantined",
                    status="quarantined", quarantine_reason="malformed_json",
                ))
                continue

            if _json_depth(parsed, max_json_depth) > max_json_depth:
                results.append(IngestedFile(
                    rel_path=rel, out_rel=rel, sha256=sha, ext=ext, fmt="quarantined",
                    status="quarantined", quarantine_reason="excessive_json_depth",
                ))
                continue

            fmt = "fhir" if isinstance(parsed, dict) and parsed.get("resourceType") == "Bundle" else "json"
            results.append(IngestedFile(
                rel_path=rel, out_rel=rel, sha256=sha, ext=ext, fmt=fmt,
                encoding=enc, text=text, parsed_json=parsed,
            ))

        else:  # .txt
            results.append(IngestedFile(
                rel_path=rel, out_rel=rel, sha256=sha, ext=ext, fmt="txt",
                encoding=enc, text=text,
            ))

    return results
