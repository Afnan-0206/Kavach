"""Resilient, deterministic file ingestion with encoding detection and safe quarantine."""
from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import stat
from pathlib import Path
from typing import Any

from engine.record_model import IngestedFile

SUPPORTED_EXTS = {".csv", ".tsv", ".json", ".txt"}


def _is_reparse_or_symlink(path: Path) -> bool:
    """Return True if path is a symlink or Windows reparse point (junction/mount)."""
    if path.is_symlink():
        return True
    try:
        st = os.lstat(path)
    except OSError:
        return True
    if stat.S_ISLNK(st.st_mode):
        return True
    attrs = getattr(st, "st_file_attributes", 0)
    if attrs & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0):
        return True
    return False


def _has_unsafe_path_component(path: Path, input_root: Path) -> bool:
    """Reject symlinks/reparse points anywhere in path or resolved escapes outside input_root."""
    cur = path
    while True:
        if _is_reparse_or_symlink(cur):
            return True
        if cur == input_root or cur.parent == cur:
            break
        cur = cur.parent
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        return True
    return not resolved.is_relative_to(input_root)


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

    all_paths: list[Path] = []
    unsafe_paths: list[Path] = []
    input_root = input_dir.resolve()
    for root, dirs, files in os.walk(input_dir, followlinks=False):
        root_p = Path(root)
        safe_dirs: list[str] = []
        for d in sorted(dirs):
            dp = root_p / d
            if _is_reparse_or_symlink(dp) or not dp.resolve().is_relative_to(input_root):
                unsafe_paths.append(dp)
            else:
                safe_dirs.append(d)
        dirs[:] = safe_dirs
        for fn in sorted(files):
            fp = root_p / fn
            if _has_unsafe_path_component(fp, input_root):
                unsafe_paths.append(fp)
            else:
                all_paths.append(fp)

    for up in sorted(unsafe_paths):
        rel = up.relative_to(input_dir).as_posix()
        results.append(IngestedFile(
            rel_path=rel, out_rel=rel, sha256="0" * 64, ext=up.suffix.lower(), fmt="quarantined",
            status="quarantined", quarantine_reason="symlink_or_path_escape",
        ))

    for path in sorted(all_paths):
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
