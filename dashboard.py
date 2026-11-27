#!/usr/bin/env python3
"""Local, offline, localhost-only browser dashboard for KAVACH-FHIR."""
from __future__ import annotations

import argparse
import base64
import csv
import hmac
import html
import io
import json
import os
import re
import secrets
import subprocess
import sys
import threading
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

_HERE = Path(__file__).resolve().parent
_MAIN_PY = _HERE / "main.py"
_DEFAULT_TOOLKIT = _HERE.parent / "Secret-Wards-ToolKit-LF"
_MAX_PREVIEW_BYTES = 200 * 1024


def _is_secret_configured(env: dict[str, str] | None = None) -> bool:
    src = env if env is not None else os.environ
    return bool(src.get("RAKSHA_SECRET", "").strip())


def parse_report_json(report_path: Path) -> dict[str, Any]:
    """Parse raksha-report/1 JSON into safe overview metrics without exposing raw paths."""
    if not report_path.is_file():
        return {"available": False}
    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))
        mtime = datetime.fromtimestamp(report_path.stat().st_mtime, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (OSError, ValueError):
        return {"available": False}
    if not isinstance(data, dict):
        return {"available": False}
    counts = data.get("counts") if isinstance(data.get("counts"), dict) else {}
    timing = data.get("timing") if isinstance(data.get("timing"), dict) else {}
    entities = data.get("entities") if isinstance(data.get("entities"), dict) else {}
    resources = data.get("resources") if isinstance(data.get("resources"), dict) else {}
    raw_files = data.get("files") if isinstance(data.get("files"), list) else []
    quarantined_files: list[dict[str, Any]] = []
    for idx, entry in enumerate(raw_files):
        if not isinstance(entry, dict):
            continue
        status = str(entry.get("status", ""))
        if status and status != "sanitized":
            sha = str(entry.get("input_sha256", "")).strip()
            quarantined_files.append(
                {
                    "id": sha[:12] if sha else f"quar-{idx + 1}",
                    "status": status,
                    "reason": str(entry.get("reason") or "quarantined"),
                    "raw_copy_prevented": True,
                }
            )
    return {
        "available": True,
        "schema": str(data.get("schema", "Not reported")),
        "files_total": counts.get("files_total", "Not reported"),
        "files_sanitized": counts.get("files_sanitized", "Not reported"),
        "files_quarantined": counts.get("files_quarantined", "Not reported"),
        "records_processed": counts.get("records_processed", "Not reported"),
        "records_linked": counts.get("records_linked", "Not reported"),
        "identifiers_detected": counts.get("identifiers_detected", "Not reported"),
        "timing_seconds": timing.get("seconds", "Not reported"),
        "peak_rss_mb": resources.get("peak_rss_mb", "Not reported"),
        "rss_status": str(resources.get("measurement_status", "Not reported")),
        "last_updated": mtime,
        "entities": {str(k): int(v) for k, v in entities.items() if isinstance(v, (int, float))},
        "quarantined_files": quarantined_files,
    }


def _norm_probe_text(s: str) -> str:
    return " ".join(re.findall(r"[a-z0-9]+", str(s).lower()))


def _with_decoded_b64(text: str) -> str:
    extra: list[str] = []
    for tok in re.findall(r"[A-Za-z0-9+/]{24,}={0,2}", text):
        try:
            raw = base64.b64decode(tok, validate=True).decode("utf-8", errors="ignore")
            if raw:
                extra.append(raw)
        except Exception:
            pass
    return text if not extra else text + "\n" + "\n".join(extra)


def compute_probe_breakdown(sanitized_dir: Path, truth_json: Path) -> dict[str, Any] | None:
    """Compute aggregate Preservation Probe Retention by category without exposing probe text."""
    if not sanitized_dir.is_dir() or not truth_json.is_file():
        return None
    try:
        truth = json.loads(truth_json.read_text(encoding="utf-8"))
        # Build input sha256 -> sanitized relative path map from report.json if available
        sha_map: dict[str, str] = {}
        rep_path = sanitized_dir.parent / "report.json"
        if rep_path.is_file():
            try:
                rep_data = json.loads(rep_path.read_text(encoding="utf-8"))
                for rf in rep_data.get("files") or []:
                    if isinstance(rf, dict) and rf.get("input_sha256") and rf.get("output"):
                        sha_map[str(rf["input_sha256"])] = str(rf["output"]).replace("\\", "/").replace("sanitized/", "", 1)
            except ValueError:
                pass

        file_text_cache: dict[str, str] = {}

        def _file_norm_text(rel: str, sha: str = "") -> str:
            out_rel = sha_map.get(sha, rel.replace("\\", "/"))
            if out_rel not in file_text_cache:
                target = sanitized_dir / out_rel
                if target.is_file():
                    raw = target.read_text(encoding="utf-8", errors="ignore")
                    file_text_cache[out_rel] = _norm_probe_text(_with_decoded_b64(raw))
                else:
                    file_text_cache[out_rel] = ""
            return file_text_cache[out_rel]

        by_kind: dict[str, dict[str, int]] = {}
        retained = 0

        if isinstance(truth.get("files"), dict):
            for rel, f_entry in truth["files"].items():
                if not isinstance(f_entry, dict):
                    continue
                units = f_entry.get("units")
                if not isinstance(units, dict):
                    continue
                ftext = _file_norm_text(str(rel), str(f_entry.get("sha256") or ""))
                if not ftext:
                    continue
                for u in units.values():
                    if not isinstance(u, dict):
                        continue
                    for pv in u.get("preserve") or []:
                        if not isinstance(pv, dict):
                            continue
                        kind = str(pv.get("kind", "unknown"))
                        np = _norm_probe_text(str(pv.get("text", "")))
                        bucket = by_kind.setdefault(kind, {"total": 0, "retained": 0, "lost": 0})
                        bucket["total"] += 1
                        if np and np in ftext:
                            bucket["retained"] += 1
                            retained += 1
                        else:
                            bucket["lost"] += 1
        elif isinstance(truth.get("preserve"), list):
            norm_texts: list[str] = []
            for p in sorted(sanitized_dir.rglob("*")):
                if p.is_file():
                    try:
                        raw = p.read_text(encoding="utf-8", errors="ignore")
                        norm_texts.append(_norm_probe_text(_with_decoded_b64(raw)))
                    except OSError:
                        continue
            joined = "\n".join(norm_texts)
            for probe in truth["preserve"]:
                if not isinstance(probe, dict):
                    continue
                kind = str(probe.get("kind", "unknown"))
                np = _norm_probe_text(str(probe.get("text", "")))
                bucket = by_kind.setdefault(kind, {"total": 0, "retained": 0, "lost": 0})
                bucket["total"] += 1
                if np and np in joined:
                    bucket["retained"] += 1
                    retained += 1
                else:
                    bucket["lost"] += 1

        total = sum(b["total"] for b in by_kind.values())
        if not total:
            return None
        demographic_kinds = {"district", "hospital", "age", "pin", "pincode"}
        categories = [
            {
                "kind": k,
                "group": "demographic" if k in demographic_kinds else "clinical",
                "retained": v["retained"],
                "total": v["total"],
                "lost": v["lost"],
                "pct": round((100.0 * v["retained"] / v["total"]), 1) if v["total"] else 100.0,
            }
            for k, v in sorted(by_kind.items(), key=lambda kv: (-kv[1]["lost"], -kv[1]["total"], kv[0]))
        ]
        return {
            "total": total,
            "retained": retained,
            "lost": total - retained,
            "pct": round((100.0 * retained / total), 1) if total else 100.0,
            "categories": categories,
        }
    except (OSError, ValueError):
        return None


def parse_check_dev_output(stdout: str) -> dict[str, Any]:
    """Extract aggregate metrics from official check_dev.py summary output."""
    out: dict[str, Any] = {
        "pii_leakage": "Not reported",
        "canaries": "Not reported",
        "clinical_preservation": "Not reported",
        "linkage_precision": "Not reported",
        "linkage_recall": "Not reported",
        "linkage_f05": "Not reported",
        "false_merges": "Not reported",
        "raw_copies": "Not reported",
    }
    m_pii = re.search(r"PERSONAL DATA:\s*(\d+)\s+of\s+(\d+)\s+pieces\s+still\s+visible\s*\(([^)]+)\)", stdout)
    if m_pii:
        out["pii_leakage"] = f"{m_pii.group(1)} / {m_pii.group(2)} ({m_pii.group(3).strip()})"
    m_can = re.search(r"CANARIES:\s*(\d+)\s+of\s+(\d+)", stdout)
    if m_can:
        out["canaries"] = f"{m_can.group(1)} / {m_can.group(2)}"
    m_med = re.search(r"MEDICAL DATA KEPT:\s*(\d+)\s+of\s+(\d+)\s+medical\s+values\s+survived\s*\(([^)]+)\)", stdout)
    if m_med:
        out["clinical_preservation"] = f"{m_med.group(1)} / {m_med.group(2)} ({m_med.group(3).split(';')[0].strip()})"
    m_lnk = re.search(
        r"PATIENT LINKING:\s*precision\s+([0-9.]+),\s*recall\s+([0-9.]+),\s*F0\.5\s+([0-9.]+).*?(\d+)\s*\)",
        stdout,
    )
    if m_lnk:
        out["linkage_precision"] = m_lnk.group(1)
        out["linkage_recall"] = m_lnk.group(2)
        out["linkage_f05"] = m_lnk.group(3)
        out["false_merges"] = m_lnk.group(4)
    m_raw = re.search(r"RAW COPIES:\s*(\d+)", stdout)
    if m_raw:
        out["raw_copies"] = m_raw.group(1)
    return out


def parse_validate_output(stdout: str, exit_code: int) -> str:
    """Parse validate_output.py status conservatively."""
    if exit_code == 0 and "CONTRACT OK" in stdout:
        return "CONTRACT OK"
    if "ERROR" in stdout or exit_code != 0:
        return f"FAILED (exit {exit_code})"
    return "Not reported"


def resolve_sanitized_file(sanitized_dir: Path, rel_path: str) -> Path | None:
    """Resolve a relative path strictly inside sanitized_dir; reject traversal and symlinks."""
    if not rel_path or "\x00" in rel_path or "\\" in rel_path or rel_path.startswith("/"):
        return None
    parts = rel_path.split("/")
    if any(p in ("", ".", "..") for p in parts):
        return None
    try:
        san_root = sanitized_dir.resolve()
        candidate = (san_root / rel_path).resolve()
    except OSError:
        return None
    if not candidate.is_relative_to(san_root) or candidate == san_root:
        return None
    if candidate.is_symlink() or not candidate.is_file():
        return None
    return candidate


def list_sanitized_files(sanitized_dir: Path) -> list[str]:
    """List sorted relative POSIX paths strictly inside sanitized_dir."""
    if not sanitized_dir.is_dir():
        return []
    out: list[str] = []
    san_root = sanitized_dir.resolve()
    for p in sorted(san_root.rglob("*")):
        if p.is_file() and not p.is_symlink():
            out.append(p.relative_to(san_root).as_posix())
    return out


def read_sanitized_preview(sanitized_dir: Path, rel_path: str) -> dict[str, Any] | None:
    """Read a bounded preview of a sanitized file with HTML-escaped metadata."""
    target = resolve_sanitized_file(sanitized_dir, rel_path)
    if target is None:
        return None
    raw = target.read_bytes()
    truncated = len(raw) > _MAX_PREVIEW_BYTES
    text = raw[:_MAX_PREVIEW_BYTES].decode("utf-8", errors="replace")
    ext = target.suffix.lower()
    fmt = "txt"
    parsed_rows: list[list[str]] | None = None
    pretty_json: str | None = None
    if ext in (".csv", ".tsv"):
        fmt = ext.lstrip(".")
        delim = "\t" if ext == ".tsv" else ","
        try:
            parsed_rows = list(csv.reader(io.StringIO(text, newline=""), delimiter=delim))[:101]
        except csv.Error:
            parsed_rows = None
    elif ext == ".json":
        fmt = "json"
        try:
            pretty_json = json.dumps(json.loads(text), ensure_ascii=False, indent=2)
        except ValueError:
            pretty_json = None

    return {
        "path": rel_path,
        "label": "SANITIZED OUTPUT",
        "format": fmt,
        "size_bytes": len(raw),
        "truncated": truncated,
        "text": text,
        "pretty_json": pretty_json,
        "table_rows": parsed_rows,
    }


class DashboardState:
    """Thread-safe controller for running main.py and official evaluators."""

    def __init__(
        self,
        input_dir: Path,
        output_dir: Path,
        toolkit_dir: Path | None = None,
        main_py: Path = _MAIN_PY,
    ) -> None:
        self.input_dir = input_dir.resolve()
        self.output_dir = output_dir.resolve()
        self.sanitized_dir = self.output_dir / "sanitized"
        self.toolkit_dir = toolkit_dir.resolve() if toolkit_dir else None
        self.main_py = main_py.resolve()
        self.csrf_token = secrets.token_urlsafe(32)
        self._lock = threading.Lock()
        self.pipeline_status = "idle"
        self.pipeline_exit_code: int | None = None
        self.pipeline_message = "Ready to run"
        self.eval_status = "idle"
        self.eval_message = "Not run yet"
        self.validate_exit_code: int | None = None
        self.check_dev_exit_code: int | None = None
        self.contract_status = "Not reported"
        self.last_error: str | None = None
        self.eval_timestamp: str | None = None
        self.probe_breakdown: dict[str, Any] | None = None
        self.eval_metrics: dict[str, Any] = {
            "pii_leakage": "Not reported",
            "canaries": "Not reported",
            "clinical_preservation": "Not reported",
            "linkage_precision": "Not reported",
            "linkage_recall": "Not reported",
            "linkage_f05": "Not reported",
            "false_merges": "Not reported",
            "raw_copies": "Not reported",
        }

    def _compute_execution_state(self) -> str:
        if self.pipeline_status == "running":
            return "pipeline_running"
        if self.eval_status == "running":
            return "evaluation_running"
        if self.pipeline_status == "failed" or self.eval_status == "failed":
            return "failed"
        if self.pipeline_status == "succeeded" or self.eval_status == "completed":
            return "completed"
        return "idle"

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            report = parse_report_json(self.output_dir / "report.json")
            files = list_sanitized_files(self.sanitized_dir)
            execution_state = self._compute_execution_state()
            return {
                "execution_state": execution_state,
                "last_error": self.last_error,
                "input_label": self.input_dir.name,
                "output_label": self.output_dir.name,
                "eval_timestamp": self.eval_timestamp,
                "probe_breakdown": self.probe_breakdown,
                "secret_configured": _is_secret_configured(),
                "pipeline": {
                    "status": self.pipeline_status,
                    "exit_code": self.pipeline_exit_code,
                    "message": self.pipeline_message,
                },
                "evaluation": {
                    "status": self.eval_status,
                    "message": self.eval_message,
                    "validate_exit_code": self.validate_exit_code,
                    "check_dev_exit_code": self.check_dev_exit_code,
                    "contract_status": self.contract_status,
                    "metrics": dict(self.eval_metrics),
                    "toolkit_available": bool(
                        self.toolkit_dir
                        and (self.toolkit_dir / "validate_output.py").is_file()
                        and (self.toolkit_dir / "check_dev.py").is_file()
                    ),
                },
                "report": report,
                "sanitized_file_count": len(files),
            }

    def start_pipeline(self) -> tuple[bool, str]:
        if not _is_secret_configured():
            return False, "RAKSHA_SECRET is not set in the server environment."
        with self._lock:
            if self.pipeline_status == "running" or self.eval_status == "running":
                return False, "Another job is already running."
            self.pipeline_status = "running"
            self.pipeline_exit_code = None
            self.pipeline_message = "Running privacy firewall..."
            self.last_error = None

        threading.Thread(target=self._run_pipeline_worker, daemon=True).start()
        return True, "Pipeline started."

    def _run_pipeline_worker(self) -> None:
        try:
            proc = subprocess.run(
                [sys.executable, str(self.main_py), "--input", str(self.input_dir), "--output", str(self.output_dir)],
                capture_output=True,
                text=True,
                env=os.environ.copy(),
                timeout=900,
                check=False,
            )
            summary = ""
            for line in proc.stdout.splitlines():
                if line.startswith("files "):
                    summary = line.strip()
                    break
            with self._lock:
                self.pipeline_exit_code = proc.returncode
                if proc.returncode == 0:
                    self.pipeline_status = "succeeded"
                    self.pipeline_message = summary or "Completed (exit 0)."
                else:
                    self.pipeline_status = "failed"
                    self.pipeline_message = f"Pipeline failed (exit code {proc.returncode})."
                    self.last_error = f"Pipeline exited with code {proc.returncode}. Inspect local terminal for details."
            if proc.returncode == 0 and self.toolkit_dir:
                val_py = self.toolkit_dir / "validate_output.py"
                chk_py = self.toolkit_dir / "check_dev.py"
                truth_json = self.toolkit_dir / "dev" / "truth" / "truth.json"
                if val_py.is_file() and chk_py.is_file() and truth_json.is_file():
                    with self._lock:
                        self.eval_status = "running"
                        self.eval_message = "Running evaluation..."
                    self._run_eval_worker(val_py, chk_py, truth_json)
        except (OSError, subprocess.SubprocessError):
            with self._lock:
                self.pipeline_status = "failed"
                self.pipeline_exit_code = 1
                self.pipeline_message = "Pipeline execution error."
                self.last_error = "Pipeline execution error. Inspect local terminal for details."

    def start_evaluation(self) -> tuple[bool, str]:
        if not self.toolkit_dir:
            return False, "Official toolkit directory is not configured."
        val_py = self.toolkit_dir / "validate_output.py"
        chk_py = self.toolkit_dir / "check_dev.py"
        truth_json = self.toolkit_dir / "dev" / "truth" / "truth.json"
        if not (val_py.is_file() and chk_py.is_file() and truth_json.is_file()):
            return False, "Official evaluator scripts or truth.json not found in toolkit directory."
        if not self.sanitized_dir.is_dir():
            return False, "No sanitized output found yet. Run the pipeline first."
        with self._lock:
            if self.pipeline_status == "running" or self.eval_status == "running":
                return False, "Another job is already running."
            self.eval_status = "running"
            self.eval_message = "Running validate_output.py and check_dev.py..."
            self.last_error = None

        threading.Thread(target=self._run_eval_worker, args=(val_py, chk_py, truth_json), daemon=True).start()
        return True, "Evaluation started."

    def _run_eval_worker(self, val_py: Path, chk_py: Path, truth_json: Path) -> None:
        try:
            vo = subprocess.run(
                [sys.executable, str(val_py), "--input", str(self.input_dir), "--output", str(self.output_dir)],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
            cd = subprocess.run(
                [sys.executable, str(chk_py), "--output", str(self.output_dir), "--truth", str(truth_json)],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
            contract = parse_validate_output(vo.stdout, vo.returncode)
            metrics = parse_check_dev_output(cd.stdout)
            breakdown = compute_probe_breakdown(self.sanitized_dir, truth_json)
            ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            with self._lock:
                self.validate_exit_code = vo.returncode
                self.check_dev_exit_code = cd.returncode
                self.contract_status = contract
                self.eval_metrics = metrics
                self.probe_breakdown = breakdown
                self.eval_timestamp = ts
                if vo.returncode == 0 and cd.returncode == 0:
                    self.eval_status = "completed"
                    self.eval_message = "Official practice evaluation and contract check completed."
                else:
                    self.eval_status = "failed"
                    self.eval_message = f"Evaluator exited with codes validate={vo.returncode}, check_dev={cd.returncode}."
                    self.last_error = self.eval_message
        except (OSError, subprocess.SubprocessError):
            with self._lock:
                self.eval_status = "failed"
                self.eval_message = "Evaluator execution error."
                self.last_error = "Evaluator execution error. Inspect local terminal for details."


_DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<meta name="kavach-csrf" content="__KAVACH_CSRF__" />
<title>KAVACH-FHIR Local Dashboard</title>
<style>
  :root {
    --page-bg: #ECECEC;
    --frame: #5A5A58;
    --frame-dark: #252623;

    --surface-main: #DFDFD7;
    --surface-alt: #EFEFEB;

    --card: #F7F7F4;
    --card-white: #FDFDFD;

    --text-primary: #252623;
    --text-secondary: #595C56;
    --text-muted: #5D5F5A;

    --border-soft: #D2D2CB;

    --accent-lime: #F3FE4A;
    --accent-olive: #C5C849;

    --danger: #B85C50;
    --success: #637D65;

    --shadow-soft: 0 10px 28px rgba(30, 30, 27, 0.07);
    --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    --sans: Inter, "Helvetica Neue", Arial, sans-serif;
  }

  * { box-sizing: border-box; }

  html, body {
    width: 100%;
    height: 100%;
    margin: 0;
    overflow: hidden;
    background: var(--page-bg);
    color: var(--text-primary);
    font-family: var(--sans);
    -webkit-font-smoothing: antialiased;
  }

  button:focus-visible, input:focus-visible, select:focus-visible, a:focus-visible {
    outline: 2px solid var(--frame-dark);
    outline-offset: 2px;
  }

  .sr-only {
    position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px;
    overflow: hidden; clip: rect(0, 0, 0, 0); white-space: nowrap; border: 0;
  }

  #app {
    width: 100%;
    height: 100dvh;
    overflow: hidden;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 10px;
  }

  /* Outer Charcoal Application Shell */
  .app-shell {
    width: min(96vw, 1760px);
    height: calc(100dvh - 20px);
    background: var(--frame);
    border-radius: 44px;
    padding: 10px;
    display: flex;
    flex-direction: column;
    min-width: 0;
    min-height: 0;
    overflow: hidden;
    box-shadow: 0 22px 54px rgba(37, 38, 35, 0.18), inset 0 1px 0 rgba(255,255,255,0.12);
  }

  .app-frame {
    flex: 1;
    background: var(--frame-dark);
    border-radius: 36px;
    padding: 8px 10px 10px;
    display: flex;
    flex-direction: column;
    min-width: 0;
    min-height: 0;
    overflow: hidden;
  }

  /* Top Dark Navigation Region */
  .top-nav {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    padding: 6px 14px 10px;
    color: var(--card-white);
    flex-shrink: 0;
    min-width: 0;
  }

  .brand-group {
    display: flex;
    align-items: center;
    gap: 10px;
    flex-shrink: 0;
  }

  .emblem {
    width: 34px;
    height: 34px;
    border-radius: 50%;
    background: var(--accent-lime);
    color: var(--frame-dark);
    display: grid;
    place-items: center;
    font-weight: 700;
    font-size: 0.8rem;
    flex-shrink: 0;
  }

  .brand-text { display: flex; flex-direction: column; gap: 1px; }
  .brand-name { font-size: 0.68rem; letter-spacing: 0.14em; text-transform: uppercase; color: var(--text-muted); }
  .brand-section { font-size: 0.96rem; font-weight: 500; color: var(--card-white); }

  .nav-pills {
    display: flex;
    align-items: center;
    gap: 5px;
    overflow-x: auto;
    min-width: 0;
    scrollbar-width: none;
  }
  .nav-pills::-webkit-scrollbar { display: none; }

  .nav-pill {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 7px 13px;
    border-radius: 999px;
    border: 1px solid rgba(255, 255, 255, 0.14);
    background: rgba(255, 255, 255, 0.06);
    color: #E4E4DE;
    font-size: 0.78rem;
    font-weight: 500;
    cursor: pointer;
    white-space: nowrap;
    flex-shrink: 0;
    transition: transform 180ms ease, background 180ms ease, color 180ms ease;
  }
  .nav-pill:hover { background: rgba(255, 255, 255, 0.14); }
  .nav-pill.active {
    background: var(--card-white);
    color: var(--text-primary);
    border-color: var(--card-white);
  }
  .nav-pill .dot { width: 6px; height: 6px; border-radius: 50%; display: none; }
  .nav-pill.active .dot { display: inline-block; background: var(--frame-dark); box-shadow: 0 0 0 3px var(--accent-lime); }

  .action-group {
    display: flex;
    align-items: center;
    gap: 7px;
    flex-shrink: 0;
  }

  .status-pill {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 6px 11px;
    border-radius: 999px;
    font-size: 0.73rem;
    font-weight: 500;
    background: rgba(255,255,255,0.08);
    color: #E4E4DE;
    border: 1px solid rgba(255,255,255,0.14);
    white-space: nowrap;
  }
  .status-pill.ok { background: rgba(99, 125, 101, 0.28); color: #DCEAD9; border-color: rgba(99, 125, 101, 0.55); }
  .status-pill.bad { background: rgba(184, 92, 80, 0.28); color: #F7D8D4; border-color: rgba(184, 92, 80, 0.55); }
  .status-pill.light { background: var(--surface-alt); color: var(--text-primary); border-color: var(--border-soft); }
  .status-pill.light.ok { background: rgba(99, 125, 101, 0.14); color: #3D523F; border-color: rgba(99, 125, 101, 0.35); }
  .status-pill.light.bad { background: rgba(184, 92, 80, 0.14); color: #8A3D34; border-color: rgba(184, 92, 80, 0.35); }
  .status-pill.light.lime { background: var(--accent-lime); color: var(--text-primary); border-color: var(--accent-olive); }

  .btn {
    border-radius: 999px;
    padding: 7px 14px;
    font-size: 0.78rem;
    font-weight: 500;
    border: 1px solid transparent;
    cursor: pointer;
    white-space: nowrap;
    transition: transform 180ms ease, filter 180ms ease;
  }
  .btn:active:not(:disabled) { transform: scale(0.98); }
  .btn:disabled { opacity: 0.45; cursor: not-allowed; }
  .btn-lime { background: var(--accent-lime); color: var(--text-primary); border-color: var(--accent-olive); }
  .btn-lime:hover:not(:disabled) { filter: brightness(0.96); }
  .btn-ivory { background: var(--card); color: var(--text-primary); border-color: var(--border-soft); }
  .btn-ivory:hover:not(:disabled) { background: var(--card-white); }

  /* Warm Grey Inner Canvas */
  .inner-canvas {
    flex: 1;
    background: var(--surface-main);
    border-radius: 28px;
    padding: 16px 20px 12px;
    display: flex;
    flex-direction: column;
    min-width: 0;
    min-height: 0;
    overflow: hidden;
    gap: 10px;
  }

  .banner {
    display: none;
    padding: 8px 14px;
    border-radius: 14px;
    font-size: 0.8rem;
    border: 1px solid var(--border-soft);
    background: var(--card-white);
    flex-shrink: 0;
  }
  .banner.show { display: flex; align-items: center; justify-content: space-between; gap: 10px; }
  .banner.bad { border-color: rgba(184, 92, 80, 0.45); background: #FAF1EF; color: #7C342B; }
  .banner.info { border-color: var(--accent-olive); background: #FAFCE6; color: var(--text-primary); }

  .view-host {
    flex: 1;
    min-width: 0;
    min-height: 0;
    overflow: hidden;
    display: flex;
    flex-direction: column;
  }

  .view-panel {
    display: none;
    width: 100%;
    height: 100%;
    min-width: 0;
    min-height: 0;
    overflow-y: auto;
    overflow-x: hidden;
    flex-direction: column;
    gap: 12px;
  }
  .view-panel.active { display: flex; }

  .section-label {
    font-size: 0.68rem;
    text-transform: uppercase;
    letter-spacing: 0.12em;
    color: var(--text-secondary);
    margin: 0;
    font-weight: 600;
  }

  /* Overview Layout */
  .overview-top {
    display: grid;
    grid-template-columns: minmax(0, 1.15fr) minmax(0, 1.65fr);
    gap: 12px;
    min-width: 0;
  }

  .summary-card {
    background: var(--card-white);
    border: 1px solid var(--border-soft);
    border-radius: 24px;
    padding: 16px 18px;
    box-shadow: var(--shadow-soft);
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    gap: 10px;
    min-width: 0;
  }

  .summary-head { display: flex; justify-content: space-between; align-items: flex-start; gap: 10px; min-width: 0; }
  .page-title { margin: 0; font-size: 1.35rem; font-weight: 400; letter-spacing: -0.02em; }
  .page-sub { margin: 2px 0 0; font-size: 0.8rem; color: var(--text-secondary); }

  .marker-row { display: flex; flex-wrap: wrap; gap: 5px; }
  .marker {
    font-size: 0.64rem; letter-spacing: 0.07em; text-transform: uppercase;
    padding: 4px 9px; border-radius: 999px; background: var(--surface-alt);
    border: 1px solid var(--border-soft); color: var(--text-secondary); font-weight: 600;
  }

  .summary-meta {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 8px 12px;
    padding-top: 8px;
    border-top: 1px solid var(--border-soft);
  }
  .meta-item { min-width: 0; }
  .meta-item span { display: block; font-size: 0.68rem; color: var(--text-muted); }
  .meta-item strong { display: block; font-size: 0.82rem; font-weight: 500; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

  .vitals-grid {
    display: grid;
    grid-template-columns: repeat(5, minmax(0, 1fr));
    gap: 10px;
    min-width: 0;
  }

  .vital-card {
    background: var(--card);
    border: 1px solid var(--border-soft);
    border-radius: 22px;
    padding: 14px 12px;
    box-shadow: var(--shadow-soft);
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    gap: 8px;
    min-width: 0;
  }
  .vital-icon {
    width: 32px; height: 32px; border-radius: 50%;
    background: var(--surface-alt); border: 1px solid var(--border-soft);
    display: grid; place-items: center; color: var(--text-primary);
  }
  .vital-label { font-size: 0.7rem; color: var(--text-secondary); }
  .vital-val { font-size: 1.32rem; font-weight: 500; letter-spacing: -0.02em; font-variant-numeric: tabular-nums; overflow-wrap: anywhere; }
  .vital-sub { font-size: 0.69rem; color: var(--text-muted); }

  /* Compact 6-stage overview strip */
  .overview-strip {
    background: var(--card);
    border: 1px solid var(--border-soft);
    border-radius: 22px;
    padding: 10px 14px;
    display: grid;
    grid-template-columns: repeat(6, minmax(0, 1fr));
    gap: 8px;
    min-width: 0;
  }
  .mini-stage {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 6px 8px;
    border-radius: 14px;
    background: var(--card-white);
    border: 1px solid var(--border-soft);
    cursor: pointer;
    min-width: 0;
    text-align: left;
    transition: transform 180ms ease, border-color 180ms ease;
  }
  .mini-stage:hover { transform: translateY(-1px); border-color: var(--frame-dark); }
  .mini-dot {
    width: 24px; height: 24px; border-radius: 50%; background: var(--accent-lime);
    border: 1.5px solid var(--frame-dark); display: grid; place-items: center;
    font-size: 0.68rem; font-weight: 700; flex-shrink: 0;
  }
  .mini-stage-text { min-width: 0; }
  .mini-stage-text span { display: block; font-size: 0.66rem; color: var(--text-secondary); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .mini-stage-text strong { display: block; font-size: 0.74rem; font-weight: 500; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

  .overview-bottom {
    flex: 1;
    min-height: 0;
    display: grid;
    grid-template-columns: minmax(0, 1.3fr) minmax(0, 1fr) minmax(0, 1fr);
    gap: 12px;
    min-width: 0;
  }

  .info-card {
    background: var(--card);
    border: 1px solid var(--border-soft);
    border-radius: 24px;
    padding: 15px 17px;
    box-shadow: var(--shadow-soft);
    display: flex;
    flex-direction: column;
    min-width: 0;
    min-height: 0;
    overflow: hidden;
  }
  .info-card.white { background: var(--card-white); }
  .card-head { display: flex; justify-content: space-between; align-items: center; gap: 8px; margin-bottom: 10px; min-width: 0; }
  .card-head h3 { margin: 0; font-size: 0.94rem; font-weight: 500; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

  .fmt-pill {
    font-size: 0.66rem; padding: 3px 8px; border-radius: 999px;
    background: var(--surface-alt); border: 1px solid var(--border-soft);
    color: var(--text-secondary); white-space: nowrap; flex-shrink: 0;
  }

  .entity-bars { display: flex; flex-direction: column; gap: 6px; overflow-y: auto; min-height: 0; }
  .entity-row { display: grid; grid-template-columns: minmax(70px, 110px) 1fr 44px; align-items: center; gap: 8px; font-size: 0.74rem; min-width: 0; }
  .entity-name { font-family: var(--mono); color: var(--text-secondary); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .mini-bar-track { height: 5px; background: var(--surface-alt); border-radius: 999px; overflow: hidden; min-width: 0; }
  .mini-bar-fill { height: 100%; background: var(--frame-dark); border-radius: 999px; }
  .entity-count { text-align: right; font-variant-numeric: tabular-nums; font-weight: 500; }

  .kv-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; min-width: 0; }
  .kv-box { background: var(--card-white); border: 1px solid var(--border-soft); border-radius: 14px; padding: 8px 10px; min-width: 0; }
  .info-card.white .kv-box { background: var(--surface-alt); }
  .kv-box span { display: block; font-size: 0.68rem; color: var(--text-secondary); }
  .kv-box strong { display: block; margin-top: 2px; font-size: 0.98rem; font-weight: 500; overflow-wrap: anywhere; }

  /* Pipeline View (6 Connected Stages fitting 100% width & height) */
  .pipeline-header {
    display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 10px;
    background: var(--card-white); border: 1px solid var(--border-soft); border-radius: 22px; padding: 12px 18px;
    flex-shrink: 0;
  }
  .timeline-track-wrap { position: relative; flex: 1; min-height: 0; display: flex; flex-direction: column; justify-content: center; }
  .timeline-rail {
    position: absolute; top: 20px; left: 7%; right: 7%; height: 2px;
    background: linear-gradient(90deg, var(--border-soft), var(--accent-olive), var(--border-soft));
    z-index: 0;
  }
  .timeline-grid {
    position: relative; z-index: 1;
    display: grid;
    grid-template-columns: repeat(6, minmax(0, 1fr));
    gap: 10px;
    min-width: 0;
  }
  .stage-col { display: flex; flex-direction: column; align-items: center; min-width: 0; }
  .stage-node {
    width: 38px; height: 38px; border-radius: 50%; background: var(--accent-lime);
    border: 2px solid var(--frame-dark); color: var(--frame-dark);
    display: grid; place-items: center; cursor: pointer; flex-shrink: 0;
    transition: transform 180ms ease, box-shadow 180ms ease;
  }
  .stage-col.selected .stage-node, .stage-node:hover { box-shadow: 0 0 0 4px rgba(243, 254, 74, 0.48); }
  .stage-kicker {
    margin-top: 6px; font-size: 0.62rem; letter-spacing: 0.08em; text-transform: uppercase;
    color: var(--text-secondary); text-align: center; font-weight: 600;
  }
  .stage-stem { width: 1.5px; height: 12px; background: var(--border-soft); margin: 3px 0; }
  .stage-card {
    width: 100%; min-width: 0; background: var(--card-white); border: 1px solid var(--border-soft);
    border-radius: 22px; padding: 12px; box-shadow: var(--shadow-soft);
    display: flex; flex-direction: column; gap: 7px; overflow: hidden;
  }
  .stage-col.selected .stage-card { border-color: var(--frame-dark); }
  .stage-title { margin: 0; font-size: 0.84rem; font-weight: 500; overflow-wrap: anywhere; }
  .stage-stat { font-size: 1.02rem; font-weight: 500; overflow-wrap: anywhere; }
  .stage-list { font-size: 0.71rem; color: var(--text-secondary); display: flex; flex-direction: column; gap: 4px; }
  .fmt-pills { display: flex; flex-wrap: wrap; gap: 4px; }
  .synth-box {
    background: var(--surface-alt); border: 1px dashed var(--border-soft); border-radius: 12px;
    padding: 7px 8px; font-family: var(--mono); font-size: 0.65rem; line-height: 1.38; overflow-wrap: anywhere;
  }

  /* Sanitized Files View */
  .explorer-grid {
    flex: 1;
    min-height: 0;
    min-width: 0;
    display: grid;
    grid-template-columns: minmax(240px, 320px) minmax(0, 1fr);
    gap: 12px;
  }
  .explorer-card {
    background: var(--card);
    border: 1px solid var(--border-soft);
    border-radius: 24px;
    padding: 14px 16px;
    box-shadow: var(--shadow-soft);
    display: flex;
    flex-direction: column;
    min-width: 0;
    min-height: 0;
    overflow: hidden;
  }
  .explorer-card.white { background: var(--card-white); }
  .search-input {
    width: 100%; padding: 8px 12px; border-radius: 999px; border: 1px solid var(--border-soft);
    background: var(--card-white); color: var(--text-primary); font-size: 0.8rem; margin: 8px 0 6px;
  }
  .filter-row { display: flex; flex-wrap: wrap; gap: 4px; margin-bottom: 8px; }
  .filter-chip {
    padding: 4px 9px; border-radius: 999px; font-size: 0.7rem;
    border: 1px solid var(--border-soft); background: var(--surface-alt);
    color: var(--text-secondary); cursor: pointer;
  }
  .filter-chip.active { background: var(--frame-dark); color: var(--card-white); border-color: var(--frame-dark); }
  .file-list { flex: 1; min-height: 0; overflow-y: auto; display: flex; flex-direction: column; gap: 3px; }
  .file-btn {
    text-align: left; width: 100%; padding: 7px 10px; border-radius: 10px;
    border: 1px solid transparent; background: transparent; color: var(--text-primary);
    font-family: var(--mono); font-size: 0.72rem; cursor: pointer; overflow-wrap: anywhere;
  }
  .file-btn:hover { background: var(--surface-alt); }
  .file-btn.active { background: var(--accent-lime); border-color: var(--accent-olive); font-weight: 600; }

  .preview-box {
    flex: 1; min-height: 0; min-width: 0; overflow: auto;
    margin-top: 10px; background: var(--surface-alt); border: 1px solid var(--border-soft);
    border-radius: 16px; padding: 12px;
  }
  .preview-box pre { margin: 0; font-family: var(--mono); font-size: 0.76rem; line-height: 1.5; white-space: pre-wrap; overflow-wrap: anywhere; }
  .preview-box table { width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 0.73rem; }
  .preview-box th, .preview-box td { padding: 6px 8px; border-bottom: 1px solid var(--border-soft); text-align: left; white-space: nowrap; }
  .preview-box th { position: sticky; top: 0; background: var(--card-white); font-weight: 600; }

  /* Evaluation View */
  .eval-grid {
    flex: 1; min-height: 0;
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 10px;
  }
  .eval-card {
    background: var(--card-white); border: 1px solid var(--border-soft); border-radius: 22px;
    padding: 14px 16px; box-shadow: var(--shadow-soft); display: flex; flex-direction: column; justify-content: center; min-width: 0;
  }
  .eval-card.highlight { background: #FAFCE6; border-color: var(--accent-olive); }
  .eval-card span { font-size: 0.72rem; color: var(--text-secondary); }
  .eval-card strong { margin-top: 4px; font-size: 1.2rem; font-weight: 500; overflow-wrap: anywhere; }

  /* Security View */
  .security-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(min(100%, 250px), 1fr));
    gap: 12px;
    min-width: 0;
  }
  .sec-card {
    background: var(--card-white); border: 1px solid var(--border-soft); border-radius: 22px;
    padding: 14px 16px; box-shadow: var(--shadow-soft); display: flex; flex-direction: column; gap: 6px; min-width: 0;
  }
  .sec-card h4 { margin: 0; font-size: 0.88rem; font-weight: 500; }
  .sec-card p { margin: 0; font-size: 0.74rem; color: var(--text-secondary); }

  /* Expandable Details, Tooltips & Evidence Badges */
  .info-tip {
    display: inline-flex; align-items: center; justify-content: center;
    width: 15px; height: 15px; border-radius: 50%; margin-left: 4px;
    background: var(--surface-alt); border: 1px solid var(--border-soft);
    color: var(--text-primary); font-size: 0.64rem; font-weight: 700;
    cursor: help; vertical-align: middle;
  }
  .info-tip:focus-visible, button:focus-visible, a:focus-visible, summary:focus-visible, input:focus-visible {
    outline: 2px solid var(--frame-dark); outline-offset: 2px;
  }
  .detail-drawer {
    background: var(--card-white); border: 1px solid var(--border-soft);
    border-radius: 18px; padding: 10px 14px; box-shadow: var(--shadow-soft);
  }
  .detail-drawer summary {
    cursor: pointer; font-size: 0.8rem; font-weight: 600; color: var(--text-primary);
    display: flex; align-items: center; justify-content: space-between; gap: 8px;
  }
  .detail-grid {
    margin-top: 10px; display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 8px; font-size: 0.74rem;
  }
  .detail-chip {
    background: var(--surface-alt); border: 1px solid var(--border-soft);
    border-radius: 12px; padding: 7px 10px; display: flex; justify-content: space-between; gap: 8px;
  }
  .clickable-card { cursor: pointer; text-align: left; width: 100%; font: inherit; color: inherit; }
  .clickable-card:hover { border-color: var(--accent-olive); }
  .scope-note {
    font-size: 0.72rem; color: var(--text-secondary); background: var(--surface-alt);
    border: 1px solid var(--border-soft); border-radius: 14px; padding: 8px 12px;
  }
  .sec-meta { font-size: 0.68rem; font-family: var(--mono); color: var(--text-muted); margin-top: auto; }

  /* Bottom Floating Navigation Rail (mobile/tablet only) */
  .bottom-rail-wrap { display: flex; justify-content: center; flex-shrink: 0; padding-top: 2px; }
  @media (min-width: 769px) { .bottom-rail-wrap { display: none; } }
  .bottom-rail {
    display: inline-flex; align-items: center; gap: 5px; padding: 5px; border-radius: 999px;
    background: rgba(247, 247, 244, 0.96); border: 1px solid var(--border-soft);
    box-shadow: 0 8px 24px rgba(37, 38, 35, 0.12); max-width: 100%; overflow-x: auto;
  }
  .rail-btn {
    display: inline-flex; align-items: center; gap: 6px; padding: 6px 14px; border-radius: 999px;
    border: 0; background: transparent; color: var(--text-secondary); font-size: 0.76rem;
    font-weight: 500; cursor: pointer; white-space: nowrap;
  }
  .rail-btn:hover { color: var(--text-primary); background: var(--surface-alt); }
  .rail-btn.active { background: var(--frame-dark); color: var(--card-white); }
  .rail-btn.active .rail-dot { width: 6px; height: 6px; border-radius: 50%; background: var(--accent-lime); display: inline-block; }

  /* Tablet & Mobile */
  @media (max-width: 1120px) {
    .top-nav { flex-wrap: wrap; }
    .overview-top { grid-template-columns: 1fr; }
    .vitals-grid { grid-template-columns: repeat(3, minmax(0, 1fr)); }
    .overview-strip { grid-template-columns: repeat(3, minmax(0, 1fr)); }
    .overview-bottom { grid-template-columns: 1fr 1fr; }
    .timeline-rail { display: none; }
    .timeline-grid { grid-template-columns: repeat(3, minmax(0, 1fr)); }
  }
  @media (max-width: 768px) {
    #app { padding: 4px; }
    .app-shell { width: 100%; height: calc(100dvh - 8px); border-radius: 26px; padding: 6px; }
    .app-frame { border-radius: 22px; padding: 6px; }
    .inner-canvas { border-radius: 18px; padding: 12px 10px 10px; }
    .vitals-grid, .overview-strip, .overview-bottom, .eval-grid, .explorer-grid { grid-template-columns: 1fr; }
    .timeline-grid { grid-template-columns: 1fr; }
    .stage-col { align-items: stretch; }
    .stage-node { align-self: flex-start; }
    .stage-kicker { text-align: left; }
    .stage-stem { margin-left: 18px; height: 8px; }
  }
  @media (prefers-reduced-motion: reduce) {
    *, *::before, *::after { transition: none !important; }
  }
</style>
</head>
<body>
<div id="app">
  <div class="app-shell">
    <div class="app-frame">
      <!-- Top Dark Navigation -->
      <header class="top-nav">
        <div class="brand-group">
          <div class="emblem" aria-hidden="true">KF</div>
          <div class="brand-text">
            <span class="brand-name">KAVACH-FHIR</span>
            <span class="brand-section">Privacy Operations</span>
          </div>
        </div>

        <nav class="nav-pills" role="tablist" aria-label="Primary sections">
          <button class="nav-pill active" role="tab" aria-selected="true" data-route="overview" onclick="setRoute('overview')"><span class="dot"></span>Overview</button>
          <button class="nav-pill" role="tab" aria-selected="false" data-route="pipeline" onclick="setRoute('pipeline')"><span class="dot"></span>Pipeline</button>
          <button class="nav-pill" role="tab" aria-selected="false" data-route="files" onclick="setRoute('files')"><span class="dot"></span>Sanitized Files</button>
          <button class="nav-pill" role="tab" aria-selected="false" data-route="evaluation" onclick="setRoute('evaluation')"><span class="dot"></span>Evaluation</button>
          <button class="nav-pill" role="tab" aria-selected="false" data-route="security" onclick="setRoute('security')"><span class="dot"></span>Security</button>
        </nav>

        <div class="action-group">
          <span id="secret-pill" class="status-pill">Checking secret...</span>
          <button id="btn-run" class="btn btn-lime" onclick="triggerRun()">Run Pipeline</button>
          <button id="btn-eval" class="btn btn-ivory" onclick="triggerEval()">Run Evaluation</button>
        </div>
      </header>

      <!-- Warm Grey Inner Canvas -->
      <main class="inner-canvas">
        <div id="live-announcer" class="sr-only" aria-live="polite"></div>
        <div id="banner" class="banner" role="status"></div>

        <div class="view-host">
          <!-- VIEW 1: OVERVIEW -->
          <section id="view-overview" class="view-panel active" role="tabpanel" aria-label="Overview">
            <div class="overview-top">
              <div class="summary-card">
                <div class="summary-head">
                  <div>
                    <h1 class="page-title">Healthcare Privacy Firewall</h1>
                    <p class="page-sub">Offline clinical record anonymization</p>
                  </div>
                  <span id="pipe-pill" class="status-pill light">Ready</span>
                </div>
                <div class="marker-row">
                  <span class="marker">OFFLINE ENGINE</span>
                  <span class="marker">LLM-FREE PROCESSING</span>
                  <span class="marker">127.0.0.1 ONLY</span>
                </div>
                <div class="summary-meta">
                  <div class="meta-item"><span>Execution Status</span><strong id="pipe-msg">Ready to run</strong></div>
                  <div class="meta-item"><span>Run Scope (Input &rarr; Output)</span><strong id="ov-scope">-</strong></div>
                  <div class="meta-item"><span>Records Processed</span><strong id="ov-records">Not reported</strong></div>
                  <div class="meta-item"><span>Runtime &amp; Peak RSS</span><strong id="ov-runtime">Not reported</strong></div>
                  <div class="meta-item"><span>Last Updated</span><strong id="ov-updated">Not reported</strong></div>
                  <div class="meta-item"><span>Supported Formats</span><strong>5 (CSV, TSV, JSON, FHIR, TXT)</strong></div>
                </div>
              </div>

              <div class="vitals-grid">
                <button type="button" class="vital-card clickable-card" onclick="setRoute('pipeline')">
                  <div class="vital-icon" aria-hidden="true"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg></div>
                  <div><div class="vital-label">Total Files</div><div id="k-total" class="vital-val">Not reported</div><div class="vital-sub">Input corpus</div></div>
                </button>
                <button type="button" class="vital-card clickable-card" onclick="setRoute('files')">
                  <div class="vital-icon" aria-hidden="true"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></div>
                  <div><div class="vital-label">Sanitized</div><div id="k-sanitized" class="vital-val">Not reported</div><div class="vital-sub">Inspect sanitized/</div></div>
                </button>
                <button type="button" class="vital-card clickable-card" onclick="setRoute('pipeline')">
                  <div class="vital-icon" aria-hidden="true"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg></div>
                  <div><div class="vital-label">Quarantined</div><div id="k-quarantined" class="vital-val">Not reported</div><div class="vital-sub">0 raw copies</div></div>
                </button>
                <button type="button" class="vital-card clickable-card" onclick="setRoute('pipeline')">
                  <div class="vital-icon" aria-hidden="true"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="4" width="18" height="16" rx="2"/><line x1="7" y1="9" x2="17" y2="9"/><line x1="7" y1="13" x2="13" y2="13"/></svg></div>
                  <div><div class="vital-label">Records</div><div id="k-records" class="vital-val">Not reported</div><div class="vital-sub">Structured &amp; notes</div></div>
                </button>
                <button type="button" class="vital-card clickable-card" onclick="setRoute('evaluation')">
                  <div class="vital-icon" aria-hidden="true"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg></div>
                  <div><div class="vital-label">Linked</div><div id="k-linked" class="vital-val">Not reported</div><div id="k-unlinked" class="vital-sub">Unresolved: -</div></div>
                </button>
              </div>
            </div>

            <!-- 6-Stage Summary Strip -->
            <div class="overview-strip" aria-label="6-stage pipeline summary">
              <button class="mini-stage" onclick="setRoute('pipeline')"><span class="mini-dot">1</span><div class="mini-stage-text"><span>Ingestion</span><strong id="ms-1">Not reported</strong></div></button>
              <button class="mini-stage" onclick="setRoute('pipeline')"><span class="mini-dot">2</span><div class="mini-stage-text"><span>PII Detection</span><strong id="ms-2">Not reported</strong></div></button>
              <button class="mini-stage" onclick="setRoute('pipeline')"><span class="mini-dot">3</span><div class="mini-stage-text"><span>Linkage</span><strong id="ms-3">Not reported</strong></div></button>
              <button class="mini-stage" onclick="setRoute('evaluation')"><span class="mini-dot">4</span><div class="mini-stage-text"><span>Probe Retention</span><strong id="ms-4">Not reported</strong></div></button>
              <button class="mini-stage" onclick="setRoute('security')"><span class="mini-dot">5</span><div class="mini-stage-text"><span>Privacy</span><strong>HMAC + Shift</strong></div></button>
              <button class="mini-stage" onclick="setRoute('evaluation')"><span class="mini-dot">6</span><div class="mini-stage-text"><span>Contract</span><strong id="ms-6">Not run yet</strong></div></button>
            </div>

            <div class="overview-bottom">
              <div class="info-card white">
                <div class="card-head"><h3>Entity Detection Summary</h3><button type="button" class="fmt-pill clickable-card" style="width:auto;" onclick="setRoute('pipeline')" id="schema-pill">schema: Not reported</button></div>
                <div id="entities-bars" class="entity-bars"><div class="vital-sub">Run pipeline to populate entity counts from report.json.</div></div>
              </div>
              <div class="info-card">
                <div class="card-head"><h3>Identity Resolution Summary</h3><button type="button" class="fmt-pill clickable-card" style="width:auto;" onclick="setRoute('evaluation')">F0.5 Priority &rarr;</button></div>
                <div class="kv-grid">
                  <div class="kv-box"><span>Precision</span><strong id="ov-prec">Not reported</strong></div>
                  <div class="kv-box"><span>Recall</span><strong id="ov-rec">Not reported</strong></div>
                  <div class="kv-box"><span>F0.5 Score</span><strong id="ov-f05">Not reported</strong></div>
                  <div class="kv-box"><span>False Merges</span><strong id="ov-merges">Not reported</strong></div>
                </div>
              </div>
              <div class="info-card white">
                <div class="card-head"><h3>Probe Retention &amp; Evaluation</h3><span id="eval-pill" class="status-pill light">Not run yet</span></div>
                <div class="kv-grid">
                  <div class="kv-box"><span>Probe Retention <span class="info-tip" tabindex="0" title="Preservation Probe Retention across all truth.json preserve probes. Clinical facts stay 100%; 76 district probes are generalized to [REGION] for k-anonymity.">?</span></span><strong id="ov-med">Not reported</strong></div>
                  <div class="kv-box"><span>PII Leakage</span><strong id="ov-pii">Not reported</strong></div>
                  <div class="kv-box"><span>Canaries</span><strong id="ov-can">Not reported</strong></div>
                  <div class="kv-box"><span>Contract</span><strong id="ov-contract">Not reported</strong></div>
                </div>
              </div>
            </div>
          </section>

          <!-- VIEW 2: PIPELINE -->
          <section id="view-pipeline" class="view-panel" role="tabpanel" aria-label="Pipeline">
            <div class="pipeline-header">
              <div>
                <h2 class="page-title" style="font-size:1.2rem;">Privacy Pipeline</h2>
                <p class="page-sub">6-stage deterministic offline workflow</p>
              </div>
              <div class="marker-row">
                <span class="marker" id="pl-runtime">Runtime: Not reported</span>
                <span class="marker" id="pl-entities">Entities: Not reported</span>
                <span class="marker" id="pl-records">Records: Not reported</span>
              </div>
            </div>

            <div class="timeline-track-wrap">
              <div class="timeline-rail" aria-hidden="true"></div>
              <div class="timeline-grid">
                <div class="stage-col selected" data-stage="0">
                  <button class="stage-node" onclick="highlightStage(0)" aria-label="Input Ingestion"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg></button>
                  <span class="stage-kicker">1. Input Ingestion</span>
                  <div class="stage-stem"></div>
                  <article class="stage-card">
                    <h3 class="stage-title">Input Ingestion</h3>
                    <div id="st1-total" class="stage-stat">Not reported</div>
                    <div class="stage-list"><div>Valid: <strong id="st1-valid">-</strong> &bull; Quarantined: <strong id="st1-quar">-</strong></div></div>
                    <div class="fmt-pills"><span class="fmt-pill">CSV</span><span class="fmt-pill">TSV</span><span class="fmt-pill">JSON</span><span class="fmt-pill">FHIR</span><span class="fmt-pill">TXT</span></div>
                  </article>
                </div>

                <div class="stage-col" data-stage="1">
                  <button class="stage-node" onclick="highlightStage(1)" aria-label="PII Detection"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg></button>
                  <span class="stage-kicker">2. PII Detection</span>
                  <div class="stage-stem"></div>
                  <article class="stage-card">
                    <h3 class="stage-title">Sensitive Entity Detection</h3>
                    <div id="st2-total" class="stage-stat">Not reported</div>
                    <div id="st2-bars" class="stage-list"><span>Run pipeline to inspect entities.</span></div>
                  </article>
                </div>

                <div class="stage-col" data-stage="2">
                  <button class="stage-node" onclick="highlightStage(2)" aria-label="Patient Linkage"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="6" cy="6" r="3"/><circle cx="18" cy="18" r="3"/><path d="M8.5 8.5 15.5 15.5"/></svg></button>
                  <span class="stage-kicker">3. Patient Linkage</span>
                  <div class="stage-stem"></div>
                  <article class="stage-card">
                    <h3 class="stage-title">Identity Resolution</h3>
                    <div id="st3-pr" class="stage-stat">Not reported</div>
                    <svg width="100%" height="32" viewBox="0 0 180 32" aria-hidden="true">
                      <line x1="24" y1="16" x2="78" y2="9" stroke="#C5C849" stroke-width="1.6"/>
                      <line x1="78" y1="9" x2="146" y2="18" stroke="#777A75" stroke-width="1.4" stroke-dasharray="3 3"/>
                      <circle cx="24" cy="16" r="5" fill="#F3FE4A" stroke="#252623" stroke-width="1.5"/>
                      <circle cx="78" cy="9" r="5" fill="#F3FE4A" stroke="#252623" stroke-width="1.5"/>
                      <circle cx="146" cy="18" r="5" fill="#EFEFEB" stroke="#777A75" stroke-width="1.5"/>
                    </svg>
                    <div class="stage-list"><div>Linked: <strong id="st3-linked">-</strong> &bull; Unresolved: <strong id="st3-unres">-</strong></div><div>Conservative cross-record identity resolution</div></div>
                  </article>
                </div>

                <div class="stage-col" data-stage="3">
                  <button class="stage-node" onclick="highlightStage(3)" aria-label="Clinical Shield"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12h6"/><path d="M12 9v6"/></svg></button>
                  <span class="stage-kicker">4. Clinical Shield</span>
                  <div class="stage-stem"></div>
                  <article class="stage-card">
                    <h3 class="stage-title">Preservation Probe Retention</h3>
                    <div id="st4-med" class="stage-stat">Not reported</div>
                    <div class="fmt-pills"><span class="fmt-pill">Medicines</span><span class="fmt-pill">Dosages</span><span class="fmt-pill">Diagnoses</span><span class="fmt-pill">Labs</span><span class="fmt-pill">Vitals</span></div>
                  </article>
                </div>

                <div class="stage-col" data-stage="4">
                  <button class="stage-node" onclick="highlightStage(4)" aria-label="Privacy Transform"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg></button>
                  <span class="stage-kicker">5. Privacy Transform</span>
                  <div class="stage-stem"></div>
                  <article class="stage-card">
                    <h3 class="stage-title">Privacy Protection</h3>
                    <div class="fmt-pills"><span class="fmt-pill">Keyed pseudonyms</span><span class="fmt-pill">Date shifting</span><span class="fmt-pill">Filename protection</span></div>
                    <div class="synth-box">Before: Patient Name: Example Person<br/>After: Patient Name: [PERSON]<br/><span style="color:var(--text-secondary);">Illustrative synthetic example</span></div>
                  </article>
                </div>

                <div class="stage-col" data-stage="5">
                  <button class="stage-node" onclick="highlightStage(5)" aria-label="Output Validation"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg></button>
                  <span class="stage-kicker">6. Output Validation</span>
                  <div class="stage-stem"></div>
                  <article class="stage-card">
                    <h3 class="stage-title">Sanitized Output</h3>
                    <div id="st6-contract" class="stage-stat">Validation not yet performed</div>
                    <div class="stage-list"><div>Sanitized: <strong id="st6-san">-</strong> &bull; Raw copies: <strong id="st6-raw">-</strong></div></div>
                  </article>
                </div>
              </div>
            </div>

            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,320px),1fr));gap:10px;">
              <details class="detail-drawer" id="pl-entities-details">
                <summary><span>All Detected PII Entity Categories</span><span class="fmt-pill" id="pl-ent-count">0 categories</span></summary>
                <div id="pl-all-entities" class="detail-grid"><div class="vital-sub">Run pipeline to inspect full entity breakdown.</div></div>
              </details>
              <details class="detail-drawer" id="pl-quarantine-details">
                <summary><span>Quarantine Report (Safe Metadata Only)</span><span class="fmt-pill" id="pl-quar-count">0 quarantined</span></summary>
                <div id="pl-quarantine-list" class="detail-grid"><div class="vital-sub">No quarantined files recorded.</div></div>
              </details>
            </div>
            <div class="scope-note" id="pl-timing-note">Total pipeline runtime is read from report.json (per-stage sub-timings are not instrumented in raksha-report/1).</div>
          </section>

          <!-- VIEW 3: SANITIZED FILES -->
          <section id="view-files" class="view-panel" role="tabpanel" aria-label="Sanitized Files">
            <div class="explorer-grid">
              <div class="explorer-card">
                <div class="card-head" style="margin-bottom:0;">
                  <h3>Sanitized Files</h3>
                  <span id="file-count" class="status-pill light">0 files</span>
                </div>
                <input id="file-search" class="search-input" type="text" placeholder="Search sanitized files..." aria-label="Search sanitized files" oninput="renderFileList()" />
                <div class="filter-row" role="group" aria-label="Filter by format">
                  <button class="filter-chip active" onclick="setFmtFilter('all', this)">All</button>
                  <button class="filter-chip" onclick="setFmtFilter('.txt', this)">TXT</button>
                  <button class="filter-chip" onclick="setFmtFilter('.csv', this)">CSV</button>
                  <button class="filter-chip" onclick="setFmtFilter('.tsv', this)">TSV</button>
                  <button class="filter-chip" onclick="setFmtFilter('.json', this)">JSON</button>
                </div>
                <div class="filter-row" id="folder-filters" role="group" aria-label="Filter by folder"></div>
                <div id="file-list" class="file-list"></div>
              </div>

              <div class="explorer-card white">
                <div class="card-head" style="margin-bottom:0;">
                  <div style="min-width:0;">
                    <h3 id="prev-title">Select a sanitized file</h3>
                    <div id="prev-meta" class="vital-sub">Only files strictly inside sanitized/ are accessible.</div>
                  </div>
                  <div style="display:flex;gap:8px;align-items:center;flex-shrink:0;">
                    <button id="btn-copy" class="btn btn-ivory" style="padding:5px 11px;font-size:0.74rem;" disabled onclick="copyPreview()">Copy Sanitized</button>
                    <span class="status-pill light ok">SANITIZED OUTPUT</span>
                  </div>
                </div>
                <div id="preview-body" class="preview-box">
                  <div class="vital-sub">Choose any file on the left to inspect its sanitized content.</div>
                </div>
              </div>
            </div>
          </section>

          <!-- VIEW 4: EVALUATION -->
          <section id="view-evaluation" class="view-panel" role="tabpanel" aria-label="Evaluation">
            <div class="pipeline-header">
              <div>
                <h2 class="page-title" style="font-size:1.2rem;">Official Practice Evaluation &amp; Contract Check</h2>
                <p id="eval-state-text" class="page-sub">Not run yet</p>
              </div>
              <div class="marker-row" style="align-items:center;">
                <span id="chk-pipe" class="marker">1. Pipeline: Not run yet</span>
                <span id="chk-eval" class="marker">2. Practice Eval (check_dev.py): Not run yet</span>
                <span id="chk-val" class="marker">3. Output Contract (validate_output.py): Not reported</span>
                <span class="marker">4. Full Submission Check (check_submission.py): CLI ONLY</span>
              </div>
            </div>

            <div class="eval-grid">
              <div class="eval-card highlight"><span>PII Leakage <span class="info-tip" tabindex="0" title="Visible ground-truth PII items in sanitized output (check_dev.py denominator: 3,230 practice PII probes).">?</span></span><strong id="ev-pii">Not reported</strong></div>
              <div class="eval-card"><span>Canary Leakage <span class="info-tip" tabindex="0" title="Synthetic high-risk canary strings detected in sanitized output (practice corpus: 4 canaries).">?</span></span><strong id="ev-can">Not reported</strong></div>
              <div class="eval-card highlight"><span>Preservation Probe Retention <span class="info-tip" tabindex="0" title="All truth.json preserve probes (total 4,855). Clinical categories remain 100%; generalized demographic probes (e.g. 76 district probes -> [REGION]) reflect intentional k-anonymity protection.">?</span></span><strong id="ev-med">Not reported</strong></div>
              <div class="eval-card"><span>Linkage Precision <span class="info-tip" tabindex="0" title="Fraction of predicted patient record links that are true matches (F0.5 prioritizes precision over recall).">?</span></span><strong id="ev-prec">Not reported</strong></div>
              <div class="eval-card"><span>Linkage Recall <span class="info-tip" tabindex="0" title="Fraction of true patient links successfully recovered across formats.">?</span></span><strong id="ev-rec">Not reported</strong></div>
              <div class="eval-card"><span>F0.5 Score <span class="info-tip" tabindex="0" title="Weighted linkage score emphasizing precision twice as much as recall.">?</span></span><strong id="ev-f05">Not reported</strong></div>
              <div class="eval-card"><span>False Merges</span><strong id="ev-merges">Not reported</strong></div>
              <div class="eval-card"><span>Raw Copies</span><strong id="ev-raw">Not reported</strong></div>
              <div class="eval-card highlight"><span>Contract Validation</span><strong id="ev-contract">Not reported</strong></div>
            </div>

            <details class="detail-drawer" id="eval-probe-details">
              <summary><span>Preservation Probe Retention Breakdown (Clinical Facts vs. Quasi-Identifier Generalization)</span><span class="fmt-pill" id="ev-probe-summary">Run evaluation to compute</span></summary>
              <div id="eval-probe-breakdown" class="detail-grid"><div class="vital-sub">Run official practice evaluation to separate 100% clinical retention from intentional demographic generalization.</div></div>
            </details>
            <div class="scope-note">Practice dataset scores reflect local dev/truth.json only and are distinct from hidden evaluation. Run <code>check_submission.py --repo . --run</code> in CLI for full submission verification.</div>
          </section>

          <!-- VIEW 5: SECURITY -->
          <section id="view-security" class="view-panel" role="tabpanel" aria-label="Security">
            <div class="pipeline-header">
              <div>
                <h2 class="page-title" style="font-size:1.2rem;">Security &amp; Cryptographic Controls</h2>
                <p class="page-sub">Distinguishing Browser Dashboard boundaries from CLI Pipeline execution controls</p>
              </div>
              <span id="sec-secret-chip" class="status-pill light">RAKSHA_SECRET: Checking</span>
            </div>

            <div class="security-grid">
              <div class="sec-card"><h4>Localhost-Only Binding (Dashboard)</h4><span class="status-pill light ok" style="align-self:flex-start;">Verified</span><p>Server binds strictly to 127.0.0.1 with Host/Origin validation and per-session CSRF token.</p><div class="sec-meta">Evidence: tests/test_dashboard.py (bind + CSRF/Host/Origin)</div></div>
              <div class="sec-card"><h4>Offline Execution (Dashboard &amp; CLI)</h4><span class="status-pill light ok" style="align-self:flex-start;">Verified</span><p>Zero external CDNs, fonts, analytics, or outbound HTTP requests; strict CSP enforced.</p><div class="sec-meta">Evidence: tests/test_dashboard.py (AST + HTML scan)</div></div>
              <div class="sec-card"><h4>Path Traversal Containment (Dashboard)</h4><span class="status-pill light ok" style="align-self:flex-start;">Verified</span><p>Preview endpoint enforces realpath containment strictly inside sanitized/.</p><div class="sec-meta">Evidence: tests/test_dashboard.py (preview traversal)</div></div>
              <div class="sec-card"><h4>LLM-Free CPU Pipeline (CLI)</h4><span class="status-pill light ok" style="align-self:flex-start;">Verified</span><p>Deterministic CPU-only regex/lexicon/linker pipeline with zero hosted or generative models.</p><div class="sec-meta">Evidence: engine/ &amp; detectors/ static imports</div></div>
              <div class="sec-card"><h4>Fail-Closed Secret Handling (CLI &amp; UI)</h4><span id="sec-failclosed-badge" class="status-pill light ok" style="align-self:flex-start;">Verified</span><p>Missing, empty, or whitespace-only RAKSHA_SECRET blocks execution before creating output.</p><div class="sec-meta">Evidence: tests/test_security.py + dashboard /api/run</div></div>
              <div class="sec-card"><h4>Input Immutability (CLI)</h4><span class="status-pill light ok" style="align-self:flex-start;">Verified</span><p>Source files are read-only; no raw input or secret is written to browser or logs.</p><div class="sec-meta">Evidence: tests/test_security.py + tests/test_dashboard.py</div></div>
              <div class="sec-card"><h4>Quarantine Isolation (CLI)</h4><span id="sec-quar-badge" class="status-pill light" style="align-self:flex-start;">Not verified yet</span><p>Malformed inputs are quarantined and never copied raw into sanitized/.</p><div id="sec-quar-meta" class="sec-meta">Evidence: Run evaluation (check_dev.py RAW COPIES)</div></div>
              <div class="sec-card"><h4>Deterministic Repeat-Run (CLI ONLY)</h4><span class="status-pill light" style="align-self:flex-start;">CLI only</span><p>Repeat-run byte determinism and READY TO SUBMIT must be verified from the terminal.</p><div class="sec-meta">Evidence: python ../Secret-Wards-ToolKit-LF/check_submission.py --repo . --run</div></div>
            </div>
          </section>
        </div>

        <!-- Floating Bottom Navigation Rail -->
        <div class="bottom-rail-wrap">
          <nav class="bottom-rail" aria-label="Quick section navigation">
            <button class="rail-btn active" data-route="overview" onclick="setRoute('overview')"><span class="rail-dot"></span>Overview</button>
            <button class="rail-btn" data-route="pipeline" onclick="setRoute('pipeline')"><span class="rail-dot"></span>Pipeline</button>
            <button class="rail-btn" data-route="files" onclick="setRoute('files')"><span class="rail-dot"></span>Files</button>
            <button class="rail-btn" data-route="evaluation" onclick="setRoute('evaluation')"><span class="rail-dot"></span>Evaluation</button>
            <button class="rail-btn" data-route="security" onclick="setRoute('security')"><span class="rail-dot"></span>Security</button>
          </nav>
        </div>
      </main>
    </div>
  </div>
</div>

<script>
const ROUTES = ['overview', 'pipeline', 'files', 'evaluation', 'security'];
let allFiles = [];
let activeFile = null;
let fmtFilter = 'all';
let folderFilter = 'all';
let pollTimer = null;
let lastPreviewText = '';
let lastSnapshot = null;
let lastExecState = 'idle';

function esc(s) {
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

function announce(msg) {
  document.getElementById('live-announcer').textContent = msg;
}

function showBanner(msg, kind) {
  const el = document.getElementById('banner');
  el.textContent = msg;
  el.className = 'banner show ' + (kind || 'info');
}

function hideBanner() {
  document.getElementById('banner').className = 'banner';
}

function resolveHashRoute() {
  const raw = (window.location.hash || '').replace(/^#/, '').toLowerCase();
  return ROUTES.includes(raw) ? raw : 'overview';
}

function applyRoute(route) {
  const activeRoute = ROUTES.includes(route) ? route : 'overview';
  ROUTES.forEach(r => {
    const panel = document.getElementById('view-' + r);
    if (panel) panel.classList.toggle('active', r === activeRoute);
  });
  document.querySelectorAll('.nav-pill, .rail-btn').forEach(btn => {
    const isSel = btn.getAttribute('data-route') === activeRoute;
    btn.classList.toggle('active', isSel);
    if (btn.hasAttribute('aria-selected')) btn.setAttribute('aria-selected', isSel ? 'true' : 'false');
  });
  announce('Switched to ' + activeRoute + ' view');
}

function setRoute(route) {
  const target = ROUTES.includes(route) ? route : 'overview';
  if (window.location.hash !== '#' + target) {
    window.location.hash = '#' + target;
  } else {
    applyRoute(target);
  }
}

window.addEventListener('hashchange', () => applyRoute(resolveHashRoute()));

document.querySelectorAll('.nav-pills, .bottom-rail').forEach(nav => {
  nav.addEventListener('keydown', e => {
    if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
    const btns = Array.from(nav.querySelectorAll('button[data-route]'));
    const idx = btns.indexOf(document.activeElement);
    if (idx === -1) return;
    e.preventDefault();
    const next = btns[(idx + (e.key === 'ArrowRight' ? 1 : -1) + btns.length) % btns.length];
    next.focus();
    setRoute(next.getAttribute('data-route'));
  });
});

function highlightStage(idx) {
  document.querySelectorAll('.stage-col').forEach(col => {
    col.classList.toggle('selected', Number(col.getAttribute('data-stage')) === idx);
  });
}

function setFmtFilter(fmt, btn) {
  fmtFilter = fmt;
  document.querySelectorAll('.filter-row[aria-label="Filter by format"] .filter-chip').forEach(c => c.classList.remove('active'));
  btn.classList.add('active');
  renderFileList();
}

function setFolderFilter(folder, btn) {
  folderFilter = folder;
  document.querySelectorAll('#folder-filters .filter-chip').forEach(c => c.classList.remove('active'));
  btn.classList.add('active');
  renderFileList();
}

async function refreshStatus() {
  try {
    const res = await fetch('/api/status');
    const st = await res.json();
    lastSnapshot = st;

    const secPill = document.getElementById('secret-pill');
    const secChip = document.getElementById('sec-secret-chip');
    const failClosedBadge = document.getElementById('sec-failclosed-badge');
    if (st.secret_configured) {
      secPill.textContent = 'RAKSHA_SECRET: Configured';
      secPill.className = 'status-pill ok';
      secChip.textContent = 'RAKSHA_SECRET: Configured (hidden)';
      secChip.className = 'status-pill light ok';
      failClosedBadge.textContent = 'Verified';
      failClosedBadge.className = 'status-pill light ok';
    } else {
      secPill.textContent = 'RAKSHA_SECRET: Missing';
      secPill.className = 'status-pill bad';
      secChip.textContent = 'RAKSHA_SECRET: Missing';
      secChip.className = 'status-pill light bad';
      failClosedBadge.textContent = 'Failed (missing secret)';
      failClosedBadge.className = 'status-pill light bad';
      showBanner('RAKSHA_SECRET is not set in the server environment. Pipeline execution fails closed.', 'bad');
    }

    const p = st.pipeline;
    const e = st.evaluation;
    const execState = st.execution_state || 'idle';
    const pipeLabel = p.status === 'idle' ? 'Ready'
      : p.status === 'running' ? 'Processing'
      : p.status === 'succeeded' ? 'Succeeded (exit 0)'
      : 'Failed — inspect local terminal';
    const pipePill = document.getElementById('pipe-pill');
    pipePill.textContent = pipeLabel;
    pipePill.className = 'status-pill light ' + (p.status === 'succeeded' ? 'ok' : p.status === 'failed' ? 'bad' : p.status === 'running' ? 'lime' : '');
    document.getElementById('pipe-msg').textContent = p.status === 'failed' ? 'Failed — inspect local terminal' : p.message;

    const evalPill = document.getElementById('eval-pill');
    const evalLabel = e.status === 'idle' ? 'Not run yet'
      : e.status === 'running' ? 'Running'
      : e.status === 'completed' ? 'Completed'
      : 'Failed — inspect local terminal';
    evalPill.textContent = evalLabel;
    evalPill.className = 'status-pill light ' + (e.status === 'completed' ? 'ok' : e.status === 'failed' ? 'bad' : e.status === 'running' ? 'lime' : '');
    document.getElementById('eval-state-text').textContent =
      e.status === 'failed' ? (st.last_error || 'Failed — inspect local terminal')
      : (st.eval_timestamp ? `${e.message} (${st.eval_timestamp})` : e.message);

    document.getElementById('chk-pipe').textContent = '1. Pipeline: ' + pipeLabel;
    document.getElementById('chk-eval').textContent = '2. Practice Eval (check_dev.py): ' + evalLabel;
    document.getElementById('chk-val').textContent = '3. Output Contract (validate_output.py): ' + e.contract_status;

    const busy = execState === 'pipeline_running' || execState === 'evaluation_running';
    const btnRun = document.getElementById('btn-run');
    const btnEval = document.getElementById('btn-eval');
    btnRun.disabled = busy || !st.secret_configured;
    btnEval.disabled = busy || !e.toolkit_available || st.sanitized_file_count === 0;
    btnRun.textContent = execState === 'pipeline_running' ? 'Running Pipeline...' : 'Run Pipeline';
    btnEval.textContent = execState === 'evaluation_running' ? 'Evaluating...' : 'Run Official Evaluation';

    if (st.secret_configured) {
      if (execState === 'pipeline_running') {
        showBanner('Processing privacy pipeline locally...', 'info');
      } else if (execState === 'evaluation_running') {
        showBanner('Running official practice evaluator and contract validator...', 'info');
      } else if (execState === 'failed') {
        showBanner(st.last_error || 'Execution failed — inspect local terminal.', 'bad');
      } else if (execState === 'completed') {
        if (lastExecState === 'pipeline_running' || lastExecState === 'evaluation_running') {
          showBanner('Completed — ' + (e.status === 'completed' ? e.message : p.message), 'ok');
        } else {
          const cur = document.getElementById('banner');
          if (cur.classList.contains('info') && cur.textContent.includes('Processing')) {
            showBanner('Completed — ' + (e.status === 'completed' ? e.message : p.message), 'ok');
          }
        }
      }
    }
    lastExecState = execState;

    document.getElementById('ov-scope').textContent = `${st.input_label || 'input'} -> ${st.output_label || 'output'}`;
    const r = st.report;
    if (r.available) {
      document.getElementById('k-total').textContent = r.files_total;
      document.getElementById('k-sanitized').textContent = r.files_sanitized;
      document.getElementById('k-quarantined').textContent = r.files_quarantined;
      document.getElementById('k-records').textContent = r.records_processed;
      document.getElementById('k-linked').textContent = r.records_linked;
      const unres = (typeof r.records_processed === 'number' && typeof r.records_linked === 'number')
        ? (r.records_processed - r.records_linked) : '-';
      document.getElementById('k-unlinked').textContent = 'Unresolved: ' + unres;
      document.getElementById('ov-records').textContent = r.records_processed;
      const rssText = (typeof r.peak_rss_mb === 'number' && r.peak_rss_mb > 0) ? ` / ${r.peak_rss_mb} MB RSS` : '';
      document.getElementById('ov-runtime').textContent = r.timing_seconds + 's' + rssText;
      document.getElementById('ov-updated').textContent = r.last_updated || 'Not reported';
      document.getElementById('schema-pill').textContent = 'schema: ' + r.schema + ' ->';

      document.getElementById('ms-1').textContent = r.files_sanitized + '/' + r.files_total + ' valid';
      document.getElementById('ms-2').textContent = r.identifiers_detected + ' entities';
      document.getElementById('ms-3').textContent = r.records_linked + ' linked';
      document.getElementById('pl-runtime').textContent = 'Runtime: ' + r.timing_seconds + 's';
      document.getElementById('pl-entities').textContent = 'Entities: ' + r.identifiers_detected;
      document.getElementById('pl-records').textContent = 'Records: ' + r.records_processed;

      document.getElementById('st1-total').textContent = r.files_total + ' files';
      document.getElementById('st1-valid').textContent = r.files_sanitized;
      document.getElementById('st1-quar').textContent = r.files_quarantined;
      document.getElementById('st2-total').textContent = r.identifiers_detected + ' entities';
      document.getElementById('st3-linked').textContent = r.records_linked;
      document.getElementById('st3-unres').textContent = unres;
      document.getElementById('st6-san').textContent = r.files_sanitized;

      const entries = Object.entries(r.entities || {}).sort((a, b) => b[1] - a[1]);
      const maxVal = entries.length ? entries[0][1] : 1;
      document.getElementById('st2-bars').innerHTML = entries.slice(0, 4).map(([k, v]) =>
        `<div style="display:flex;justify-content:space-between;gap:6px;"><span>${esc(k)}</span><span>${esc(v)}</span></div>`
      ).join('') || '<span>No entities recorded.</span>';
      document.getElementById('entities-bars').innerHTML = entries.slice(0, 8).map(([k, v]) => {
        const pct = Math.max(4, Math.round((v / maxVal) * 100));
        return `<div class="entity-row"><span class="entity-name">${esc(k)}</span><div class="mini-bar-track"><div class="mini-bar-fill" style="width:${pct}%"></div></div><span class="entity-count">${esc(v)}</span></div>`;
      }).join('') || '<div class="vital-sub">No entities recorded.</div>';

      document.getElementById('pl-ent-count').textContent = `${entries.length} categories`;
      document.getElementById('pl-all-entities').innerHTML = entries.map(([k, v]) =>
        `<div class="detail-chip"><span>${esc(k)}</span><strong>${esc(v)}</strong></div>`
      ).join('') || '<div class="vital-sub">No entities recorded.</div>';

      const qList = r.quarantined_files || [];
      document.getElementById('pl-quar-count').textContent = `${qList.length} quarantined`;
      document.getElementById('pl-quarantine-list').innerHTML = qList.map(q =>
        `<div class="detail-chip"><span>${esc(q.id)} (${esc(q.reason)})</span><strong>raw_copy_prevented: ${esc(q.raw_copy_prevented)}</strong></div>`
      ).join('') || '<div class="vital-sub">No quarantined files recorded.</div>';
    }

    const m = e.metrics;
    const prText = (m.linkage_precision !== 'Not reported') ? `${m.linkage_precision} / ${m.linkage_recall}` : 'Not reported';
    document.getElementById('st3-pr').textContent = prText;
    document.getElementById('st4-med').textContent = m.clinical_preservation;
    document.getElementById('st6-contract').textContent = e.status === 'idle' ? 'Validation not yet performed' : e.contract_status;
    document.getElementById('st6-raw').textContent = m.raw_copies;

    document.getElementById('ms-4').textContent = m.clinical_preservation === 'Not reported' ? 'Not run yet' : m.clinical_preservation.split(' ')[0];
    document.getElementById('ms-6').textContent = e.contract_status === 'Not reported' ? 'Not run yet' : e.contract_status;

    document.getElementById('ov-prec').textContent = m.linkage_precision;
    document.getElementById('ov-rec').textContent = m.linkage_recall;
    document.getElementById('ov-f05').textContent = m.linkage_f05;
    document.getElementById('ov-merges').textContent = m.false_merges;
    document.getElementById('ov-med').textContent = m.clinical_preservation;
    document.getElementById('ov-pii').textContent = m.pii_leakage;
    document.getElementById('ov-can').textContent = m.canaries;
    document.getElementById('ov-contract').textContent = e.contract_status;

    document.getElementById('ev-pii').textContent = m.pii_leakage;
    document.getElementById('ev-can').textContent = m.canaries;
    document.getElementById('ev-med').textContent = m.clinical_preservation;
    document.getElementById('ev-prec').textContent = m.linkage_precision;
    document.getElementById('ev-rec').textContent = m.linkage_recall;
    document.getElementById('ev-f05').textContent = m.linkage_f05;
    document.getElementById('ev-merges').textContent = m.false_merges;
    document.getElementById('ev-raw').textContent = m.raw_copies;
    document.getElementById('ev-contract').textContent = e.contract_status;

    const quarBadge = document.getElementById('sec-quar-badge');
    const quarMeta = document.getElementById('sec-quar-meta');
    if (m.raw_copies === '0') {
      quarBadge.textContent = 'Verified (0 raw copies)';
      quarBadge.className = 'status-pill light ok';
      quarMeta.textContent = 'Evidence: check_dev.py RAW COPIES: 0';
    } else if (m.raw_copies !== 'Not reported') {
      quarBadge.textContent = `Failed (${m.raw_copies} raw copies)`;
      quarBadge.className = 'status-pill light bad';
      quarMeta.textContent = 'Evidence: check_dev.py RAW COPIES';
    }

    const pb = st.probe_breakdown;
    if (pb && Array.isArray(pb.categories)) {
      document.getElementById('ev-probe-summary').textContent =
        `${pb.retained} / ${pb.total} (${pb.pct}%) — ${pb.lost} generalized`;
      document.getElementById('eval-probe-breakdown').innerHTML = pb.categories.map(c =>
        `<div class="detail-chip"><span>${esc(c.kind)} (${esc(c.group)})</span><strong>${esc(c.retained)}/${esc(c.total)} (${esc(c.pct)}%)${c.lost ? ` • ${esc(c.lost)} generalized` : ''}</strong></div>`
      ).join('');
    }

    if (busy && !pollTimer) {
      pollTimer = setInterval(async () => { await refreshStatus(); await refreshFiles(); }, 900);
    } else if (!busy && pollTimer) {
      clearInterval(pollTimer);
      pollTimer = null;
    }
  } catch (err) {
    showBanner('Unable to reach local dashboard backend.', 'bad');
  }
}

async function refreshFiles() {
  const res = await fetch('/api/files');
  const data = await res.json();
  allFiles = data.files || [];
  document.getElementById('file-count').textContent = `${allFiles.length} files`;
  const folders = Array.from(new Set(allFiles.map(f => f.includes('/') ? f.split('/')[0] : '.'))).sort();
  const folderEl = document.getElementById('folder-filters');
  folderEl.innerHTML =
    `<button class="filter-chip ${folderFilter === 'all' ? 'active' : ''}" data-folder="all">All folders</button>` +
    folders.slice(0, 6).map(fd =>
      `<button class="filter-chip ${folderFilter === fd ? 'active' : ''}" data-folder="${esc(fd)}">${esc(fd)}</button>`
    ).join('');
  renderFileList();
}

function renderFileList() {
  const q = document.getElementById('file-search').value.trim().toLowerCase();
  const shown = allFiles.filter(f => {
    const okFmt = fmtFilter === 'all' || f.toLowerCase().endsWith(fmtFilter);
    const fd = f.includes('/') ? f.split('/')[0] : '.';
    const okFolder = folderFilter === 'all' || fd === folderFilter;
    const okQ = !q || f.toLowerCase().includes(q);
    return okFmt && okFolder && okQ;
  });
  document.getElementById('file-list').innerHTML = shown.map(f =>
    `<button class="file-btn ${f === activeFile ? 'active' : ''}" data-path="${esc(f)}">${esc(f)}</button>`
  ).join('') || '<div class="vital-sub">No matching sanitized files.</div>';
}

document.getElementById('folder-filters').addEventListener('click', e => {
  const btn = e.target.closest('button[data-folder]');
  if (btn) setFolderFilter(btn.getAttribute('data-folder'), btn);
});

document.getElementById('file-list').addEventListener('click', e => {
  const btn = e.target.closest('button[data-path]');
  if (btn) loadPreview(btn.getAttribute('data-path'));
});

async function loadPreview(relPath) {
  activeFile = relPath;
  renderFileList();
  const res = await fetch('/api/preview?path=' + encodeURIComponent(relPath));
  if (!res.ok) {
    lastPreviewText = '';
    document.getElementById('btn-copy').disabled = true;
    document.getElementById('preview-body').innerHTML = '<div class="vital-sub">Unable to load sanitized file preview.</div>';
    return;
  }
  const d = await res.json();
  lastPreviewText = d.pretty_json || d.text || '';
  document.getElementById('btn-copy').disabled = !lastPreviewText;
  document.getElementById('prev-title').textContent = d.path;
  document.getElementById('prev-meta').textContent =
    `${d.label} • ${d.format.toUpperCase()} • ${d.size_bytes} bytes` + (d.truncated ? ' (truncated to 200 KB)' : '');
  const body = document.getElementById('preview-body');
  if (d.table_rows && d.table_rows.length) {
    const hdr = d.table_rows[0];
    const rows = d.table_rows.slice(1);
    let tbl = '<table><thead><tr>' + hdr.map(c => `<th>${esc(c)}</th>`).join('') + '</tr></thead><tbody>';
    for (const r of rows) {
      tbl += '<tr>' + r.map(c => `<td>${esc(c)}</td>`).join('') + '</tr>';
    }
    tbl += '</tbody></table>';
    body.innerHTML = tbl;
  } else if (d.pretty_json) {
    body.innerHTML = `<pre>${esc(d.pretty_json)}</pre>`;
  } else {
    body.innerHTML = `<pre>${esc(d.text)}</pre>`;
  }
}

async function copyPreview() {
  if (!lastPreviewText || !navigator.clipboard) return;
  await navigator.clipboard.writeText(lastPreviewText);
  announce('Copied sanitized preview text');
  showBanner('Copied sanitized preview content to clipboard.', 'info');
}

function getCsrfToken() {
  const el = document.querySelector('meta[name="kavach-csrf"]');
  return el ? el.getAttribute('content') || '' : '';
}

async function triggerRun() {
  if (lastSnapshot && lastSnapshot.sanitized_file_count > 0) {
    const ok = window.confirm(
      `Sanitized output already exists (${lastSnapshot.sanitized_file_count} files). Re-running will overwrite the current output directory. Continue?`
    );
    if (!ok) return;
  }
  hideBanner();
  const res = await fetch('/api/run', {
    method: 'POST',
    headers: { 'X-Kavach-CSRF': getCsrfToken() },
  });
  const d = await res.json();
  if (!res.ok) showBanner(d.error || 'Failed to start pipeline.', 'bad');
  else showBanner('Processing privacy pipeline locally...', 'info');
  announce('Pipeline execution started');
  await refreshStatus();
  await refreshFiles();
}

async function triggerEval() {
  hideBanner();
  const res = await fetch('/api/evaluate', {
    method: 'POST',
    headers: { 'X-Kavach-CSRF': getCsrfToken() },
  });
  const d = await res.json();
  if (!res.ok) showBanner(d.error || 'Failed to start evaluation.', 'bad');
  else showBanner('Running official practice evaluator and contract validator...', 'info');
  announce('Evaluation started');
  await refreshStatus();
}

applyRoute(resolveHashRoute());
refreshStatus();
refreshFiles();
</script>
</body>
</html>
"""


def make_handler(state: DashboardState) -> type[BaseHTTPRequestHandler]:
    class DashboardHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            # Suppress default HTTP access logging to keep logs free of paths/noise.
            return

        def _send_json(self, status: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _is_valid_host(self) -> bool:
            host_hdr = self.headers.get("Host", "").strip()
            if not host_hdr:
                return True
            parsed_host = urlparse(f"http://{host_hdr}")
            return parsed_host.hostname in ("127.0.0.1", "localhost")

        def _is_valid_origin(self) -> bool:
            port = self.server.server_port
            for hdr in ("Origin", "Referer"):
                val = self.headers.get(hdr)
                if not val:
                    continue
                p = urlparse(val)
                if p.scheme != "http" or p.hostname not in ("127.0.0.1", "localhost"):
                    return False
                if p.port is not None and p.port != port:
                    return False
            return True

        def _send_html(self, html_text: str) -> None:
            body = html_text.replace("__KAVACH_CSRF__", state.csrf_token).encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:;",
            )
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            if not self._is_valid_host():
                self._send_json(HTTPStatus.FORBIDDEN, {"error": "Invalid Host header."})
                return
            parsed = urlparse(self.path)
            if parsed.path == "/":
                self._send_html(_DASHBOARD_HTML)
                return
            if parsed.path == "/api/status":
                self._send_json(HTTPStatus.OK, state.snapshot())
                return
            if parsed.path == "/api/files":
                self._send_json(HTTPStatus.OK, {"files": list_sanitized_files(state.sanitized_dir)})
                return
            if parsed.path == "/api/preview":
                qs = parse_qs(parsed.query)
                rel = (qs.get("path") or [""])[0]
                preview = read_sanitized_preview(state.sanitized_dir, rel)
                if preview is None:
                    self._send_json(HTTPStatus.FORBIDDEN, {"error": "Invalid or disallowed sanitized file path."})
                    return
                self._send_json(HTTPStatus.OK, preview)
                return
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "Not found."})

        def do_POST(self) -> None:
            if not self._is_valid_host() or not self._is_valid_origin():
                self._send_json(HTTPStatus.FORBIDDEN, {"error": "Forbidden Host or Origin."})
                return
            csrf_hdr = self.headers.get("X-Kavach-CSRF", "")
            if not csrf_hdr or not hmac.compare_digest(csrf_hdr, state.csrf_token):
                self._send_json(HTTPStatus.FORBIDDEN, {"error": "Missing or invalid CSRF token."})
                return
            parsed = urlparse(self.path)
            if parsed.path == "/api/run":
                ok, msg = state.start_pipeline()
                self._send_json(HTTPStatus.ACCEPTED if ok else HTTPStatus.BAD_REQUEST, {"ok": ok, "error": None if ok else msg})
                return
            if parsed.path == "/api/evaluate":
                ok, msg = state.start_evaluation()
                self._send_json(HTTPStatus.ACCEPTED if ok else HTTPStatus.BAD_REQUEST, {"ok": ok, "error": None if ok else msg})
                return
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "Not found."})

    return DashboardHandler


def create_server(
    input_dir: Path,
    output_dir: Path,
    port: int = 8765,
    toolkit_dir: Path | None = None,
    allow_existing: bool = False,
) -> tuple[ThreadingHTTPServer, DashboardState]:
    """Validate paths and bind the dashboard server strictly on 127.0.0.1."""
    if not input_dir.is_dir():
        raise ValueError(f"Input directory does not exist: {input_dir}")
    if output_dir.exists() and any(output_dir.iterdir()) and not allow_existing:
        raise ValueError(
            "Output directory already exists and is non-empty. Pass a new --output path or --allow-existing."
        )
    state = DashboardState(input_dir=input_dir, output_dir=output_dir, toolkit_dir=toolkit_dir)
    server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(state))
    return server, state


def main() -> int:
    ap = argparse.ArgumentParser(description="KAVACH-FHIR Local Browser Dashboard (127.0.0.1 only)")
    ap.add_argument("--input", required=True, help="Input directory")
    ap.add_argument("--output", required=True, help="Output directory")
    ap.add_argument("--port", type=int, default=8765, help="Local port on 127.0.0.1 (default: 8765)")
    ap.add_argument("--toolkit", default=str(_DEFAULT_TOOLKIT), help="Path to Secret-Wards toolkit (optional)")
    ap.add_argument("--allow-existing", action="store_true", help="Allow inspecting/re-running an existing output dir")
    args = ap.parse_args()

    inp = Path(args.input.strip("'\""))
    out = Path(args.output.strip("'\""))
    tk = Path(args.toolkit.strip("'\"")) if args.toolkit else None
    if tk and not tk.is_dir():
        tk = None

    try:
        server, _ = create_server(inp, out, port=args.port, toolkit_dir=tk, allow_existing=args.allow_existing)
    except (ValueError, OSError) as exc:
        print(f"Error: {html.escape(str(exc))}", file=sys.stderr)
        return 1

    print(f"KAVACH-FHIR dashboard listening at http://127.0.0.1:{server.server_port}/ (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
