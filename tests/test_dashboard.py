"""Tests for KAVACH-FHIR local browser dashboard (security, offline, parsing, and preview)."""
from __future__ import annotations

import ast
import json
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

import dashboard
from dashboard import (
    _DASHBOARD_HTML,
    create_server,
    parse_check_dev_output,
    parse_report_json,
    parse_validate_output,
)


def _http_json(url: str, method: str = "GET", headers: dict[str, str] | None = None) -> tuple[int, dict]:
    req = urllib.request.Request(url, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as err:
        return err.code, json.loads(err.read().decode("utf-8"))


def _fetch_csrf(base: str) -> str:
    with urllib.request.urlopen(f"{base}/", timeout=5) as resp:
        body = resp.read().decode("utf-8")
    import re as _re
    m = _re.search(r'<meta name="kavach-csrf" content="([^"]+)"', body)
    assert m is not None
    return m.group(1)


def test_dashboard_no_external_network_or_api_keys():
    # No external URLs or API-key inputs in dashboard HTML
    assert "https://" not in _DASHBOARD_HTML
    assert "http://" not in _DASHBOARD_HTML
    for forbidden in ("openai", "anthropic", "gemini", "api_key", "apikey", "googleapis"):
        assert forbidden not in _DASHBOARD_HTML.lower()

    # dashboard.py uses stdlib http.server only, no requests/httpx/urllib client
    tree = ast.parse(Path(dashboard.__file__).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(n.name.split(".")[0] for n in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert imported.isdisjoint({"requests", "httpx", "aiohttp", "socket"})


def test_startup_without_api_key_binds_localhost_and_blocks_overwrite(tmp_path: Path):
    inp = tmp_path / "in"
    inp.mkdir()
    (inp / "note.txt").write_text("C/O: fever\n", encoding="utf-8")
    out = tmp_path / "out"

    srv, _ = create_server(inp, out, port=0)
    try:
        assert srv.server_address[0] == "127.0.0.1"
    finally:
        srv.server_close()

    # Non-empty output dir rejected unless allow_existing=True
    out.mkdir()
    (out / "existing.txt").write_text("keep", encoding="utf-8")
    with pytest.raises(ValueError, match="already exists"):
        create_server(inp, out, port=0, allow_existing=False)


def test_missing_secret_fails_closed_and_never_leaks_secret(tmp_path: Path, monkeypatch, capsys):
    inp = tmp_path / "in"
    inp.mkdir()
    (inp / "note.txt").write_text("Patient Name: Ramesh Kumar\nBP 120/80\n", encoding="utf-8")
    out = tmp_path / "out"

    monkeypatch.delenv("RAKSHA_SECRET", raising=False)
    srv, _ = create_server(inp, out, port=0)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    base = f"http://127.0.0.1:{srv.server_port}"
    try:
        code, st = _http_json(f"{base}/api/status")
        assert code == 200
        assert st["secret_configured"] is False

        csrf = _fetch_csrf(base)
        code_run, res_run = _http_json(f"{base}/api/run", method="POST", headers={"X-Kavach-CSRF": csrf})
        assert code_run == 400
        assert res_run["ok"] is False
        assert "RAKSHA_SECRET" in res_run["error"]
        assert not out.exists()
    finally:
        srv.shutdown()
        srv.server_close()

    cap = capsys.readouterr()
    assert cap.out == "" and cap.err == ""


def test_successful_run_preview_escaping_traversal_and_no_secret_leak(tmp_path: Path, monkeypatch):
    secret_val = "ultra-secret-dashboard-token-999"
    monkeypatch.setenv("RAKSHA_SECRET", secret_val)

    inp = tmp_path / "in"
    inp.mkdir()
    (inp / "note.txt").write_text("Patient Name: Meena Devi\nC/O: fever <script>alert(1)</script>\n", encoding="utf-8")
    (inp / "raw_only.pdf").write_bytes(b"%PDF-1.4 RAW_SECRET_PDF")
    out = tmp_path / "out"

    srv, _ = create_server(inp, out, port=0)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    base = f"http://127.0.0.1:{srv.server_port}"
    try:
        with urllib.request.urlopen(f"{base}/", timeout=5) as resp:
            html_body = resp.read().decode("utf-8")
            assert resp.status == 200
            assert "KAVACH-FHIR Local Dashboard" in html_body
            assert "function esc(s)" in html_body
            assert secret_val not in html_body

        csrf = _fetch_csrf(base)
        code, run_res = _http_json(f"{base}/api/run", method="POST", headers={"X-Kavach-CSRF": csrf})
        assert code == 202 and run_res["ok"] is True

        # Poll until pipeline completes
        st = None
        for _ in range(40):
            _, st = _http_json(f"{base}/api/status")
            if st["pipeline"]["status"] in ("succeeded", "failed"):
                break
            time.sleep(0.15)
        assert st is not None
        assert st["pipeline"]["status"] == "succeeded"
        assert st["pipeline"]["exit_code"] == 0
        assert st["report"]["available"] is True
        assert st["report"]["files_total"] == 2
        assert st["report"]["files_sanitized"] == 1
        assert st["report"]["files_quarantined"] == 1
        assert secret_val not in json.dumps(st)

        # File listing contains only sanitized note.txt, never raw_only.pdf
        _, files_res = _http_json(f"{base}/api/files")
        assert files_res["files"] == ["note.txt"]

        # Preview works & labels sanitized output
        code_p, prev = _http_json(f"{base}/api/preview?path=note.txt")
        assert code_p == 200
        assert prev["label"] == "SANITIZED OUTPUT"
        assert "Meena Devi" not in prev["text"]
        assert secret_val not in prev["text"]

        # Path traversal & raw input access rejected (403)
        for bad in ("../report.json", "../../in/raw_only.pdf", "raw_only.pdf", "/etc/passwd", "a\\b"):
            c_bad, _ = _http_json(f"{base}/api/preview?path={bad}")
            assert c_bad == 403
    finally:
        srv.shutdown()
        srv.server_close()


def test_failed_pipeline_run_does_not_expose_traceback(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("RAKSHA_SECRET", "dash-sec")
    inp = tmp_path / "in"
    inp.mkdir()
    out = tmp_path / "out"
    bad_main = tmp_path / "missing_main.py"

    srv = dashboard.ThreadingHTTPServer(
        ("127.0.0.1", 0),
        dashboard.make_handler(dashboard.DashboardState(inp, out, main_py=bad_main)),
    )
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    base = f"http://127.0.0.1:{srv.server_port}"
    try:
        csrf = _fetch_csrf(base)
        _http_json(f"{base}/api/run", method="POST", headers={"X-Kavach-CSRF": csrf})
        st = None
        for _ in range(30):
            _, st = _http_json(f"{base}/api/status")
            if st["pipeline"]["status"] in ("succeeded", "failed"):
                break
            time.sleep(0.1)
        assert st is not None
        assert st["pipeline"]["status"] == "failed"
        assert "Traceback" not in st["pipeline"]["message"]
    finally:
        srv.shutdown()
        srv.server_close()


def test_single_screen_tab_routing_and_viewport_rules():
    for route in ("overview", "pipeline", "files", "evaluation", "security"):
        assert f'id="view-{route}"' in _DASHBOARD_HTML
        assert f'data-route="{route}"' in _DASHBOARD_HTML
    assert "window.addEventListener('hashchange'" in _DASHBOARD_HTML
    assert "resolveHashRoute()" in _DASHBOARD_HTML
    assert "height: 100dvh;" in _DASHBOARD_HTML
    assert ".view-panel {\n    display: none;" in _DASHBOARD_HTML
    assert ".view-panel.active { display: flex; }" in _DASHBOARD_HTML


def test_report_and_evaluator_parsers():
    sample_cd = (
        "1) PERSONAL DATA: 0 of 3230 pieces still visible (  0.0% leaked; lower is better)\n"
        "2) CANARIES: 0 of 4 planted canaries found\n"
        "3) MEDICAL DATA KEPT: 4855 of 4855 medical values survived (100.0%; higher is better)\n"
        "4) PATIENT LINKING: precision 1.00, recall 0.87, F0.5 0.97  (pseudonyms that wrongly merge different people: 0)\n"
        "5) RAW COPIES: 0 broken/unsupported files\n"
    )
    m = parse_check_dev_output(sample_cd)
    assert m["pii_leakage"] == "0 / 3230 (0.0% leaked; lower is better)"
    assert m["canaries"] == "0 / 4"
    assert m["clinical_preservation"] == "4855 / 4855 (100.0%)"
    assert m["linkage_precision"] == "1.00"
    assert m["linkage_recall"] == "0.87"
    assert m["false_merges"] == "0"
    assert parse_validate_output("CONTRACT OK\n", 0) == "CONTRACT OK"
    assert parse_report_json(Path("nonexistent_report.json"))["available"] is False


def test_dashboard_csrf_origin_host_and_no_inline_onclick(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("RAKSHA_SECRET", "dashboard-csrf-test-secret-1234")
    inp = tmp_path / "in"
    inp.mkdir()
    (inp / "note.txt").write_text("C/O: fever\n", encoding="utf-8")
    out = tmp_path / "out"

    srv, _ = create_server(inp, out, port=0)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    base = f"http://127.0.0.1:{srv.server_port}"
    try:
        csrf = _fetch_csrf(base)
        # Missing CSRF token -> 403
        c1, r1 = _http_json(f"{base}/api/run", method="POST")
        assert c1 == 403 and "CSRF" in r1["error"]

        # Cross-origin POST even with token -> 403
        c2, r2 = _http_json(
            f"{base}/api/run",
            method="POST",
            headers={"X-Kavach-CSRF": csrf, "Origin": "http://evil.example:9999"},
        )
        assert c2 == 403 and "Origin" in r2["error"]

        # Invalid Host header (DNS rebinding) -> 403
        c3, _ = _http_json(f"{base}/api/status", headers={"Host": "evil.example:8765"})
        assert c3 == 403

        # No inline onclick interpolation for filenames/folders
        assert "onclick=\"loadPreview" not in _DASHBOARD_HTML
        assert "onclick=\"setFolderFilter" not in _DASHBOARD_HTML
        assert 'data-path="${esc(f)}"' in _DASHBOARD_HTML
    finally:
        srv.shutdown()
        srv.server_close()
