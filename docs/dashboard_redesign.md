# KAVACH-FHIR — Dashboard Redesign Documentation (Historical Snapshot)

> **Historical Snapshot Notice:** Records the initial dashboard redesign verification (`57 passed`). Subsequent security hardening (`Host`, `Origin`/`Referer`, `X-Kavach-CSRF`, `data-*` event delegation) is documented in [security_remediation_report.md](security_remediation_report.md), and current release practice metrics (`78 passed, 1 xfailed`) are in [README.md](../README.md).

---

## 1. Design System & Colour Tokens

Implemented in [dashboard.py](../dashboard.py) using local CSS custom properties and system/geometric sans-serif typography (`Inter, "Helvetica Neue", Arial, sans-serif`) with zero external fonts, CDNs, or network requests:

- `--page-bg: #ECECEC` (neutral outer canvas)
- `--frame: #5A5A58` & `--frame-dark: #252623` (large rounded charcoal outer application shell, `50px` / `42px` radius)
- `--surface-main: #DFDFD7` & `--surface-alt: #EFEFEB` (warm grey inner canvas, `36px` radius)
- `--card: #F7F7F4` & `--card-white: #FDFDFD` (floating rounded cards, `24px–28px` radius)
- `--text-primary: #252623`, `--text-secondary: #777A75`, `--text-muted: #999B94`
- `--border-soft: #D2D2CB`
- `--accent-lime: #F3FE4A` & `--accent-olive: #C5C849` (sparingly used on active indicators, 6 timeline stage nodes, primary Run button, and highlighted evaluation cards)
- `--danger: #B85C50` & `--success: #637D65`

---

## 2. Layout & Components Implemented

1. **Outer Charcoal Shell & Top Navigation:** `KAVACH-FHIR • Privacy Operations`, 5 pill navigation items (`Overview`, `Pipeline`, `Sanitized Files`, `Evaluation`, `Security`), `RAKSHA_SECRET` status pill (`Configured` / `Missing`), and `Run Pipeline` / `Run Evaluation` pill actions.
2. **Product Overview Header & Metrics Strip:** `Healthcare Privacy Firewall` summary card (`OFFLINE ENGINE`, `LLM-FREE PROCESSING`, `127.0.0.1 ONLY`) + 5 horizontal vital cards (`Total Files`, `Sanitized Files`, `Quarantined`, `Records Processed`, `Linked Records`) + 5 interactive metric-filter pills.
3. **Connected 6-Stage Privacy Pipeline Timeline:** Horizontal connected timeline with circular lime-yellow stage nodes and stem connectors to rounded white stage cards:
   - `1. Input Ingestion` (formats, valid vs. quarantined counts)
   - `2. Sensitive Entity Detection` (real `entities` breakdown from `report.json`)
   - `3. Identity Resolution` (precision, recall, linked/unresolved, abstract SVG linkage graph)
   - `4. Clinical Information Preservation` (actual `check_dev` preservation result + clinical category chips)
   - `5. Privacy Protection` (implemented mechanisms + clearly labeled synthetic illustrative example)
   - `6. Sanitized Output` (sanitized count, raw-copy count, contract status)
4. **Floating Information Cards:** `Detection Coverage`, `Identity Resolution`, `Clinical Preservation`, `Evaluation Summary`, `File Security`.
5. **Sanitized File Explorer:** Search input, format filter chips (`All`, `TXT`, `CSV`, `TSV`, `JSON`), sanitized file list, formatted table/JSON/text preview with `SANITIZED OUTPUT` badge, HTML escaping (`esc()`), and copy-sanitized action.
6. **Evaluation Center & Security Status Center:** Distinguishes pipeline completion, practice evaluation, contract validation, and CLI-only full submission check (`READY TO SUBMIT` is never fabricated).
7. **Floating Bottom Navigation Rail:** Sticky pill rail with keyboard-accessible navigation and horizontal scroll on narrow viewports.

---

## 3. Preserved Backend & API Endpoints

All existing backend behavior in [dashboard.py](../dashboard.py) is preserved unchanged:
- `GET /` — self-contained HTML/CSS/JS with strict CSP (`default-src 'self' 'unsafe-inline'; connect-src 'self'`)
- `GET /api/status` — pipeline, evaluation, `report.json`, and `secret_configured` status
- `POST /api/run` — subprocess `main.py` inheriting `RAKSHA_SECRET` (fail-closed if missing)
- `POST /api/evaluate` — subprocess `validate_output.py` + `check_dev.py` (no `--show`)
- `GET /api/files` — sorted files strictly under `output/sanitized/`
- `GET /api/preview?path=...` — bounded 200 KB sanitized preview with traversal/symlink rejection

---

## 4. Responsive Behavior

- **Desktop (`> 1180px`):** Centered horizontal shell (`min(93vw, 1440px)`), 6-column horizontal connected timeline, multi-column floating cards.
- **Tablet (`769px–1180px`):** Overview stacks, 3-column timeline grid, 2-column floating cards.
- **Mobile (`≤ 768px`):** Compact rounded shell, horizontally scrollable nav/rail, vertical connected timeline, stacked explorer panels, `prefers-reduced-motion` respected.

---

## 5. Tests Executed & Results

- `python -m pytest -v`: **57 passed in 6.85s** (including all 6 dashboard security/functional tests in [tests/test_dashboard.py](../tests/test_dashboard.py)).
- Live HTTP/API verification on `http://127.0.0.1:8771/`: `GET /` (`200`), `POST /api/evaluate` (`completed`, `CONTRACT OK`, `0 / 3230` PII, `4855 / 4855` medical), `GET /api/files` (`193` files), `GET /api/preview` (`csv`, `json`, `txt` all labeled `SANITIZED OUTPUT`), and `403` on `../report.json`.

---

## 6. Known Limitations

- Automated Chrome visual inspection did not run because `DevToolsActivePort` was unavailable on this machine; open `http://127.0.0.1:8765/` in Chrome locally to visually inspect the rendered layout.
- `check_submission.py` (`READY TO SUBMIT`) remains CLI-only and is not triggered from the browser.
