"""Standalone k-anonymity adaptive generalization experiment & tests (no production edits)."""
from __future__ import annotations

import csv
import datetime as dt
import io
import json
import re
import shutil
import statistics
import subprocess
from collections import Counter, defaultdict
from pathlib import Path

_AGE_HDR_RE = re.compile(r"\b(?:age|umar|आयु|उम्र)\b", re.IGNORECASE)
_DIST_HDR_RE = re.compile(r"\b(?:district|jila|जिला)\b", re.IGNORECASE)
_SEX_HDR_RE = re.compile(r"^(?:sex|gender|ling|लिंग)$", re.IGNORECASE)
_BAND_RE = re.compile(r"^(\d{1,3})-(\d{1,3})(.*)$")
_TOP_BAND_RE = re.compile(r"^85\+(.*)$")


def _norm_age(val: str) -> str:
    return re.sub(r"\s+", " ", val.strip().lower())


def _norm_gender(val: str) -> str:
    v = val.strip().lower()
    if v in ("m", "male", "पुरुष"):
        return "M"
    if v in ("f", "female", "महिला"):
        return "F"
    return v


def _norm_dist(val: str) -> str:
    return re.sub(r"\s+", " ", val.strip().lower())


def widen_age_band(val: str) -> str:
    """Widen 5-year age band (or 85+) into a 20-year bucket while preserving suffix."""
    s = val.strip()
    m = _BAND_RE.match(s)
    if m:
        lo = int(m.group(1))
        b20 = (lo // 20) * 20
        hi = b20 + 19
        return f"{b20}-{hi}{m.group(3)}"
    m85 = _TOP_BAND_RE.match(s)
    if m85:
        return f"80+{m85.group(1)}"
    return s


def compute_equivalence_classes(sanitized_dir: Path) -> tuple[Counter[tuple[str, str, str]], list[dict]]:
    """Collect structured CSV/TSV records and count (age_band, gender, district) classes."""
    records: list[dict] = []
    classes: Counter[tuple[str, str, str]] = Counter()

    for p in sorted(sanitized_dir.rglob("*.csv")) + sorted(sanitized_dir.rglob("*.tsv")):
        delim = "\t" if p.suffix.lower() == ".tsv" else ","
        try:
            rows = list(csv.reader(io.StringIO(p.read_text(encoding="utf-8"), newline=""), delimiter=delim))
        except (OSError, csv.Error):
            continue
        if len(rows) < 2:
            continue
        headers = [h.strip() for h in rows[0]]
        age_idx = next((i for i, h in enumerate(headers) if _AGE_HDR_RE.search(h)), None)
        dist_idx = next((i for i, h in enumerate(headers) if _DIST_HDR_RE.search(h)), None)
        sex_idx = next((i for i, h in enumerate(headers) if _SEX_HDR_RE.match(h)), None)
        if age_idx is None and dist_idx is None:
            continue

        for r_idx, row in enumerate(rows[1:]):
            a_raw = row[age_idx].strip() if age_idx is not None and age_idx < len(row) else ""
            g_raw = row[sex_idx].strip() if sex_idx is not None and sex_idx < len(row) else ""
            d_raw = row[dist_idx].strip() if dist_idx is not None and dist_idx < len(row) else ""
            if not (a_raw or d_raw):
                continue
            key = (_norm_age(a_raw), _norm_gender(g_raw), _norm_dist(d_raw))
            classes[key] += 1
            records.append({
                "path": p,
                "delim": delim,
                "row_idx": r_idx + 1,
                "age_idx": age_idx,
                "sex_idx": sex_idx,
                "dist_idx": dist_idx,
                "key": key,
            })
    return classes, records


def _class_distribution(classes: Counter[tuple[str, str, str]]) -> dict:
    vals = list(classes.values())
    total = sum(vals)
    return {
        "total_records": total,
        "num_classes": len(vals),
        "k1_records": sum(v for v in vals if v == 1),
        "k_lt_3_records": sum(v for v in vals if v < 3),
        "k_lt_5_records": sum(v for v in vals if v < 5),
        "min_k": min(vals) if vals else 0,
        "median_k": statistics.median(vals) if vals else 0,
        "max_k": max(vals) if vals else 0,
    }


def apply_k_anonymity_policy(sanitized_dir: Path, mode: str, k_threshold: int = 3) -> dict:
    """Apply adaptive Policy D, E, or F to CSV/TSV files in sanitized_dir."""
    classes_before, records = compute_equivalence_classes(sanitized_dir)
    dist_before = _class_distribution(classes_before)
    if mode == "BASELINE":
        return {
            "mode": mode,
            "generalized_records": 0,
            "generalized_pct": 0.0,
            "before": dist_before,
            "after": dist_before,
        }

    # Load all affected CSV/TSV tables into memory once
    tables: dict[Path, tuple[str, list[list[str]]]] = {}
    for rec in records:
        p = rec["path"]
        if p not in tables:
            rows = list(csv.reader(io.StringIO(p.read_text(encoding="utf-8"), newline=""), delimiter=rec["delim"]))
            tables[p] = (rec["delim"], rows)

    generalized_rows: set[tuple[Path, int]] = set()

    def _rec_key(rec: dict) -> tuple[str, str, str]:
        _, rows = tables[rec["path"]]
        row = rows[rec["row_idx"]]
        a_raw = row[rec["age_idx"]].strip() if rec["age_idx"] is not None and rec["age_idx"] < len(row) else ""
        g_raw = row[rec["sex_idx"]].strip() if rec["sex_idx"] is not None and rec["sex_idx"] < len(row) else ""
        d_raw = row[rec["dist_idx"]].strip() if rec["dist_idx"] is not None and rec["dist_idx"] < len(row) else ""
        return (_norm_age(a_raw), _norm_gender(g_raw), _norm_dist(d_raw))

    def _current_classes() -> Counter[tuple[str, str, str]]:
        c: Counter[tuple[str, str, str]] = Counter()
        for rec in records:
            c[_rec_key(rec)] += 1
        return c

    # Policy D: generalize district -> [REGION] for classes with k < k_threshold
    if mode in ("D", "E", "F"):
        c_d = _current_classes()
        for rec in records:
            if c_d[_rec_key(rec)] < k_threshold and rec["dist_idx"] is not None:
                _, rows = tables[rec["path"]]
                row = rows[rec["row_idx"]]
                if row[rec["dist_idx"]].strip() and row[rec["dist_idx"]].strip() != "[REGION]":
                    row[rec["dist_idx"]] = "[REGION]"
                    generalized_rows.add((rec["path"], rec["row_idx"]))

    # Policy E: recalculate k, then widen age bands for remaining classes with k < k_threshold
    if mode in ("E", "F"):
        c_e = _current_classes()
        for rec in records:
            if c_e[_rec_key(rec)] < k_threshold and rec["age_idx"] is not None:
                _, rows = tables[rec["path"]]
                row = rows[rec["row_idx"]]
                old_age = row[rec["age_idx"]].strip()
                new_age = widen_age_band(old_age)
                if new_age != old_age:
                    row[rec["age_idx"]] = new_age
                    generalized_rows.add((rec["path"], rec["row_idx"]))

    # Policy F: recalculate k, then generalize gender -> Unknown for remaining k < k_threshold
    if mode == "F":
        c_f = _current_classes()
        for rec in records:
            if c_f[_rec_key(rec)] < k_threshold and rec["sex_idx"] is not None:
                _, rows = tables[rec["path"]]
                row = rows[rec["row_idx"]]
                old_sex = row[rec["sex_idx"]].strip()
                if old_sex and old_sex.lower() != "unknown":
                    row[rec["sex_idx"]] = "Unknown"
                    generalized_rows.add((rec["path"], rec["row_idx"]))

    for p, (delim, rows) in sorted(tables.items()):
        buf = io.StringIO()
        w = csv.writer(buf, delimiter=delim, lineterminator="\n")
        w.writerows(rows)
        p.write_text(buf.getvalue(), encoding="utf-8")

    classes_after = _current_classes()
    dist_after = _class_distribution(classes_after)
    total = dist_before["total_records"]
    n_gen = len(generalized_rows)
    return {
        "mode": mode,
        "generalized_records": n_gen,
        "generalized_pct": round((n_gen / total * 100.0) if total else 0.0, 2),
        "before": dist_before,
        "after": dist_after,
    }


# ---------------------------------------------------------------------------
# Unit tests (synthetic fixtures only)
# ---------------------------------------------------------------------------

def _write_synthetic_csv(path: Path) -> None:
    rows = [
        ["Age", "Gender", "District", "Diagnosis", "Medication", "Dosage"],
        # Class 1 (k=3): stays untouched under D, E, F
        ["30-34", "M", "AlphaDist", "Dengue", "Paracetamol", "650mg"],
        ["30-34", "M", "AlphaDist", "Dengue", "Paracetamol", "650mg"],
        ["30-34", "M", "AlphaDist", "Dengue", "Paracetamol", "650mg"],
        # Class 2 & 3 (k=2 and k=1 in different districts -> merge to k=3 after Policy D!)
        ["40-44", "F", "BetaDist", "Asthma", "Salbutamol", "2mg"],
        ["40-44", "F", "BetaDist", "Asthma", "Salbutamol", "2mg"],
        ["40-44", "F", "GammaDist", "Asthma", "Salbutamol", "2mg"],
        # Class 4 & 5 (k=1 + k=1 in different 5-yr bands -> merge to k=2 in Policy E, then Unknown in F)
        ["60-64", "M", "DeltaDist", "RareSyndrome", "DrugX", "10mg"],
        ["65-69", "F", "EpsDist", "RareSyndrome", "DrugY", "20mg"],
    ]
    buf = io.StringIO()
    csv.writer(buf, lineterminator="\n").writerows(rows)
    path.write_text(buf.getvalue(), encoding="utf-8")


def test_k_calculation_counts_equivalence_classes(tmp_path: Path):
    san = tmp_path / "sanitized"
    san.mkdir()
    _write_synthetic_csv(san / "synth.csv")
    classes, records = compute_equivalence_classes(san)
    assert len(records) == 8
    assert classes[("30-34", "M", "alphadist")] == 3
    assert classes[("40-44", "F", "betadist")] == 2
    assert classes[("40-44", "F", "gammadist")] == 1


def test_policy_d_generalizes_only_small_k_districts(tmp_path: Path):
    san = tmp_path / "sanitized"
    san.mkdir()
    csv_p = san / "synth.csv"
    _write_synthetic_csv(csv_p)
    res = apply_k_anonymity_policy(san, "D", k_threshold=3)
    rows = list(csv.reader(io.StringIO(csv_p.read_text(encoding="utf-8"))))
    # k=3 rows keep AlphaDist
    assert rows[1][2] == "AlphaDist"
    # k<3 rows generalized to [REGION]
    assert rows[4][2] == "[REGION]"
    assert rows[6][2] == "[REGION]"
    # Clinical columns untouched
    assert rows[7][3:] == ["RareSyndrome", "DrugX", "10mg"]
    assert res["generalized_records"] == 5


def test_policy_e_recalculates_k_then_widens_age(tmp_path: Path):
    san = tmp_path / "sanitized"
    san.mkdir()
    csv_p = san / "synth.csv"
    _write_synthetic_csv(csv_p)
    apply_k_anonymity_policy(san, "E", k_threshold=3)
    rows = list(csv.reader(io.StringIO(csv_p.read_text(encoding="utf-8"))))
    # BetaDist + GammaDist merged to k=3 after Policy D, so age 40-44 is NOT widened
    assert rows[4][0] == "40-44"
    assert rows[6][0] == "40-44"
    # Remaining k=1 rows ARE widened to 20-year band 60-79
    assert rows[7][0] == "60-79"
    assert rows[8][0] == "60-79"


def test_policy_f_generalizes_gender_only_when_still_k_lt_3(tmp_path: Path):
    san = tmp_path / "sanitized"
    san.mkdir()
    csv_p = san / "synth.csv"
    _write_synthetic_csv(csv_p)
    apply_k_anonymity_policy(san, "F", k_threshold=3)
    rows = list(csv.reader(io.StringIO(csv_p.read_text(encoding="utf-8"))))
    assert rows[1][1] == "M"
    assert rows[4][1] == "F"
    # Remaining k=1 rows generalized to Unknown
    assert rows[7][1] == "Unknown"
    assert rows[8][1] == "Unknown"


def test_policy_determinism_and_clinical_preservation(tmp_path: Path, capsys):
    for name in ("run1", "run2"):
        san = tmp_path / name / "sanitized"
        san.mkdir(parents=True)
        _write_synthetic_csv(san / "synth.csv")
        apply_k_anonymity_policy(san, "F", k_threshold=3)
    b1 = (tmp_path / "run1" / "sanitized" / "synth.csv").read_bytes()
    b2 = (tmp_path / "run2" / "sanitized" / "synth.csv").read_bytes()
    assert b1 == b2
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err == ""


# ---------------------------------------------------------------------------
# Standalone experiment runner (invoked only via __main__)
# ---------------------------------------------------------------------------

def _run_attacks(out_dir: Path, att_dir: Path, truth: dict) -> dict:
    """ATTACKS.md-aligned A3/A4/A5 evaluator with demographic consistency."""
    pid_to_rid = {pt_id: p["rid"] for pt_id, p in truth["patients"].items()}
    true_rids = set(pid_to_rid.values())
    with open(att_dir / "registry.csv", encoding="utf-8") as f:
        registry = list(csv.DictReader(f))
    known_facts = [
        json.loads(line)
        for line in (att_dir / "known_facts.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    age_band_re = re.compile(
        r"(?:Age(?:\s*/\s*Sex)?|आयु|उम्र)\s*[:\-]?\s*(\d{1,3})-(\d{1,3})\b"
        r"|\b(\d{1,3})-(\d{1,3})(?=\s*(?:Yrs?|Years?|Y|वर्ष|साल)?\s*/\s*[MF]\b|\s+(?:Yrs?|Years?|Y|वर्ष|साल)\b)",
        re.I,
    )
    age_85_re = re.compile(r"(?:Age(?:\s*/\s*Sex)?\s*[:\-]?\s*|\b)(?:85|80)\+(?=\s*(?:Yrs?|Years?|Y|वर्ष|साल|/|$))", re.I)
    age_exact_re = re.compile(r"(?:Age(?:\s*/\s*Sex)?\s*[:\-]\s*|\b)(\d{1,3})\s*(?:Yrs?|Years?|Y|वर्ष|साल)?\s*/\s*([MF])\b", re.I)
    iso_re = re.compile(r"\b(19\d{2}|20\d{2})-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])\b")
    dmy_re = re.compile(r"\b(0?[1-9]|[12]\d|3[01])[/-](0?[1-9]|[12]\d|3[01])[/-](19\d{2}|20\d{2})\b")
    districts = {r["district"].lower(): r["district"] for r in registry if r["district"]}
    hospitals = {kf["hospital"].lower(): kf["hospital"] for kf in known_facts if kf.get("hospital")}

    def extract_ev(text: str):
        ev = {"ages": [], "gender": None, "district": None, "dates": set(), "hospital": None, "text_lower": text.lower()}
        tl = ev["text_lower"]
        for m in age_band_re.finditer(text):
            lo_s, hi_s = (m.group(1), m.group(2)) if m.group(1) else (m.group(3), m.group(4))
            lo, hi = int(lo_s), int(hi_s)
            if 0 <= lo <= hi <= 110 and (hi - lo) <= 25:
                ev["ages"].append((lo, hi))
        if age_85_re.search(text):
            ev["ages"].append((80, 120))
        for m in age_exact_re.finditer(text):
            a = int(m.group(1))
            if 0 <= a <= 110:
                ev["ages"].append((a, a))
            ev["gender"] = m.group(2).upper()
        if not ev["gender"]:
            if re.search(r"\bFemale\b|\bमहिला\b|/F\b", text, re.I):
                ev["gender"] = "F"
            elif re.search(r"\bMale\b|\bपुरुष\b|/M\b", text, re.I):
                ev["gender"] = "M"
        for dl, d in districts.items():
            if dl in tl:
                ev["district"] = d
                break
        for m in iso_re.finditer(text):
            try:
                ev["dates"].add(dt.date(int(m.group(1)), int(m.group(2)), int(m.group(3))).isoformat())
            except ValueError:
                pass
        for m in dmy_re.finditer(text):
            a, b, y = int(m.group(1)), int(m.group(2)), int(m.group(3))
            try:
                if b <= 12:
                    ev["dates"].add(dt.date(y, b, a).isoformat())
            except ValueError:
                pass
        for hl, h in hospitals.items():
            if hl.split()[0] in tl:
                ev["hospital"] = h
                break
        return ev

    def score_cands(ev):
        cands = list(registry)
        for pred in [
            (lambda r: r["district"].lower() == ev["district"].lower()) if ev["district"] else None,
            (lambda r: r["gender"].upper() == ev["gender"]) if ev["gender"] else None,
            (lambda r: r["age"].isdigit() and (min(a[0] for a in ev["ages"]) - 2) <= int(r["age"]) <= (max(a[1] for a in ev["ages"]) + 2)) if ev["ages"] else None,
        ]:
            if pred is not None:
                sub = [r for r in cands if pred(r)]
                if sub:
                    cands = sub
        tl = ev["text_lower"]
        weights = {}
        for r in cands:
            w = 1.0
            nm = r["name"].lower()
            if nm and nm in tl:
                w *= 60.0
            weights[r["rid"]] = w
        tot = sum(weights.values()) or 1.0
        return {rid: w / tot for rid, w in weights.items()}

    report = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
    sha_to_out = {f["input_sha256"]: f["output"] for f in report["files"] if f["status"] == "sanitized"}
    rec_psn = {}
    for line in (out_dir / "records.jsonl").read_text(encoding="utf-8").splitlines():
        if line.strip():
            r = json.loads(line)
            rec_psn[(r["file"], r["loc"])] = r["patient"]

    rec_risks = []
    profiles = defaultdict(list)
    for rel_path, finfo in truth["files"].items():
        if finfo.get("expect") == "quarantine" or finfo.get("clean"):
            continue
        out_rel = sha_to_out.get(finfo["sha256"])
        if not out_rel:
            continue
        fpath = out_dir / out_rel
        txt = fpath.read_text(encoding="utf-8", errors="replace")
        for loc, uinfo in finfo.get("units", {}).items():
            pid = uinfo.get("patient") if isinstance(uinfo, dict) else None
            if not pid:
                continue
            true_rid = pid_to_rid.get(pid)
            if not true_rid:
                continue
            utxt = txt
            if loc.startswith("row:") and fpath.suffix.lower() in (".csv", ".tsv"):
                idx = int(loc.split(":")[1])
                delim = "\t" if fpath.suffix.lower() == ".tsv" else ","
                rows = list(csv.reader(io.StringIO(txt, newline=""), delimiter=delim))
                if idx + 1 < len(rows):
                    utxt = " ".join(f"{h}: {c}" for h, c in zip(rows[0], rows[idx + 1]))
            ev = extract_ev(utxt)
            probs = score_cands(ev)
            rec_risks.append(probs.get(true_rid, 0.0))
            pkey = rec_psn.get((out_rel, loc)) or f"{out_rel}:{loc}"
            profiles[pkey].append((true_rid, ev, utxt))

    pat_max_risk = defaultdict(float)
    prof_scores = {}
    for pkey, items in profiles.items():
        merged = {"ages": [], "gender": None, "district": None, "dates": set(), "hospital": None, "text_lower": " ".join(x[2].lower() for x in items)}
        for _, ev, _ in items:
            merged["ages"].extend(ev["ages"])
            for k in ("gender", "district", "hospital"):
                if not merged[k] and ev[k]:
                    merged[k] = ev[k]
            merged["dates"].update(ev["dates"])
        probs = score_cands(merged)
        prof_scores[pkey] = (probs, merged)
        for true_rid, _, _ in items:
            pat_max_risk[true_rid] = max(pat_max_risk[true_rid], probs.get(true_rid, 0.0))

    cond_counts = Counter()
    for kf in known_facts:
        c = (kf.get("condition_hint") or "").lower()
        if c:
            for _, (_, merged) in prof_scores.items():
                if c in merged["text_lower"]:
                    cond_counts[c] += 1

    a5_hits, a5_targets, decoy_fps = 0, 0, 0
    for kf in known_facts:
        rid = kf["rid"]
        is_target = rid in true_rids
        cond = (kf.get("condition_hint") or "").lower()
        hosp = (kf.get("hospital") or "").lower().split()[0] if kf.get("hospital") else ""
        vdates = set(kf.get("visit_dates") or [])
        prof_weights = {}
        for pkey, (probs, merged) in prof_scores.items():
            s = 0.0
            if vdates & merged["dates"]:
                s += 4.0
            if cond and cond in merged["text_lower"]:
                s += 8.0 if cond_counts[cond] <= 3 else 2.0
            if s > 0 and rid in probs:
                if hosp and hosp in merged["text_lower"]:
                    s *= 2.0
                prof_weights[pkey] = s * probs[rid]
        tot_pw = sum(prof_weights.values())
        best_p = max(prof_weights, key=prof_weights.get) if prof_weights else None
        norm_p = (prof_weights[best_p] / tot_pw) if best_p and tot_pw > 0 else 0.0
        hit = best_p is not None and any(x[0] == rid for x in profiles[best_p])
        if is_target:
            a5_targets += 1
            if hit and norm_p >= 0.5 and prof_weights[best_p] >= 0.3:
                a5_hits += 1
        else:
            if best_p is not None and norm_p >= 0.5 and prof_weights[best_p] >= 0.3:
                decoy_fps += 1

    return {
        "a3_mean_risk": round(sum(rec_risks) / len(rec_risks), 4),
        "a4_reid_rate": round(sum(1 for r in pat_max_risk.values() if r >= 0.5) / len(pat_max_risk), 4),
        "a5_hits": f"{a5_hits}/{a5_targets}",
        "decoy_fps": f"{decoy_fps}/4",
    }


if __name__ == "__main__":
    base_out = Path(r"C:\Users\hp\devforge\Kavach-FHIR\output\kavach-spec-final")
    exp_root = Path(r"C:\Users\hp\.gemini\antigravity\brain\706c3fd8-9458-4b26-b6d8-2f5abaf51927\scratch\k_anon_exps")
    att_dir = Path(r"C:\Users\hp\devforge\Secret-Wards-ToolKit-LF\dev\attacker")
    truth_path = Path(r"C:\Users\hp\devforge\Secret-Wards-ToolKit-LF\dev\truth\truth.json")
    input_dir = Path(r"C:\Users\hp\devforge\Secret-Wards-ToolKit-LF\dev\input")
    check_dev = Path(r"C:\Users\hp\devforge\Secret-Wards-ToolKit-LF\check_dev.py")
    validate_out = Path(r"C:\Users\hp\devforge\Secret-Wards-ToolKit-LF\validate_output.py")
    truth = json.loads(truth_path.read_text(encoding="utf-8"))

    for mode in ("BASELINE", "D", "E", "F"):
        if mode == "BASELINE":
            target_dir = base_out
            p_res = apply_k_anonymity_policy(target_dir / "sanitized", "BASELINE")
        else:
            target_dir = exp_root / f"policy_{mode.lower()}"
            if target_dir.exists():
                shutil.rmtree(target_dir)
            shutil.copytree(base_out, target_dir)
            p_res = apply_k_anonymity_policy(target_dir / "sanitized", mode)

        atk = _run_attacks(target_dir, att_dir, truth)
        cd = subprocess.run(["python", str(check_dev), "--output", str(target_dir), "--truth", str(truth_path)], capture_output=True, text=True)
        vo = subprocess.run(["python", str(validate_out), "--input", str(input_dir), "--output", str(target_dir)], capture_output=True, text=True)
        med = next((l.strip() for l in cd.stdout.splitlines() if "MEDICAL DATA KEPT" in l), "")
        print(f"=== {mode} ===")
        print("  policy:", p_res)
        print("  attacks:", atk)
        print("  medical:", med)
        print("  contract:", vo.stdout.strip())
