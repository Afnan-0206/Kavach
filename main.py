#!/usr/bin/env python3
"""KAVACH-FHIR: Offline, CPU-only, LLM-free healthcare privacy firewall."""
from __future__ import annotations

import argparse
import base64
import binascii
import csv
import io
import json
import re
import sys
import time
from pathlib import Path
from typing import Any

import yaml

from detectors.indian_ids import detect_indian_ids
from detectors.name_detector import DynamicGazetteer, detect_contextual_names
from detectors.phone_detector import detect_phones
from detectors.residual_scanner import scan_and_scrub_residual
from engine.clinical_shield import find_protected_spans
from engine.exporter import atomic_write_text, write_records_jsonl
from engine.identity_linker import link_records
from engine.ingestion import ingest_directory
from engine.normalization import deva_to_latin, has_devanagari, latin_to_deva, normalize_text
from engine.pii_detector import classify_field_name, detect_all_spans, redact_text
from engine.privacy_engine import (
    age_to_band,
    generalize_pin,
    get_shift_for_record,
    parse_date_flexible,
    shift_date_str,
)
from engine.record_model import IngestedFile, PipelineStats, RecordUnit
from engine.reporting import write_report
from engine.security import KeyRing

_AGE_INLINE_RE = re.compile(
    r"(\b(?:Age(?:\s*/\s*Sex)?|आयु|उम्र)\s*[:\-]?\s*)(\d{1,3})(\s*(?:Yrs?|Years?|Y|वर्ष)?(?:\s*/\s*[MF])?)",
    re.IGNORECASE,
)
_AGE_SEX_CELL_RE = re.compile(r"^(\d{1,3})(\s*(?:Yrs?|Years?|Y)?\s*/\s*[MF])$", re.IGNORECASE)
_B64_RE = re.compile(r"^[A-Za-z0-9+/]{24,}={0,2}$")


def load_policy(path: Path) -> dict:
    if not path.is_file():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def _extract_clues_from_text(text: str, clues: dict[str, Any], gazetteer: DynamicGazetteer) -> None:
    """Extract identity clues from unstructured text and populate gazetteer."""
    protected = find_protected_spans(text)
    for sp in detect_all_spans(text):
        val = normalize_text(sp.text).strip()
        if sp.entity_type == "AADHAAR":
            clues.setdefault("aadhaar", re.sub(r"\D", "", val))
        elif sp.entity_type == "ABHA_NUMBER":
            clues.setdefault("abha", re.sub(r"\D", "", val))
        elif sp.entity_type == "PAN":
            clues.setdefault("pan", val.upper())
        elif sp.entity_type == "EMAIL":
            clues.setdefault("email", val.lower())
        elif sp.entity_type == "INSURANCE_ID":
            clues.setdefault("insurance_id", val.upper())
        elif sp.entity_type == "PHONE":
            digits = re.sub(r"\D", "", val)
            if len(digits) >= 10:
                clues.setdefault("phone", digits[-10:])
        elif sp.entity_type == "MRN":
            clues.setdefault("mrns", []).append(val)
        elif sp.entity_type == "PATIENT_NAME":
            if "name" not in clues or len(val) > len(clues["name"]):
                clues["name"] = val
            gazetteer.add_name(val)
            if has_devanagari(val):
                lat = deva_to_latin(val)
                if lat:
                    gazetteer.add_name(lat)
            else:
                deva = latin_to_deva(val)
                if deva:
                    gazetteer.add_name(deva)
        elif sp.entity_type == "RELATIVE_NAME":
            clues.setdefault("relative", val)
            gazetteer.add_name(val)

    m_age = _AGE_INLINE_RE.search(text)
    if m_age and "age" not in clues:
        try:
            clues["age"] = int(m_age.group(2))
        except ValueError:
            pass
    if "gender" not in clues:
        if re.search(r"\b(?:Yrs?|Y)?\s*/\s*F\b|\bFemale\b|\bमहिला\b|W/o|D/o|पत्नी|पुत्री", text, re.I):
            clues["gender"] = "F"
        elif re.search(r"\b(?:Yrs?|Y)?\s*/\s*M\b|\bMale\b|\bपुरुष\b|S/o|पुत्र", text, re.I):
            clues["gender"] = "M"


def _extract_clues_from_row(
    headers: list[str],
    row: list[str],
    month_first: bool,
    clues: dict[str, Any],
    gazetteer: DynamicGazetteer,
) -> None:
    first_name, last_name = "", ""
    for h, cell in zip(headers, row):
        val = cell.strip()
        if not val:
            continue
        cls = classify_field_name(h)
        hl = h.lower()
        if cls == "PATIENT_NAME":
            if "first" in hl:
                first_name = val
            elif "last" in hl:
                last_name = val
            else:
                clues["name"] = val
                gazetteer.add_name(val)
        elif cls == "RELATIVE_NAME":
            clues["relative"] = val
            gazetteer.add_name(val)
        elif cls == "PHONE":
            digits = re.sub(r"\D", "", normalize_text(val))
            if len(digits) >= 10:
                clues["phone"] = digits[-10:]
        elif cls == "EMAIL":
            clues["email"] = val.lower()
        elif cls == "AADHAAR":
            digits = re.sub(r"\D", "", normalize_text(val))
            if len(digits) == 12:
                clues["aadhaar"] = digits
        elif cls == "ABHA_NUMBER":
            digits = re.sub(r"\D", "", normalize_text(val))
            if len(digits) == 14:
                clues["abha"] = digits
        elif cls == "PAN":
            clues["pan"] = val.upper()
        elif cls == "INSURANCE_ID":
            clues["insurance_id"] = val.upper()
        elif cls == "MRN":
            clues.setdefault("mrns", []).append(val)
        elif cls == "DOB":
            d = parse_date_flexible(val, month_first=month_first)
            if d:
                clues["dob"] = d.isoformat()
        elif cls == "AGE":
            m = re.search(r"\d{1,3}", normalize_text(val))
            if m:
                clues["age"] = int(m.group(0))
            if "/F" in val.upper():
                clues["gender"] = "F"
            elif "/M" in val.upper():
                clues["gender"] = "M"
        elif cls == "GENDER":
            v = val.upper()
            if v.startswith("F") or "महिला" in val:
                clues["gender"] = "F"
            elif v.startswith("M") or "पुरुष" in val:
                clues["gender"] = "M"
        elif cls == "VILLAGE":
            clues["village"] = val
        elif cls == "DISTRICT":
            clues["district"] = val
        elif cls is None:
            _extract_clues_from_text(val, clues, gazetteer)

    if first_name or last_name:
        full = f"{first_name} {last_name}".strip()
        clues["name"] = full
        gazetteer.add_name(full)


def _extract_clues_from_json(
    obj: Any,
    clues: dict[str, Any],
    gazetteer: DynamicGazetteer,
    parent_key: str = "",
) -> None:
    if isinstance(obj, dict):
        # FHIR Practitioner / Organization should not contribute patient clues
        rt = obj.get("resourceType")
        if rt in ("Practitioner", "Organization"):
            return
        for k, v in obj.items():
            cls = classify_field_name(k)
            if isinstance(v, (str, int, float)) and not isinstance(v, bool):
                sv = str(v).strip()
                if not sv:
                    continue
                if cls == "PATIENT_NAME" or (rt == "Patient" and k == "text"):
                    if cls == "PATIENT_NAME":
                        clues.setdefault("name", sv)
                        gazetteer.add_name(sv)
                elif cls == "RELATIVE_NAME":
                    clues.setdefault("relative", sv)
                    gazetteer.add_name(sv)
                elif cls == "PHONE":
                    digits = re.sub(r"\D", "", normalize_text(sv))
                    if len(digits) >= 10:
                        clues.setdefault("phone", digits[-10:])
                elif cls == "EMAIL":
                    clues.setdefault("email", sv.lower())
                elif cls == "AADHAAR":
                    digits = re.sub(r"\D", "", normalize_text(sv))
                    if len(digits) == 12:
                        clues.setdefault("aadhaar", digits)
                elif cls == "ABHA_NUMBER":
                    digits = re.sub(r"\D", "", normalize_text(sv))
                    if len(digits) == 14:
                        clues.setdefault("abha", digits)
                elif cls == "MRN":
                    clues.setdefault("mrns", []).append(sv)
                elif cls == "DOB" or k == "birthDate":
                    d = parse_date_flexible(sv)
                    if d:
                        clues.setdefault("dob", d.isoformat())
                elif cls == "AGE":
                    m = re.search(r"\d{1,3}", normalize_text(sv))
                    if m:
                        clues.setdefault("age", int(m.group(0)))
                elif cls == "GENDER":
                    if sv.upper().startswith("F"):
                        clues.setdefault("gender", "F")
                    elif sv.upper().startswith("M"):
                        clues.setdefault("gender", "M")
                elif cls == "DISTRICT":
                    clues.setdefault("district", sv)
                elif cls == "VILLAGE":
                    clues.setdefault("village", sv)
                else:
                    _extract_clues_from_text(sv, clues, gazetteer)
            else:
                _extract_clues_from_json(v, clues, gazetteer, k)
    elif isinstance(obj, list):
        for item in obj:
            _extract_clues_from_json(item, clues, gazetteer, parent_key)


def _filename_has_pii(rel_path: str, gazetteer: DynamicGazetteer) -> bool:
    name = Path(rel_path).stem
    norm_stem = re.sub(r"[_\-]+", " ", name)
    if detect_phones(name) or detect_indian_ids(name) or detect_phones(norm_stem) or detect_indian_ids(norm_stem):
        return True
    if gazetteer._compiled_full and gazetteer._compiled_full.search(norm_stem):
        return True
    return False


def _sanitize_json_obj(
    obj: Any,
    gazetteer: DynamicGazetteer,
    stats: PipelineStats,
    pseudonym: str | None,
    shift_days: int,
    age_band_w: int,
    pin_prefix: int,
    in_fhir_practitioner_or_org: bool = False,
    parent_key: str = "",
) -> Any:
    if isinstance(obj, dict):
        rt = obj.get("resourceType")
        is_clinical_actor = in_fhir_practitioner_or_org or rt in ("Practitioner", "Organization")
        new_dict: dict[str, Any] = {}
        for k, v in obj.items():
            # Sanitize PII in JSON keys
            new_k = k
            if detect_indian_ids(k) or detect_phones(k) or (
                gazetteer._compiled_full and gazetteer._compiled_full.search(k)
            ):
                new_k = redact_text(k, gazetteer=gazetteer, stats=stats, pseudonym=pseudonym)

            cls = classify_field_name(k)
            if is_clinical_actor and k in ("name", "text", "qualification", "address"):
                new_dict[new_k] = v
                continue

            if rt == "Patient" and k == "text" and isinstance(v, dict) and "div" in v:
                new_dict[new_k] = {
                    "status": v.get("status", "generated"),
                    "div": f'<div xmlns="http://www.w3.org/1999/xhtml">{pseudonym or "[PATIENT_NAME]"}</div>',
                }
                continue

            if k == "source" and isinstance(v, str) and v.startswith("#"):
                new_dict[new_k] = f"#{pseudonym}" if pseudonym else "#[MRN]"
                stats.add_entity("MRN")
                continue

            if cls == "METADATA_PATH" and isinstance(v, str):
                new_dict[new_k] = "[METADATA_PATH]"
                stats.add_entity("METADATA_PATH")
                continue

            if isinstance(v, (str, int, float)) and not isinstance(v, bool):
                sv = str(v)
                if cls == "PATIENT_NAME":
                    new_dict[new_k] = pseudonym if pseudonym else "[PATIENT_NAME]"
                    stats.add_entity("PATIENT_NAME")
                elif cls == "RELATIVE_NAME":
                    new_dict[new_k] = "[RELATIVE_NAME]"
                    stats.add_entity("RELATIVE_NAME")
                elif cls == "PHONE":
                    new_dict[new_k] = "[PHONE]"
                    stats.add_entity("PHONE")
                elif cls == "EMAIL":
                    new_dict[new_k] = "[EMAIL]"
                    stats.add_entity("EMAIL")
                elif cls == "AADHAAR":
                    new_dict[new_k] = "[AADHAAR]"
                    stats.add_entity("AADHAAR")
                elif cls == "ABHA_NUMBER":
                    new_dict[new_k] = "[ABHA_NUMBER]"
                    stats.add_entity("ABHA_NUMBER")
                elif cls == "PAN":
                    new_dict[new_k] = "[PAN]"
                    stats.add_entity("PAN")
                elif cls == "INSURANCE_ID":
                    new_dict[new_k] = "[INSURANCE_ID]"
                    stats.add_entity("INSURANCE_ID")
                elif cls == "MRN" and k not in ("visit_id", "sample_id", "bill_no"):
                    new_dict[new_k] = pseudonym if pseudonym else "[MRN]"
                    stats.add_entity("MRN")
                elif cls == "PIN":
                    new_dict[new_k] = generalize_pin(sv, pin_prefix)
                    stats.add_entity("PIN")
                elif cls == "VILLAGE":
                    new_dict[new_k] = "[VILLAGE]"
                    stats.add_entity("VILLAGE")
                elif cls == "ADDRESS":
                    new_dict[new_k] = "[ADDRESS]"
                    stats.add_entity("HOUSE")
                elif cls == "AGE" and isinstance(v, int):
                    new_dict[new_k] = age_to_band(v, age_band_w)
                elif cls in ("DOB", "DATE") or k in ("birthDate", "recordedDate", "authoredOn", "effectiveDateTime", "performedDateTime", "timestamp", "date", "start", "end"):
                    if isinstance(v, str):
                        new_dict[new_k] = shift_date_str(v, shift_days)
                    else:
                        new_dict[new_k] = v
                elif cls in ("DISTRICT", "GENDER", "CLINICIAN"):
                    new_dict[new_k] = v
                elif isinstance(v, str):
                    # Base64 attachment or free-text string
                    if _B64_RE.match(v.strip()):
                        try:
                            dec = base64.b64decode(v.strip() + "=" * (-len(v.strip()) % 4)).decode("utf-8", errors="strict")
                            if dec and sum(ch.isprintable() or ch in "\r\n\t" for ch in dec) / len(dec) >= 0.85:
                                cleaned = redact_text(dec, gazetteer=gazetteer, stats=stats, pseudonym=pseudonym)
                                cleaned = shift_date_str(cleaned, shift_days)
                                new_dict[new_k] = base64.b64encode(cleaned.encode("utf-8")).decode("ascii")
                                continue
                        except (binascii.Error, UnicodeDecodeError, ValueError):
                            pass
                    cleaned = redact_text(v, gazetteer=gazetteer, stats=stats, pseudonym=pseudonym)
                    cleaned = shift_date_str(cleaned, shift_days)
                    new_dict[new_k] = cleaned
                else:
                    new_dict[new_k] = v
            else:
                new_dict[new_k] = _sanitize_json_obj(
                    v, gazetteer, stats, pseudonym, shift_days, age_band_w, pin_prefix,
                    in_fhir_practitioner_or_org=is_clinical_actor, parent_key=k,
                )
        return new_dict
    elif isinstance(obj, list):
        return [
            _sanitize_json_obj(
                x, gazetteer, stats, pseudonym, shift_days, age_band_w, pin_prefix,
                in_fhir_practitioner_or_org=in_fhir_practitioner_or_org, parent_key=parent_key,
            )
            for x in obj
        ]
    elif isinstance(obj, str):
        cleaned = redact_text(obj, gazetteer=gazetteer, stats=stats, pseudonym=pseudonym)
        return shift_date_str(cleaned, shift_days)
    return obj


def run_pipeline(input_dir: Path, output_dir: Path, policy_path: Path) -> int:
    t0 = time.monotonic()
    policy = load_policy(policy_path)
    keyring = KeyRing.from_env()
    age_band_w = int(policy.get("age_band_years", 5))
    max_shift = int(policy.get("date_shift_max_days", 180))
    pin_prefix = int(policy.get("pin_prefix_digits", 3))

    sanitized_dir = output_dir / "sanitized"
    sanitized_dir.mkdir(parents=True, exist_ok=True)
    sys.setrecursionlimit(5000)

    ingested = ingest_directory(
        input_dir,
        max_json_depth=int(policy.get("max_json_depth", 500)),
        max_file_size_mb=int(policy.get("max_file_size_mb", 50)),
    )

    gazetteer = DynamicGazetteer()
    all_units: list[RecordUnit] = []
    file_units: dict[str, list[RecordUnit]] = {}

    # PASS 1: Extract record units, clues, and populate per-run gazetteer
    for item in ingested:
        if item.status != "sanitized":
            continue
        is_clean_ref = item.rel_path.startswith("clean/")
        units_for_file: list[RecordUnit] = []

        if item.fmt in ("csv", "tsv") and item.csv_rows is not None:
            headers, body = item.csv_rows[0], item.csv_rows[1:]
            month_first = any("MM/DD" in h for h in headers)
            for idx, row in enumerate(body):
                clues: dict[str, Any] = {}
                if not is_clean_ref:
                    _extract_clues_from_row(headers, row, month_first, clues, gazetteer)
                ru = RecordUnit(
                    file_rel=item.rel_path, out_rel=item.out_rel, loc=f"row:{idx}",
                    raw_text=item.delimiter.join(row), clues=clues,
                )
                units_for_file.append(ru)
                all_units.append(ru)

        elif item.fmt in ("json", "fhir") and item.parsed_json is not None:
            data = item.parsed_json
            is_doc = (
                not isinstance(data, dict)
                or data.get("resourceType") == "Bundle"
                or not any(isinstance(v, list) and v and all(isinstance(x, dict) for x in v) for v in data.values())
            )
            if is_doc:
                clues = {}
                if not is_clean_ref:
                    _extract_clues_from_json(data, clues, gazetteer)
                ru = RecordUnit(
                    file_rel=item.rel_path, out_rel=item.out_rel, loc="doc",
                    raw_text="", clues=clues,
                )
                units_for_file.append(ru)
                all_units.append(ru)
            else:
                for k, v in data.items():
                    if isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
                        ptr_k = k.replace("~", "~0").replace("/", "~1")
                        for idx, elem in enumerate(v):
                            clues = {}
                            if not is_clean_ref:
                                _extract_clues_from_json(elem, clues, gazetteer)
                            ru = RecordUnit(
                                file_rel=item.rel_path, out_rel=item.out_rel,
                                loc=f"/{ptr_k}/{idx}", raw_text="", clues=clues,
                            )
                            units_for_file.append(ru)
                            all_units.append(ru)
        else:
            clues = {}
            if not is_clean_ref:
                _extract_clues_from_text(item.text, clues, gazetteer)
            ru = RecordUnit(
                file_rel=item.rel_path, out_rel=item.out_rel, loc="doc",
                raw_text=item.text, clues=clues,
            )
            units_for_file.append(ru)
            all_units.append(ru)

        file_units[item.rel_path] = units_for_file

    gazetteer.build()
    link_records(all_units, keyring)

    # PASS 2: Sanitize, generalize, residual-scan, and write outputs
    stats = PipelineStats(files_total=len(ingested))
    records_out: list[dict] = []

    for item in ingested:
        if item.status != "sanitized":
            stats.files_quarantined += 1
            continue

        is_clean_ref = item.rel_path.startswith("clean/")
        if not is_clean_ref and _filename_has_pii(item.rel_path, gazetteer):
            p = Path(item.rel_path)
            token = keyring.safe_file_token(item.rel_path)
            item.out_rel = (p.parent / f"doc_{token}{p.suffix}").as_posix()
            item.filename_has_pii = True

        units = file_units.get(item.rel_path, [])

        if item.fmt in ("csv", "tsv") and item.csv_rows is not None:
            headers, body = item.csv_rows[0], item.csv_rows[1:]
            month_first = any("MM/DD" in h for h in headers)
            clean_headers = [
                redact_text(h, gazetteer=gazetteer, stats=stats) if not is_clean_ref else h
                for h in headers
            ]
            has_mrn_col = any(classify_field_name(h) == "MRN" for h in headers)

            buf = io.StringIO()
            writer = csv.writer(buf, delimiter=item.delimiter, lineterminator="\n")
            writer.writerow(clean_headers)

            for idx, row in enumerate(body):
                ru = units[idx]
                psn = ru.pseudonym
                shift_days = get_shift_for_record(keyring, ru.patient_key, f"{item.rel_path}:{idx}", max_shift)
                new_row: list[str] = []
                psn_written = False

                for h, cell in zip(headers, row):
                    if is_clean_ref:
                        new_row.append(cell)
                        continue
                    cls = classify_field_name(h)
                    val = cell.strip()
                    if not val:
                        new_row.append(cell)
                        continue
                    if cls == "CLINICIAN" or cls in ("DISTRICT", "TEHSIL", "GENDER"):
                        new_row.append(cell)
                    elif cls == "MRN":
                        if psn and not psn_written:
                            new_row.append(psn)
                            psn_written = True
                        else:
                            new_row.append("[MRN]")
                        stats.add_entity("MRN")
                    elif cls == "PATIENT_NAME":
                        if psn and not has_mrn_col and not psn_written:
                            new_row.append(psn)
                            psn_written = True
                        else:
                            new_row.append("[PATIENT_NAME]")
                        stats.add_entity("PATIENT_NAME")
                    elif cls == "RELATIVE_NAME":
                        new_row.append("[RELATIVE_NAME]")
                        stats.add_entity("RELATIVE_NAME")
                    elif cls in ("PHONE", "EMAIL", "AADHAAR", "ABHA_NUMBER", "PAN", "INSURANCE_ID"):
                        new_row.append(f"[{cls}]")
                        stats.add_entity(cls)
                    elif cls == "ADDRESS":
                        new_row.append("[ADDRESS]")
                        stats.add_entity("HOUSE")
                    elif cls == "VILLAGE":
                        new_row.append("[VILLAGE]")
                        stats.add_entity("VILLAGE")
                    elif cls == "PIN":
                        new_row.append(generalize_pin(val, pin_prefix))
                        stats.add_entity("PIN")
                    elif cls == "AGE":
                        m_as = _AGE_SEX_CELL_RE.match(normalize_text(val))
                        if m_as:
                            new_row.append(f"{age_to_band(int(m_as.group(1)), age_band_w)}{m_as.group(2)}")
                        elif normalize_text(val).isdigit():
                            new_row.append(age_to_band(int(normalize_text(val)), age_band_w))
                        else:
                            new_row.append(val)
                        stats.records_generalized += 1
                    elif cls in ("DOB", "DATE"):
                        new_row.append(shift_date_str(val, shift_days, month_first=month_first))
                        stats.records_generalized += 1
                    else:
                        cleaned = redact_text(cell, gazetteer=gazetteer, stats=stats, pseudonym=psn)
                        cleaned = shift_date_str(cleaned, shift_days, month_first=month_first)
                        cleaned, n_res = scan_and_scrub_residual(cleaned, gazetteer=gazetteer)
                        if n_res:
                            stats.add_entity("RESIDUAL", n_res)
                        new_row.append(cleaned)

                writer.writerow(new_row)
                records_out.append({
                    "file": f"sanitized/{item.out_rel}",
                    "loc": ru.loc,
                    "patient": psn,
                })
                stats.records_processed += 1
                if psn:
                    stats.records_linked += 1

            atomic_write_text(sanitized_dir / item.out_rel, buf.getvalue())
            stats.files_sanitized += 1

        elif item.fmt in ("json", "fhir") and item.parsed_json is not None:
            data = item.parsed_json
            if is_clean_ref:
                san_obj = data
                for ru in units:
                    records_out.append({"file": f"sanitized/{item.out_rel}", "loc": ru.loc, "patient": None})
                    stats.records_processed += 1
            elif len(units) == 1 and units[0].loc == "doc":
                ru = units[0]
                psn = ru.pseudonym
                shift_days = get_shift_for_record(keyring, ru.patient_key, item.rel_path, max_shift)
                san_obj = _sanitize_json_obj(
                    data, gazetteer, stats, psn, shift_days, age_band_w, pin_prefix
                )
                records_out.append({
                    "file": f"sanitized/{item.out_rel}",
                    "loc": "doc",
                    "patient": psn,
                })
                stats.records_processed += 1
                if psn:
                    stats.records_linked += 1
            else:
                # Top-level dict with list-of-dict records
                unit_by_loc = {u.loc: u for u in units}
                san_obj = {}
                for k, v in data.items():
                    if isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
                        ptr_k = k.replace("~", "~0").replace("/", "~1")
                        new_list = []
                        for idx, elem in enumerate(v):
                            loc = f"/{ptr_k}/{idx}"
                            ru = unit_by_loc[loc]
                            psn = ru.pseudonym
                            shift_days = get_shift_for_record(keyring, ru.patient_key, f"{item.rel_path}:{loc}", max_shift)
                            new_elem = _sanitize_json_obj(
                                elem, gazetteer, stats, psn, shift_days, age_band_w, pin_prefix
                            )
                            new_list.append(new_elem)
                            records_out.append({
                                "file": f"sanitized/{item.out_rel}",
                                "loc": loc,
                                "patient": psn,
                            })
                            stats.records_processed += 1
                            if psn:
                                stats.records_linked += 1
                        san_obj[k] = new_list
                    else:
                        san_obj[k] = _sanitize_json_obj(
                            v, gazetteer, stats, None, get_shift_for_record(keyring, None, item.rel_path, max_shift),
                            age_band_w, pin_prefix,
                        )

            out_json = json.dumps(san_obj, ensure_ascii=False, indent=2) + "\n"
            if not is_clean_ref:
                out_json, n_res = scan_and_scrub_residual(out_json, gazetteer=gazetteer)
                if n_res:
                    stats.add_entity("RESIDUAL", n_res)
            atomic_write_text(sanitized_dir / item.out_rel, out_json)
            stats.files_sanitized += 1

        else:
            ru = units[0]
            psn = ru.pseudonym
            if is_clean_ref:
                out_txt = item.text
            else:
                shift_days = get_shift_for_record(keyring, ru.patient_key, item.rel_path, max_shift)
                out_txt = redact_text(item.text, gazetteer=gazetteer, stats=stats, pseudonym=psn)
                out_txt = _AGE_INLINE_RE.sub(
                    lambda m: f"{m.group(1)}{age_to_band(int(m.group(2)), age_band_w)}{m.group(3)}",
                    out_txt,
                )
                out_txt = shift_date_str(out_txt, shift_days)
                out_txt, n_res = scan_and_scrub_residual(out_txt, gazetteer=gazetteer)
                if n_res:
                    stats.add_entity("RESIDUAL", n_res)
                if psn and psn not in out_txt:
                    out_txt = f"Patient: {psn}\n" + out_txt

            atomic_write_text(sanitized_dir / item.out_rel, out_txt)
            records_out.append({
                "file": f"sanitized/{item.out_rel}",
                "loc": "doc",
                "patient": psn,
            })
            stats.records_processed += 1
            if psn:
                stats.records_linked += 1
            stats.files_sanitized += 1

    write_records_jsonl(output_dir, records_out)
    elapsed = time.monotonic() - t0
    write_report(output_dir, ingested, stats, elapsed)

    print(
        f"files {stats.files_total} sanitized {stats.files_sanitized} "
        f"quarantined {stats.files_quarantined} records {stats.records_processed}"
    )
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="KAVACH-FHIR privacy firewall")
    ap.add_argument("--input", required=True, help="Input directory")
    ap.add_argument("--output", required=True, help="Output directory")
    args = ap.parse_args()

    here = Path(__file__).resolve().parent
    policy_path = here / "config" / "policy.yaml"
    return run_pipeline(Path(args.input), Path(args.output), policy_path)


if __name__ == "__main__":
    sys.exit(main())
