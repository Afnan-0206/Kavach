#!/usr/bin/env python3
"""KAVACH-FHIR: Offline, CPU-only, LLM-free healthcare privacy firewall."""
from __future__ import annotations

import argparse
import base64
import binascii
import csv
import datetime as dt
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
    broaden_rare_diagnosis,
    choose_collision_safe_shift,
    extract_candidate_clinical_terms,
    extract_dates_in_text,
    generalize_hospital_name,
    generalize_pin,
    get_shift_for_record,
    jitter_los_dates,
    parse_date_flexible,
    shift_date_str,
    widen_age_band_20yr,
)
from engine.record_model import IngestedFile, PipelineStats, RecordUnit
from engine.reporting import write_report
from engine.security import KeyRing

_AGE_INLINE_RE = re.compile(
    r"(\b(?:Age(?:\s*/\s*Sex)?|आयु|उम्र)\s*[:\-]?\s*)(\d{1,3})(\s*(?:Yrs?|Years?|Y|वर्ष)?(?:\s*/\s*[MF])?)",
    re.IGNORECASE,
)
_AGE_SEX_CELL_RE = re.compile(
    r"^(\d{1,3})(\s*(?:Yrs?|Years?|Y|वर्ष|साल)?(?:\s*/\s*(?:[MF]|महिला|पुरुष))?)$",
    re.IGNORECASE,
)
_B64_RE = re.compile(r"^[A-Za-z0-9+/]{24,}={0,2}$")
_TEHSIL_INLINE_RE = re.compile(
    r"\b(?:Tehsil|Taluka|तहसील)\s+[A-Z\u0900-\u097F][A-Za-z\u0900-\u097F\s\-]{1,25}?(?=[,\n;]|$|\s+(?:Distt|District|PIN|State|जिला))",
    re.IGNORECASE,
)
_DISTRICT_INLINE_RE = re.compile(
    r"(?i)((?<![A-Za-z\u0900-\u097F])(?:District|Distt?\.?|Jila|जिला)[ \t]*[:\-][ \t]*)"
    r"([A-Za-z\u0900-\u097F][A-Za-z\u0900-\u097F \t]{1,30}?)"
    r"(?=[,\r\n;]|$|[ \t]+(?:Age|Gender|Sex|DOB|Date|Hospital|PIN|Tehsil|State|Phone|Mobile|Aadhaar|ABHA|MRN|UHID|Village|Gram|आयु|उम्र|लिंग|पिन|तहसील|राज्य|जन्म)(?![A-Za-z\u0900-\u097F]))"
)


def _suppress_tehsil_inline(text: str) -> str:
    return _TEHSIL_INLINE_RE.sub("[TEHSIL]", text) if text else text


def _generalize_district_inline(text: str) -> str:
    return _DISTRICT_INLINE_RE.sub(r"\1[REGION]", text) if text else text


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
    if "dob" not in clues:
        m_dob = re.search(r"(?i)(?:DOB|Date\s+of\s+Birth|जन्म\s*तिथि)\s*[:\-]\s*([^\n,;]+)", text)
        if m_dob:
            d = parse_date_flexible(m_dob.group(1))
            if d:
                clues["dob"] = d.isoformat()
    if "district" not in clues:
        m_dist = re.search(
            r"(?i)(?<![A-Za-z\u0900-\u097F])(?:District|Distt?\.?|Jila|जिला)[ \t]*[:\-][ \t]*"
            r"([A-Za-z\u0900-\u097F][A-Za-z\u0900-\u097F \t]{1,30}?)"
            r"(?=[,\r\n;]|$|[ \t]+(?:Age|Gender|Sex|DOB|Date|Hospital|PIN|Tehsil|State|Phone|Mobile|Aadhaar|ABHA|MRN|UHID|Village|Gram|आयु|उम्र|लिंग|पिन|तहसील|राज्य|जन्म)(?![A-Za-z\u0900-\u097F]))",
            text,
        )
        if m_dist:
            clues["district"] = m_dist.group(1).strip()
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
        ext_url = str(obj.get("url", "")).lower()
        if ext_url and isinstance(obj.get("valueString"), str):
            val_s = obj["valueString"].strip()
            if val_s and any(w in ext_url for w in ("mother", "father", "spouse", "relative", "guardian", "maiden")):
                clues.setdefault("relative", val_s)
                gazetteer.add_name(val_s)
            elif val_s and "name" in ext_url:
                clues.setdefault("name", val_s)
                gazetteer.add_name(val_s)
        for k, v in obj.items():
            cls = classify_field_name(k)
            if isinstance(v, (str, int, float)) and not isinstance(v, bool):
                sv = str(v).strip()
                if not sv:
                    continue
                if cls == "PATIENT_NAME" or (parent_key == "name" and k in ("text", "family", "given")):
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


def _component_has_pii(component: str, gazetteer: DynamicGazetteer | None) -> bool:
    """Return True if a single path component (directory name or filename stem) contains PII."""
    norm_raw = normalize_text(component)
    norm_space = normalize_text(re.sub(r"[_\-]+", " ", component))
    if (
        detect_phones(norm_raw)
        or detect_phones(norm_space)
        or detect_indian_ids(norm_raw)
        or detect_indian_ids(norm_space)
        or extract_dates_in_text(norm_raw)
        or extract_dates_in_text(norm_space)
    ):
        return True
    if gazetteer is not None and gazetteer.match(norm_space, []):
        return True
    if detect_contextual_names(norm_space, []):
        return True
    return False


def _selective_out_rel(
    rel_path: str,
    keyring: KeyRing,
    gazetteer: DynamicGazetteer | None,
    used_paths: set[str],
    dir_map: dict[str, str],
) -> tuple[str, bool]:
    """Preserve safe path components; deterministically rename only PII-bearing components."""
    p = Path(rel_path)
    any_renamed = False
    safe_parts: list[str] = []
    acc_parts: list[str] = []
    for part in p.parent.parts:
        if part in (".", ""):
            continue
        acc_parts.append(part)
        dir_key = "/".join(acc_parts)
        if _component_has_pii(part, gazetteer):
            any_renamed = True
            if dir_key not in dir_map:
                dir_map[dir_key] = f"dir_{keyring.safe_file_token(dir_key)}"
            safe_parts.append(dir_map[dir_key])
        else:
            safe_parts.append(part)

    ext = p.suffix.lower() if p.suffix else ""
    stem = p.stem
    if _component_has_pii(stem, gazetteer):
        any_renamed = True
        salt = 0
        while True:
            token = keyring.safe_file_token(rel_path, collision_salt=salt)
            candidate = "/".join(safe_parts + [f"doc_{token}{ext}"]) if safe_parts else f"doc_{token}{ext}"
            if candidate not in used_paths:
                used_paths.add(candidate)
                return candidate, any_renamed
            salt += 1

    candidate = "/".join(safe_parts + [p.name]) if safe_parts else p.name
    if candidate not in used_paths:
        used_paths.add(candidate)
        return candidate, any_renamed

    # Collision fallback if another file mapped to the same safe name
    salt = 0
    while True:
        token = keyring.safe_file_token(rel_path, collision_salt=salt)
        fallback = "/".join(safe_parts + [f"doc_{token}{ext}"]) if safe_parts else f"doc_{token}{ext}"
        if fallback not in used_paths:
            used_paths.add(fallback)
            return fallback, True
        salt += 1


def _sanitize_json_key(
    k: str,
    gazetteer: DynamicGazetteer,
    stats: PipelineStats,
    pseudonym: str | None,
    shift_days: int,
    use_clinical_shield: bool = True,
) -> str:
    """Sanitize PII or dates embedded inside JSON keys while preserving safe schema keys."""
    if not k:
        return k
    k_space = re.sub(r"_+", " ", k)
    k_flat = re.sub(r"[_\-]+", " ", k)
    k_has_dates = bool(extract_dates_in_text(k_space))
    k_has_pii = bool(
        detect_all_spans(k, gazetteer=gazetteer, use_clinical_shield=use_clinical_shield)
        or detect_all_spans(k_space, gazetteer=gazetteer, use_clinical_shield=use_clinical_shield)
        or detect_all_spans(k_flat, gazetteer=gazetteer, use_clinical_shield=use_clinical_shield)
    )
    if not k_has_dates and not k_has_pii:
        return k
    base = k_space if (k_has_dates or detect_all_spans(k_space, gazetteer=gazetteer, use_clinical_shield=use_clinical_shield)) else k_flat
    cleaned = redact_text(
        base, gazetteer=gazetteer, stats=stats, pseudonym=pseudonym,
        use_clinical_shield=use_clinical_shield,
    )
    cleaned = shift_date_str(cleaned, shift_days)
    return cleaned


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
    suppress_rare_pin: bool = True,
    suppress_village: bool = True,
    preserve_clinician_names: bool = True,
    use_clinical_shield: bool = True,
    widen_age: bool = False,
    generalize_district: bool = False,
    broaden_diagnosis: bool = False,
    rare_terms: set[str] | None = None,
    suppress_tehsil: bool = False,
    generalize_hospital: bool = False,
    los_jitter: tuple[KeyRing, str] | None = None,
) -> Any:
    if isinstance(obj, dict):
        rt = obj.get("resourceType")
        is_clinical_actor = in_fhir_practitioner_or_org or rt in ("Practitioner", "Organization")
        ext_url = str(obj.get("url", "")).lower()
        new_dict: dict[str, Any] = {}
        for k, v in obj.items():
            if not is_clinical_actor and k == "valueString" and isinstance(v, str) and ext_url:
                if any(w in ext_url for w in ("mother", "father", "spouse", "relative", "guardian", "maiden")):
                    new_dict[k] = "[RELATIVE_NAME]"
                    stats.add_entity("RELATIVE_NAME")
                    continue
                if "name" in ext_url:
                    new_dict[k] = pseudonym if pseudonym else "[PATIENT_NAME]"
                    stats.add_entity("PATIENT_NAME")
                    continue
                if any(w in ext_url for w in ("birthplace", "address", "village", "location")):
                    new_dict[k] = "[ADDRESS]"
                    stats.add_entity("HOUSE")
                    continue
            new_k = _sanitize_json_key(
                k, gazetteer, stats, pseudonym, shift_days, use_clinical_shield=use_clinical_shield
            )

            cls = classify_field_name(k)
            if is_clinical_actor and preserve_clinician_names and k in ("name", "text", "qualification", "address"):
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
                if cls == "PATIENT_NAME" or (not is_clinical_actor and parent_key == "name" and k in ("text", "family", "given")):
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
                    new_dict[new_k] = generalize_pin(sv, pin_prefix) if suppress_rare_pin else v
                    stats.add_entity("PIN")
                elif cls == "VILLAGE":
                    new_dict[new_k] = "[VILLAGE]" if suppress_village else v
                    stats.add_entity("VILLAGE")
                elif cls == "ADDRESS":
                    new_dict[new_k] = "[ADDRESS]"
                    stats.add_entity("HOUSE")
                elif cls == "AGE":
                    band_fn = widen_age_band_20yr if widen_age else (lambda a: age_to_band(a, age_band_w))
                    if isinstance(v, int):
                        new_dict[new_k] = band_fn(v)
                        stats.records_generalized += 1
                    elif isinstance(v, str):
                        nv = normalize_text(sv)
                        m_as = _AGE_SEX_CELL_RE.match(nv)
                        if m_as:
                            new_dict[new_k] = f"{band_fn(int(m_as.group(1)))}{m_as.group(2)}"
                            stats.records_generalized += 1
                        elif nv.isdigit():
                            new_dict[new_k] = band_fn(int(nv))
                            stats.records_generalized += 1
                        else:
                            new_dict[new_k] = _AGE_INLINE_RE.sub(
                                lambda m: f"{m.group(1)}{band_fn(int(m.group(2)))}{m.group(3)}",
                                redact_text(sv, gazetteer=gazetteer, stats=stats, pseudonym=pseudonym, use_clinical_shield=use_clinical_shield, pin_prefix=pin_prefix),
                            )
                elif cls in ("DOB", "DATE") or k in ("birthDate", "recordedDate", "authoredOn", "effectiveDateTime", "performedDateTime", "timestamp", "date", "start", "end"):
                    if isinstance(v, str):
                        new_dict[new_k] = shift_date_str(v, shift_days)
                    else:
                        new_dict[new_k] = v
                elif cls == "CLINICIAN":
                    new_dict[new_k] = v if preserve_clinician_names else "[CLINICIAN]"
                elif cls == "DISTRICT":
                    new_dict[new_k] = "[REGION]" if generalize_district else v
                elif cls == "TEHSIL":
                    new_dict[new_k] = "[TEHSIL]" if suppress_tehsil else v
                elif cls == "GENDER":
                    new_dict[new_k] = v
                elif k.lower() == "ward" and isinstance(v, str):
                    has_res_sibling = any(
                        classify_field_name(sk) in ("PATIENT_NAME", "RELATIVE_NAME", "ADDRESS", "VILLAGE", "PIN", "PHONE", "AADHAAR", "ABHA_NUMBER", "MRN")
                        for sk in obj.keys()
                        if sk != k
                    )
                    if not has_res_sibling and re.fullmatch(r"\s*(?:Ward\s+\d+(?:\s*\([^)]+\))?|[A-Za-z\s]{2,30})\s*", sv, re.I) and not re.search(r"\b(?:No\.?|Mohalla|Colony|Nagar|Sector|Gali|Street|Lane|Road|PIN)\b", sv, re.I):
                        new_dict[new_k] = v
                    else:
                        cleaned = redact_text(v, gazetteer=gazetteer, stats=stats, pseudonym=pseudonym, use_clinical_shield=use_clinical_shield)
                        new_dict[new_k] = shift_date_str(cleaned, shift_days)
                elif isinstance(v, str):
                    # Base64 attachment or free-text string
                    if _B64_RE.match(v.strip()):
                        try:
                            dec = base64.b64decode(v.strip() + "=" * (-len(v.strip()) % 4)).decode("utf-8", errors="strict")
                            if dec and sum(ch.isprintable() or ch in "\r\n\t" for ch in dec) / len(dec) >= 0.85:
                                cleaned = redact_text(dec, gazetteer=gazetteer, stats=stats, pseudonym=pseudonym, use_clinical_shield=use_clinical_shield)
                                cleaned = shift_date_str(cleaned, shift_days)
                                new_dict[new_k] = base64.b64encode(cleaned.encode("utf-8")).decode("ascii")
                                continue
                        except (binascii.Error, UnicodeDecodeError, ValueError):
                            pass
                    cleaned = redact_text(v, gazetteer=gazetteer, stats=stats, pseudonym=pseudonym, use_clinical_shield=use_clinical_shield, pin_prefix=pin_prefix)
                    if broaden_diagnosis:
                        cleaned = broaden_rare_diagnosis(cleaned, rare_terms=rare_terms)
                    if generalize_hospital:
                        cleaned = generalize_hospital_name(cleaned)
                    if suppress_tehsil:
                        cleaned = _suppress_tehsil_inline(cleaned)
                    if los_jitter is not None:
                        cleaned = jitter_los_dates(cleaned, los_jitter[0], los_jitter[1], shift_days)
                    else:
                        cleaned = shift_date_str(cleaned, shift_days)
                    new_dict[new_k] = cleaned
                else:
                    new_dict[new_k] = v
            else:
                new_dict[new_k] = _sanitize_json_obj(
                    v, gazetteer, stats, pseudonym, shift_days, age_band_w, pin_prefix,
                    in_fhir_practitioner_or_org=is_clinical_actor, parent_key=k,
                    suppress_rare_pin=suppress_rare_pin, suppress_village=suppress_village,
                    preserve_clinician_names=preserve_clinician_names, use_clinical_shield=use_clinical_shield,
                    widen_age=widen_age, generalize_district=generalize_district, broaden_diagnosis=broaden_diagnosis,
                    rare_terms=rare_terms, suppress_tehsil=suppress_tehsil,
                    generalize_hospital=generalize_hospital, los_jitter=los_jitter,
                )
        return new_dict
    elif isinstance(obj, list):
        return [
            _sanitize_json_obj(
                x, gazetteer, stats, pseudonym, shift_days, age_band_w, pin_prefix,
                in_fhir_practitioner_or_org=in_fhir_practitioner_or_org, parent_key=parent_key,
                suppress_rare_pin=suppress_rare_pin, suppress_village=suppress_village,
                preserve_clinician_names=preserve_clinician_names, use_clinical_shield=use_clinical_shield,
                widen_age=widen_age, generalize_district=generalize_district, broaden_diagnosis=broaden_diagnosis,
                rare_terms=rare_terms, suppress_tehsil=suppress_tehsil,
                generalize_hospital=generalize_hospital, los_jitter=los_jitter,
            )
            for x in obj
        ]
    elif isinstance(obj, str):
        cleaned = redact_text(obj, gazetteer=gazetteer, stats=stats, pseudonym=pseudonym, use_clinical_shield=use_clinical_shield, pin_prefix=pin_prefix)
        if broaden_diagnosis:
            cleaned = broaden_rare_diagnosis(cleaned, rare_terms=rare_terms)
        if generalize_hospital:
            cleaned = generalize_hospital_name(cleaned)
        if suppress_tehsil:
            cleaned = _suppress_tehsil_inline(cleaned)
        if los_jitter is not None:
            return jitter_los_dates(cleaned, los_jitter[0], los_jitter[1], shift_days)
        return shift_date_str(cleaned, shift_days)
    return obj


def run_pipeline(input_dir: Path, output_dir: Path, policy_path: Path) -> int:
    t0 = time.monotonic()
    policy = load_policy(policy_path)
    keyring = KeyRing.from_env()
    age_band_w = int(policy.get("age_band_years", 5))
    max_shift = int(policy.get("date_shift_max_days", 180))
    pin_prefix = int(policy.get("pin_prefix_digits", 3))
    suppress_rare_pin = bool(policy.get("suppress_rare_pin", True))
    suppress_village = bool(policy.get("suppress_village", True))
    preserve_clinician_names = bool(policy.get("preserve_clinician_names", True))
    use_clinical_shield = bool(policy.get("preserve_clinical_values", True))
    linkage_auto_merge_threshold = float(policy.get("linkage_auto_merge_threshold", 0.88))
    linkage_min_independent_clues = int(policy.get("linkage_min_independent_clues", 2))
    min_group_size = int(policy.get("min_group_size", 5))
    qi_enabled = bool(policy.get("qi_generalization_enabled", True))
    qi_widen_pin = bool(policy.get("qi_widen_pin", True))
    qi_suppress_k1_pin = bool(policy.get("qi_suppress_k1_pin", True))
    qi_widen_age_band = bool(policy.get("qi_widen_age_band", True))
    qi_suppress_small_tehsil = bool(policy.get("qi_suppress_small_tehsil", True))
    qi_jitter_high_risk_los = bool(policy.get("qi_jitter_high_risk_los", True))
    qi_gen_district = bool(policy.get("qi_generalize_rare_district", False))
    qi_gen_hospital = bool(policy.get("qi_generalize_rare_hospital", False))
    qi_gen_diag = bool(policy.get("qi_generalize_rare_diagnosis", False))
    qi_rare_max_profiles = int(policy.get("qi_rare_condition_max_profiles", 3))

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
    used_out_paths: set[str] = set()
    protected_dobs: set[dt.date] = set()

    def _collect_json_dates(obj: Any, out_dates: set[dt.date]) -> None:
        if isinstance(obj, dict):
            for v in obj.values():
                _collect_json_dates(v, out_dates)
        elif isinstance(obj, list):
            for v in obj:
                _collect_json_dates(v, out_dates)
        elif isinstance(obj, str):
            out_dates.update(extract_dates_in_text(obj))

    # PASS 1: Extract clues, dates, and protected DOBs
    top_json_meta_dates: dict[str, set[dt.date]] = {}
    for item in ingested:
        if item.status != "sanitized":
            continue
        units_for_file: list[RecordUnit] = []

        if item.fmt in ("csv", "tsv") and item.csv_rows is not None:
            headers, body = item.csv_rows[0], item.csv_rows[1:]
            month_first = any("MM/DD" in h for h in headers)
            for idx, row in enumerate(body):
                clues: dict[str, Any] = {}
                row_dates: set[dt.date] = set()
                _extract_clues_from_row(headers, row, month_first, clues, gazetteer)
                if clues.get("dob"):
                    protected_dobs.add(dt.date.fromisoformat(clues["dob"]))
                for cell in row:
                    row_dates.update(extract_dates_in_text(cell, month_first=month_first))
                ru = RecordUnit(
                    file_rel=item.rel_path, out_rel=item.out_rel, loc=f"row:{idx}",
                    raw_text=item.delimiter.join(row), clues=clues,
                    structured_fields={"dates": row_dates},
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
                doc_dates: set[dt.date] = set()
                _extract_clues_from_json(data, clues, gazetteer)
                if clues.get("dob"):
                    protected_dobs.add(dt.date.fromisoformat(clues["dob"]))
                _collect_json_dates(data, doc_dates)
                ru = RecordUnit(
                    file_rel=item.rel_path, out_rel=item.out_rel, loc="doc",
                    raw_text="", clues=clues,
                    structured_fields={"dates": doc_dates},
                )
                units_for_file.append(ru)
                all_units.append(ru)
            else:
                meta_dates: set[dt.date] = set()
                for k, v in data.items():
                    if isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
                        ptr_k = k.replace("~", "~0").replace("/", "~1")
                        for idx, elem in enumerate(v):
                            clues = {}
                            elem_dates: set[dt.date] = set()
                            _extract_clues_from_json(elem, clues, gazetteer)
                            if clues.get("dob"):
                                protected_dobs.add(dt.date.fromisoformat(clues["dob"]))
                            _collect_json_dates(elem, elem_dates)
                            ru = RecordUnit(
                                file_rel=item.rel_path, out_rel=item.out_rel,
                                loc=f"/{ptr_k}/{idx}", raw_text="", clues=clues,
                                structured_fields={"dates": elem_dates},
                            )
                            units_for_file.append(ru)
                            all_units.append(ru)
                    else:
                        _collect_json_dates(v, meta_dates)
                if meta_dates:
                    top_json_meta_dates[f"unlinked|{item.rel_path}:meta"] = meta_dates
        else:
            clues = {}
            txt_dates: set[dt.date] = set()
            _extract_clues_from_text(item.text, clues, gazetteer)
            if clues.get("dob"):
                protected_dobs.add(dt.date.fromisoformat(clues["dob"]))
            txt_dates.update(extract_dates_in_text(item.text))
            ru = RecordUnit(
                file_rel=item.rel_path, out_rel=item.out_rel, loc="doc",
                raw_text=item.text, clues=clues,
                structured_fields={"dates": txt_dates},
            )
            units_for_file.append(ru)
            all_units.append(ru)

        file_units[item.rel_path] = units_for_file

    gazetteer.build()
    dir_map: dict[str, str] = {}
    for item in ingested:
        if item.status != "sanitized":
            continue
        item.out_rel, item.filename_has_pii = _selective_out_rel(
            item.rel_path, keyring, gazetteer, used_out_paths, dir_map
        )
        for ru in file_units.get(item.rel_path, []):
            ru.out_rel = item.out_rel
    link_records(
        all_units,
        keyring,
        auto_merge_threshold=linkage_auto_merge_threshold,
        min_independent_clues=linkage_min_independent_clues,
    )

    # Risk-aware equivalence-class sizing across distinct patients/unlinked units
    ec_counts: dict[tuple[str, str, str], int] = {}
    unit_qi_key: dict[int, tuple[str, str, str]] = {}
    cluster_qi: dict[str, tuple[str, str, str]] = {}
    for ru in all_units:
        c = ru.clues
        if c.get("age") is None and not c.get("district"):
            continue
        ab = age_to_band(int(c["age"]), age_band_w) if c.get("age") is not None else ""
        gk = c.get("gender", "")
        dk = normalize_text(c.get("district", "")).strip().lower()
        qkey = (ab, gk, dk)
        unit_qi_key[id(ru)] = qkey
        pid_key = ru.patient_key if ru.patient_key else f"unlinked|{ru.file_rel}:{ru.loc}"
        if pid_key not in cluster_qi:
            cluster_qi[pid_key] = qkey
            ec_counts[qkey] = ec_counts.get(qkey, 0) + 1
    small_ec_units: set[int] = set()
    k1_units: set[int] = set()
    if qi_enabled:
        for ru in all_units:
            pid_key = ru.patient_key if ru.patient_key else f"unlinked|{ru.file_rel}:{ru.loc}"
            qkey = cluster_qi.get(pid_key) or unit_qi_key.get(id(ru))
            if qkey is None:
                continue
            cnt = ec_counts.get(qkey, 0)
            if cnt < min_group_size:
                small_ec_units.add(id(ru))
            if cnt == 1:
                k1_units.add(id(ru))

    # Dataset-wide rare clinical terms (occurring in <= qi_rare_condition_max_profiles distinct profiles)
    rare_terms: set[str] | None = None
    if qi_gen_diag:
        term_profiles: dict[str, set[str]] = {}
        for ru in all_units:
            pid_key = ru.patient_key if ru.patient_key else f"unlinked|{ru.file_rel}:{ru.loc}"
            txt_src = ru.raw_text
            if not txt_src:
                item_obj = next((x for x in ingested if x.rel_path == ru.file_rel), None)
                if item_obj and item_obj.parsed_json is not None:
                    txt_src = json.dumps(item_obj.parsed_json, ensure_ascii=False)
            for term in extract_candidate_clinical_terms(txt_src):
                term_profiles.setdefault(term, set()).add(pid_key)
        rare_terms = {t for t, profs in term_profiles.items() if len(profs) <= qi_rare_max_profiles}

    # Resolve collision-safe patient-level date shifts across the entire dataset
    dates_by_shift_key: dict[str, set[dt.date]] = dict(top_json_meta_dates)
    for ru in all_units:
        skey = ru.patient_key if ru.patient_key else f"unlinked|{ru.file_rel}:{ru.loc}"
        dates_by_shift_key.setdefault(skey, set()).update(ru.structured_fields.get("dates", set()))
    safe_shifts: dict[str, int] = {
        skey: choose_collision_safe_shift(keyring, skey, dset, protected_dobs, max_shift)
        for skey, dset in sorted(dates_by_shift_key.items())
    }

    # PASS 2: Sanitize, generalize, residual-scan, and write outputs
    stats = PipelineStats(files_total=len(ingested))
    records_out: list[dict] = []

    for item in ingested:
        if item.status != "sanitized":
            stats.files_quarantined += 1
            continue

        units = file_units.get(item.rel_path, [])

        if item.fmt in ("csv", "tsv") and item.csv_rows is not None:
            headers, body = item.csv_rows[0], item.csv_rows[1:]
            month_first = any("MM/DD" in h for h in headers)
            clean_headers = [
                redact_text(h, gazetteer=gazetteer, stats=stats, use_clinical_shield=use_clinical_shield)
                for h in headers
            ]
            has_mrn_col = any(classify_field_name(h) == "MRN" for h in headers)

            buf = io.StringIO()
            writer = csv.writer(buf, delimiter=item.delimiter, lineterminator="\n")
            writer.writerow(clean_headers)

            for idx, row in enumerate(body):
                ru = units[idx]
                psn = ru.pseudonym
                is_small_ec = id(ru) in small_ec_units
                is_k1 = id(ru) in k1_units
                eff_pin_prefix = (
                    0 if (is_k1 and qi_suppress_k1_pin)
                    else (max(1, pin_prefix - 1) if (is_small_ec and qi_widen_pin) else pin_prefix)
                )
                eff_widen_age = is_small_ec and qi_widen_age_band
                eff_gen_dist = is_small_ec and qi_gen_district
                eff_suppress_tehsil = is_small_ec and qi_suppress_small_tehsil
                eff_gen_hosp = is_small_ec and qi_gen_hospital
                eff_broaden_diag = is_small_ec and qi_gen_diag
                eff_jitter_los = is_small_ec and qi_jitter_high_risk_los
                band_fn = widen_age_band_20yr if eff_widen_age else (lambda a: age_to_band(a, age_band_w))
                skey = ru.patient_key if ru.patient_key else f"unlinked|{ru.file_rel}:{ru.loc}"
                shift_days = safe_shifts.get(skey, get_shift_for_record(keyring, ru.patient_key, f"{item.rel_path}:{idx}", max_shift))
                new_row: list[str] = []
                psn_written = False

                for h, cell in zip(headers, row):
                    cls = classify_field_name(h)
                    val = cell.strip()
                    if not val:
                        new_row.append(cell)
                        continue
                    if cls == "GENDER":
                        new_row.append(cell)
                    elif cls == "TEHSIL":
                        new_row.append("[TEHSIL]" if eff_suppress_tehsil else cell)
                    elif cls == "DISTRICT":
                        new_row.append("[REGION]" if eff_gen_dist else cell)
                    elif cls == "CLINICIAN":
                        new_row.append(cell if preserve_clinician_names else "[CLINICIAN]")
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
                        new_row.append("[VILLAGE]" if suppress_village else cell)
                        stats.add_entity("VILLAGE")
                    elif cls == "PIN":
                        new_row.append(generalize_pin(val, eff_pin_prefix) if suppress_rare_pin else cell)
                        stats.add_entity("PIN")
                    elif cls == "AGE":
                        m_as = _AGE_SEX_CELL_RE.match(normalize_text(val))
                        if m_as:
                            new_row.append(f"{band_fn(int(m_as.group(1)))}{m_as.group(2)}")
                        elif normalize_text(val).isdigit():
                            new_row.append(band_fn(int(normalize_text(val))))
                        else:
                            new_row.append(val)
                        stats.records_generalized += 1
                    elif cls in ("DOB", "DATE"):
                        new_row.append(shift_date_str(val, shift_days, month_first=month_first))
                        stats.records_generalized += 1
                    else:
                        cleaned = redact_text(cell, gazetteer=gazetteer, stats=stats, pseudonym=psn, use_clinical_shield=use_clinical_shield, pin_prefix=eff_pin_prefix)
                        if eff_broaden_diag:
                            cleaned = broaden_rare_diagnosis(cleaned, rare_terms=rare_terms)
                        if eff_gen_hosp:
                            cleaned = generalize_hospital_name(cleaned)
                        if eff_suppress_tehsil:
                            cleaned = _suppress_tehsil_inline(cleaned)
                        if eff_jitter_los:
                            cleaned = jitter_los_dates(cleaned, keyring, skey, shift_days, month_first=month_first)
                        else:
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
            if len(units) == 1 and units[0].loc == "doc":
                ru = units[0]
                psn = ru.pseudonym
                is_small_ec = id(ru) in small_ec_units
                is_k1 = id(ru) in k1_units
                eff_pin_prefix = (
                    0 if (is_k1 and qi_suppress_k1_pin)
                    else (max(1, pin_prefix - 1) if (is_small_ec and qi_widen_pin) else pin_prefix)
                )
                skey = ru.patient_key if ru.patient_key else f"unlinked|{ru.file_rel}:{ru.loc}"
                shift_days = safe_shifts.get(skey, get_shift_for_record(keyring, ru.patient_key, item.rel_path, max_shift))
                san_obj = _sanitize_json_obj(
                    data, gazetteer, stats, psn, shift_days, age_band_w, eff_pin_prefix,
                    suppress_rare_pin=suppress_rare_pin, suppress_village=suppress_village,
                    preserve_clinician_names=preserve_clinician_names, use_clinical_shield=use_clinical_shield,
                    widen_age=(is_small_ec and qi_widen_age_band),
                    generalize_district=(is_small_ec and qi_gen_district),
                    broaden_diagnosis=(is_small_ec and qi_gen_diag),
                    rare_terms=rare_terms,
                    suppress_tehsil=(is_small_ec and qi_suppress_small_tehsil),
                    generalize_hospital=(is_small_ec and qi_gen_hospital),
                    los_jitter=(keyring, skey) if (is_small_ec and qi_jitter_high_risk_los) else None,
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
                meta_skey = f"unlinked|{item.rel_path}:meta"
                meta_shift = safe_shifts.get(meta_skey, get_shift_for_record(keyring, None, f"{item.rel_path}:meta", max_shift))
                san_obj = {}
                for k, v in data.items():
                    if isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
                        ptr_k = k.replace("~", "~0").replace("/", "~1")
                        new_list = []
                        for idx, elem in enumerate(v):
                            loc = f"/{ptr_k}/{idx}"
                            ru = unit_by_loc[loc]
                            psn = ru.pseudonym
                            is_small_ec = id(ru) in small_ec_units
                            is_k1 = id(ru) in k1_units
                            eff_pin_prefix = (
                                0 if (is_k1 and qi_suppress_k1_pin)
                                else (max(1, pin_prefix - 1) if (is_small_ec and qi_widen_pin) else pin_prefix)
                            )
                            skey = ru.patient_key if ru.patient_key else f"unlinked|{ru.file_rel}:{ru.loc}"
                            shift_days = safe_shifts.get(skey, get_shift_for_record(keyring, ru.patient_key, f"{item.rel_path}:{loc}", max_shift))
                            new_elem = _sanitize_json_obj(
                                elem, gazetteer, stats, psn, shift_days, age_band_w, eff_pin_prefix,
                                suppress_rare_pin=suppress_rare_pin, suppress_village=suppress_village,
                                preserve_clinician_names=preserve_clinician_names, use_clinical_shield=use_clinical_shield,
                                widen_age=(is_small_ec and qi_widen_age_band),
                                generalize_district=(is_small_ec and qi_gen_district),
                                broaden_diagnosis=(is_small_ec and qi_gen_diag),
                                rare_terms=rare_terms,
                                suppress_tehsil=(is_small_ec and qi_suppress_small_tehsil),
                                generalize_hospital=(is_small_ec and qi_gen_hospital),
                                los_jitter=(keyring, skey) if (is_small_ec and qi_jitter_high_risk_los) else None,
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
                        new_k = _sanitize_json_key(
                            k, gazetteer, stats, None, meta_shift, use_clinical_shield=use_clinical_shield
                        )
                        san_obj[new_k] = _sanitize_json_obj(
                            v, gazetteer, stats, None, meta_shift,
                            age_band_w, pin_prefix,
                            suppress_rare_pin=suppress_rare_pin, suppress_village=suppress_village,
                            preserve_clinician_names=preserve_clinician_names, use_clinical_shield=use_clinical_shield,
                        )

            out_json = json.dumps(san_obj, ensure_ascii=False, indent=2) + "\n"
            out_json, n_res = scan_and_scrub_residual(out_json, gazetteer=gazetteer)
            if n_res:
                stats.add_entity("RESIDUAL", n_res)
            atomic_write_text(sanitized_dir / item.out_rel, out_json)
            stats.files_sanitized += 1

        else:
            ru = units[0]
            psn = ru.pseudonym
            is_small_ec = id(ru) in small_ec_units
            is_k1 = id(ru) in k1_units
            eff_pin_prefix = (
                0 if (is_k1 and qi_suppress_k1_pin)
                else (max(1, pin_prefix - 1) if (is_small_ec and qi_widen_pin) else pin_prefix)
            )
            band_fn = widen_age_band_20yr if (is_small_ec and qi_widen_age_band) else (lambda a: age_to_band(a, age_band_w))
            skey = ru.patient_key if ru.patient_key else f"unlinked|{ru.file_rel}:{ru.loc}"
            shift_days = safe_shifts.get(skey, get_shift_for_record(keyring, ru.patient_key, item.rel_path, max_shift))
            out_txt = redact_text(item.text, gazetteer=gazetteer, stats=stats, pseudonym=psn, use_clinical_shield=use_clinical_shield, pin_prefix=eff_pin_prefix)
            if is_small_ec and qi_gen_diag:
                out_txt = broaden_rare_diagnosis(out_txt, rare_terms=rare_terms)
            if is_small_ec and qi_gen_hospital:
                out_txt = generalize_hospital_name(out_txt)
            if is_small_ec and qi_gen_district:
                out_txt = _generalize_district_inline(out_txt)
            if is_small_ec and qi_suppress_small_tehsil:
                out_txt = _suppress_tehsil_inline(out_txt)
            out_txt = _AGE_INLINE_RE.sub(
                lambda m: f"{m.group(1)}{band_fn(int(m.group(2)))}{m.group(3)}",
                out_txt,
            )
            if is_small_ec and qi_jitter_high_risk_los:
                out_txt = jitter_los_dates(out_txt, keyring, skey, shift_days)
            else:
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
    inp_path = Path(args.input.strip("'\""))
    out_path = Path(args.output.strip("'\""))
    try:
        return run_pipeline(inp_path, out_path, policy_path)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
