"""Privacy transformations: deterministic date shifting, age banding, location generalization."""
from __future__ import annotations

import datetime as dt
import re

from engine.normalization import normalize_text
from engine.security import KeyRing

# ISO date: 2026-02-15
_ISO_DATE_RE = re.compile(r"\b(19\d{2}|20\d{2})-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])\b")
# Slash/dash date: DD/MM/YYYY or MM/DD/YYYY
_DMY_DATE_RE = re.compile(r"\b(0?[1-9]|[12]\d|3[01])[/-](0?[1-9]|[12]\d|3[01])[/-](19\d{2}|20\d{2})\b")


def parse_date_flexible(text: str, month_first: bool = False) -> dt.date | None:
    """Parse ISO or DD/MM/YYYY (or MM/DD/YYYY) dates safely."""
    s = normalize_text(text).strip()
    m = _ISO_DATE_RE.search(s)
    if m:
        try:
            return dt.date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
        except ValueError:
            return None
    m = _DMY_DATE_RE.search(s)
    if m:
        a, b, y = int(m.group(1)), int(m.group(2)), int(m.group(3))
        try:
            if month_first:
                if a <= 12 and b <= 31:
                    return dt.date(y, a, b)
            if b <= 12 and a <= 31:
                return dt.date(y, b, a)
            if a <= 12 and b <= 31:
                return dt.date(y, a, b)
        except ValueError:
            return None
    return None


def shift_date_str(
    text: str,
    shift_days: int,
    month_first: bool = False,
) -> str:
    """Shift dates in a string deterministically while preserving format."""
    if not text:
        return text

    def _repl_iso(m: re.Match) -> str:
        try:
            d = dt.date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
            nd = d + dt.timedelta(days=shift_days)
            return nd.strftime("%Y-%m-%d")
        except ValueError:
            return m.group(0)

    def _repl_dmy(m: re.Match) -> str:
        a, b, y = int(m.group(1)), int(m.group(2)), int(m.group(3))
        sep = "/" if "/" in m.group(0) else "-"
        try:
            if month_first and a <= 12:
                d = dt.date(y, a, b)
                nd = d + dt.timedelta(days=shift_days)
                return f"{nd.month:02d}{sep}{nd.day:02d}{sep}{nd.year:04d}"
            elif b <= 12:
                d = dt.date(y, b, a)
                nd = d + dt.timedelta(days=shift_days)
                return f"{nd.day:02d}{sep}{nd.month:02d}{sep}{nd.year:04d}"
            elif a <= 12:
                d = dt.date(y, a, b)
                nd = d + dt.timedelta(days=shift_days)
                return f"{nd.month:02d}{sep}{nd.day:02d}{sep}{nd.year:04d}"
        except ValueError:
            pass
        return m.group(0)

    out = _ISO_DATE_RE.sub(_repl_iso, text)
    out = _DMY_DATE_RE.sub(_repl_dmy, out)
    return out


def age_to_band(age: int, band_width: int = 5) -> str:
    """Convert integer age into a truthful band containing the true age."""
    if age < 0:
        return "0-4"
    if age >= 85:
        return "85+"
    lo = (age // band_width) * band_width
    return f"{lo}-{lo + band_width - 1}"


def generalize_pin(pin: str, prefix_digits: int = 3) -> str:
    """Generalize a 6-digit Indian PIN code to its 3-digit prefix (e.g., 229***)."""
    digits = re.sub(r"\D", "", normalize_text(pin))
    if len(digits) == 6:
        return digits[:prefix_digits] + "*" * (6 - prefix_digits)
    return "[PIN]"


def get_shift_for_record(
    keyring: KeyRing,
    patient_key: str | None,
    fallback_id: str,
    max_days: int = 180,
) -> int:
    """Get deterministic date shift for a patient (or record-scoped if unlinked)."""
    key = patient_key if patient_key else f"unlinked|{fallback_id}"
    return keyring.date_shift_days(key, max_days=max_days)
