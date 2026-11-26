"""Tests for date shifting, age banding, and PIN generalization."""
from __future__ import annotations

from engine.privacy_engine import age_to_band, generalize_pin, shift_date_str
from engine.security import KeyRing


def test_age_bands_contain_true_age():
    for age in (0, 4, 5, 46, 48, 84, 85, 97):
        band = age_to_band(age, 5)
        if band == "85+":
            assert age >= 85
        else:
            lo, hi = (int(x) for x in band.split("-"))
            assert lo <= age <= hi


def test_date_shift_preserves_length_of_stay():
    kr = KeyRing(b"test-secret")
    shift = kr.date_shift_days("patient-1", 180)
    adm = shift_date_str("02/01/2026", shift, month_first=False)
    dis = shift_date_str("11/01/2026", shift, month_first=False)
    # Both shifted by exact same offset -> 9-day gap preserved
    from engine.privacy_engine import parse_date_flexible
    d1 = parse_date_flexible(adm, month_first=False)
    d2 = parse_date_flexible(dis, month_first=False)
    assert d1 is not None and d2 is not None
    assert (d2 - d1).days == 9


def test_month_first_date_shift():
    assert shift_date_str("04/20/1979", 10, month_first=True) == "04/30/1979"


def test_pin_generalization():
    assert generalize_pin("229073", 3) == "229***"
