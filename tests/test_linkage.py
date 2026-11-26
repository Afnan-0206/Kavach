"""Tests for conservative cross-script identity linkage and homonym separation."""
from __future__ import annotations

from engine.identity_linker import link_records
from engine.record_model import RecordUnit
from engine.security import KeyRing


def test_cross_script_linkage():
    kr = KeyRing(b"test-secret")
    u1 = RecordUnit("a.csv", "a.csv", "row:0", "", clues={"name": "Mohammad Shahid", "dob": "1986-05-10", "gender": "M"})
    u2 = RecordUnit("b.txt", "b.txt", "doc", "", clues={"name": "मोहम्मद शाहिद", "dob": "1986-05-10", "gender": "M"})
    link_records([u1, u2], kr)
    assert u1.pseudonym is not None
    assert u1.pseudonym == u2.pseudonym


def test_shared_phone_does_not_merge_different_people():
    kr = KeyRing(b"test-secret")
    u1 = RecordUnit("a.csv", "a.csv", "row:0", "", clues={"name": "Ramesh Kumar", "phone": "9876543210", "gender": "M", "age": 45})
    u2 = RecordUnit("b.csv", "b.csv", "row:1", "", clues={"name": "Sunita Devi", "phone": "9876543210", "gender": "F", "age": 42})
    link_records([u1, u2], kr)
    assert u1.pseudonym is not None and u2.pseudonym is not None
    assert u1.pseudonym != u2.pseudonym


def test_homonym_separation():
    kr = KeyRing(b"test-secret")
    u1 = RecordUnit("a.csv", "a.csv", "row:0", "", clues={"name": "Anita Sharma", "district": "Sitapur", "age": 30, "gender": "F", "mrns": ["SNJ/26/001"]})
    u2 = RecordUnit("b.csv", "b.csv", "row:1", "", clues={"name": "Anita Sharma", "district": "Hardoi", "age": 55, "gender": "F", "mrns": ["SNJ/26/002"]})
    link_records([u1, u2], kr)
    assert u1.pseudonym != u2.pseudonym
