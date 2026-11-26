"""Tests for HKDF key derivation, AES-GCM temp encryption, and secret isolation."""
from __future__ import annotations

from engine.security import KeyRing


def test_hkdf_domain_separation_and_secret_sensitivity():
    k1 = KeyRing(b"secret-alpha")
    k2 = KeyRing(b"secret-beta")
    assert k1.pseudonym("pt-1") == k1.pseudonym("pt-1")
    assert k1.pseudonym("pt-1") != k2.pseudonym("pt-1")
    assert k1.date_shift_days("pt-1") != k2.date_shift_days("pt-1")


def test_aes_gcm_roundtrip():
    kr = KeyRing(b"secret-alpha")
    ct = kr.encrypt_bytes(b"sensitive-payload")
    assert b"sensitive-payload" not in ct
    assert kr.decrypt_bytes(ct) == b"sensitive-payload"
