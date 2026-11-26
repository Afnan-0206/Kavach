"""Tests for HKDF key derivation, AES-GCM temp encryption, and secret isolation."""
from __future__ import annotations

from pathlib import Path

import pytest

from engine.security import KeyRing
from main import run_pipeline


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


@pytest.mark.parametrize("bad_secret", [b"", b"   ", b"\t\n "])
def test_keyring_rejects_empty_or_whitespace_secret(bad_secret: bytes):
    with pytest.raises(ValueError, match="RAKSHA_SECRET"):
        KeyRing(bad_secret)


@pytest.mark.parametrize("env_val", [None, "", "   ", "\t\n"])
def test_from_env_and_pipeline_fail_closed_without_partial_output(
    tmp_path: Path, monkeypatch, env_val
):
    if env_val is None:
        monkeypatch.delenv("RAKSHA_SECRET", raising=False)
    else:
        monkeypatch.setenv("RAKSHA_SECRET", env_val)

    with pytest.raises(ValueError, match="RAKSHA_SECRET"):
        KeyRing.from_env()

    inp = tmp_path / "in"
    inp.mkdir()
    (inp / "note.txt").write_text("Name: Ramesh Kumar\n", encoding="utf-8")
    out = tmp_path / "out"
    policy = Path(__file__).resolve().parents[1] / "config" / "policy.yaml"

    with pytest.raises(ValueError, match="RAKSHA_SECRET"):
        run_pipeline(inp, out, policy)

    assert not out.exists()
