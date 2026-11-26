"""Cryptographic key derivation, HMAC pseudonymization, and secret-safe utilities."""
from __future__ import annotations

import hashlib
import hmac
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_CROCKFORD_B32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


class KeyRing:
    """Derives domain-separated keys from RAKSHA_SECRET using HKDF-SHA256."""

    def __init__(self, secret: bytes) -> None:
        if not secret:
            secret = b"default-empty-secret-fallback"
        self._pseudonym_key = self._derive(secret, b"kavach-fhir:pseudonym:v1", 32)
        self._date_shift_key = self._derive(secret, b"kavach-fhir:date-shift:v1", 32)
        self._filename_key = self._derive(secret, b"kavach-fhir:filename:v1", 32)
        self._temp_enc_key = self._derive(secret, b"kavach-fhir:temp-aesgcm:v1", 32)

    @staticmethod
    def _derive(secret: bytes, info: bytes, length: int) -> bytes:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=b"kavach-fhir-salt-v1",
            info=info,
        )
        return hkdf.derive(secret)

    @classmethod
    def from_env(cls) -> "KeyRing":
        raw = os.environ.get("RAKSHA_SECRET", "").encode("utf-8")
        return cls(raw)

    def pseudonym(self, canonical_patient_key: str, collision_salt: int = 0) -> str:
        """Generate a deterministic, non-reversible PSN-XXXXXX pseudonym."""
        msg = canonical_patient_key.encode("utf-8")
        if collision_salt:
            msg += f"|{collision_salt}".encode("utf-8")
        digest = hmac.new(self._pseudonym_key, msg, hashlib.sha256).digest()
        n = int.from_bytes(digest[:5], "big")
        code = "".join(_CROCKFORD_B32[(n >> (5 * i)) & 31] for i in range(6))
        return f"PSN-{code}"

    def date_shift_days(self, canonical_key: str, max_days: int = 180) -> int:
        """Deterministic non-zero date shift in [-max_days, +max_days]."""
        if max_days <= 0:
            return 1
        digest = hmac.new(self._date_shift_key, canonical_key.encode("utf-8"), hashlib.sha256).digest()
        val = int.from_bytes(digest[:4], "big") % (2 * max_days) - max_days
        return val if val != 0 else 1

    def safe_file_token(self, rel_path: str) -> str:
        """Deterministic 8-char hex token for renaming files whose names contain PII."""
        digest = hmac.new(self._filename_key, rel_path.encode("utf-8"), hashlib.sha256).digest()
        return digest[:4].hex()

    def encrypt_bytes(self, plaintext: bytes) -> bytes:
        """Encrypt temporary disk artifacts with AES-256-GCM (deterministic nonce-free not used here; random 96-bit nonce)."""
        nonce = os.urandom(12)
        aesgcm = AESGCM(self._temp_enc_key)
        return nonce + aesgcm.encrypt(nonce, plaintext, None)

    def decrypt_bytes(self, blob: bytes) -> bytes:
        nonce, ct = blob[:12], blob[12:]
        aesgcm = AESGCM(self._temp_enc_key)
        return aesgcm.decrypt(nonce, ct, None)
