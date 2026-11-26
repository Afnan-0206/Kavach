"""Unicode, homoglyph, digit, and cross-script transliteration normalization."""
from __future__ import annotations

import re
import unicodedata

from indic_transliteration import sanscript
from indic_transliteration.sanscript import transliterate

# Zero-width and invisible formatting characters
_ZERO_WIDTH_RE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060\ufeff\u00ad]")

# Common Cyrillic and Greek homoglyphs -> Latin ASCII
_HOMOGLYPHS = str.maketrans({
    "А": "A", "а": "a", "В": "B", "Е": "E", "е": "e", "Ё": "E", "ё": "e",
    "З": "3", "К": "K", "к": "k", "М": "M", "Н": "H", "О": "O", "о": "o",
    "Р": "P", "р": "p", "С": "C", "с": "c", "Т": "T", "У": "Y", "у": "y",
    "Х": "X", "х": "x", "І": "I", "і": "i", "Ј": "J", "ј": "j", "Ѕ": "S",
    "Α": "A", "α": "a", "Β": "B", "Ε": "E", "ε": "e", "Ζ": "Z", "Η": "H",
    "Ι": "I", "ι": "i", "Κ": "K", "κ": "k", "Μ": "M", "Ν": "N", "Ο": "O",
    "ο": "o", "Ρ": "P", "ρ": "p", "Τ": "T", "Υ": "Y", "Χ": "X", "χ": "x",
})

# Devanagari digits -> ASCII
_INDIC_DIGITS = str.maketrans("०१२३४५६७८९", "0123456789")

_HONORIFICS_RE = re.compile(
    r"\b(?:mr|mrs|ms|miss|smt|shri|shree|kumari|km|ji|sahab|saheb|didi|bhai|behenji|bhaiyya|babu)\.?\b",
    re.IGNORECASE,
)
_DEVA_HONORIFICS_RE = re.compile(r"(?:^|\s)(?:श्री|श्रीमती|कुमारी|जी|साहब|साहिब|दीदी|भाई)(?=\s|$)")

_NAME_PREFIX_ALIASES = {
    "md": "mohammad",
    "mohd": "mohammad",
    "mohammed": "mohammad",
    "muhammad": "mohammad",
    "muhammed": "mohammad",
    "mahammad": "mohammad",
    "sk": "shaikh",
    "sheikh": "shaikh",
}


def normalize_text(text: str) -> str:
    """Normalize NFKC, strip zero-width chars, fold homoglyphs, and convert Indic digits."""
    if not text:
        return ""
    if text.isascii():
        return text
    s = unicodedata.normalize("NFKC", text)
    s = _ZERO_WIDTH_RE.sub("", s)
    s = s.translate(_HOMOGLYPHS)
    s = s.translate(_INDIC_DIGITS)
    return s


def strip_diacritics(text: str) -> str:
    """Remove combining diacritical marks from Latin text."""
    nfd = unicodedata.normalize("NFD", text)
    return "".join(ch for ch in nfd if unicodedata.category(ch) != "Mn")


def has_devanagari(text: str) -> bool:
    return any("\u0900" <= ch <= "\u097f" for ch in text)


def deva_to_latin(text: str) -> str:
    """Transliterate Devanagari text to approximate ASCII Latin."""
    if not has_devanagari(text):
        return text
    try:
        # ITRANS produces readable ASCII; clean up schwa/case artifacts
        out = transliterate(text, sanscript.DEVANAGARI, sanscript.ITRANS)
        out = out.replace("~N", "n").replace("~n", "n").replace("N^", "n")
        out = out.replace("Ch", "ch").replace("shh", "sh").replace("Sh", "sh")
        out = re.sub(r"[^A-Za-z0-9\s]", " ", out)
        return " ".join(out.lower().split())
    except Exception:
        return text


def latin_to_deva(text: str) -> str:
    """Best-effort transliteration of simple Latin name to Devanagari."""
    try:
        return transliterate(text.lower(), sanscript.ITRANS, sanscript.DEVANAGARI)
    except Exception:
        return ""


def phonetic_key(token: str) -> str:
    """Indian phonetic normalization for cross-script / spelling-variant matching."""
    t = strip_diacritics(normalize_text(token)).lower().strip()
    if has_devanagari(t):
        t = deva_to_latin(t)
    t = re.sub(r"[^a-z]", "", t)
    if not t:
        return ""
    if t in _NAME_PREFIX_ALIASES:
        t = _NAME_PREFIX_ALIASES[t]
    # Common Indian transliteration equivalences
    t = t.replace("ph", "f").replace("bh", "b").replace("gh", "g").replace("kh", "k")
    t = t.replace("th", "t").replace("dh", "d").replace("sh", "s").replace("ch", "c")
    t = t.replace("ee", "i").replace("oo", "u").replace("aa", "a")
    t = t.replace("v", "w").replace("z", "j").replace("q", "k")
    # Collapse consecutive duplicate letters
    t = re.sub(r"(.)\1+", r"\1", t)
    # Drop trailing schwa 'a' for Devanagari-to-Latin alignment (e.g., rama vs ram)
    if len(t) > 3 and t.endswith("a"):
        t = t[:-1]
    return t


def normalize_person_name(name: str) -> str:
    """Canonical lowercase Latin name with honorifics removed and aliases expanded."""
    s = normalize_text(name)
    s = _DEVA_HONORIFICS_RE.sub(" ", s)
    if has_devanagari(s):
        s = deva_to_latin(s)
    s = strip_diacritics(s).lower()
    s = _HONORIFICS_RE.sub(" ", s)
    s = re.sub(r"[^a-z\s]", " ", s)
    tokens = []
    for tok in s.split():
        tokens.append(_NAME_PREFIX_ALIASES.get(tok, tok))
    return " ".join(tokens)


def name_phonetic_tokens(name: str) -> list[str]:
    """Return sorted list of phonetic keys for non-trivial tokens in a person name."""
    norm = normalize_person_name(name)
    keys = [phonetic_key(t) for t in norm.split() if len(t) >= 2]
    return [k for k in keys if k]
