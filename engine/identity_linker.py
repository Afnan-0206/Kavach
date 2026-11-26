"""Conservative, cross-script patient identity resolution and cluster validation."""
from __future__ import annotations

import re
from collections import defaultdict
from rapidfuzz import fuzz

from engine.normalization import name_phonetic_tokens, normalize_person_name, normalize_text
from engine.record_model import RecordUnit
from engine.security import KeyRing


def _norm_digits(val: str) -> str:
    return re.sub(r"\D", "", normalize_text(val))


def _norm_mrn(val: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", normalize_text(val).upper())


def _name_similarity(n1: str, n2: str) -> float:
    """Cross-script phonetic + fuzzy name similarity in [0, 1]."""
    if not n1 or not n2:
        return 0.0
    t1 = name_phonetic_tokens(n1)
    t2 = name_phonetic_tokens(n2)
    if not t1 or not t2:
        return 0.0
    s1 = " ".join(sorted(t1))
    s2 = " ".join(sorted(t2))
    if s1 == s2:
        return 1.0
    # Single-token (first name only) vs full name
    if len(t1) == 1 or len(t2) == 1:
        single = t1[0] if len(t1) == 1 else t2[0]
        other = t2 if len(t1) == 1 else t1
        best = max(fuzz.ratio(single, o) / 100.0 for o in other)
        return best * 0.90  # slightly discounted because single token
    return fuzz.token_sort_ratio(s1, s2) / 100.0


_GENERIC_MRN_PREFIXES = {"UHID", "MRN", "PAT", "REG", "IPD", "OPD", "ADM", "IP", "SMP", "LAB"}


def _cannot_link(c1: dict, c2: dict) -> bool:
    """Return True if two clue dicts have contradictory evidence (must NEVER merge)."""
    g1, g2 = c1.get("gender"), c2.get("gender")
    if g1 and g2 and g1 != g2:
        return True

    a1, a2 = c1.get("age"), c2.get("age")
    if a1 is not None and a2 is not None and abs(a1 - a2) > 3:
        return True

    d1, d2 = c1.get("dob"), c2.get("dob")
    if d1 and d2 and d1 != d2:
        return True

    for id_key in ("aadhaar", "abha", "pan"):
        v1, v2 = c1.get(id_key), c2.get(id_key)
        if v1 and v2 and v1 != v2:
            return True

    has_verified_gov_id_match = any(
        c1.get(k) and c2.get(k) and c1[k] == c2[k]
        for k in ("aadhaar", "abha", "pan")
    )

    # Different MRNs from the same facility-specific prefix (e.g., SNJ- vs SNJ-, JJH- vs JJH-).
    # Generic prefixes (UHID, MRN, PAT, REG) are used by unrelated hospitals and must not block linkage,
    # and verified government ID matches override facility-prefix conflicts.
    if not has_verified_gov_id_match:
        m1s = {_norm_mrn(x) for x in c1.get("mrns", ()) if x}
        m2s = {_norm_mrn(x) for x in c2.get("mrns", ()) if x}
        if m1s and m2s and m1s.isdisjoint(m2s):
            p1 = {
                re.match(r"^[A-Z]+", m).group(0)
                for m in m1s
                if re.match(r"^[A-Z]+", m) and re.match(r"^[A-Z]+", m).group(0) not in _GENERIC_MRN_PREFIXES
            }
            p2 = {
                re.match(r"^[A-Z]+", m).group(0)
                for m in m2s
                if re.match(r"^[A-Z]+", m) and re.match(r"^[A-Z]+", m).group(0) not in _GENERIC_MRN_PREFIXES
            }
            if p1 & p2:
                return True

    d1, d2 = c1.get("district"), c2.get("district")
    if d1 and d2 and normalize_person_name(d1) != normalize_person_name(d2):
        return True

    n1, n2 = c1.get("name"), c2.get("name")
    if n1 and n2:
        t1, t2 = name_phonetic_tokens(n1), name_phonetic_tokens(n2)
        if len(t1) >= 2 and len(t2) >= 2 and _name_similarity(n1, n2) < 0.45:
            return True

    return False


class _DisjointSet:
    def __init__(self, n: int, clues_list: list[dict]) -> None:
        self.parent = list(range(n))
        self.members: dict[int, list[int]] = {i: [i] for i in range(n)}
        self.clues = clues_list

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def try_union(self, a: int, b: int) -> bool:
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return False
        # Cluster-wide cannot-link check to prevent transitive over-merging
        for ma in self.members[ra]:
            for mb in self.members[rb]:
                if _cannot_link(self.clues[ma], self.clues[mb]):
                    return False
        if len(self.members[ra]) < len(self.members[rb]):
            ra, rb = rb, ra
        self.parent[rb] = ra
        self.members[ra].extend(self.members[rb])
        del self.members[rb]
        return True


def link_records(
    units: list[RecordUnit],
    keyring: KeyRing,
    auto_merge_threshold: float = 0.80,
    min_independent_clues: int = 2,
) -> None:
    """Conservatively cluster RecordUnits and assign deterministic HMAC pseudonyms."""
    n = len(units)
    if n == 0:
        return
    clues_list = [u.clues for u in units]
    dsu = _DisjointSet(n, clues_list)

    # 1. Blocking by strong unique identifiers (excluding phone alone)
    strong_blocks: dict[tuple[str, str], list[int]] = defaultdict(list)
    phone_blocks: dict[str, list[int]] = defaultdict(list)
    name_token_blocks: dict[str, list[int]] = defaultdict(list)

    for idx, c in enumerate(clues_list):
        for k in ("aadhaar", "abha", "pan", "email", "insurance_id"):
            val = c.get(k)
            if val:
                strong_blocks[(k, val)].append(idx)
        for mrn in c.get("mrns", ()):
            strong_blocks[("mrn", _norm_mrn(mrn))].append(idx)
        if c.get("phone"):
            phone_blocks[_norm_digits(c["phone"])[-10:]].append(idx)
        if c.get("name"):
            for tok in name_phonetic_tokens(c["name"]):
                if len(tok) >= 3:
                    name_token_blocks[tok].append(idx)

    # Merge on strong identifiers (with cannot-link guard)
    for idxs in strong_blocks.values():
        if len(idxs) > 1:
            base = idxs[0]
            for other in idxs[1:]:
                dsu.try_union(base, other)

    # Merge on shared phone ONLY when corroborated by name, DOB, or relative
    for idxs in phone_blocks.values():
        if len(idxs) < 2:
            continue
        for i in range(len(idxs)):
            for j in range(i + 1, len(idxs)):
                a, b = idxs[i], idxs[j]
                ca, cb = clues_list[a], clues_list[b]
                sim = _name_similarity(ca.get("name", ""), cb.get("name", ""))
                rel_sim = _name_similarity(ca.get("relative", ""), cb.get("relative", ""))
                dob_ok = bool(ca.get("dob") and cb.get("dob") and ca["dob"] == cb["dob"])
                if sim >= 0.72 or rel_sim >= 0.80 or dob_ok:
                    dsu.try_union(a, b)

    # Merge on name + independent corroborating clue (DOB, relative, or village+age)
    candidate_pairs: set[tuple[int, int]] = set()
    for idxs in name_token_blocks.values():
        if 1 < len(idxs) <= 40:
            for i in range(len(idxs)):
                for j in range(i + 1, len(idxs)):
                    a, b = idxs[i], idxs[j]
                    if a > b:
                        a, b = b, a
                    candidate_pairs.add((a, b))

    for a, b in sorted(candidate_pairs):
        if dsu.find(a) == dsu.find(b):
            continue
        ca, cb = clues_list[a], clues_list[b]
        sim = _name_similarity(ca.get("name", ""), cb.get("name", ""))
        if sim < min(0.80, auto_merge_threshold):
            continue

        corroborations = 0
        if ca.get("dob") and cb.get("dob") and ca["dob"] == cb["dob"]:
            corroborations += 2
        if ca.get("relative") and cb.get("relative"):
            if _name_similarity(ca["relative"], cb["relative"]) >= 0.80:
                corroborations += 2
        if ca.get("village") and cb.get("village"):
            if normalize_person_name(ca["village"]) == normalize_person_name(cb["village"]):
                if ca.get("age") is not None and cb.get("age") is not None and abs(ca["age"] - cb["age"]) <= 2:
                    corroborations += 1
        if ca.get("district") and cb.get("district"):
            if normalize_person_name(ca["district"]) == normalize_person_name(cb["district"]):
                if ca.get("age") is not None and cb.get("age") is not None and abs(ca["age"] - cb["age"]) <= 1:
                    if ca.get("gender") and cb.get("gender") and ca["gender"] == cb["gender"]:
                        corroborations += 1

        if corroborations >= min_independent_clues:
            dsu.try_union(a, b)

    # Assign deterministic canonical key and collision-checked HMAC pseudonym per cluster
    used_pseudonyms: set[str] = set()
    used_canon_keys: set[str] = set()
    for root, members in sorted(dsu.members.items()):
        # Determine if this cluster has enough identity evidence to deserve a pseudonym
        has_evidence = any(
            clues_list[m].get(k)
            for m in members
            for k in ("aadhaar", "abha", "pan", "email", "mrns", "name", "phone")
        )
        if not has_evidence:
            continue

        # Build canonical key from strongest sorted evidence in cluster
        evidence_parts: list[str] = []
        for key_name in ("aadhaar", "abha", "pan", "email"):
            vals = sorted({clues_list[m][key_name] for m in members if clues_list[m].get(key_name)})
            if vals:
                evidence_parts.append(f"{key_name}:{vals[0]}")
                break
        if not evidence_parts:
            mrns = sorted({_norm_mrn(x) for m in members for x in clues_list[m].get("mrns", ()) if x})
            if mrns:
                evidence_parts.append(f"mrn:{mrns[0]}")
        if not evidence_parts:
            names = sorted({normalize_person_name(clues_list[m]["name"]) for m in members if clues_list[m].get("name")})
            dobs = sorted({clues_list[m]["dob"] for m in members if clues_list[m].get("dob")})
            rels = sorted({normalize_person_name(clues_list[m]["relative"]) for m in members if clues_list[m].get("relative")})
            if names:
                evidence_parts.append(f"name:{names[0]}")
            if dobs:
                evidence_parts.append(f"dob:{dobs[0]}")
            elif rels:
                evidence_parts.append(f"rel:{rels[0]}")

        if not evidence_parts:
            continue

        canon_key = "|".join(evidence_parts)
        if canon_key in used_canon_keys:
            canon_key = f"{canon_key}|cluster:{root}"
        used_canon_keys.add(canon_key)

        salt = 0
        psn = keyring.pseudonym(canon_key, salt)
        while psn in used_pseudonyms:
            salt += 1
            psn = keyring.pseudonym(canon_key, salt)
        used_pseudonyms.add(psn)

        for m in members:
            units[m].patient_key = canon_key
            units[m].pseudonym = psn
