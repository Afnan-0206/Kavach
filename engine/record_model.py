"""Core data models for KAVACH-FHIR pipeline."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class EntitySpan:
    """Detected PII or protected clinical span within a text."""
    start: int
    end: int
    entity_type: str
    text: str
    channel: str = "content"
    confidence: float = 1.0
    role: str = "patient"  # patient, relative, clinician, clinical


@dataclass
class RecordUnit:
    """A single patient-bearing record unit (CSV row, JSON pointer, or whole document)."""
    file_rel: str
    out_rel: str
    loc: str
    raw_text: str
    out_loc: str | None = None
    patient_key: str | None = None
    pseudonym: str | None = None
    status: str = "sanitized"  # sanitized, generalized, suppressed
    clues: dict[str, Any] = field(default_factory=dict)
    structured_fields: dict[str, Any] = field(default_factory=dict)


@dataclass
class IngestedFile:
    """Represents one input file after resilient ingestion."""
    rel_path: str
    out_rel: str
    sha256: str
    ext: str
    fmt: str  # csv, tsv, json, fhir, txt, quarantined
    encoding: str = "utf-8"
    delimiter: str = ","
    text: str = ""
    parsed_json: Any = None
    csv_rows: list[list[str]] | None = None
    status: str = "sanitized"  # sanitized, quarantined, suppressed
    quarantine_reason: str | None = None
    filename_has_pii: bool = False


@dataclass
class PipelineStats:
    """Truthful runtime counters for report.json."""
    files_total: int = 0
    files_sanitized: int = 0
    files_quarantined: int = 0
    records_processed: int = 0
    identifiers_detected: int = 0
    records_linked: int = 0
    records_generalized: int = 0
    records_suppressed: int = 0
    records_quarantined: int = 0
    entity_counts: dict[str, int] = field(default_factory=dict)

    def add_entity(self, etype: str, count: int = 1) -> None:
        self.identifiers_detected += count
        self.entity_counts[etype] = self.entity_counts.get(etype, 0) + count
