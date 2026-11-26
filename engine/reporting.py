"""Truthful report.json generator and resource measurement."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from engine.exporter import atomic_write_text
from engine.record_model import IngestedFile, PipelineStats


def peak_rss_mb() -> float:
    """Measure peak resident set size in MB (Linux/macOS via resource, Windows fallback)."""
    try:
        import resource
        r = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return round(r / 1024.0 if sys.platform != "darwin" else r / 1048576.0, 2)
    except Exception:
        pass
    if sys.platform == "win32":
        try:
            import ctypes
            from ctypes import wintypes

            class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
                _fields_ = [
                    ("cb", wintypes.DWORD),
                    ("PageFaultCount", wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t),
                ]

            pmc = PROCESS_MEMORY_COUNTERS()
            pmc.cb = ctypes.sizeof(pmc)
            handle = ctypes.windll.kernel32.GetCurrentProcess()
            if ctypes.windll.psapi.GetProcessMemoryInfo(handle, ctypes.byref(pmc), pmc.cb):
                return round(pmc.PeakWorkingSetSize / (1024 * 1024), 2)
        except Exception:
            pass
    return 0.0


def write_report(
    output_dir: Path,
    ingested_files: list[IngestedFile],
    stats: PipelineStats,
    elapsed_seconds: float,
) -> None:
    """Write report.json conforming to raksha-report/1."""
    file_entries = []
    for item in ingested_files:
        if item.status == "sanitized":
            file_entries.append({
                "input_sha256": item.sha256,
                "output": f"sanitized/{item.out_rel}",
                "status": "sanitized",
            })
        else:
            file_entries.append({
                "input_sha256": item.sha256,
                "output": None,
                "status": item.status,
                "reason": item.quarantine_reason or "quarantined",
            })

    report = {
        "schema": "raksha-report/1",
        "files": file_entries,
        "counts": {
            "files_total": stats.files_total,
            "files_sanitized": stats.files_sanitized,
            "files_quarantined": stats.files_quarantined,
            "records_processed": stats.records_processed,
            "identifiers_detected": stats.identifiers_detected,
            "records_linked": stats.records_linked,
            "records_generalized": stats.records_generalized,
            "records_suppressed": stats.records_suppressed,
            "records_quarantined": stats.records_quarantined,
        },
        "entities": dict(sorted(stats.entity_counts.items())),
        "timing": {"seconds": round(elapsed_seconds, 2)},
        "resources": {"peak_rss_mb": peak_rss_mb()},
    }
    atomic_write_text(output_dir / "report.json", json.dumps(report, indent=2) + "\n")
