#!/usr/bin/env python3
"""KAVACH-FHIR: Offline, CPU-only, LLM-free healthcare privacy firewall."""
from __future__ import annotations

import argparse
import csv
import io
import json
import sys
import time
from pathlib import Path

import yaml

from engine.exporter import atomic_write_text, write_records_jsonl
from engine.ingestion import ingest_directory
from engine.record_model import PipelineStats
from engine.reporting import write_report
from engine.security import KeyRing


def load_policy(path: Path) -> dict:
    if not path.is_file():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def run_pipeline(input_dir: Path, output_dir: Path, policy_path: Path) -> int:
    t0 = time.monotonic()
    policy = load_policy(policy_path)
    _keyring = KeyRing.from_env()

    sanitized_dir = output_dir / "sanitized"
    sanitized_dir.mkdir(parents=True, exist_ok=True)

    sys.setrecursionlimit(5000)
    ingested = ingest_directory(
        input_dir,
        max_json_depth=int(policy.get("max_json_depth", 500)),
        max_file_size_mb=int(policy.get("max_file_size_mb", 50)),
    )

    stats = PipelineStats(files_total=len(ingested))
    records: list[dict] = []

    for item in ingested:
        if item.status != "sanitized":
            stats.files_quarantined += 1
            continue

        if item.fmt in ("csv", "tsv") and item.csv_rows is not None:
            buf = io.StringIO()
            writer = csv.writer(buf, delimiter=item.delimiter, lineterminator="\n")
            header, body = item.csv_rows[0], item.csv_rows[1:]
            writer.writerow(header)
            for idx, row in enumerate(body):
                writer.writerow(row)
                records.append({
                    "file": f"sanitized/{item.out_rel}",
                    "loc": f"row:{idx}",
                    "patient": None,
                })
                stats.records_processed += 1
            atomic_write_text(sanitized_dir / item.out_rel, buf.getvalue())
            stats.files_sanitized += 1

        elif item.fmt in ("json", "fhir") and item.parsed_json is not None:
            data = item.parsed_json
            is_doc = (
                not isinstance(data, dict)
                or data.get("resourceType") == "Bundle"
                or not any(isinstance(v, list) and v and all(isinstance(x, dict) for x in v) for v in data.values())
            )
            if is_doc:
                records.append({
                    "file": f"sanitized/{item.out_rel}",
                    "loc": "doc",
                    "patient": None,
                })
                stats.records_processed += 1
            else:
                for k, v in data.items():
                    if isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
                        ptr_k = k.replace("~", "~0").replace("/", "~1")
                        for idx, _ in enumerate(v):
                            records.append({
                                "file": f"sanitized/{item.out_rel}",
                                "loc": f"/{ptr_k}/{idx}",
                                "patient": None,
                            })
                            stats.records_processed += 1
            atomic_write_text(
                sanitized_dir / item.out_rel,
                json.dumps(data, ensure_ascii=False, indent=2) + "\n",
            )
            stats.files_sanitized += 1

        else:
            records.append({
                "file": f"sanitized/{item.out_rel}",
                "loc": "doc",
                "patient": None,
            })
            stats.records_processed += 1
            atomic_write_text(sanitized_dir / item.out_rel, item.text)
            stats.files_sanitized += 1

    write_records_jsonl(output_dir, records)
    elapsed = time.monotonic() - t0
    write_report(output_dir, ingested, stats, elapsed)

    print(
        f"files {stats.files_total} sanitized {stats.files_sanitized} "
        f"quarantined {stats.files_quarantined} records {stats.records_processed}"
    )
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="KAVACH-FHIR privacy firewall")
    ap.add_argument("--input", required=True, help="Input directory")
    ap.add_argument("--output", required=True, help="Output directory")
    args = ap.parse_args()

    here = Path(__file__).resolve().parent
    policy_path = here / "config" / "policy.yaml"
    return run_pipeline(Path(args.input), Path(args.output), policy_path)


if __name__ == "__main__":
    sys.exit(main())
