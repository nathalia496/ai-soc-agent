#!/usr/bin/env python3
"""
Merges the Task 9 per-scenario results (results.csv, from run_evaluation.py)
with the Task 14 consistency runs (results/consistency/<scenario>/run_*.json,
from run_consistency_evaluation.py) into one extended table covering all four
evaluation dimensions: time saved, schema validity, report consistency, and
analyst agreement.

`consistency_rating` and `analyst_agreement_rating` are always written blank
(or left as whatever a human already typed into consistency_worksheet.md) -
this script only computes the one thing that's mechanically checkable (the
schema pass rate across the N consistency runs); the two rating columns are
filled in by hand by whoever reads consistency_worksheet.md and are then
pasted into results_extended.csv directly.

Usage:
    python scripts/build_extended_results.py
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Dict, List

RESULTS_DIR = Path(__file__).parent / "evaluation" / "results"
CONSISTENCY_DIR = RESULTS_DIR / "consistency"

FIELDNAMES = [
    "scenario", "alert_id", "duration_seconds", "schema_valid",
    "consistency_runs_schema_pass_rate", "consistency_rating",
    "analyst_agreement_rating", "notes",
]


def load_baseline_rows() -> List[Dict[str, Any]]:
    with open(RESULTS_DIR / "results.csv", newline="") as f:
        return list(csv.DictReader(f))


def schema_pass_rate(scenario: str) -> str:
    scenario_dir = CONSISTENCY_DIR / scenario
    if not scenario_dir.is_dir():
        return "n/a"
    run_files = sorted(scenario_dir.glob("run_*.json"))
    if not run_files:
        return "n/a"
    passed = 0
    for run_file in run_files:
        with open(run_file) as f:
            data = json.load(f)
        if data.get("report") is not None:
            passed += 1
    return f"{passed}/{len(run_files)}"


def main() -> int:
    baseline_rows = load_baseline_rows()

    rows = []
    for row in baseline_rows:
        rows.append({
            "scenario": row["scenario"],
            "alert_id": row["alert_id"],
            "duration_seconds": row["duration_seconds"],
            "schema_valid": row["schema_valid"],
            "consistency_runs_schema_pass_rate": schema_pass_rate(row["scenario"]),
            "consistency_rating": "",
            "analyst_agreement_rating": "",
            "notes": "",
        })

    csv_path = RESULTS_DIR / "results_extended.csv"
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)

    md_path = RESULTS_DIR / "results_extended.md"
    with open(md_path, "w") as f:
        f.write("# Extended evaluation results (time, schema, consistency, analyst agreement)\n\n")
        f.write(
            "| Scenario | Duration (s) | Schema Valid | Schema pass rate (N=5 consistency runs) "
            "| Consistency rating (1-3) | Analyst agreement | Notes |\n"
        )
        f.write("|---|---|---|---|---|---|---|\n")
        for row in rows:
            f.write(
                f"| {row['scenario']} | {row['duration_seconds']} | {row['schema_valid']} | "
                f"{row['consistency_runs_schema_pass_rate']} | {row['consistency_rating'] or '_pending_'} | "
                f"{row['analyst_agreement_rating'] or '_pending_'} | {row['notes']} |\n"
            )

    print(f"Wrote {csv_path} and {md_path}")
    print("Fill in consistency_rating / analyst_agreement_rating / notes from consistency_worksheet.md by hand.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
