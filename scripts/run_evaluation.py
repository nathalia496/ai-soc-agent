#!/usr/bin/env python3
"""
Runs investigate_alert() (the Task 6 orchestration pipeline) against the 4
hand-authored evaluation scenarios under scripts/evaluation/fixtures/ - one per
run_books/soc{1,2}/cases/*.md runbook - and records raw timing/schema metrics
for the TCC's evaluation chapter.

This script deliberately does NOT score whether a report's hypothesis is
"correct": that's a human judgment call (an analyst reads the printed report
and compares it against the known scenario). What it does check mechanically
is the report's *shape* - that it has the timeline/observables/hypothesis/
next_steps the rest of the pipeline (case comments, storage) depends on.

CTI (lookup_hash_ti) and MISP enrichment are left unconfigured here on purpose:
config.json's "cti"/"misp" sections only hold placeholder example.com URLs for
this local dev setup, and investigate_alert already degrades those to a
recorded warning instead of failing (see tests/orchestrator/test_investigate_
alert.py::TestBestEffortDegradation) - exercising that real CTI/MISP enrichment
only has value with the local OpenSearch + Ollama stack configured in this repo,
and leaving it off keeps this evaluation run local and deterministic.
ATT&CK mapping is enabled: the AttackMapper dataset is already cached locally
(data/attack/enterprise-attack.json), so it runs with no network dependency.

Usage:
    python scripts/run_evaluation.py
"""

from __future__ import annotations

import csv
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

# File is at: scripts/run_evaluation.py -> project root is one level up.
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(Path(__file__).parent / "evaluation"))

from src.core.config_storage import load_config_from_file  # noqa: E402
from src.integrations.attack.attack_mapper import AttackMapper  # noqa: E402
from src.integrations.llm.ollama_client import OllamaClient  # noqa: E402
from src.integrations.siem.elastic.elastic_client import ElasticSIEMClient  # noqa: E402
from src.orchestrator.investigate_alert import investigate_alert  # noqa: E402

import seed_fixtures  # noqa: E402

RESULTS_DIR = Path(__file__).parent / "evaluation" / "results"

REQUIRED_REPORT_KEYS = ("timeline", "observables", "hypothesis", "next_steps")


def validate_report_schema(report: Any) -> Tuple[bool, str]:
    """
    Check the report against the fixed schema: timeline/observables/hypothesis/
    next_steps. Returns (is_valid, reason) - reason is "" when valid, otherwise
    a short description of what's wrong.
    """
    if not isinstance(report, dict):
        return False, f"report is not a dict (got {type(report).__name__})"

    missing = [key for key in REQUIRED_REPORT_KEYS if key not in report]
    if missing:
        return False, f"missing key(s): {missing}"

    timeline = report["timeline"]
    if not isinstance(timeline, list) or not all(
        isinstance(e, dict) and "timestamp" in e and "description" in e for e in timeline
    ):
        return False, "timeline must be a list of {timestamp, description} objects"

    observables = report["observables"]
    if not isinstance(observables, list) or not all(
        isinstance(o, dict) and "type" in o and "value" in o for o in observables
    ):
        return False, "observables must be a list of {type, value} objects"

    if not isinstance(report["hypothesis"], str) or not report["hypothesis"].strip():
        return False, "hypothesis must be a non-empty string"

    next_steps = report["next_steps"]
    if not isinstance(next_steps, list) or not all(isinstance(s, str) for s in next_steps):
        return False, "next_steps must be a list of strings"

    return True, ""


def print_report(scenario: str, result: Dict[str, Any]) -> None:
    print("\n" + "=" * 80)
    print(f"REPORT: {scenario}")
    print("=" * 80)
    print(json.dumps(result.get("report"), indent=2, default=str))
    if result.get("warnings"):
        print("\nWarnings:")
        for warning in result["warnings"]:
            print(f"  - {warning}")


def run_evaluation() -> List[Dict[str, Any]]:
    config = load_config_from_file()
    if not config.elastic:
        print("FAIL: no 'elastic' section configured in config.json.")
        sys.exit(1)
    if not config.ollama:
        print("FAIL: no 'ollama' section configured in config.json.")
        sys.exit(1)

    siem_client = ElasticSIEMClient.from_config(config)
    llm_client = OllamaClient.from_config(config)
    attack_mapper = AttackMapper()

    print("Seeding evaluation fixtures into OpenSearch...")
    fixtures = seed_fixtures.seed_all(siem_client)
    for fixture in fixtures:
        print(f"  seeded '{fixture['scenario']}' as alert '{fixture['alert_id']}'")

    rows: List[Dict[str, Any]] = []
    for fixture in fixtures:
        scenario = fixture["scenario"]
        alert_id = fixture["alert_id"]
        print(f"\nInvestigating '{scenario}' (alert_id={alert_id})...")

        row: Dict[str, Any] = {
            "scenario": scenario,
            "alert_id": alert_id,
            "runbook": fixture["runbook"],
            "duration_seconds": None,
            "schema_valid": False,
            "schema_failure_reason": "",
            "warnings_count": None,
            "exception": "",
        }

        start = time.perf_counter()
        try:
            result = investigate_alert(
                alert_id,
                siem_client=siem_client,
                llm_client=llm_client,
                attack_mapper=attack_mapper,
            )
            row["duration_seconds"] = round(time.perf_counter() - start, 3)
            row["warnings_count"] = len(result.get("warnings") or [])

            is_valid, reason = validate_report_schema(result.get("report"))
            row["schema_valid"] = is_valid
            row["schema_failure_reason"] = reason

            print_report(scenario, result)
        except Exception as e:  # noqa: BLE001 - recorded, not re-raised, so one
            # bad scenario doesn't stop the rest of the evaluation run.
            row["duration_seconds"] = round(time.perf_counter() - start, 3)
            row["exception"] = f"{type(e).__name__}: {e}"
            print(f"  EXCEPTION: {row['exception']}")

        rows.append(row)

    return rows


def write_results(rows: List[Dict[str, Any]]) -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "scenario", "alert_id", "runbook", "duration_seconds",
        "schema_valid", "schema_failure_reason", "warnings_count", "exception",
    ]

    csv_path = RESULTS_DIR / "results.csv"
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    md_path = RESULTS_DIR / "results.md"
    with open(md_path, "w") as f:
        f.write(f"# Evaluation results\n\nGenerated: {datetime.now(timezone.utc).isoformat()}\n\n")
        f.write("| Scenario | Alert ID | Duration (s) | Schema Valid | Warnings | Exception |\n")
        f.write("|---|---|---|---|---|---|\n")
        for row in rows:
            f.write(
                f"| {row['scenario']} | {row['alert_id']} | {row['duration_seconds']} | "
                f"{row['schema_valid']}{' (' + row['schema_failure_reason'] + ')' if row['schema_failure_reason'] else ''} | "
                f"{row['warnings_count'] if row['warnings_count'] is not None else '-'} | "
                f"{row['exception'] or '-'} |\n"
            )

    print(f"\nResults written to {csv_path} and {md_path}")


def print_summary(rows: List[Dict[str, Any]]) -> None:
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    header = f"{'scenario':<32} {'duration_s':>10} {'schema_ok':>10} {'warnings':>9} {'exception':>10}"
    print(header)
    print("-" * len(header))
    for row in rows:
        print(
            f"{row['scenario']:<32} {row['duration_seconds']:>10} {str(row['schema_valid']):>10} "
            f"{row['warnings_count'] if row['warnings_count'] is not None else '-':>9} "
            f"{'yes' if row['exception'] else 'no':>10}"
        )


def main() -> int:
    rows = run_evaluation()
    print_summary(rows)
    write_results(rows)
    return 0


if __name__ == "__main__":
    sys.exit(main())
