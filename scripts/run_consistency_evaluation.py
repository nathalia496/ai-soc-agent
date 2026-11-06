#!/usr/bin/env python3
"""
Extends the Task 9 evaluation (run_evaluation.py) with the two other axes
named in this project's own literature review for SOC-copilot evaluation:
report consistency and analyst agreement (alongside time saved, which
run_evaluation.py already measures).

This script does NOT score consistency or agreement itself - like
run_evaluation.py, it deliberately leaves that to a human: it runs
investigate_alert() N times per scenario and writes a worksheet for a person
to read and rate by hand. Automating a semantic-similarity score instead was
explicitly ruled out of scope for this first version.

What it does:
  1. Seeds the same 4 scenario fixtures run_evaluation.py uses.
  2. For each scenario, runs investigate_alert() N times (default 5) and
     saves each run's full report to results/consistency/<scenario>/run_<i>.json.
  3. Writes results/consistency_worksheet.md: for each scenario, the N
     hypothesis/timeline/next_steps side by side, with a blank "Consistency
     rating" field (1-3 scale) and a free-text notes field; plus one
     representative run (run_1) reproduced separately for "analyst agreement"
     rating, with a reminder not to open the scenario's runbook answer key
     until after rating.

Usage:
    python scripts/run_consistency_evaluation.py [--runs N]
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(Path(__file__).parent / "evaluation"))

import seed_fixtures  # noqa: E402

from src.core.config_storage import load_config_from_file  # noqa: E402
from src.integrations.attack.attack_mapper import AttackMapper  # noqa: E402
from src.integrations.llm.ollama_client import OllamaClient  # noqa: E402
from src.integrations.siem.elastic.elastic_client import ElasticSIEMClient  # noqa: E402
from src.orchestrator.investigate_alert import investigate_alert  # noqa: E402

RESULTS_DIR = Path(__file__).parent / "evaluation" / "results"
CONSISTENCY_DIR = RESULTS_DIR / "consistency"


def run_scenario_n_times(
    scenario: str,
    alert_id: str,
    runs: int,
    siem_client: ElasticSIEMClient,
    llm_client: OllamaClient,
    attack_mapper: AttackMapper,
) -> List[Dict[str, Any]]:
    """Run investigate_alert() `runs` times for one scenario, saving each result to disk."""
    scenario_dir = CONSISTENCY_DIR / scenario
    scenario_dir.mkdir(parents=True, exist_ok=True)

    results = []
    for i in range(1, runs + 1):
        print(f"  run {i}/{runs}...", end=" ", flush=True)
        start = time.perf_counter()
        try:
            result = investigate_alert(
                alert_id,
                siem_client=siem_client,
                llm_client=llm_client,
                attack_mapper=attack_mapper,
            )
            duration = round(time.perf_counter() - start, 3)
            print(f"ok ({duration}s)")
        except Exception as e:  # noqa: BLE001 - recorded, not re-raised
            duration = round(time.perf_counter() - start, 3)
            result = {"report": None, "warnings": [], "exception": f"{type(e).__name__}: {e}"}
            print(f"EXCEPTION: {result['exception']}")

        run_path = scenario_dir / f"run_{i}.json"
        with open(run_path, "w") as f:
            json.dump(result, f, indent=2, default=str)
        results.append(result)

    return results


def _format_report_block(label: str, result: Dict[str, Any]) -> str:
    report = result.get("report")
    if not report:
        return f"**{label}**: FAILED - {result.get('exception', 'no report')}\n"

    lines = [f"**{label}**", ""]
    lines.append(f"- Hypothesis: {report.get('hypothesis', '')}")
    lines.append(f"- Observables: {[o.get('value') for o in report.get('observables', [])]}")
    lines.append("- Next steps:")
    for step in report.get("next_steps", []):
        lines.append(f"  - {step}")
    lines.append("")
    return "\n".join(lines)


def write_worksheet(all_results: Dict[str, List[Dict[str, Any]]], fixtures_by_scenario: Dict[str, Dict[str, Any]]) -> Path:
    worksheet_path = RESULTS_DIR / "consistency_worksheet.md"

    with open(worksheet_path, "w") as f:
        f.write("# Consistency & analyst agreement rating worksheet\n\n")
        f.write(
            "For each scenario below: read the N runs' hypothesis/next_steps and fill in "
            "`Consistency rating` using this scale:\n\n"
            "- **1** = contradicts itself across runs\n"
            "- **2** = mostly consistent, minor wording differences\n"
            "- **3** = fully consistent core claim\n\n"
            "Then, for the single \"Analyst agreement\" run per scenario: read ONLY that report "
            "(not the scenario's runbook answer key) and decide whether the hypothesis matches what "
            "actually happened, before opening the runbook to check. Record pass/fail (or 1-5) "
            "in `Analyst agreement rating`. Only look at the runbook file named under each scenario "
            "after you've written your rating down.\n\n"
            "---\n\n"
        )

        for scenario, results in all_results.items():
            fixture = fixtures_by_scenario[scenario]
            f.write(f"## {scenario}\n\n")
            f.write(f"Runbook (answer key - **do not open until after rating**): `{fixture['runbook']}`\n\n")

            f.write("### Consistency across runs\n\n")
            for i, result in enumerate(results, start=1):
                f.write(_format_report_block(f"Run {i}", result))
            f.write("\n**Consistency rating (1-3):** ____\n\n")
            f.write("**Notes:** \n\n")

            f.write("### Analyst agreement (representative run: run 1)\n\n")
            f.write(_format_report_block("Run 1 (same as above)", results[0]))
            f.write("\n**Analyst agreement rating (pass/fail or 1-5):** ____\n\n")
            f.write("**Notes:** \n\n")
            f.write("---\n\n")

    return worksheet_path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=5, help="Number of runs per scenario (default: 5)")
    args = parser.parse_args()

    config = load_config_from_file()
    if not config.elastic:
        print("FAIL: no 'elastic' section configured in config.json.")
        return 1
    if not config.ollama:
        print("FAIL: no 'ollama' section configured in config.json.")
        return 1

    siem_client = ElasticSIEMClient.from_config(config)
    llm_client = OllamaClient.from_config(config)
    attack_mapper = AttackMapper()

    print("Seeding evaluation fixtures into OpenSearch...")
    fixtures = seed_fixtures.seed_all(siem_client)
    fixtures_by_scenario = {f["scenario"]: f for f in fixtures}

    all_results: Dict[str, List[Dict[str, Any]]] = {}
    for fixture in fixtures:
        scenario = fixture["scenario"]
        alert_id = fixture["alert_id"]
        print(f"\nRunning '{scenario}' (alert_id={alert_id}) {args.runs} times...")
        all_results[scenario] = run_scenario_n_times(
            scenario, alert_id, args.runs, siem_client, llm_client, attack_mapper
        )

    worksheet_path = write_worksheet(all_results, fixtures_by_scenario)
    print(f"\nRaw runs saved under {CONSISTENCY_DIR}/<scenario>/run_<i>.json")
    print(f"Rating worksheet written to {worksheet_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
