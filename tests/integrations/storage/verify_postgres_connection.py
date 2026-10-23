#!/usr/bin/env python3
"""
Standalone verification script for the PostgreSQL storage integration.

This does NOT use pytest - it's a small, readable end-to-end smoke test you
run by hand against a local PostgreSQL instance (e.g. the one started by
`docker compose up -d postgres`).

It verifies the full path this project relies on:
1. Connects to PostgreSQL using the same config.json / PostgresClient code
   path the MCP server uses.
2. Ensures the investigation_reports table exists.
3. Writes a sample investigation report row.
4. Reads it back via get_report and confirms the fields round-trip.
5. Confirms it shows up via list_reports.

Usage:
    python tests/integrations/storage/verify_postgres_connection.py
    python tests/integrations/storage/verify_postgres_connection.py --cleanup
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# File is at: tests/integrations/storage/verify_postgres_connection.py
# Need to go up 4 levels: storage -> integrations -> tests -> project root
project_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(project_root))

from src.core.config_storage import load_config_from_file  # noqa: E402
from src.integrations.storage.postgres_client import PostgresClient  # noqa: E402

TEST_ALERT_ID = "verify-alert-0001"
TEST_CASE_ID = "verify-case-0001"
TEST_REPORT = {
    "timeline": [{"timestamp": "2024-01-01T00:00:00Z", "description": "Synthetic verification event"}],
    "observables": [{"type": "ip", "value": "10.10.10.50"}],
    "hypothesis": "Synthetic report created by verify_postgres_connection.py",
    "next_steps": ["No action needed - this is a verification record"],
}
TEST_WARNINGS = ["This report was created for verification purposes only"]


def step(title: str) -> None:
    print("\n" + "=" * 80)
    print(title)
    print("=" * 80)


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify the PostgreSQL storage integration")
    parser.add_argument(
        "--cleanup",
        action="store_true",
        help="Delete the test row created by this script when done",
    )
    args = parser.parse_args()

    print("=" * 80)
    print("POSTGRESQL STORAGE INTEGRATION VERIFICATION")
    print("=" * 80)

    # ---- Load config ----
    step("STEP 1: Load configuration")
    try:
        config = load_config_from_file()
    except Exception as e:
        print(f"FAIL: could not load configuration: {e}")
        return 1

    if not config.postgres:
        print("FAIL: no 'postgres' section configured in config.json.")
        print("Add a 'postgres' section pointing at your PostgreSQL instance, e.g.:")
        print(json.dumps({
            "postgres": {
                "host": "localhost",
                "port": 5432,
                "database": "soc_copilot",
                "user": "soc_user",
                "password": "soc_password",
            }
        }, indent=2))
        return 1

    print(f"OK: host={config.postgres.host}, port={config.postgres.port}, database={config.postgres.database}")

    # ---- Build client & connect ----
    step("STEP 2: Connect to PostgreSQL and ensure the investigation_reports table exists")
    try:
        storage_client = PostgresClient.from_config(config)
        storage_client.ensure_table()
        print("OK: connected and investigation_reports table is present")
    except Exception as e:
        print(f"FAIL: could not connect to PostgreSQL at {config.postgres.host}:{config.postgres.port}: {e}")
        import traceback
        traceback.print_exc()
        return 1

    # ---- Write a sample report ----
    step("STEP 3: Save a sample investigation report")
    try:
        saved = storage_client.save_report(
            alert_id=TEST_ALERT_ID,
            case_id=TEST_CASE_ID,
            report=TEST_REPORT,
            warnings=TEST_WARNINGS,
        )
        report_id = saved["id"]
        print(f"OK: saved report id={report_id}")
        print(json.dumps(saved, indent=2, default=str))
    except Exception as e:
        print(f"FAIL: could not save report: {e}")
        import traceback
        traceback.print_exc()
        return 1

    # ---- Read it back ----
    step("STEP 4: Read the report back via get_report")
    try:
        fetched = storage_client.get_report(report_id)
        if fetched is None:
            print(f"FAIL: get_report({report_id}) returned None")
            return 1
        if fetched["alert_id"] != TEST_ALERT_ID or fetched["report"] != TEST_REPORT:
            print("FAIL: fetched report does not match what was saved")
            print(json.dumps(fetched, indent=2, default=str))
            return 1
        print("OK: get_report returned matching alert_id/report")
        print(json.dumps(fetched, indent=2, default=str))
    except Exception as e:
        print(f"FAIL: could not fetch report back: {e}")
        import traceback
        traceback.print_exc()
        return 1

    # ---- Confirm it shows up in list_reports ----
    step("STEP 5: Confirm the report appears via list_reports")
    try:
        reports = storage_client.list_reports(limit=50)
        found = [r for r in reports if r["id"] == report_id]
        if not found:
            print(f"FAIL: report id={report_id} not found via list_reports")
            return 1
        print(f"OK: list_reports returned {len(reports)} report(s), including id={report_id}")
    except Exception as e:
        print(f"FAIL: could not list reports: {e}")
        import traceback
        traceback.print_exc()
        return 1

    # ---- Optional cleanup ----
    if args.cleanup:
        step("STEP 6: Cleanup test row")
        conn = storage_client._connect()
        try:
            with conn, conn.cursor() as cur:
                cur.execute("DELETE FROM investigation_reports WHERE id = %s", (report_id,))
            print(f"OK: deleted report id={report_id}")
        except Exception as e:
            print(f"WARN: could not delete report id={report_id}: {e}")
        finally:
            conn.close()
    else:
        print(f"\n(Test report id={report_id} was left in place; re-run with --cleanup to remove it.)")

    print("\n" + "=" * 80)
    print("ALL CHECKS PASSED")
    print("=" * 80)
    return 0


if __name__ == "__main__":
    sys.exit(main())
