#!/usr/bin/env python3
"""
Standalone verification script for the OpenSearch SIEM integration.

This does NOT use pytest - it's a small, readable end-to-end smoke test you
run by hand against a local OpenSearch instance (e.g. the one started by
`docker-compose up opensearch`, with DISABLE_SECURITY_PLUGIN=true).

It verifies the full path this project relies on:
1. Connects to OpenSearch using the same config.json / ElasticSIEMClient
   code path the MCP server uses - no SSL or auth errors should occur.
2. Indexes a sample SIEM alert (JSON object) into an `alerts-*` index.
3. Indexes a couple of "nearby" log events sharing the alert's host/user/IP.
4. Confirms the alert can be pulled back via get_security_alerts /
   get_security_alert_by_id (the "receive/pull a SIEM alert" tool path).
5. Confirms the nearby logs can be retrieved via get_logs_for_alert (the
   "query nearby logs/evidence for an alert" tool path).

Usage:
    python tests/integrations/siem/opensearch/verify_opensearch_connection.py
    python tests/integrations/siem/opensearch/verify_opensearch_connection.py --cleanup
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

# File is at: tests/integrations/siem/opensearch/verify_opensearch_connection.py
# Need to go up 5 levels: opensearch -> siem -> integrations -> tests -> project root
project_root = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(project_root))

from src.core.config_storage import load_config_from_file
from src.integrations.siem.elastic.elastic_client import ElasticSIEMClient
from src.orchestrator import tools_siem

ALERT_INDEX = "alerts-verification-test"
LOG_INDEX = "logs-verification-test"
ALERT_DOC_ID = "verify-alert-0001"

TEST_HOST = "verify-host-01"
TEST_USER = "verify.user"
TEST_SRC_IP = "10.10.10.50"
TEST_DST_IP = "8.8.8.8"


def step(title: str) -> None:
    print("\n" + "=" * 80)
    print(title)
    print("=" * 80)


def build_sample_alert(alert_time: datetime) -> dict:
    """A realistic-enough alert document matching the `alerts-*` index pattern."""
    return {
        "@timestamp": alert_time.isoformat(),
        "signal": {
            "rule": {
                "name": "Verification: Suspicious PowerShell Execution",
                "description": "Synthetic alert created by verify_opensearch_connection.py",
            },
            "severity": "high",
            "status": "open",
        },
        "host": {"name": TEST_HOST},
        "user": {"name": TEST_USER},
        "source": {"ip": TEST_SRC_IP},
        "destination": {"ip": TEST_DST_IP},
        "event": {"category": ["process"], "reason": "Encoded PowerShell command detected"},
        "process": {"name": "powershell.exe"},
    }


def build_nearby_log(log_time: datetime, message: str) -> dict:
    """A log event sharing the alert's host/user/IP, for get_logs_for_alert to find."""
    return {
        "@timestamp": log_time.isoformat(),
        "message": message,
        "host": {"name": TEST_HOST},
        "user": {"name": TEST_USER},
        "source": {"ip": TEST_SRC_IP},
        "destination": {"ip": TEST_DST_IP},
        "process": {"name": "powershell.exe"},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify the OpenSearch SIEM integration")
    parser.add_argument(
        "--cleanup",
        action="store_true",
        help="Delete the test indices created by this script when done",
    )
    args = parser.parse_args()

    print("=" * 80)
    print("OPENSEARCH SIEM INTEGRATION VERIFICATION")
    print("=" * 80)
    print(f"Started at: {datetime.now().isoformat()}")

    # ---- Load config ----
    step("STEP 1: Load configuration")
    try:
        config = load_config_from_file()
    except Exception as e:
        print(f"FAIL: could not load configuration: {e}")
        return 1

    if not config.elastic:
        print("FAIL: no 'elastic' section configured in config.json.")
        print("Add an 'elastic' section pointing at your OpenSearch instance, e.g.:")
        print(json.dumps({
            "elastic": {
                "siem_type": "opensearch",
                "base_url": "http://localhost:9200",
                "verify_ssl": False,
            }
        }, indent=2))
        return 1

    print(f"OK: siem_type={config.elastic.siem_type}, base_url={config.elastic.base_url}, "
          f"auth={'api_key' if config.elastic.api_key else ('basic' if config.elastic.username else 'none')}")

    # ---- Build client & check connectivity ----
    step("STEP 2: Connect to OpenSearch (no SSL/auth errors expected)")
    try:
        siem_client = ElasticSIEMClient.from_config(config)
        health = siem_client._http.get("/_cluster/health")
        print(f"OK: connected. cluster_name={health.get('cluster_name')}, status={health.get('status')}")
    except Exception as e:
        print(f"FAIL: could not connect to OpenSearch at {config.elastic.base_url}: {e}")
        import traceback
        traceback.print_exc()
        return 1

    # ---- Index a sample alert ----
    step("STEP 3: Index a sample SIEM alert (JSON object)")
    alert_time = datetime.now(timezone.utc)
    alert_doc = build_sample_alert(alert_time)
    try:
        siem_client._http.request(
            "PUT",
            f"/{ALERT_INDEX}/_doc/{ALERT_DOC_ID}?refresh=wait_for",
            json_data=alert_doc,
        )
        print(f"OK: indexed alert '{ALERT_DOC_ID}' into '{ALERT_INDEX}':")
        print(json.dumps(alert_doc, indent=2))
    except Exception as e:
        print(f"FAIL: could not index sample alert: {e}")
        return 1

    # ---- Index nearby log events (within the alert's time window) ----
    step("STEP 4: Index nearby log events (evidence around the alert)")
    log_docs = [
        build_nearby_log(alert_time - timedelta(minutes=5), "User authenticated successfully"),
        build_nearby_log(alert_time - timedelta(minutes=1), "powershell.exe spawned with encoded command"),
        build_nearby_log(alert_time + timedelta(minutes=2), "Outbound connection to 8.8.8.8:443"),
    ]
    try:
        for i, doc in enumerate(log_docs):
            siem_client._http.request(
                "PUT",
                f"/{LOG_INDEX}/_doc/verify-log-{i:04d}?refresh=wait_for",
                json_data=doc,
            )
        print(f"OK: indexed {len(log_docs)} nearby log events into '{LOG_INDEX}'")
    except Exception as e:
        print(f"FAIL: could not index nearby log events: {e}")
        return 1

    # ---- Pull the alert back (the "receive/pull a SIEM alert" tool path) ----
    step("STEP 5: Pull the alert back via get_security_alerts / get_security_alert_by_id")
    try:
        alerts = tools_siem.get_security_alerts(hours_back=24, max_alerts=50, client=siem_client)
        found = [a for a in alerts.get("alerts", []) if a["id"] == ALERT_DOC_ID]
        if not found:
            print(f"FAIL: alert '{ALERT_DOC_ID}' not found via get_security_alerts")
            print(json.dumps(alerts, indent=2, default=str))
            return 1
        print(f"OK: get_security_alerts found the alert (title={found[0]['title']!r})")

        alert_detail = tools_siem.get_security_alert_by_id(alert_id=ALERT_DOC_ID, client=siem_client)
        print("OK: get_security_alert_by_id returned:")
        print(json.dumps(alert_detail, indent=2, default=str))
    except Exception as e:
        print(f"FAIL: could not pull alert back: {e}")
        import traceback
        traceback.print_exc()
        return 1

    # ---- Fetch nearby logs for the alert (the "nearby logs/evidence" tool path) ----
    step("STEP 6: Fetch nearby logs/evidence via get_logs_for_alert")
    try:
        logs_result = tools_siem.get_logs_for_alert(
            alert_id=ALERT_DOC_ID,
            minutes_before=30,
            minutes_after=30,
            client=siem_client,
        )
        print(json.dumps(logs_result, indent=2, default=str))
        returned = logs_result.get("returned_count", 0)
        if returned < len(log_docs):
            print(f"FAIL: expected at least {len(log_docs)} nearby log events, got {returned}")
            return 1
        print(f"OK: get_logs_for_alert returned {returned} nearby log event(s), filtered by "
              f"host={TEST_HOST!r}, user={TEST_USER!r}, ip={TEST_SRC_IP!r}, and a time window.")
    except Exception as e:
        print(f"FAIL: could not fetch nearby logs: {e}")
        import traceback
        traceback.print_exc()
        return 1

    # ---- Optional cleanup ----
    if args.cleanup:
        step("STEP 7: Cleanup test indices")
        for index in (ALERT_INDEX, LOG_INDEX):
            try:
                siem_client._http.request("DELETE", f"/{index}")
                print(f"OK: deleted index '{index}'")
            except Exception as e:
                print(f"WARN: could not delete index '{index}': {e}")
    else:
        print(f"\n(Test indices '{ALERT_INDEX}' and '{LOG_INDEX}' were left in place; "
              f"re-run with --cleanup to remove them.)")

    print("\n" + "=" * 80)
    print("ALL CHECKS PASSED")
    print("=" * 80)
    return 0


if __name__ == "__main__":
    sys.exit(main())
