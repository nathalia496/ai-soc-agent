#!/usr/bin/env python3
"""
Seeds the hand-authored evaluation fixtures (one per run_books/soc{1,2}/cases/*.md
scenario) into the local OpenSearch instance, in the same document shape used by
tests/integrations/siem/opensearch/verify_opensearch_connection.py.

Each fixture under fixtures/*.json carries an alert document plus a handful of
nearby log events, with log timestamps expressed as `offset_minutes` relative to
the alert's own `alert_timestamp` - that's what get_logs_for_alert's time window
is centered on, so the fixture is independent of when it's actually seeded.

Usage:
    python scripts/evaluation/seed_fixtures.py
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List

# File is at: scripts/evaluation/seed_fixtures.py -> project root is two levels up.
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.core.config_storage import load_config_from_file  # noqa: E402
from src.integrations.siem.elastic.elastic_client import ElasticSIEMClient  # noqa: E402

FIXTURES_DIR = Path(__file__).parent / "fixtures"
FIXTURE_FILES = [
    "malware_initial_triage.json",
    "suspicious_login_triage.json",
    "malware_deep_analysis.json",
    "suspicious_login_investigation.json",
]


def load_fixtures() -> List[Dict[str, Any]]:
    """Load the 4 hand-authored scenario fixtures, in a stable order."""
    fixtures = []
    for filename in FIXTURE_FILES:
        with open(FIXTURES_DIR / filename) as f:
            fixtures.append(json.load(f))
    return fixtures


def _resolve_log_timestamp(alert_timestamp: str, offset_minutes: int) -> str:
    alert_time = datetime.fromisoformat(alert_timestamp.replace("Z", "+00:00"))
    return (alert_time + timedelta(minutes=offset_minutes)).isoformat()


def seed_fixture(siem_client: ElasticSIEMClient, fixture: Dict[str, Any]) -> None:
    """Index one fixture's alert + nearby logs into OpenSearch (idempotent)."""
    alert_doc = fixture["alert"]
    siem_client._http.request(
        "PUT",
        f"/{fixture['alert_index']}/_doc/{fixture['alert_id']}?refresh=wait_for",
        json_data=alert_doc,
    )

    for i, log in enumerate(fixture["logs"]):
        log_doc = {k: v for k, v in log.items() if k != "offset_minutes"}
        log_doc["@timestamp"] = _resolve_log_timestamp(fixture["alert_timestamp"], log["offset_minutes"])
        siem_client._http.request(
            "PUT",
            f"/{fixture['log_index']}/_doc/{fixture['alert_id']}-log-{i:04d}?refresh=wait_for",
            json_data=log_doc,
        )


def seed_all(siem_client: ElasticSIEMClient) -> List[Dict[str, Any]]:
    """Seed all 4 fixtures. Returns the loaded fixtures (for the caller to iterate)."""
    fixtures = load_fixtures()
    for fixture in fixtures:
        seed_fixture(siem_client, fixture)
    return fixtures


def main() -> int:
    config = load_config_from_file()
    if not config.elastic:
        print("FAIL: no 'elastic' section configured in config.json.")
        return 1

    siem_client = ElasticSIEMClient.from_config(config)
    fixtures = seed_all(siem_client)
    for fixture in fixtures:
        print(f"OK: seeded '{fixture['scenario']}' as alert '{fixture['alert_id']}' "
              f"({len(fixture['logs'])} nearby log events)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
