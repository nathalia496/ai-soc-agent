"""
Unit tests for the end-to-end investigate_alert() orchestration pipeline.

Mocks every client (SIEM, CTI, MISP, ATT&CK mapper, LLM, case management) to
verify the pipeline's wiring and its error-handling contract: a missing
SIEM/LLM client or a failed alert fetch/report generation is fatal, while
every enrichment stage (logs, CTI, MISP, ATT&CK, case comment) is
best-effort and degrades to a recorded warning instead of raising.

One test (TestRealAttackMapper) runs the pipeline against the real
AttackMapper (built in the ATT&CK mapper task) instead of a mock, to confirm
the two pieces actually fit together end to end for a PowerShell-style
scenario shaped like the one tests/integrations/siem/opensearch/
verify_opensearch_connection.py seeds into a live OpenSearch instance.
"""

from datetime import datetime, timezone
from unittest.mock import Mock

import pytest

from src.api.siem import SiemEvent, SourceType
from src.core.errors import IntegrationError
from src.orchestrator.investigate_alert import investigate_alert

VALID_REPORT = {
    "timeline": [{"timestamp": "2026-01-01T00:00:00Z", "description": "d"}],
    "observables": [{"type": "ip", "value": "8.8.8.8"}],
    "hypothesis": "Likely malicious PowerShell activity.",
    "next_steps": ["Isolate the endpoint for review (human action required)."],
}


def _make_alert(related_entities):
    return {
        "id": "verify-alert-0001",
        "title": "Verification: Suspicious PowerShell Execution",
        "description": "Synthetic alert for testing",
        "severity": "high",
        "status": "open",
        "related_entities": related_entities,
    }


def _make_siem_client(alert, events=None):
    client = Mock()
    client.get_security_alert_by_id.return_value = alert
    client.get_logs_for_alert.return_value = Mock(
        query="mocked",
        total_count=len(events or []),
        events=events or [],
    )
    return client


def _make_event(message, host="verify-host-01", username="verify.user", ip="10.10.10.50",
                 process_name="powershell.exe", file_hash=None):
    return SiemEvent(
        id="evt-1",
        timestamp=datetime.now(timezone.utc),
        source_type=SourceType.ENDPOINT,
        message=message,
        host=host,
        username=username,
        ip=ip,
        process_name=process_name,
        file_hash=file_hash,
    )


class TestRequiredClients:
    def test_missing_siem_client_raises(self):
        with pytest.raises(IntegrationError, match="SIEM client not provided"):
            investigate_alert("alert-1", siem_client=None, llm_client=Mock())

    def test_missing_llm_client_raises(self):
        with pytest.raises(IntegrationError, match="LLM client not provided"):
            investigate_alert("alert-1", siem_client=Mock(), llm_client=None)


class TestHappyPath:
    def test_full_pipeline_with_everything_configured(self):
        alert = _make_alert(["ip:8.8.8.8", "hash:" + "a" * 64])
        siem_client = _make_siem_client(alert, events=[_make_event("powershell.exe with encoded command")])

        cti_client = Mock()
        cti_client.lookup_hash.return_value = {
            "found": True, "classification": "malicious", "threat_score": 85, "labels": ["malware"],
        }

        misp_client = Mock()
        misp_client.lookup_indicator.return_value = {
            "indicator": "8.8.8.8", "indicator_type": "ip", "found": True,
            "tags": ["known-bad"], "events": [{"event_id": "1"}],
        }

        attack_mapper = Mock()
        attack_mapper.match_techniques.return_value = [
            {"technique_id": "T1059.001", "technique_name": "PowerShell",
             "tactics": ["execution"], "score": 0.42},
        ]

        llm_client = Mock()
        llm_client.generate_report.return_value = VALID_REPORT

        case_comment = Mock(id="c1", case_id="case-1", author="SamiGPT", content="...", created_at=None)
        case_client = Mock()
        case_client.add_case_comment.return_value = case_comment

        result = investigate_alert(
            "verify-alert-0001",
            siem_client=siem_client,
            cti_clients=[cti_client],
            misp_client=misp_client,
            attack_mapper=attack_mapper,
            llm_client=llm_client,
            case_client=case_client,
            case_id="case-1",
        )

        assert result["success"] is True
        assert result["alert_id"] == "verify-alert-0001"
        assert result["alert"] == alert
        assert result["report"] == VALID_REPORT
        assert result["warnings"] == []

        # CTI: hash went to both lookup_hash_ti and lookup_ioc_misp; IP only to MISP.
        assert len(result["cti_results"]["hash_lookups"]) == 1
        assert len(result["cti_results"]["ioc_lookups"]) == 2
        cti_client.lookup_hash.assert_called_once_with("a" * 64)
        misp_client.lookup_indicator.assert_any_call("a" * 64)
        misp_client.lookup_indicator.assert_any_call("8.8.8.8")

        # ATT&CK mapping ran and its result made it into the final context.
        assert result["attack_matches"][0]["technique_id"] == "T1059.001"
        attack_mapper.match_techniques.assert_called_once()

        # Final LLM context includes alert, logs, CTI, and ATT&CK sections.
        llm_context = llm_client.generate_report.call_args[0][0]
        assert "Alert: Verification: Suspicious PowerShell Execution" in llm_context
        assert "powershell.exe with encoded command" in llm_context
        assert "T1059.001" in llm_context

        # Report got attached to the case.
        assert result["case_comment"]["comment"]["id"] == "c1"
        case_client.add_case_comment.assert_called_once()
        call_kwargs = case_client.add_case_comment.call_args
        assert call_kwargs[0][0] == "case-1"  # case_id positional arg to the raw client call


class TestBestEffortDegradation:
    def test_logs_fetch_failure_is_non_fatal(self):
        alert = _make_alert([])
        siem_client = Mock()
        siem_client.get_security_alert_by_id.return_value = alert
        siem_client.get_logs_for_alert.side_effect = IntegrationError("SIEM timeout")

        llm_client = Mock()
        llm_client.generate_report.return_value = VALID_REPORT

        result = investigate_alert("alert-1", siem_client=siem_client, llm_client=llm_client)

        assert result["success"] is True
        assert result["report"] == VALID_REPORT
        assert any("nearby logs" in w for w in result["warnings"])
        assert result["logs"]["events"] == []

    def test_missing_cti_and_misp_clients_warns_but_continues(self):
        alert = _make_alert(["hash:" + "b" * 64, "ip:1.2.3.4"])
        siem_client = _make_siem_client(alert)
        llm_client = Mock()
        llm_client.generate_report.return_value = VALID_REPORT

        result = investigate_alert(
            "alert-1", siem_client=siem_client, llm_client=llm_client,
            cti_clients=None, misp_client=None,
        )

        assert result["success"] is True
        assert result["cti_results"] == {"hash_lookups": [], "ioc_lookups": []}
        assert any("no CTI client" in w for w in result["warnings"])
        assert any("no MISP client" in w for w in result["warnings"])

    def test_entities_without_hash_or_ip_do_not_warn_about_cti(self):
        alert = _make_alert(["user:bob", "domain:example.com"])
        siem_client = _make_siem_client(alert)
        llm_client = Mock()
        llm_client.generate_report.return_value = VALID_REPORT

        result = investigate_alert("alert-1", siem_client=siem_client, llm_client=llm_client)

        assert result["cti_results"] == {"hash_lookups": [], "ioc_lookups": []}
        assert not any("CTI" in w or "MISP" in w for w in result["warnings"])

    def test_missing_attack_mapper_warns_but_continues(self):
        alert = _make_alert([])
        siem_client = _make_siem_client(alert)
        llm_client = Mock()
        llm_client.generate_report.return_value = VALID_REPORT

        result = investigate_alert(
            "alert-1", siem_client=siem_client, llm_client=llm_client, attack_mapper=None,
        )

        assert result["success"] is True
        assert result["attack_matches"] == []
        assert any("ATT&CK mapper not configured" in w for w in result["warnings"])

    def test_attack_mapping_exception_is_non_fatal(self):
        alert = _make_alert([])
        siem_client = _make_siem_client(alert)
        llm_client = Mock()
        llm_client.generate_report.return_value = VALID_REPORT
        attack_mapper = Mock()
        attack_mapper.match_techniques.side_effect = RuntimeError("corrupt dataset")

        result = investigate_alert(
            "alert-1", siem_client=siem_client, llm_client=llm_client, attack_mapper=attack_mapper,
        )

        assert result["success"] is True
        assert result["attack_matches"] == []
        assert any("ATT&CK mapping failed" in w for w in result["warnings"])

    def test_case_client_without_case_id_warns_and_skips_comment(self):
        alert = _make_alert([])
        siem_client = _make_siem_client(alert)
        llm_client = Mock()
        llm_client.generate_report.return_value = VALID_REPORT
        case_client = Mock()

        result = investigate_alert(
            "alert-1", siem_client=siem_client, llm_client=llm_client,
            case_client=case_client, case_id=None,
        )

        assert result["case_comment"] is None
        case_client.add_case_comment.assert_not_called()
        assert any("no case_id given" in w for w in result["warnings"])

    def test_case_comment_failure_is_non_fatal(self):
        alert = _make_alert([])
        siem_client = _make_siem_client(alert)
        llm_client = Mock()
        llm_client.generate_report.return_value = VALID_REPORT
        case_client = Mock()
        case_client.add_case_comment.side_effect = RuntimeError("case API down")

        result = investigate_alert(
            "alert-1", siem_client=siem_client, llm_client=llm_client,
            case_client=case_client, case_id="case-1",
        )

        assert result["success"] is True
        assert result["report"] == VALID_REPORT
        assert result["case_comment"] is None
        assert any("Failed to attach report to case" in w for w in result["warnings"])

    def test_storage_client_persists_report(self):
        alert = _make_alert([])
        siem_client = _make_siem_client(alert)
        llm_client = Mock()
        llm_client.generate_report.return_value = VALID_REPORT
        storage_client = Mock()
        storage_client.save_report.return_value = {
            "id": 1, "alert_id": "alert-1", "case_id": "case-1", "created_at": "t",
        }

        result = investigate_alert(
            "alert-1", siem_client=siem_client, llm_client=llm_client,
            storage_client=storage_client, case_id="case-1",
        )

        assert result["success"] is True
        assert result["stored_report"]["id"] == 1
        storage_client.save_report.assert_called_once()
        call_kwargs = storage_client.save_report.call_args.kwargs
        assert call_kwargs["alert_id"] == "alert-1"
        assert call_kwargs["case_id"] == "case-1"
        assert call_kwargs["report"] == VALID_REPORT

    def test_storage_failure_is_non_fatal(self):
        alert = _make_alert([])
        siem_client = _make_siem_client(alert)
        llm_client = Mock()
        llm_client.generate_report.return_value = VALID_REPORT
        storage_client = Mock()
        storage_client.save_report.side_effect = RuntimeError("database down")

        result = investigate_alert(
            "alert-1", siem_client=siem_client, llm_client=llm_client,
            storage_client=storage_client,
        )

        assert result["success"] is True
        assert result["report"] == VALID_REPORT
        assert result["stored_report"] is None
        assert any("Failed to persist investigation report" in w for w in result["warnings"])

    def test_no_storage_client_leaves_stored_report_none(self):
        alert = _make_alert([])
        siem_client = _make_siem_client(alert)
        llm_client = Mock()
        llm_client.generate_report.return_value = VALID_REPORT

        result = investigate_alert("alert-1", siem_client=siem_client, llm_client=llm_client)

        assert result["stored_report"] is None


@pytest.fixture(scope="module")
def real_attack_mapper():
    from src.integrations.attack.attack_mapper import AttackMapper
    return AttackMapper()


class TestRealAttackMapper:
    """Runs the pipeline against the real AttackMapper, not a mock."""

    def test_powershell_scenario_matches_t1059_001(self, real_attack_mapper):
        # Shaped like the synthetic alert verify_opensearch_connection.py seeds
        # into a live OpenSearch instance (id "verify-alert-0001").
        alert = _make_alert(["ip:10.10.10.50", "ip:8.8.8.8", "user:verify.user"])
        alert["title"] = "Verification: Suspicious PowerShell Execution"
        alert["description"] = "Encoded PowerShell command detected"

        events = [
            _make_event("User authenticated successfully"),
            _make_event("powershell.exe spawned with encoded command"),
            _make_event("Outbound connection to 8.8.8.8:443"),
        ]
        siem_client = _make_siem_client(alert, events=events)

        llm_client = Mock()
        llm_client.generate_report.return_value = VALID_REPORT

        result = investigate_alert(
            "verify-alert-0001",
            siem_client=siem_client,
            llm_client=llm_client,
            attack_mapper=real_attack_mapper,
        )

        assert result["success"] is True
        technique_ids = [m["technique_id"] for m in result["attack_matches"]]
        assert "T1059.001" in technique_ids
