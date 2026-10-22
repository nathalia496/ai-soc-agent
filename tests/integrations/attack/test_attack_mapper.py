"""
Unit tests for the MITRE ATT&CK technique mapper.

Uses the real (locally cached) ATT&CK Enterprise dataset to verify that a
handful of known investigation findings map to the expected techniques, so
the matcher isn't trivially broken.
"""

import pytest

from src.core.errors import IntegrationError
from src.integrations.attack.attack_mapper import AttackMapper
from src.orchestrator.tools_attack import map_to_attack


@pytest.fixture(scope="module")
def mapper() -> AttackMapper:
    return AttackMapper()


class TestMatchTechniques:
    def test_powershell_encoded_command_matches_t1059_001(self, mapper):
        text = (
            "powershell.exe spawned with encoded command, outbound connection "
            "to an external IP"
        )
        matches = mapper.match_techniques(text)

        technique_ids = [m["technique_id"] for m in matches]
        assert "T1059.001" in technique_ids

    def test_top_match_includes_expected_fields(self, mapper):
        matches = mapper.match_techniques("powershell.exe with an encoded command")
        assert matches, "expected at least one match"

        top = matches[0]
        assert top["technique_id"] == "T1059.001"
        assert top["technique_name"] == "PowerShell"
        assert "execution" in top["tactics"]
        assert 0 < top["score"] <= 1

    def test_scheduled_task_persistence_matches_t1053_005(self, mapper):
        text = "adversary created a new scheduled task on Windows to run a malicious binary at logon for persistence"
        matches = mapper.match_techniques(text)

        technique_ids = [m["technique_id"] for m in matches]
        assert "T1053.005" in technique_ids

    def test_results_are_sorted_by_descending_score(self, mapper):
        matches = mapper.match_techniques("powershell.exe with an encoded command")
        scores = [m["score"] for m in matches]
        assert scores == sorted(scores, reverse=True)

    def test_top_n_limits_results(self, mapper):
        matches = mapper.match_techniques("powershell.exe with an encoded command", top_n=1)
        assert len(matches) <= 1

    def test_unrelated_text_returns_no_strong_matches(self, mapper):
        matches = mapper.match_techniques("the quick brown fox jumps over the lazy dog")
        technique_ids = [m["technique_id"] for m in matches]

        assert "T1059.001" not in technique_ids
        assert "T1053.005" not in technique_ids
        assert all(m["score"] < 0.1 for m in matches)

    def test_empty_text_returns_no_matches(self, mapper):
        assert mapper.match_techniques("") == []


class TestMapToAttackTool:
    def test_success_wraps_matches(self, mapper):
        result = map_to_attack(
            "powershell.exe spawned with encoded command, outbound connection to an external IP",
            mapper=mapper,
        )

        assert result["success"] is True
        technique_ids = [m["technique_id"] for m in result["matches"]]
        assert "T1059.001" in technique_ids
        assert result["match_count"] == len(result["matches"])

    def test_no_mapper_raises_integration_error(self):
        with pytest.raises(IntegrationError):
            map_to_attack("powershell.exe with an encoded command", mapper=None)

    def test_empty_text_raises_integration_error(self, mapper):
        with pytest.raises(IntegrationError):
            map_to_attack("   ", mapper=mapper)
