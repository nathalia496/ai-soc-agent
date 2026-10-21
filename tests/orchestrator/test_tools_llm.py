"""
Unit tests for the generate_investigation_report orchestrator tool.

Covers the wrapper's error handling around OllamaClient.generate_report:
missing client, validation failure, and the success path.
"""

from unittest.mock import Mock

import pytest

from src.core.errors import IntegrationError, ValidationError
from src.orchestrator.tools_llm import generate_investigation_report

VALID_REPORT = {
    "timeline": [{"timestamp": "t", "description": "d"}],
    "observables": [{"type": "ip", "value": "1.2.3.4"}],
    "hypothesis": "h",
    "next_steps": ["s"],
}


class TestGenerateInvestigationReport:
    def test_no_client_raises(self):
        with pytest.raises(IntegrationError, match="No Ollama client provided"):
            generate_investigation_report("some context", client=None)

    def test_validation_error_wrapped(self):
        mock_client = Mock()
        mock_client.generate_report.side_effect = ValidationError("missing required key(s)")

        with pytest.raises(IntegrationError, match="failed validation"):
            generate_investigation_report("some context", client=mock_client)

    def test_integration_error_propagates(self):
        mock_client = Mock()
        mock_client.generate_report.side_effect = IntegrationError("Ollama request failed")

        with pytest.raises(IntegrationError, match="Ollama request failed"):
            generate_investigation_report("some context", client=mock_client)

    def test_success(self):
        mock_client = Mock()
        mock_client.generate_report.return_value = VALID_REPORT

        result = generate_investigation_report("some context", client=mock_client)

        mock_client.generate_report.assert_called_once_with("some context")
        assert result == {"success": True, "report": VALID_REPORT}
