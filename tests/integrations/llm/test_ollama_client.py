"""
Unit tests for the Ollama structured-report client.

Covers the fixed-schema JSON contract and the code-fence fallback: some
local models wrap their JSON reply in ```-fences despite the system prompt
forbidding it, and the client must still parse the report.
"""

from unittest.mock import Mock, patch

import pytest

from src.core.errors import ValidationError
from src.integrations.llm.ollama_client import OllamaClient
from src.integrations.llm.ollama_http import OllamaHttpClient

VALID_REPORT = (
    '{"timeline": [{"timestamp": "t", "description": "d"}], '
    '"observables": [{"type": "ip", "value": "1.2.3.4"}], '
    '"hypothesis": "h", "next_steps": ["s"]}'
)


def _client() -> OllamaClient:
    return OllamaClient(OllamaHttpClient(base_url="http://localhost:11434/v1", model="llama3.2"))


class TestGenerateReport:
    @patch.object(OllamaHttpClient, "chat_completion")
    def test_parses_clean_json(self, mock_chat):
        mock_chat.return_value = VALID_REPORT
        report = _client().generate_report("some context")
        assert report["hypothesis"] == "h"
        assert report["observables"] == [{"type": "ip", "value": "1.2.3.4"}]

    @patch.object(OllamaHttpClient, "chat_completion")
    def test_strips_code_fence(self, mock_chat):
        mock_chat.return_value = f"```\n{VALID_REPORT}\n```"
        report = _client().generate_report("some context")
        assert report["hypothesis"] == "h"

    @patch.object(OllamaHttpClient, "chat_completion")
    def test_strips_json_code_fence(self, mock_chat):
        mock_chat.return_value = f"```json\n{VALID_REPORT}\n```"
        report = _client().generate_report("some context")
        assert report["hypothesis"] == "h"

    @patch.object(OllamaHttpClient, "chat_completion")
    def test_missing_required_key_raises(self, mock_chat):
        mock_chat.return_value = '{"timeline": [], "observables": [], "hypothesis": "h"}'
        with pytest.raises(ValidationError, match="missing required key"):
            _client().generate_report("some context")

    @patch.object(OllamaHttpClient, "chat_completion")
    def test_non_json_raises(self, mock_chat):
        mock_chat.return_value = "not json at all"
        with pytest.raises(ValidationError, match="not valid JSON"):
            _client().generate_report("some context")


class TestChatCompletionRequestsJsonMode:
    @patch("src.integrations.llm.ollama_http.requests.post")
    def test_sends_response_format_json_object(self, mock_post):
        mock_response = Mock()
        mock_response.json.return_value = {"choices": [{"message": {"content": VALID_REPORT}}]}
        mock_post.return_value = mock_response

        OllamaHttpClient(base_url="http://localhost:11434/v1", model="llama3.2").chat_completion(
            "system", "user"
        )

        sent_payload = mock_post.call_args[1]["json"]
        assert sent_payload["response_format"] == {"type": "json_object"}
