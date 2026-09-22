"""
Unit tests for the MISP CTI client.

Tests indicator type detection, attribute search, and error handling.
"""

from unittest.mock import MagicMock, patch

import pytest
import requests
from pymisp import MISPAttribute, MISPEvent, MISPTag, PyMISPError

from src.core.config import MISPConfig, SamiConfig
from src.core.errors import IntegrationError
from src.integrations.cti.misp.misp_client import MISPClient, _detect_indicator_type
from src.integrations.cti.misp.misp_http import MISPHttpClient


def _make_attribute(value: str, tags, event_id, event_info, threat_level_id) -> MISPAttribute:
    attribute = MISPAttribute()
    attribute.from_dict(
        **{
            "type": "ip-dst",
            "value": value,
            "Tag": [{"name": tag} for tag in tags],
        }
    )
    event = MISPEvent()
    event.from_dict(
        **{
            "id": event_id,
            "info": event_info,
            "threat_level_id": threat_level_id,
        }
    )
    attribute.Event = event
    return attribute


class TestDetectIndicatorType:
    def test_detects_ipv4(self):
        assert _detect_indicator_type("8.8.8.8") == "ip"

    def test_detects_ipv6(self):
        assert _detect_indicator_type("2001:4860:4860::8888") == "ip"

    def test_detects_sha256_hash(self):
        assert _detect_indicator_type("a" * 64) == "hash"

    def test_detects_md5_hash(self):
        assert _detect_indicator_type("a" * 32) == "hash"

    def test_unknown_value(self):
        assert _detect_indicator_type("not-an-ioc") == "unknown"


class TestMISPHttpClient:
    def test_init_strips_trailing_slash(self):
        client = MISPHttpClient(base_url="https://misp.example.com/", api_key="key")
        assert client.base_url == "https://misp.example.com"

    @patch("src.integrations.cti.misp.misp_http.ExpandedPyMISP")
    def test_search_attribute_success(self, mock_expanded_pymisp):
        mock_misp = MagicMock()
        mock_misp.search.return_value = [_make_attribute("8.8.8.8", ["tlp:red"], "1", "Test event", "1")]
        mock_expanded_pymisp.return_value = mock_misp

        client = MISPHttpClient(base_url="https://misp.example.com", api_key="key")
        results = client.search_attribute("8.8.8.8")

        assert len(results) == 1
        mock_misp.search.assert_called_once_with(
            controller="attributes", value="8.8.8.8", include_context=True, pythonify=True
        )

    @patch("src.integrations.cti.misp.misp_http.ExpandedPyMISP")
    def test_search_attribute_empty(self, mock_expanded_pymisp):
        mock_misp = MagicMock()
        mock_misp.search.return_value = []
        mock_expanded_pymisp.return_value = mock_misp

        client = MISPHttpClient(base_url="https://misp.example.com", api_key="key")
        assert client.search_attribute("8.8.8.8") == []

    @patch("src.integrations.cti.misp.misp_http.ExpandedPyMISP")
    def test_search_attribute_error_response(self, mock_expanded_pymisp):
        mock_misp = MagicMock()
        mock_misp.search.return_value = {"errors": ["invalid API key"]}
        mock_expanded_pymisp.return_value = mock_misp

        client = MISPHttpClient(base_url="https://misp.example.com", api_key="key")
        with pytest.raises(IntegrationError) as exc_info:
            client.search_attribute("8.8.8.8")

        assert "invalid API key" in str(exc_info.value)

    @patch("src.integrations.cti.misp.misp_http.ExpandedPyMISP")
    def test_search_attribute_timeout(self, mock_expanded_pymisp):
        mock_misp = MagicMock()
        mock_misp.search.side_effect = requests.exceptions.Timeout("timed out")
        mock_expanded_pymisp.return_value = mock_misp

        client = MISPHttpClient(base_url="https://misp.example.com", api_key="key")
        with pytest.raises(IntegrationError) as exc_info:
            client.search_attribute("8.8.8.8")

        assert "Timeout" in str(exc_info.value)

    @patch("src.integrations.cti.misp.misp_http.ExpandedPyMISP")
    def test_connection_error_on_client_init(self, mock_expanded_pymisp):
        mock_expanded_pymisp.side_effect = requests.exceptions.ConnectionError("refused")

        client = MISPHttpClient(base_url="https://misp.example.com", api_key="key")
        with pytest.raises(IntegrationError) as exc_info:
            client.search_attribute("8.8.8.8")

        assert "Could not connect" in str(exc_info.value)

    @patch("src.integrations.cti.misp.misp_http.ExpandedPyMISP")
    def test_pymisp_error_on_client_init(self, mock_expanded_pymisp):
        mock_expanded_pymisp.side_effect = PyMISPError("bad key")

        client = MISPHttpClient(base_url="https://misp.example.com", api_key="key")
        with pytest.raises(IntegrationError) as exc_info:
            client.search_attribute("8.8.8.8")

        assert "initialization failed" in str(exc_info.value)


class TestMISPClient:
    def test_from_config_success(self):
        config = SamiConfig(misp=MISPConfig(base_url="https://misp.example.com", api_key="key"))
        client = MISPClient.from_config(config)

        assert client is not None
        assert client._http.base_url == "https://misp.example.com"

    def test_from_config_no_misp(self):
        config = SamiConfig(misp=None)
        with pytest.raises(IntegrationError) as exc_info:
            MISPClient.from_config(config)

        assert "MISP configuration is not set" in str(exc_info.value)

    @patch("src.integrations.cti.misp.misp_client.MISPHttpClient.search_attribute")
    def test_lookup_indicator_found(self, mock_search):
        mock_search.return_value = [
            _make_attribute("8.8.8.8", ["tlp:red", "malware:foo"], "42", "Suspicious IP", "1")
        ]

        http_client = MISPHttpClient(base_url="https://misp.example.com", api_key="key")
        client = MISPClient(http_client=http_client)

        result = client.lookup_indicator("8.8.8.8")

        assert result["found"] is True
        assert result["indicator_type"] == "ip"
        assert result["tags"] == ["malware:foo", "tlp:red"]
        assert result["events"] == [
            {"event_id": 42, "info": "Suspicious IP", "threat_level_id": 1, "tags": ["tlp:red", "malware:foo"]}
        ]

    @patch("src.integrations.cti.misp.misp_client.MISPHttpClient.search_attribute")
    def test_lookup_indicator_not_found(self, mock_search):
        mock_search.return_value = []

        http_client = MISPHttpClient(base_url="https://misp.example.com", api_key="key")
        client = MISPClient(http_client=http_client)

        result = client.lookup_indicator("a" * 64)

        assert result == {
            "indicator": "a" * 64,
            "indicator_type": "hash",
            "found": False,
            "tags": [],
            "events": [],
        }

    @patch("src.integrations.cti.misp.misp_client.MISPHttpClient.search_attribute")
    def test_lookup_indicator_error_propagation(self, mock_search):
        mock_search.side_effect = IntegrationError("MISP search request failed")

        http_client = MISPHttpClient(base_url="https://misp.example.com", api_key="key")
        client = MISPClient(http_client=http_client)

        with pytest.raises(IntegrationError):
            client.lookup_indicator("8.8.8.8")

    @patch("src.integrations.cti.misp.misp_client.MISPHttpClient.search_attribute")
    def test_lookup_indicator_generic_exception(self, mock_search):
        mock_search.side_effect = Exception("boom")

        http_client = MISPHttpClient(base_url="https://misp.example.com", api_key="key")
        client = MISPClient(http_client=http_client)

        with pytest.raises(IntegrationError) as exc_info:
            client.lookup_indicator("8.8.8.8")

        assert "Failed to lookup indicator" in str(exc_info.value)
