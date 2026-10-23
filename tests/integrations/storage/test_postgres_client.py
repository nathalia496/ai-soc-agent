"""
Unit tests for the PostgreSQL storage client.

Mocks psycopg2.connect so no real database is required; a live end-to-end
check against a real PostgreSQL instance lives in
verify_postgres_connection.py.
"""

from unittest.mock import MagicMock, patch

import psycopg2.extras
import pytest

from src.core.config import PostgresConfig, SamiConfig
from src.core.errors import IntegrationError
from src.integrations.storage.postgres_client import PostgresClient


def _make_conn_and_cursor():
    """A MagicMock connection whose `with conn, conn.cursor() as cur:` yields `cursor`."""
    conn = MagicMock()
    cursor = MagicMock()
    conn.cursor.return_value.__enter__.return_value = cursor
    return conn, cursor


def _client() -> PostgresClient:
    return PostgresClient(
        host="localhost", port=5432, database="soc_copilot", user="soc_user", password="soc_password"
    )


class TestFromConfig:
    def test_builds_client_from_config(self):
        config = SamiConfig(
            postgres=PostgresConfig(
                host="db.internal", port=5433, database="mydb", user="u", password="p"
            )
        )
        client = PostgresClient.from_config(config)
        assert client._conn_kwargs == {
            "host": "db.internal",
            "port": 5433,
            "dbname": "mydb",
            "user": "u",
            "password": "p",
        }

    def test_raises_when_postgres_not_configured(self):
        config = SamiConfig(postgres=None)
        with pytest.raises(IntegrationError, match="Postgres configuration is not set"):
            PostgresClient.from_config(config)


class TestConnect:
    @patch("src.integrations.storage.postgres_client.psycopg2.connect")
    def test_connect_failure_raises_integration_error(self, mock_connect):
        mock_connect.side_effect = Exception("connection refused")
        with pytest.raises(IntegrationError, match="Failed to connect to PostgreSQL"):
            _client().ensure_table()


class TestEnsureTable:
    @patch("src.integrations.storage.postgres_client.psycopg2.connect")
    def test_creates_table_and_closes_connection(self, mock_connect):
        conn, cursor = _make_conn_and_cursor()
        mock_connect.return_value = conn

        _client().ensure_table()

        executed_sql = cursor.execute.call_args[0][0]
        assert "CREATE TABLE IF NOT EXISTS investigation_reports" in executed_sql
        conn.close.assert_called_once()

    @patch("src.integrations.storage.postgres_client.psycopg2.connect")
    def test_query_failure_raises_integration_error_and_still_closes(self, mock_connect):
        conn, cursor = _make_conn_and_cursor()
        cursor.execute.side_effect = Exception("permission denied")
        mock_connect.return_value = conn

        with pytest.raises(IntegrationError, match="Failed to ensure investigation_reports table"):
            _client().ensure_table()
        conn.close.assert_called_once()


class TestSaveReport:
    @patch("src.integrations.storage.postgres_client.psycopg2.connect")
    def test_inserts_and_returns_id_and_created_at(self, mock_connect):
        conn, cursor = _make_conn_and_cursor()
        cursor.fetchone.return_value = (42, "2024-01-01T00:00:00+00:00")
        mock_connect.return_value = conn

        result = _client().save_report(
            alert_id="alert-1",
            case_id="case-1",
            report={"hypothesis": "h"},
            warnings=["w1"],
        )

        assert result == {
            "id": 42,
            "alert_id": "alert-1",
            "case_id": "case-1",
            "created_at": "2024-01-01T00:00:00+00:00",
        }
        executed_sql, params = cursor.execute.call_args[0]
        assert "INSERT INTO investigation_reports" in executed_sql
        assert params[0] == "alert-1"
        assert params[1] == "case-1"
        assert isinstance(params[2], psycopg2.extras.Json)
        assert isinstance(params[3], psycopg2.extras.Json)
        conn.close.assert_called_once()

    @patch("src.integrations.storage.postgres_client.psycopg2.connect")
    def test_defaults_warnings_to_empty_list(self, mock_connect):
        conn, cursor = _make_conn_and_cursor()
        cursor.fetchone.return_value = (1, "ts")
        mock_connect.return_value = conn

        _client().save_report(alert_id="alert-1", case_id=None, report={})

        params = cursor.execute.call_args[0][1]
        assert params[3].adapted == []

    @patch("src.integrations.storage.postgres_client.psycopg2.connect")
    def test_failure_raises_integration_error(self, mock_connect):
        conn, cursor = _make_conn_and_cursor()
        cursor.execute.side_effect = Exception("db is down")
        mock_connect.return_value = conn

        with pytest.raises(IntegrationError, match="Failed to save investigation report"):
            _client().save_report(alert_id="alert-1", case_id=None, report={})


class TestGetReport:
    @patch("src.integrations.storage.postgres_client.psycopg2.connect")
    def test_returns_row_as_dict(self, mock_connect):
        conn, cursor = _make_conn_and_cursor()
        cursor.fetchone.return_value = (
            7,
            "alert-1",
            "case-1",
            "2024-01-01T00:00:00+00:00",
            {"hypothesis": "h"},
            ["w1"],
        )
        mock_connect.return_value = conn

        result = _client().get_report(7)

        assert result == {
            "id": 7,
            "alert_id": "alert-1",
            "case_id": "case-1",
            "created_at": "2024-01-01T00:00:00+00:00",
            "report": {"hypothesis": "h"},
            "warnings": ["w1"],
        }
        conn.close.assert_called_once()

    @patch("src.integrations.storage.postgres_client.psycopg2.connect")
    def test_returns_none_when_not_found(self, mock_connect):
        conn, cursor = _make_conn_and_cursor()
        cursor.fetchone.return_value = None
        mock_connect.return_value = conn

        assert _client().get_report(999) is None

    @patch("src.integrations.storage.postgres_client.psycopg2.connect")
    def test_failure_raises_integration_error(self, mock_connect):
        conn, cursor = _make_conn_and_cursor()
        cursor.execute.side_effect = Exception("boom")
        mock_connect.return_value = conn

        with pytest.raises(IntegrationError, match="Failed to get investigation report 1"):
            _client().get_report(1)


class TestListReports:
    @patch("src.integrations.storage.postgres_client.psycopg2.connect")
    def test_returns_rows_as_dicts(self, mock_connect):
        conn, cursor = _make_conn_and_cursor()
        cursor.fetchall.return_value = [
            (2, "alert-2", None, "t2", {"hypothesis": "h2"}, []),
            (1, "alert-1", "case-1", "t1", {"hypothesis": "h1"}, ["w"]),
        ]
        mock_connect.return_value = conn

        results = _client().list_reports(limit=10)

        assert [r["id"] for r in results] == [2, 1]
        assert results[0]["alert_id"] == "alert-2"
        query, params = cursor.execute.call_args[0]
        assert "ORDER BY created_at DESC LIMIT" in query
        assert params == (10,)
        conn.close.assert_called_once()

    @patch("src.integrations.storage.postgres_client.psycopg2.connect")
    def test_empty_result(self, mock_connect):
        conn, cursor = _make_conn_and_cursor()
        cursor.fetchall.return_value = []
        mock_connect.return_value = conn

        assert _client().list_reports() == []

    @patch("src.integrations.storage.postgres_client.psycopg2.connect")
    def test_failure_raises_integration_error(self, mock_connect):
        conn, cursor = _make_conn_and_cursor()
        cursor.execute.side_effect = Exception("boom")
        mock_connect.return_value = conn

        with pytest.raises(IntegrationError, match="Failed to list investigation reports"):
            _client().list_reports()
