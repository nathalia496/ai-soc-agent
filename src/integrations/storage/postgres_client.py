"""
PostgreSQL persistence for investigation reports.

A minimal, single-table client (plain psycopg2, no ORM) that stores the
structured reports produced by ``investigate_alert`` so they can be looked
up later instead of only ever being returned once to the caller.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import psycopg2
import psycopg2.extras

from ...core.config import SamiConfig
from ...core.errors import IntegrationError
from ...core.logging import get_logger

logger = get_logger("sami.integrations.storage.postgres")

_CREATE_TABLE_SQL = """
    CREATE TABLE IF NOT EXISTS investigation_reports (
        id SERIAL PRIMARY KEY,
        alert_id TEXT NOT NULL,
        case_id TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        report JSONB NOT NULL,
        warnings JSONB
    )
"""


class PostgresClient:
    """
    Storage client backed by PostgreSQL.

    Opens a short-lived connection per operation rather than holding one
    open for the client's lifetime - this is a low-volume, best-effort
    persistence path (see ``investigate_alert``), not a hot path that
    needs connection pooling.
    """

    def __init__(self, host: str, port: int, database: str, user: str, password: str) -> None:
        self._conn_kwargs = {
            "host": host,
            "port": port,
            "dbname": database,
            "user": user,
            "password": password,
        }

    @classmethod
    def from_config(cls, config: SamiConfig) -> "PostgresClient":
        """
        Factory to construct a client from ``SamiConfig``.
        """
        if not config.postgres:
            raise IntegrationError("Postgres configuration is not set in SamiConfig")

        return cls(
            host=config.postgres.host,
            port=config.postgres.port,
            database=config.postgres.database,
            user=config.postgres.user,
            password=config.postgres.password,
        )

    def _connect(self):
        try:
            return psycopg2.connect(**self._conn_kwargs)
        except Exception as e:
            raise IntegrationError(f"Failed to connect to PostgreSQL: {e}") from e

    def ensure_table(self) -> None:
        """
        Create the ``investigation_reports`` table if it doesn't already exist.
        """
        conn = self._connect()
        try:
            with conn, conn.cursor() as cur:
                cur.execute(_CREATE_TABLE_SQL)
        except Exception as e:
            raise IntegrationError(f"Failed to ensure investigation_reports table: {e}") from e
        finally:
            conn.close()

    def save_report(
        self,
        alert_id: str,
        case_id: Optional[str],
        report: Dict[str, Any],
        warnings: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Insert a new investigation report row and return its id/created_at.
        """
        conn = self._connect()
        try:
            with conn, conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO investigation_reports (alert_id, case_id, report, warnings)
                    VALUES (%s, %s, %s, %s)
                    RETURNING id, created_at
                    """,
                    (
                        alert_id,
                        case_id,
                        psycopg2.extras.Json(report),
                        psycopg2.extras.Json(warnings or []),
                    ),
                )
                row_id, created_at = cur.fetchone()
            return {
                "id": row_id,
                "alert_id": alert_id,
                "case_id": case_id,
                "created_at": created_at,
            }
        except Exception as e:
            raise IntegrationError(f"Failed to save investigation report: {e}") from e
        finally:
            conn.close()

    def get_report(self, report_id: int) -> Optional[Dict[str, Any]]:
        """
        Fetch a single investigation report by id, or ``None`` if it doesn't exist.
        """
        conn = self._connect()
        try:
            with conn, conn.cursor() as cur:
                cur.execute(
                    "SELECT id, alert_id, case_id, created_at, report, warnings "
                    "FROM investigation_reports WHERE id = %s",
                    (report_id,),
                )
                row = cur.fetchone()
        except Exception as e:
            raise IntegrationError(f"Failed to get investigation report {report_id}: {e}") from e
        finally:
            conn.close()

        return _row_to_dict(row) if row is not None else None

    def list_reports(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        List investigation reports, most recently created first.
        """
        conn = self._connect()
        try:
            with conn, conn.cursor() as cur:
                cur.execute(
                    "SELECT id, alert_id, case_id, created_at, report, warnings "
                    "FROM investigation_reports ORDER BY created_at DESC LIMIT %s",
                    (limit,),
                )
                rows = cur.fetchall()
        except Exception as e:
            raise IntegrationError(f"Failed to list investigation reports: {e}") from e
        finally:
            conn.close()

        return [_row_to_dict(row) for row in rows]


def _row_to_dict(row) -> Dict[str, Any]:
    report_id, alert_id, case_id, created_at, report, warnings = row
    return {
        "id": report_id,
        "alert_id": alert_id,
        "case_id": case_id,
        "created_at": created_at,
        "report": report,
        "warnings": warnings,
    }
