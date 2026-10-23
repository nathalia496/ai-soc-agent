"""
LLM-callable tools for investigation report persistence.

These functions wrap the generic storage client (``PostgresClient``) and
provide LLM-friendly error handling and return values.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..core.errors import IntegrationError


def save_investigation_report(
    alert_id: str,
    case_id: Optional[str],
    report: Dict[str, Any],
    warnings: Optional[List[str]] = None,
    client: Any = None,
) -> Dict[str, Any]:
    """
    Persist a generated investigation report.

    Args:
        alert_id: The SIEM alert ID the report was generated for.
        case_id: Optional case ID the report is also associated with.
        report: The structured report to persist.
        warnings: Non-fatal warnings collected while generating the report.
        client: Storage client (e.g. PostgresClient).

    Returns:
        Dictionary with the stored report's id/alert_id/case_id/created_at.

    Raises:
        IntegrationError: If no client is provided or the save fails.
    """
    if client is None:
        raise IntegrationError("No storage client provided")

    try:
        return {
            "success": True,
            **client.save_report(alert_id=alert_id, case_id=case_id, report=report, warnings=warnings),
        }
    except IntegrationError:
        raise
    except Exception as e:
        raise IntegrationError(f"Failed to save investigation report: {e}") from e


def get_investigation_report(report_id: int, client: Any = None) -> Dict[str, Any]:
    """
    Retrieve a previously persisted investigation report by id.

    Tool schema:
    - name: get_investigation_report
    - description: Retrieve a previously stored investigation report by its id
    - parameters:
      - report_id (int, required): The stored report's id

    Args:
        report_id: The stored report's id.
        client: Storage client (e.g. PostgresClient).

    Returns:
        Dictionary containing the stored report.

    Raises:
        IntegrationError: If no client is provided, the lookup fails, or no
            report exists with that id.
    """
    if client is None:
        raise IntegrationError("No storage client provided")

    try:
        report = client.get_report(report_id)
    except IntegrationError:
        raise
    except Exception as e:
        raise IntegrationError(f"Failed to get investigation report {report_id}: {e}") from e

    if report is None:
        raise IntegrationError(f"No investigation report found with id {report_id}")

    return {"success": True, "report": report}


def list_investigation_reports(limit: int = 50, client: Any = None) -> Dict[str, Any]:
    """
    List previously persisted investigation reports, most recent first.

    Tool schema:
    - name: list_investigation_reports
    - description: List previously stored investigation reports, most recent first
    - parameters:
      - limit (int, optional): Maximum number of reports to return. Default: 50

    Args:
        limit: Maximum number of reports to return.
        client: Storage client (e.g. PostgresClient).

    Returns:
        Dictionary containing the list of stored reports.

    Raises:
        IntegrationError: If no client is provided or the lookup fails.
    """
    if client is None:
        raise IntegrationError("No storage client provided")

    try:
        reports = client.list_reports(limit=limit)
    except IntegrationError:
        raise
    except Exception as e:
        raise IntegrationError(f"Failed to list investigation reports: {e}") from e

    return {"success": True, "reports": reports, "count": len(reports)}
