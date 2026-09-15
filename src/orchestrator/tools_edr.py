"""
LLM-callable tools for EDR operations.

These functions wrap the generic EDRClient interface and provide
LLM-friendly error handling and return values.

SamiGPT policy: only read/enrichment tools are exposed here
(get_endpoint_summary, get_detection_details). Active response actions
(isolate_endpoint, release_endpoint_isolation, kill_process_on_endpoint,
collect_forensic_artifacts) have been removed — the agent must never take
those actions on its own. See README.md "Active response actions removed".
"""

from __future__ import annotations

from typing import Any, Dict

from ..api.edr import EDRClient
from ..core.errors import IntegrationError


def get_endpoint_summary(
    endpoint_id: str,
    client: EDRClient = None,  # type: ignore
) -> Dict[str, Any]:
    """
    Get a summary of an endpoint.

    Tool schema:
    - name: get_endpoint_summary
    - description: Retrieve summary information about an endpoint including
      hostname, platform, last seen time, primary user, and isolation status.
    - parameters:
      - endpoint_id (str, required): The endpoint ID.

    Args:
        endpoint_id: The endpoint ID.
        client: The EDR client.

    Returns:
        Dictionary containing endpoint summary.

    Raises:
        IntegrationError: If retrieving endpoint fails.
    """
    if client is None:
        raise IntegrationError("EDR client not provided")

    try:
        endpoint = client.get_endpoint_summary(endpoint_id)

        return {
            "success": True,
            "endpoint": {
                "id": endpoint.id,
                "hostname": endpoint.hostname,
                "platform": endpoint.platform.value,
                "last_seen": endpoint.last_seen.isoformat()
                if endpoint.last_seen
                else None,
                "primary_user": endpoint.primary_user,
                "is_isolated": endpoint.is_isolated,
            },
        }
    except Exception as e:
        raise IntegrationError(f"Failed to get endpoint summary for {endpoint_id}: {str(e)}") from e


def get_detection_details(
    detection_id: str,
    client: EDRClient = None,  # type: ignore
) -> Dict[str, Any]:
    """
    Get details of a detection.

    Tool schema:
    - name: get_detection_details
    - description: Retrieve detailed information about a specific detection
      including type, severity, description, associated file hash, and process.
    - parameters:
      - detection_id (str, required): The detection ID.

    Args:
        detection_id: The detection ID.
        client: The EDR client.

    Returns:
        Dictionary containing detection details.

    Raises:
        IntegrationError: If retrieving detection fails.
    """
    if client is None:
        raise IntegrationError("EDR client not provided")

    try:
        detection = client.get_detection_details(detection_id)

        return {
            "success": True,
            "detection": {
                "id": detection.id,
                "endpoint_id": detection.endpoint_id,
                "created_at": detection.created_at.isoformat(),
                "detection_type": detection.detection_type.value,
                "severity": detection.severity,
                "description": detection.description,
                "file_hash": detection.file_hash,
                "process": {
                    "pid": detection.process.pid,
                    "name": detection.process.name,
                    "path": detection.process.path,
                    "user": detection.process.user,
                    "command_line": detection.process.command_line,
                }
                if detection.process
                else None,
            },
        }
    except Exception as e:
        raise IntegrationError(f"Failed to get detection details for {detection_id}: {str(e)}") from e

