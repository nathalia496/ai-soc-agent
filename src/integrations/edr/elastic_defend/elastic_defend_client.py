"""
Elastic Defend (Endpoint Security) implementation of the generic ``EDRClient`` interface.
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from ....api.edr import (
    ActionResult,
    ArtifactCollectionRequest,
    Detection,
    DetectionType,
    EDRClient,
    Endpoint,
    KillProcessAction,
    Platform,
    Process,
    QuarantineAction,
)
from ....core.config import SamiConfig
from ....core.errors import IntegrationError
from ....core.logging import get_logger
from .elastic_defend_http import ElasticDefendHttpClient


logger = get_logger("sami.integrations.elastic_defend.client")

# SamiGPT policy: the agent may only read/enrich endpoint data and produce
# recommendations. It must never take active response actions (isolating a
# host, killing a process, triggering forensic collection, etc.) on its own.
# These methods are intentionally disabled at the integration boundary so
# that no caller (tool, runbook, or future code path) can reach the EDR
# vendor API to perform them. See README.md "Active response actions
# removed" for details.
RESPONSE_ACTIONS_DISABLED_MESSAGE = (
    "Active response actions are disabled in SamiGPT. This agent is "
    "read-only/advisory: it may investigate and recommend actions, but it "
    "must never execute containment or disruptive actions (isolate a host, "
    "kill a process, trigger forensic collection, etc.) on its own. Route "
    "this recommendation to a human analyst to execute manually in the EDR "
    "console."
)


class ElasticDefendEDRClient:
    """
    EDR client backed by Elastic Defend (Endpoint Security).

    This implementation uses the Elastic Fleet API for read-only endpoint
    and detection queries. Active response actions (isolation, process
    termination, forensic collection) are intentionally disabled — see
    ``RESPONSE_ACTIONS_DISABLED_MESSAGE``.
    """

    def __init__(self, http_client: ElasticDefendHttpClient) -> None:
        self._http = http_client

    @classmethod
    def from_config(cls, config: SamiConfig) -> "ElasticDefendEDRClient":
        """
        Factory to construct a client from ``SamiConfig``.
        """
        if not config.edr:
            raise IntegrationError("EDR configuration is not set in SamiConfig")
        
        if config.edr.edr_type != "elastic_defend":
            raise IntegrationError(f"EDR type '{config.edr.edr_type}' is not supported. Use 'elastic_defend' for Elastic Defend.")

        http_client = ElasticDefendHttpClient(
            base_url=config.edr.base_url,
            api_key=config.edr.api_key,
            timeout_seconds=config.edr.timeout_seconds,
            verify_ssl=config.edr.verify_ssl,
        )
        return cls(http_client=http_client)

    def get_endpoint_summary(self, endpoint_id: str) -> Endpoint:
        """Get endpoint details by ID."""
        try:
            # Use Fleet API to get agent details
            response = self._http.get(f"/api/fleet/agents/{endpoint_id}")
            
            agent = response.get("item", {})
            local_metadata = agent.get("local_metadata", {})
            host = local_metadata.get("host", {})
            os_info = host.get("os", {})
            
            # Determine platform
            platform_name = os_info.get("name", "").lower()
            if "windows" in platform_name:
                platform = Platform.WINDOWS
            elif "linux" in platform_name:
                platform = Platform.LINUX
            elif "mac" in platform_name or "darwin" in platform_name:
                platform = Platform.MACOS
            else:
                platform = Platform.OTHER
            
            # Parse last seen
            last_seen = None
            last_checkin = agent.get("last_checkin")
            if last_checkin:
                try:
                    last_seen = datetime.fromisoformat(last_checkin.replace("Z", "+00:00"))
                except Exception:
                    pass
            
            return Endpoint(
                id=endpoint_id,
                hostname=host.get("hostname", endpoint_id),
                platform=platform,
                last_seen=last_seen,
                primary_user=local_metadata.get("user", {}).get("name"),
                is_isolated=agent.get("status") == "isolated",
            )
        except Exception as e:
            logger.exception(f"Error getting endpoint summary: {e}")
            raise IntegrationError(f"Failed to get endpoint summary: {e}") from e

    def list_endpoints(self, limit: int = 50) -> List[Endpoint]:
        """List all endpoints."""
        try:
            response = self._http.get("/api/fleet/agents", params={"perPage": limit})
            
            agents = response.get("items", [])
            endpoints = []
            
            for agent in agents:
                agent_id = agent.get("id", "")
                if not agent_id:
                    continue
                
                try:
                    endpoint = self.get_endpoint_summary(agent_id)
                    endpoints.append(endpoint)
                except Exception as e:
                    logger.warning(f"Failed to get details for endpoint {agent_id}: {e}")
                    continue
            
            return endpoints[:limit]
        except Exception as e:
            logger.exception(f"Error listing endpoints: {e}")
            raise IntegrationError(f"Failed to list endpoints: {e}") from e

    def get_detection_details(self, detection_id: str) -> Detection:
        """Get detection/alert details by ID."""
        try:
            # Search for detection in security events
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"_id": detection_id}},
                            {"term": {"event.category": "malware"}}
                        ]
                    }
                }
            }
            
            # Search in security indices
            indices = "logs-endpoint.events.*"
            response = self._http.post(f"/{indices}/_search", json_data=query)
            
            hits = response.get("hits", {}).get("hits", [])
            if not hits:
                raise IntegrationError(f"Detection {detection_id} not found")
            
            hit = hits[0]
            source = hit.get("_source", {})
            event = source.get("event", {})
            
            # Determine detection type
            detection_type = DetectionType.OTHER
            if "malware" in event.get("category", []):
                detection_type = DetectionType.MALWARE
            elif "suspicious" in event.get("category", []):
                detection_type = DetectionType.SUSPICIOUS_ACTIVITY
            
            # Parse timestamp
            timestamp_str = source.get("@timestamp")
            created_at = datetime.utcnow()
            if timestamp_str:
                try:
                    created_at = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
                except Exception:
                    pass
            
            # Extract process info
            process_data = source.get("process", {})
            process = None
            if process_data:
                process = Process(
                    pid=process_data.get("pid", 0),
                    name=process_data.get("name", ""),
                    path=process_data.get("executable"),
                    user=process_data.get("user", {}).get("name") if isinstance(process_data.get("user"), dict) else None,
                    command_line=process_data.get("command_line"),
                )
            
            return Detection(
                id=detection_id,
                endpoint_id=source.get("agent", {}).get("id", "") if isinstance(source.get("agent"), dict) else "",
                created_at=created_at,
                detection_type=detection_type,
                severity=event.get("severity"),
                description=event.get("action") or event.get("reason"),
                file_hash=source.get("file", {}).get("hash", {}).get("sha256") if isinstance(source.get("file"), dict) else None,
                process=process,
                raw=source,
            )
        except Exception as e:
            logger.exception(f"Error getting detection details: {e}")
            raise IntegrationError(f"Failed to get detection details: {e}") from e

    def list_detections(
        self,
        endpoint_id: Optional[str] = None,
        limit: int = 50,
    ) -> List[Detection]:
        """List detections, optionally filtered by endpoint."""
        try:
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"event.category": "malware"}}
                        ]
                    }
                },
                "size": limit,
                "sort": [{"@timestamp": {"order": "desc"}}]
            }
            
            if endpoint_id:
                query["query"]["bool"]["must"].append({
                    "term": {"agent.id": endpoint_id}
                })
            
            indices = "logs-endpoint.events.*"
            response = self._http.post(f"/{indices}/_search", json_data=query)
            
            hits = response.get("hits", {}).get("hits", [])
            detections = []
            
            for hit in hits:
                detection_id = hit.get("_id", "")
                try:
                    detection = self.get_detection_details(detection_id)
                    detections.append(detection)
                except Exception as e:
                    logger.warning(f"Failed to get details for detection {detection_id}: {e}")
                    continue
            
            return detections[:limit]
        except Exception as e:
            logger.exception(f"Error listing detections: {e}")
            raise IntegrationError(f"Failed to list detections: {e}") from e

    def isolate_endpoint(self, endpoint_id: str) -> QuarantineAction:
        """Disabled: active response actions are not permitted. See module docstring."""
        raise IntegrationError(RESPONSE_ACTIONS_DISABLED_MESSAGE)

    def release_endpoint_isolation(self, endpoint_id: str) -> QuarantineAction:
        """Disabled: active response actions are not permitted. See module docstring."""
        raise IntegrationError(RESPONSE_ACTIONS_DISABLED_MESSAGE)

    def kill_process_on_endpoint(
        self,
        endpoint_id: str,
        pid: int,
    ) -> KillProcessAction:
        """Disabled: active response actions are not permitted. See module docstring."""
        raise IntegrationError(RESPONSE_ACTIONS_DISABLED_MESSAGE)

    def collect_forensic_artifacts(
        self,
        endpoint_id: str,
        artifact_types: List[str],
    ) -> ArtifactCollectionRequest:
        """Disabled: active response actions are not permitted. See module docstring."""
        raise IntegrationError(RESPONSE_ACTIONS_DISABLED_MESSAGE)

