"""
Generic EDR API for SamiGPT.

This module defines vendor-neutral DTOs and the ``EDRClient`` interface
that orchestrator code and LLM tools use for endpoint investigation.

SamiGPT policy: the agent is read-only/advisory for EDR. Active response
actions (endpoint isolation, process termination, forensic collection,
etc.) are intentionally NOT part of this interface — the agent must only
retrieve data and produce recommendations for a human analyst to execute.
The ``QuarantineAction``, ``KillProcessAction`` and
``ArtifactCollectionRequest`` DTOs are kept only because vendor client
implementations still reference them on their now-disabled methods; see
``src/integrations/edr/elastic_defend/elastic_defend_client.py``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import List, Optional, Protocol

from ..core.dto import BaseDTO


class Platform(str, Enum):
    """
    Endpoint platform/OS.
    """

    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    OTHER = "other"


class DetectionType(str, Enum):
    """
    High-level detection category.
    """

    MALWARE = "malware"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    POLICY_VIOLATION = "policy_violation"
    OTHER = "other"


class ActionResult(str, Enum):
    """
    Result of a response action.
    """

    SUCCESS = "success"
    FAILED = "failed"
    PENDING = "pending"


@dataclass
class Endpoint(BaseDTO):
    """
    Endpoint (host) representation.
    """

    id: str
    hostname: str
    platform: Platform
    last_seen: Optional[datetime] = None
    primary_user: Optional[str] = None
    is_isolated: bool = False


@dataclass
class Process(BaseDTO):
    """
    Process running on an endpoint.
    """

    pid: int
    name: str
    path: Optional[str] = None
    user: Optional[str] = None
    command_line: Optional[str] = None


@dataclass
class Detection(BaseDTO):
    """
    Detection/alert from an EDR system.
    """

    id: str
    endpoint_id: str
    created_at: datetime
    detection_type: DetectionType
    severity: Optional[str] = None
    description: Optional[str] = None
    file_hash: Optional[str] = None
    process: Optional[Process] = None
    raw: Optional[dict] = None


@dataclass
class QuarantineAction(BaseDTO):
    """
    Represents an isolation/quarantine action on an endpoint.
    """

    endpoint_id: str
    requested_at: datetime
    completed_at: Optional[datetime] = None
    result: ActionResult = ActionResult.PENDING
    message: Optional[str] = None


@dataclass
class KillProcessAction(BaseDTO):
    """
    Represents a process termination action on an endpoint.
    """

    endpoint_id: str
    pid: int
    requested_at: datetime
    completed_at: Optional[datetime] = None
    result: ActionResult = ActionResult.PENDING
    message: Optional[str] = None


@dataclass
class ArtifactCollectionRequest(BaseDTO):
    """
    Represents a forensic artifact collection request.
    """

    endpoint_id: str
    requested_at: datetime
    artifact_types: List[str]
    completed_at: Optional[datetime] = None
    result: ActionResult = ActionResult.PENDING
    message: Optional[str] = None


class EDRClient(Protocol):
    """
    Vendor-neutral, read-only interface for EDR operations.

    This interface is intentionally limited to investigation/enrichment:
    - get_endpoint_summary
    - list_endpoints
    - get_detection_details
    - list_detections

    Active response actions (isolation, process termination, forensic
    collection) are NOT part of this interface. See module docstring.
    """

    # Endpoint and detection retrieval
    def get_endpoint_summary(self, endpoint_id: str) -> Endpoint:
        ...

    def list_endpoints(self, limit: int = 50) -> List[Endpoint]:
        ...

    def get_detection_details(self, detection_id: str) -> Detection:
        ...

    def list_detections(
        self,
        endpoint_id: Optional[str] = None,
        limit: int = 50,
    ) -> List[Detection]:
        ...


