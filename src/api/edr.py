"""
Generic EDR API for SamiGPT.

This module defines vendor-neutral DTOs and the ``EDRClient`` interface
that orchestrator code and LLM tools will use for endpoint investigation
and response actions.
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
    Vendor-neutral interface for EDR operations.

    Investigation-only by design: this interface intentionally supports
    read/evidence-gathering skills only. Active response actions (endpoint
    isolation, releasing isolation, process termination) are out of scope
    for this agent - remediation is always performed by a human analyst
    directly in the EDR platform.

    Skills supported:
    - get_endpoint_summary
    - get_detection_details
    - collect_forensic_artifacts
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

    def collect_forensic_artifacts(
        self,
        endpoint_id: str,
        artifact_types: List[str],
    ) -> ArtifactCollectionRequest:
        ...


