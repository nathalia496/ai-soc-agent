"""
MISP (Malware Information Sharing Platform) implementation of a CTI client.

This client looks up an IP address or a file hash against a MISP instance and
returns the tags and threat context (matching events) associated with it.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, List

from ....core.config import SamiConfig
from ....core.errors import IntegrationError
from ....core.logging import get_logger
from .misp_http import MISPHttpClient


logger = get_logger("sami.integrations.cti.misp.client")

_HASH_ALGORITHM_BY_LENGTH = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def _detect_indicator_type(value: str) -> str:
    """
    Best-effort detection of whether a value is an IP address or a file hash.

    Returns:
        "ip", "hash", or "unknown"
    """
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass

    if _HEX_RE.match(value) and len(value) in _HASH_ALGORITHM_BY_LENGTH:
        return "hash"

    return "unknown"


class MISPClient:
    """
    CTI client backed by MISP.

    Provides threat intelligence lookup capabilities for IPs and hashes.
    """

    def __init__(self, http_client: MISPHttpClient) -> None:
        """
        Initialize the MISP client.

        Args:
            http_client: HTTP client for making API requests
        """
        self._http = http_client

    @classmethod
    def from_config(cls, config: SamiConfig) -> "MISPClient":
        """
        Factory to construct a client from SamiConfig.

        Args:
            config: SamiConfig instance with MISP configuration

        Returns:
            MISPClient instance

        Raises:
            IntegrationError: If MISP configuration is not set
        """
        if not config.misp:
            raise IntegrationError("MISP configuration is not set in SamiConfig")

        http_client = MISPHttpClient(
            base_url=config.misp.base_url,
            api_key=config.misp.api_key,
            timeout_seconds=config.misp.timeout_seconds,
            verify_ssl=config.misp.verify_ssl,
        )
        return cls(http_client=http_client)

    def lookup_indicator(self, indicator: str) -> Dict[str, Any]:
        """
        Look up an IP address or hash in MISP and return its tags and threat context.

        Args:
            indicator: The IP address or hash value to look up

        Returns:
            Dictionary with the indicator, its detected type, whether it was found,
            the set of tags across all matching attributes, and the related events:
            {
                "indicator": str,
                "indicator_type": "ip" | "hash" | "unknown",
                "found": bool,
                "tags": List[str],
                "events": [{"event_id", "info", "threat_level_id", "tags"}, ...],
            }

        Raises:
            IntegrationError: If the lookup fails
        """
        indicator_value = indicator.strip()
        indicator_type = _detect_indicator_type(indicator_value)

        try:
            attributes = self._http.search_attribute(indicator_value)
        except Exception as e:
            logger.exception(f"Error looking up indicator {indicator_value} in MISP: {e}")
            if isinstance(e, IntegrationError):
                raise
            raise IntegrationError(f"Failed to lookup indicator in MISP: {e}") from e

        if not attributes:
            logger.info(f"Indicator {indicator_value} not found in MISP")
            return {
                "indicator": indicator_value,
                "indicator_type": indicator_type,
                "found": False,
                "tags": [],
                "events": [],
            }

        all_tags: set = set()
        events: List[Dict[str, Any]] = []

        for attribute in attributes:
            attribute_tags = [tag.name for tag in getattr(attribute, "Tag", []) or []]
            all_tags.update(attribute_tags)

            event = getattr(attribute, "Event", None)
            events.append(
                {
                    "event_id": getattr(event, "id", None) if event else None,
                    "info": getattr(event, "info", None) if event else None,
                    "threat_level_id": getattr(event, "threat_level_id", None) if event else None,
                    "tags": attribute_tags,
                }
            )

        logger.info(
            f"Found {len(attributes)} matching attribute(s) for {indicator_value} in MISP "
            f"with {len(all_tags)} unique tag(s)"
        )

        return {
            "indicator": indicator_value,
            "indicator_type": indicator_type,
            "found": True,
            "tags": sorted(all_tags),
            "events": events,
        }
