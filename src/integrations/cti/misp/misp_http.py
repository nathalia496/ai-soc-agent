"""
Low-level client for MISP (Malware Information Sharing Platform).

This module wraps PyMISP's ExpandedPyMISP to search for attributes (IPs, hashes)
and translates connection/timeout/API errors into IntegrationError.
"""

from __future__ import annotations

from typing import Any, List, Optional

import requests
from pymisp import ExpandedPyMISP, PyMISPError

from ....core.errors import IntegrationError
from ....core.logging import get_logger


logger = get_logger("sami.integrations.cti.misp.http")


class MISPHttpClient:
    """
    Thin wrapper around PyMISP's ExpandedPyMISP client.

    Handles attribute search (IP/hash) via the MISP REST API.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        timeout_seconds: int = 30,
        verify_ssl: bool = True,
    ) -> None:
        """
        Initialize the MISP HTTP client.

        Args:
            base_url: Base URL of the MISP instance (e.g., "https://misp.example.com")
            api_key: MISP automation API key
            timeout_seconds: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
        """
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds
        self.verify_ssl = verify_ssl
        self._misp: Optional[ExpandedPyMISP] = None

    def _client(self) -> ExpandedPyMISP:
        """
        Lazily create and cache the underlying PyMISP client.

        Raises:
            IntegrationError: If the connection to MISP cannot be established
        """
        if self._misp is not None:
            return self._misp

        try:
            logger.debug(f"Connecting to MISP at {self.base_url}")
            self._misp = ExpandedPyMISP(
                url=self.base_url,
                key=self.api_key,
                ssl=self.verify_ssl,
                timeout=self.timeout_seconds,
            )
        except requests.exceptions.Timeout as e:
            logger.error(f"Timeout connecting to MISP at {self.base_url}: {e}")
            raise IntegrationError(f"Timeout connecting to MISP: {e}") from e
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Could not connect to MISP at {self.base_url}: {e}")
            raise IntegrationError(f"Could not connect to MISP at {self.base_url}: {e}") from e
        except requests.exceptions.RequestException as e:
            logger.error(f"MISP connection failed: {e}")
            raise IntegrationError(f"MISP connection failed: {e}") from e
        except PyMISPError as e:
            logger.error(f"MISP client initialization failed: {e}")
            raise IntegrationError(f"MISP client initialization failed: {e}") from e

        return self._misp

    def search_attribute(self, value: str) -> List[Any]:
        """
        Search MISP for attributes (IP or hash) matching the given value.

        Args:
            value: The IOC value to search for (IP address or hash)

        Returns:
            List of matching MISPAttribute objects (with event context), empty if none found

        Raises:
            IntegrationError: If the search request fails
        """
        misp = self._client()

        try:
            logger.debug(f"Searching MISP attributes for value: {value}")
            results = misp.search(
                controller="attributes",
                value=value,
                include_context=True,
                pythonify=True,
            )
        except requests.exceptions.Timeout as e:
            logger.error(f"Timeout searching MISP for '{value}': {e}")
            raise IntegrationError(f"Timeout searching MISP: {e}") from e
        except requests.exceptions.RequestException as e:
            logger.error(f"MISP search request failed for '{value}': {e}")
            raise IntegrationError(f"MISP search request failed: {e}") from e
        except PyMISPError as e:
            logger.error(f"MISP search failed for '{value}': {e}")
            raise IntegrationError(f"MISP search failed: {e}") from e

        # When pythonify fails to build objects (e.g. auth error), PyMISP returns
        # a plain dict with an "errors" key instead of raising.
        if isinstance(results, dict):
            if results.get("errors"):
                raise IntegrationError(f"MISP returned an error: {results['errors']}")
            return []

        return results or []
