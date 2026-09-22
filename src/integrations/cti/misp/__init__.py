"""
MISP (Malware Information Sharing Platform) integration.

This module provides threat intel lookups (by IP or hash) against a MISP instance.
"""

from .misp_client import MISPClient

__all__ = ["MISPClient"]
