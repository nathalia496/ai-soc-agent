"""
Storage integrations.

This package provides persistence backends for data produced by the
orchestrator (currently: investigation reports in PostgreSQL).
"""

from .postgres_client import PostgresClient

__all__ = ["PostgresClient"]
