"""
Shared client bootstrap logic for ``investigate_alert()``.

Builds the subset of integration clients that the ``investigate_alert``
pipeline needs (SIEM, CTI, MISP, ATT&CK mapper, LLM, case management,
storage) from a loaded :class:`SamiConfig`. Each client is constructed via
its ``from_config(config)`` classmethod, wrapped in try/except, logged, and
left ``None`` if not configured or construction fails - mirroring the
bootstrap pattern used by the MCP server's ``main()``.

Used by both ``src/mcp/mcp_server.py`` (stdio MCP server) and
``src/web/investigation_api.py`` (HTTP API) so the two entry points stay in
sync instead of duplicating ~150 lines of client construction.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional

from .config import CTIConfig, SamiConfig
from .logging import get_logger

logger = get_logger(__name__)


def bootstrap_investigation_clients(
    config: SamiConfig, extra_logger: Optional[logging.Logger] = None
) -> Dict[str, Any]:
    """
    Construct the clients ``investigate_alert()`` needs from ``config``.

    Args:
        config: Loaded application configuration.
        extra_logger: Optional second logger (e.g. the MCP server's
            dedicated ``sami.mcp`` logger) to additionally log the same
            "attempting/succeeded/failed" messages to.

    Returns:
        Dict with keys: ``case_client``, ``siem_client``, ``cti_client``
        (single client, kept for backward compatibility), ``cti_clients``
        (list, possibly empty), ``misp_client``, ``llm_client``,
        ``storage_client``, ``attack_mapper``. Any client that is not
        configured or whose construction failed is ``None``.
    """
    from ..integrations.attack.attack_mapper import AttackMapper
    from ..integrations.case_management.iris.iris_client import (
        IRISCaseManagementClient,
    )
    from ..integrations.case_management.thehive.thehive_client import (
        TheHiveCaseManagementClient,
    )
    from ..integrations.cti.local_tip.local_tip_client import LocalTipCTIClient
    from ..integrations.cti.misp.misp_client import MISPClient
    from ..integrations.cti.opencti.opencti_client import OpenCTIClient
    from ..integrations.llm.ollama_client import OllamaClient
    from ..integrations.siem.elastic.elastic_client import ElasticSIEMClient
    from ..integrations.storage.postgres_client import PostgresClient

    def _log_info(message: str) -> None:
        logger.info(message)
        if extra_logger is not None:
            extra_logger.info(message)

    def _log_error(message: str) -> None:
        logger.error(message)
        if extra_logger is not None:
            extra_logger.error(message, exc_info=True)

    # Case management client (IRIS takes priority over TheHive, same as
    # the MCP server bootstrap).
    case_client = None
    if config.iris:
        try:
            case_client = IRISCaseManagementClient.from_config(config)
            _log_info("✓ IRIS case management client initialized successfully")
        except Exception as e:
            _log_error(f"✗ Failed to initialize IRIS client: {e}")
    elif config.thehive:
        try:
            case_client = TheHiveCaseManagementClient.from_config(config)
            _log_info("✓ TheHive case management client initialized successfully")
        except Exception as e:
            _log_error(f"✗ Failed to initialize TheHive client: {e}")

    # SIEM client (Elasticsearch or OpenSearch - same wire protocol).
    siem_client = None
    if config.elastic:
        siem_label = config.elastic.siem_type or "elasticsearch"
        try:
            siem_client = ElasticSIEMClient.from_config(config)
            _log_info(f"✓ SIEM client initialized successfully ({siem_label})")
        except Exception as e:
            _log_error(f"✗ Failed to initialize SIEM client ({siem_label}): {e}")

    # CTI client(s) - support both single and multiple platforms.
    cti_clients: List[Any] = []
    cti_client = None  # For backward compatibility.
    if config.cti:
        if config.cti.cti_type == "local_tip":
            try:
                local_tip_client = LocalTipCTIClient.from_config(config)
                cti_clients.append(local_tip_client)
                cti_client = local_tip_client
                _log_info("✓ Local TIP CTI client initialized successfully")
            except Exception as e:
                _log_error(f"✗ Failed to initialize Local TIP CTI client: {e}")
        elif config.cti.cti_type == "opencti":
            try:
                opencti_client = OpenCTIClient.from_config(config)
                cti_clients.append(opencti_client)
                cti_client = opencti_client
                _log_info("✓ OpenCTI client initialized successfully")
            except Exception as e:
                _log_error(f"✗ Failed to initialize OpenCTI client: {e}")

    # Additional CTI platforms configured via config.json's "cti_opencti" /
    # "cti_local_tip" sections, so both platforms can be queried concurrently.
    config_dict = None
    try:
        config_file = os.getenv("SAMIGPT_CONFIG_FILE", "config.json")
        if os.path.exists(config_file):
            with open(config_file, "r") as f:
                config_dict = json.load(f)
    except Exception:
        pass  # If we can't load config dict, that's okay.

    if config_dict and "cti_opencti" in config_dict:
        cti_opencti_config = config_dict["cti_opencti"]
        if cti_opencti_config.get("cti_type") == "opencti":
            try:
                opencti_config = CTIConfig(
                    cti_type="opencti",
                    base_url=cti_opencti_config.get("base_url"),
                    api_key=cti_opencti_config.get("api_key"),
                    timeout_seconds=cti_opencti_config.get("timeout_seconds", 30),
                    verify_ssl=cti_opencti_config.get("verify_ssl", True),
                )
                temp_config = SamiConfig(cti=opencti_config)
                opencti_client = OpenCTIClient.from_config(temp_config)
                if not any("OpenCTI" in c.__class__.__name__ for c in cti_clients):
                    cti_clients.append(opencti_client)
                    _log_info("✓ Additional OpenCTI client initialized successfully")
            except Exception as e:
                _log_error(f"✗ Failed to initialize additional OpenCTI client: {e}")

    if config_dict and "cti_local_tip" in config_dict:
        cti_local_tip_config = config_dict["cti_local_tip"]
        if cti_local_tip_config.get("cti_type") == "local_tip":
            try:
                local_tip_config = CTIConfig(
                    cti_type="local_tip",
                    base_url=cti_local_tip_config.get("base_url"),
                    api_key=cti_local_tip_config.get("api_key"),
                    timeout_seconds=cti_local_tip_config.get("timeout_seconds", 30),
                    verify_ssl=cti_local_tip_config.get("verify_ssl", False),
                )
                temp_config = SamiConfig(cti=local_tip_config)
                local_tip_client = LocalTipCTIClient.from_config(temp_config)
                if not any("LocalTip" in c.__class__.__name__ for c in cti_clients):
                    cti_clients.append(local_tip_client)
                    _log_info("✓ Additional Local TIP client initialized successfully")
            except Exception as e:
                _log_error(f"✗ Failed to initialize additional Local TIP client: {e}")

    # MISP client (independent of the cti_client/cti_clients merge logic above).
    misp_client = None
    if config.misp:
        try:
            misp_client = MISPClient.from_config(config)
            _log_info("✓ MISP client initialized successfully")
        except Exception as e:
            _log_error(f"✗ Failed to initialize MISP client: {e}")

    # LLM client for report generation (Ollama).
    llm_client = None
    if config.ollama:
        try:
            llm_client = OllamaClient.from_config(config)
            _log_info("✓ Ollama client initialized successfully")
        except Exception as e:
            _log_error(f"✗ Failed to initialize Ollama client: {e}")

    # PostgreSQL storage client (investigation report persistence).
    storage_client = None
    if config.postgres:
        try:
            storage_client = PostgresClient.from_config(config)
            storage_client.ensure_table()
            _log_info("✓ PostgreSQL storage client initialized successfully")
        except Exception as e:
            _log_error(f"✗ Failed to initialize PostgreSQL storage client: {e}")
            storage_client = None

    # MITRE ATT&CK technique mapper (no config needed; uses a locally
    # cached dataset, downloading it on first run if missing).
    attack_mapper = None
    try:
        attack_mapper = AttackMapper()
        _log_info("✓ ATT&CK mapper initialized successfully")
    except Exception as e:
        _log_error(f"✗ Failed to initialize ATT&CK mapper: {e}")

    return {
        "case_client": case_client,
        "siem_client": siem_client,
        "cti_client": cti_client,
        "cti_clients": cti_clients,
        "misp_client": misp_client,
        "llm_client": llm_client,
        "storage_client": storage_client,
        "attack_mapper": attack_mapper,
    }
