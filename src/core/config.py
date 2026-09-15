"""
Configuration models and loading logic for SamiGPT.

The goal of this module is to provide a single place where runtime
configuration (API URLs, auth tokens, timeouts, logging settings, etc.)
is defined and loaded from the environment.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from typing import Optional

from .errors import ConfigError

try:
    # Load variables from a local .env file (if present) into the process
    # environment, so integrations can be configured via os.getenv(...)
    # without ever hardcoding URLs/credentials in source. This does not
    # override variables that are already set in the real environment.
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:  # pragma: no cover - python-dotenv is an optional dep
    pass


@dataclass
class TheHiveConfig:
    """
    Configuration for the TheHive case management integration.
    """

    base_url: str
    api_key: str
    timeout_seconds: int = 30


@dataclass
class IrisConfig:
    """
    Configuration for the IRIS case management integration.
    """

    base_url: str
    api_key: str
    timeout_seconds: int = 30
    verify_ssl: bool = True


@dataclass
class ElasticConfig:
    """
    Configuration for Elastic (SIEM) integration.
    """

    base_url: str
    api_key: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    timeout_seconds: int = 30
    verify_ssl: bool = True


@dataclass
class EDRConfig:
    """
    Configuration for EDR integration (generic, can be Velociraptor, CrowdStrike, Elastic Defend, etc.).
    """

    edr_type: str  # e.g., "velociraptor", "crowdstrike", "elastic_defend"
    base_url: str
    api_key: str
    timeout_seconds: int = 30
    verify_ssl: bool = True
    additional_params: Optional[dict] = None


@dataclass
class CTIConfig:
    """
    Configuration for CTI (Cyber Threat Intelligence) integration.
    """

    cti_type: str  # e.g., "local_tip", "opencti"
    base_url: str
    api_key: Optional[str] = None  # Required for OpenCTI, optional for local_tip
    timeout_seconds: int = 30
    verify_ssl: bool = True


@dataclass
class TrelloConfig:
    """
    Configuration for Trello integration.
    """

    api_key: str
    api_token: str
    fine_tuning_board_id: str
    engineering_board_id: str
    timeout_seconds: int = 30
    verify_ssl: bool = True


@dataclass
class ClickUpConfig:
    """
    Configuration for ClickUp integration.
    """

    api_token: str
    fine_tuning_list_id: str
    engineering_list_id: str
    space_id: Optional[str] = None  # Optional space ID for workspace organization
    timeout_seconds: int = 30
    verify_ssl: bool = True


@dataclass
class GitHubConfig:
    """
    Configuration for GitHub integration.
    """

    api_token: str
    fine_tuning_project_id: str
    engineering_project_id: str
    timeout_seconds: int = 30
    verify_ssl: bool = True


@dataclass
class EngConfig:
    """
    Configuration for Engineering integrations.
    """

    trello: Optional[TrelloConfig] = None
    clickup: Optional[ClickUpConfig] = None
    github: Optional[GitHubConfig] = None
    provider: str = "trello"  # "trello", "clickup", or "github" - which provider to use


@dataclass
class LoggingConfig:
    """
    Logging-related configuration.
    """

    log_dir: str = "logs"
    log_level: str = "INFO"


@dataclass
class WebConfig:
    """
    Configuration for the web management interface.
    """

    admin_secret: str  # Secret/password for accessing the management interface
    session_secret: Optional[str] = None  # Secret for session signing (auto-generated if not provided)


@dataclass
class SamiConfig:
    """
    Top-level configuration for SamiGPT.

    Additional sections (for SIEM, EDR, etc.) can be added here later.
    """

    thehive: Optional[TheHiveConfig] = None
    iris: Optional[IrisConfig] = None
    elastic: Optional[ElasticConfig] = None
    edr: Optional[EDRConfig] = None
    cti: Optional[CTIConfig] = None
    eng: Optional[EngConfig] = None
    logging: Optional[LoggingConfig] = None
    web: Optional[WebConfig] = None


def _require_env(name: str) -> str:
    """
    Read a required environment variable or raise ConfigError if missing.
    """

    value = os.getenv(name)
    if not value:
        raise ConfigError(f"Required environment variable {name!r} is not set")
    return value


def load_elastic_config_from_env() -> Optional[ElasticConfig]:
    """
    Build an ``ElasticConfig`` purely from environment variables (typically
    populated from a local ``.env`` file via ``python-dotenv``).

    This is how the SIEM integration connects to a local OpenSearch/Elastic
    instance for development: the URL is never hardcoded in source, it is
    always read from ``SAMIGPT_ELASTIC_URL`` (see ``.env.example``).

    Environment variables:
        SAMIGPT_ELASTIC_URL: Base URL of the Elasticsearch/OpenSearch
            cluster (e.g. "http://localhost:9200" for a local OpenSearch
            instance). Required — if unset, this function returns None and
            the SIEM integration is treated as not configured.
        SAMIGPT_ELASTIC_API_KEY: Optional API key for authentication.
        SAMIGPT_ELASTIC_USERNAME / SAMIGPT_ELASTIC_PASSWORD: Optional basic
            auth credentials.
        SAMIGPT_ELASTIC_TIMEOUT_SECONDS: Request timeout (default: 30).
        SAMIGPT_ELASTIC_VERIFY_SSL: Whether to verify TLS certificates
            (default: "true"). Set to "false" ONLY for local/dev clusters
            reached over plain HTTP or with a self-signed certificate —
            never disable certificate verification against a production or
            internet-facing OpenSearch/Elasticsearch endpoint.

    Returns:
        ElasticConfig if SAMIGPT_ELASTIC_URL is set, otherwise None.
    """

    base_url = os.getenv("SAMIGPT_ELASTIC_URL")
    if not base_url:
        return None

    timeout_raw = os.getenv("SAMIGPT_ELASTIC_TIMEOUT_SECONDS", "30")
    try:
        timeout_seconds = int(timeout_raw)
    except ValueError as exc:
        raise ConfigError(
            "SAMIGPT_ELASTIC_TIMEOUT_SECONDS must be an integer"
        ) from exc

    # DEV-ONLY SWITCH: SAMIGPT_ELASTIC_VERIFY_SSL=false disables TLS
    # certificate verification for the SIEM HTTP client. This is only meant
    # for connecting to a local OpenSearch/Elasticsearch instance (e.g.
    # http://localhost:9200, or a self-signed local HTTPS setup). Never set
    # this to "false" for a staging/production cluster reachable outside
    # your machine — doing so allows man-in-the-middle attacks.
    verify_ssl = os.getenv("SAMIGPT_ELASTIC_VERIFY_SSL", "true").strip().lower() not in (
        "false",
        "0",
        "no",
    )

    return ElasticConfig(
        base_url=base_url,
        api_key=os.getenv("SAMIGPT_ELASTIC_API_KEY"),
        username=os.getenv("SAMIGPT_ELASTIC_USERNAME"),
        password=os.getenv("SAMIGPT_ELASTIC_PASSWORD"),
        timeout_seconds=timeout_seconds,
        verify_ssl=verify_ssl,
    )


def load_config() -> SamiConfig:
    """
    Load SamiGPT configuration from environment variables.

    Environment variables:
        SAMIGPT_THEHIVE_URL: Base URL for TheHive (required if TheHive is used).
        SAMIGPT_THEHIVE_API_KEY: API key/token for TheHive.
        SAMIGPT_THEHIVE_TIMEOUT_SECONDS: Request timeout for TheHive (default: 30).

        SAMIGPT_ELASTIC_URL: Base URL for the Elasticsearch/OpenSearch SIEM
            backend (e.g. "http://localhost:9200" for local OpenSearch).
            See load_elastic_config_from_env() for the full list of
            SAMIGPT_ELASTIC_* variables (API key, basic auth, timeout,
            verify_ssl). See .env.example.

        SAMIGPT_LOG_DIR: Directory for log files (default: "logs").
        SAMIGPT_LOG_LEVEL: Root log level (default: "INFO").

    If TheHive/Elastic variables are not set, the configuration will still be
    returned with `thehive`/`elastic` set to None, allowing you to run
    without those integrations.
    """

    # Logging config
    log_dir = os.getenv("SAMIGPT_LOG_DIR", "logs")
    log_level = os.getenv("SAMIGPT_LOG_LEVEL", "INFO")
    logging_cfg = LoggingConfig(log_dir=log_dir, log_level=log_level)

    # TheHive config (optional but recommended). If one of the key vars is set,
    # we require the others to avoid a half-configured integration.
    thehive_url = os.getenv("SAMIGPT_THEHIVE_URL")
    thehive_api_key = os.getenv("SAMIGPT_THEHIVE_API_KEY")
    thehive_timeout_raw = os.getenv("SAMIGPT_THEHIVE_TIMEOUT_SECONDS", "30")

    thehive_cfg: Optional[TheHiveConfig]
    if thehive_url or thehive_api_key:
        # If any TheHive-related env var is set, treat TheHive as enabled
        if not thehive_url:
            raise ConfigError(
                "SAMIGPT_THEHIVE_URL must be set when SAMIGPT_THEHIVE_API_KEY is provided"
            )
        if not thehive_api_key:
            raise ConfigError(
                "SAMIGPT_THEHIVE_API_KEY must be set when SAMIGPT_THEHIVE_URL is provided"
            )
        try:
            timeout_seconds = int(thehive_timeout_raw)
        except ValueError as exc:
            raise ConfigError(
                "SAMIGPT_THEHIVE_TIMEOUT_SECONDS must be an integer"
            ) from exc

        thehive_cfg = TheHiveConfig(
            base_url=thehive_url,
            api_key=thehive_api_key,
            timeout_seconds=timeout_seconds,
        )
    else:
        thehive_cfg = None

    # Elastic/OpenSearch SIEM config (optional). See
    # load_elastic_config_from_env() for the supported environment
    # variables — the URL is always read from SAMIGPT_ELASTIC_URL, never
    # hardcoded here.
    elastic_cfg = load_elastic_config_from_env()

    return SamiConfig(
        thehive=thehive_cfg,
        elastic=elastic_cfg,
        logging=logging_cfg,
    )


