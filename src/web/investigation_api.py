"""
Minimal HTTP API for the ``investigate_alert()`` pipeline.

This is a third, optional way to run an investigation end-to-end, alongside
the MCP server (src/mcp/mcp_server.py) and the configuration web UI
(src/web/config_server.py). It is intentionally narrow: one endpoint that
calls ``investigate_alert()`` and returns its report for a human analyst to
review - the same investigation-only, human-in-the-loop contract the MCP
tool already has. It does not take any remediation action.

Kept as its own module/app (rather than folded into config_server.py) to
keep configuration management and investigation execution as separate
concerns, per this project's design principles.

Run with:
    uvicorn src.web.investigation_api:app --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import os
import secrets
from contextlib import asynccontextmanager
from typing import Any, Dict, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel

from ..core.client_bootstrap import bootstrap_investigation_clients
from ..core.config_storage import load_config_from_file
from ..core.errors import ConfigError, IntegrationError
from ..core.logging import get_logger
from ..orchestrator.investigate_alert import investigate_alert

logger = get_logger(__name__)

# Same admin-secret pattern as config_server.py, adapted for a stateless API:
# a shared secret compared in constant time, sent as a header instead of a
# session cookie (there is no login page/flow here).
ADMIN_SECRET = os.getenv("SAMIGPT_ADMIN_SECRET", "admin")

# Clients are bootstrapped once on startup and stashed here; see `lifespan`.
_clients: Dict[str, Any] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        config = load_config_from_file()
    except ConfigError as e:
        logger.error(f"Failed to load configuration: {e}", exc_info=True)
        config = None

    if config is not None:
        _clients.update(bootstrap_investigation_clients(config))
    yield
    _clients.clear()


app = FastAPI(
    title="SamiGPT Investigation API",
    description="Minimal HTTP endpoint for the investigate_alert() pipeline",
    version="1.0.0",
    lifespan=lifespan,
)


def require_admin_secret(x_admin_secret: Optional[str] = Header(default=None)) -> None:
    """
    Require the ``X-Admin-Secret`` header to match SAMIGPT_ADMIN_SECRET.

    Mirrors config_server.py's constant-time secret comparison, but as a
    per-request header check instead of a cookie-backed login session,
    since this API has no browser UI to log in through.
    """
    if not x_admin_secret or not secrets.compare_digest(x_admin_secret, ADMIN_SECRET):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid X-Admin-Secret header",
        )


class InvestigateRequest(BaseModel):
    case_id: Optional[str] = None
    minutes_before: int = 30
    minutes_after: int = 30
    attack_top_n: int = 5
    comment_author: str = "SamiGPT"


@app.get("/health")
async def health() -> Dict[str, Any]:
    """Report which optional integrations are actually configured."""
    return {
        "status": "ok",
        "integrations": {
            "siem": _clients.get("siem_client") is not None,
            "cti": bool(_clients.get("cti_clients")),
            "misp": _clients.get("misp_client") is not None,
            "attack_mapper": _clients.get("attack_mapper") is not None,
            "llm": _clients.get("llm_client") is not None,
            "case_management": _clients.get("case_client") is not None,
            "storage": _clients.get("storage_client") is not None,
        },
    }


@app.post("/investigate/{alert_id}", dependencies=[Depends(require_admin_secret)])
async def investigate(alert_id: str, body: Optional[InvestigateRequest] = None) -> Dict[str, Any]:
    """
    Run the end-to-end investigate_alert() pipeline for ``alert_id``.

    Returns the same report/warnings/artifact structure investigate_alert()
    produces when called directly or via the MCP tool - a report for a
    human analyst to review, not an automated action.
    """
    params = body or InvestigateRequest()

    if _clients.get("siem_client") is None or _clients.get("llm_client") is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="SIEM and/or LLM client not configured; investigate_alert() requires both",
        )

    try:
        return investigate_alert(
            alert_id=alert_id,
            siem_client=_clients.get("siem_client"),
            cti_clients=_clients.get("cti_clients"),
            misp_client=_clients.get("misp_client"),
            attack_mapper=_clients.get("attack_mapper"),
            llm_client=_clients.get("llm_client"),
            case_client=_clients.get("case_client"),
            case_id=params.case_id,
            storage_client=_clients.get("storage_client"),
            minutes_before=params.minutes_before,
            minutes_after=params.minutes_after,
            attack_top_n=params.attack_top_n,
            comment_author=params.comment_author,
        )
    except IntegrationError as e:
        # Log the full exception server-side only; the client gets a generic
        # message so internal details (exception text, integration internals)
        # never flow into the HTTP response.
        logger.error(f"investigate_alert() failed for alert {alert_id}: {e}", exc_info=True)
        if "not found" in str(e).lower():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Alert {alert_id} not found",
            ) from e
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Upstream integration error while investigating alert",
        ) from e
