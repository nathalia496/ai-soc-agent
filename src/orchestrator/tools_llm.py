"""
LLM-callable tools for report generation.

These functions wrap the Ollama report-generation client and provide
LLM-friendly error handling and return values.
"""

from __future__ import annotations

from typing import Any, Dict

from ..core.errors import IntegrationError, ValidationError
from ..core.logging import get_logger

logger = get_logger("sami.orchestrator.tools_llm")


def generate_investigation_report(
    context: str,
    client=None,  # type: ignore
) -> Dict[str, Any]:
    """
    Generate a structured investigation report (timeline, observables,
    hypothesis, next_steps) from free-text investigation context.

    This is a recommendation only: the report is produced by a local LLM for
    a human analyst to review, and does not take or imply any automated
    action.

    Tool schema:
    - name: generate_investigation_report
    - description: Generate a structured investigation report (recommendation only) from alert details, logs, and CTI findings
    - parameters:
      - context (str, required): Free-text investigation context to analyze

    Args:
        context: Investigation context (alert details, logs, CTI findings, etc.).
        client: OllamaClient instance.

    Returns:
        Dictionary containing the generated report.

    Raises:
        IntegrationError: If no client is provided or the request fails.
    """
    if client is None:
        raise IntegrationError("No Ollama client provided")

    try:
        report = client.generate_report(context)
        return {
            "success": True,
            "report": report,
        }
    except ValidationError as e:
        raise IntegrationError(f"Ollama report failed validation: {str(e)}") from e
    except IntegrationError:
        raise
    except Exception as e:
        raise IntegrationError(f"Failed to generate investigation report: {str(e)}") from e
