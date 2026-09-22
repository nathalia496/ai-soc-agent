"""
Ollama implementation of a report-generation LLM client.

This client sends investigation context to a local Ollama model and returns
a structured JSON report (timeline, observables, hypothesis, next_steps) for
a human SOC analyst to review. It never executes actions on its own -
the output is a recommendation only.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from ...core.config import SamiConfig
from ...core.errors import IntegrationError, ValidationError
from ...core.logging import get_logger
from .ollama_http import OllamaHttpClient


logger = get_logger("sami.integrations.llm.ollama.client")

REQUIRED_REPORT_KEYS: List[str] = ["timeline", "observables", "hypothesis", "next_steps"]

REPORT_SYSTEM_PROMPT = """You are a SOC (Security Operations Center) analysis assistant.

Your role is strictly advisory: you analyze the investigation context you are given \
and produce a structured report for a human analyst to review. You never execute, \
block, remediate, or otherwise take action yourself - you only recommend.

You MUST respond with a single valid JSON object and nothing else: no markdown code \
fences, no prose before or after, no explanations outside the JSON. The JSON object \
must contain exactly these top-level keys:

- "timeline": an array of objects, each with "timestamp" and "description", describing \
  the sequence of relevant events in chronological order.
- "observables": an array of objects, each with "type" (e.g. "ip", "hash", "domain", \
  "user") and "value", listing the indicators relevant to this investigation.
- "hypothesis": a string describing the most likely explanation for what occurred, \
  based on the available evidence.
- "next_steps": an array of strings, each a concrete, actionable recommendation for the \
  human analyst to investigate or respond to this case. These are recommendations only \
  - never phrase them as actions already taken.

Respond with only the JSON object."""


class OllamaClient:
    """
    LLM client backed by a local Ollama server.

    Provides structured, JSON-validated report generation for SOC investigations.
    """

    def __init__(self, http_client: OllamaHttpClient) -> None:
        """
        Initialize the Ollama client.

        Args:
            http_client: HTTP client for making API requests
        """
        self._http = http_client

    @classmethod
    def from_config(cls, config: SamiConfig) -> "OllamaClient":
        """
        Factory to construct a client from SamiConfig.

        Args:
            config: SamiConfig instance with Ollama configuration

        Returns:
            OllamaClient instance

        Raises:
            IntegrationError: If Ollama configuration is not set
        """
        if not config.ollama:
            raise IntegrationError("Ollama configuration is not set in SamiConfig")

        http_client = OllamaHttpClient(
            base_url=config.ollama.base_url,
            model=config.ollama.model,
            timeout_seconds=config.ollama.timeout_seconds,
        )
        return cls(http_client=http_client)

    def generate_report(self, context: str) -> Dict[str, Any]:
        """
        Generate a structured investigation report from the given context.

        Args:
            context: Investigation context (alert details, logs, case notes, etc.)
                to analyze.

        Returns:
            Parsed dict with keys "timeline", "observables", "hypothesis", "next_steps".

        Raises:
            IntegrationError: If the request to Ollama fails.
            ValidationError: If the model's response is not valid JSON, or is missing
                one or more required keys.
        """
        raw_content = self._http.chat_completion(REPORT_SYSTEM_PROMPT, context)

        try:
            report = json.loads(raw_content)
        except json.JSONDecodeError as e:
            logger.error(f"Ollama response was not valid JSON: {raw_content[:500]!r}")
            raise ValidationError(
                f"Ollama response was not valid JSON: {e}. Raw response: {raw_content[:500]!r}"
            ) from e

        if not isinstance(report, dict):
            raise ValidationError(
                f"Ollama response must be a JSON object, got {type(report).__name__}"
            )

        missing_keys = [key for key in REQUIRED_REPORT_KEYS if key not in report]
        if missing_keys:
            raise ValidationError(
                f"Ollama report is missing required key(s): {missing_keys}. "
                f"Got keys: {list(report.keys())}"
            )

        logger.info("Successfully generated and validated structured report from Ollama")
        return report
