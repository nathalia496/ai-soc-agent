"""
Low-level HTTP client for a local Ollama server.

This module handles HTTP requests to Ollama's OpenAI-compatible
``/chat/completions`` endpoint.
"""

from __future__ import annotations

from typing import Dict

import requests

from ...core.errors import IntegrationError
from ...core.logging import get_logger


logger = get_logger("sami.integrations.llm.ollama.http")


class OllamaHttpClient:
    """
    HTTP client for a local Ollama server's OpenAI-compatible API.

    Handles chat completions via POST {base_url}/chat/completions.
    """

    def __init__(
        self,
        base_url: str,
        model: str,
        timeout_seconds: int = 60,
    ) -> None:
        """
        Initialize the Ollama HTTP client.

        Args:
            base_url: Base URL of the Ollama OpenAI-compatible API
                (e.g. "http://localhost:11434/v1")
            model: Name of the model to use (must already be pulled in Ollama)
            timeout_seconds: Request timeout in seconds
        """
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout_seconds = timeout_seconds

    def _headers(self) -> Dict[str, str]:
        """Build request headers."""
        return {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def chat_completion(self, system_prompt: str, user_prompt: str) -> str:
        """
        Send a chat completion request and return the raw text of the model's reply.

        Args:
            system_prompt: The system prompt (instructions for the model).
            user_prompt: The user-provided context/content to analyze.

        Returns:
            The raw string content of the model's response message.

        Raises:
            IntegrationError: If the API request fails or the response is malformed.
        """
        url = f"{self.base_url}/chat/completions"
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "stream": False,
        }

        try:
            logger.debug(f"Requesting chat completion from Ollama (POST {url}, model={self.model})")

            response = requests.post(
                url,
                json=payload,
                headers=self._headers(),
                timeout=self.timeout_seconds,
            )

            response.raise_for_status()
            result = response.json()

            try:
                content = result["choices"][0]["message"]["content"]
            except (KeyError, IndexError, TypeError) as e:
                raise IntegrationError(
                    f"Unexpected Ollama response shape (missing choices[0].message.content): {result}"
                ) from e

            logger.debug("Chat completion successful")
            return content

        except requests.exceptions.Timeout as e:
            logger.error(f"Timeout calling Ollama at {url}: {e}")
            raise IntegrationError(f"Timeout calling Ollama: {e}") from e
        except requests.exceptions.RequestException as e:
            logger.error(f"Ollama request failed: {e}")

            error_detail = None
            if hasattr(e, "response") and e.response is not None:
                try:
                    error_detail = e.response.json()
                except Exception:
                    if e.response.text:
                        error_detail = e.response.text[:200]

            error_msg = f"Ollama request failed: {e}"
            if error_detail:
                error_msg += f" - {error_detail}"

            raise IntegrationError(error_msg) from e
