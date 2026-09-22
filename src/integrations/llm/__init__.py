"""
Local LLM (Ollama) integration.

This module provides a client for generating structured JSON reports
(timeline, observables, hypothesis, next_steps) via a local Ollama server.
"""

from .ollama_client import OllamaClient, REPORT_SYSTEM_PROMPT

__all__ = ["OllamaClient", "REPORT_SYSTEM_PROMPT"]
