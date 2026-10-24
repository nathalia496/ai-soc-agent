"""
MCP (Model Context Protocol) server and rules engine for AttackLens.

This package contains:
- mcp_server.py: MCP server implementation that exposes AttackLens skills as tools
- rules_engine.py: Rules/workflow engine for automated investigations
"""

from .mcp_server import AttackLensMCPServer, configure_mcp_logging
from .rules_engine import RulesEngine

__all__ = ["AttackLensMCPServer", "configure_mcp_logging", "RulesEngine"]

