# SamiGPT MCP Server

This directory contains the Model Context Protocol (MCP) server implementation for SamiGPT, which exposes all investigation and response capabilities as tools that can be used by AI assistants and automation systems.

## Overview

The MCP server enables integration with various LLM clients including:
- **Cursor IDE** - AI-powered code editor
- **Claude Desktop** - Anthropic's Claude AI assistant
- **Open WebUI** - Web-based LLM interface
- **Cline** - VS Code extension for AI assistance
- Any MCP-compatible client

## Files

- **`mcp_server.py`**: Main MCP server implementation
  - Implements JSON-RPC 2.0 over stdio
  - Handles tool registration and execution
  - Manages client connections and protocol negotiation

- **`rules_engine.py`**: Rules/workflow engine
  - Executes automated investigation workflows
  - Chains together multiple investigation skills
  - Supports custom rule definitions

- **`TOOLS.md`**: Comprehensive tool documentation
  - Detailed documentation for all available tools
  - Usage examples and best practices
  - Parameter descriptions and return values

## Available Tools

### Case Management Tools (8 tools)
Tools for managing security incidents and cases:
- `review_case` - Get complete case details
- `list_cases` - List cases with optional filters
- `search_cases` - Advanced case search
- `add_case_comment` - Add notes to cases
- `attach_observable_to_case` - Track IOCs
- `update_case_status` - Update case workflow
- `assign_case` - Assign to analysts
- `get_case_timeline` - View case history

### SIEM Tools (27 tools)
Backed by Elasticsearch or OpenSearch (same wire protocol - see `config.json`'s `elastic.siem_type`).
A few of the most-used ones:
- `get_recent_alerts` / `get_security_alerts` / `get_security_alert_by_id` - Pull SIEM alerts
- `get_logs_for_alert` - Fetch nearby logs/evidence for an alert (by host/user/IP and time window)
- `search_security_events` - Query security logs
- `get_file_report` - Analyze files by hash
- `get_file_behavior_summary` - File behavior analysis
- `get_entities_related_to_file` - Find related entities
- `get_ip_address_report` - IP reputation and context
- `search_user_activity` - User activity investigation
- `pivot_on_indicator` - IOC-based investigation

See [TOOLS.md](TOOLS.md) for the full list.

### EDR Tools (3 tools, investigation-only)
Tools for endpoint investigation and evidence gathering. This agent is a human-in-the-loop
investigation copilot: there are intentionally **no** tools for endpoint isolation, releasing
isolation, or process termination. Those active response actions must always be performed by
a human analyst directly in the EDR platform.
- `get_endpoint_summary` - Endpoint overview
- `get_detection_details` - Detection analysis
- `collect_forensic_artifacts` - Evidence collection (read-only from the agent's perspective)

### CTI Tools (2 tools)
Tools for enriching investigations with threat intelligence:
- `lookup_hash_ti` - Look up a file hash in Local TIP or OpenCTI (whichever is configured)
- `lookup_ioc_misp` - Look up an IP address or file hash in MISP for associated tags and events

### LLM Tools (1 tool)
Tools for generating investigation recommendations. Human-in-the-loop by design: the output is a
suggestion for an analyst to review, never an action taken.
- `generate_investigation_report` - Generate a structured report (timeline, observables, hypothesis,
  next_steps) from free-text investigation context using a local Ollama model

### Investigation Pipeline Tools (1 tool)
Chains the stages above into a single "alert in, report out" call. Human-in-the-loop by
design: it only ever reads data and, optionally, adds a comment to an existing case - never
a containment/remediation action.
- `investigate_alert` - Fetch a SIEM alert, fetch nearby logs, enrich related hash/IP
  indicators via CTI/MISP, map findings to MITRE ATT&CK techniques, and generate a
  structured report, end to end. Requires `elastic` and `ollama`; CTI, MISP, and the ATT&CK
  mapper enrich the investigation when configured but aren't required.

### Rules Engine Tools (2 tools)
Tools for automated workflows:
- `list_rules` - List available workflows
- `execute_rule` - Run automated playbooks

## Quick Start

### Running the Server

```bash
python -m src.mcp.mcp_server
```

The server communicates via stdio using JSON-RPC 2.0 protocol.

### Configuration

The server automatically loads configuration from `config.json` in the project root. Configure integrations using the web configuration UI:

```bash
python -m src.web.config_server
```

### Tool Usage

All tools are documented in **[TOOLS.md](TOOLS.md)** with:
- Detailed parameter descriptions
- Return value specifications
- Usage examples
- Best practices
- Workflow examples

## Protocol Support

The server supports MCP protocol versions:
- `2024-11-05` (default)
- `2025-06-18` (auto-negotiated with compatible clients)

## Logging

MCP-specific logs are written to `logs/mcp/`:
- `mcp_all.log` - All MCP activity (DEBUG level)
- `mcp_requests.log` - Incoming requests
- `mcp_responses.log` - Outgoing responses
- `mcp_errors.log` - Errors only

## Integration Examples

### Cursor IDE

See [CURSOR_INTEGRATION.md](../../CURSOR_INTEGRATION.md) for setup instructions.

### Claude Desktop

Add to `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "sami-gpt": {
      "command": "python",
      "args": ["-m", "src.mcp.mcp_server"],
      "cwd": "/path/to/SamiGPT"
    }
  }
}
```

### Open WebUI

Configure via environment variables or UI settings.

## Tool Availability

Tools are conditionally available based on configured integrations:

- **Case Management Tools**: Require TheHive or IRIS configuration
- **SIEM Tools**: Require Elastic or other SIEM configuration
- **EDR Tools**: Require EDR platform configuration
- **CTI Tools**: `lookup_hash_ti` requires `cti` (Local TIP or OpenCTI) configuration; `lookup_ioc_misp` requires `misp` configuration independently
- **LLM Tools**: `generate_investigation_report` requires `ollama` configuration
- **Investigation Pipeline Tools**: `investigate_alert` requires `elastic` and `ollama`; `cti`/`misp`/the ATT&CK mapper are optional and enrich the investigation when available
- **Rules Engine Tools**: Always available

Use `list_rules` to discover available automated workflows.

## Security Considerations

⚠️ **Human-in-the-loop by design**: this MCP server never exposes active response / remediation
tools to the agent (endpoint isolation, releasing isolation, process termination, or any other
containment action). The agent may only investigate (read data, enrich indicators, collect
forensic artifacts) and draft recommendations for a human analyst; the analyst always makes the
final decision and executes any response action directly in the relevant platform (EDR, SIEM,
etc.). Do not add tool registrations for active response actions - see
`src/orchestrator/tools_edr.py` and `_register_edr_tools()` in `mcp_server.py` for the enforced
boundary.

## Development

### Adding New Tools

1. Implement the tool function in the appropriate `tools_*.py` module
2. Register the tool in `mcp_server.py` using `_register_*_tools()` methods
3. Add comprehensive documentation to `TOOLS.md`
4. Update this README if adding a new tool category

### Testing

Test the MCP server manually:
```bash
echo '{"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}' | python -m src.mcp.mcp_server
```

## Documentation

- **[TOOLS.md](TOOLS.md)** - Complete tool documentation
- **[../CURSOR_INTEGRATION.md](../CURSOR_INTEGRATION.md)** - Cursor setup guide
- **[../MCP_CLIENT_EXAMPLES.md](../MCP_CLIENT_EXAMPLES.md)** - Client configuration examples
- **[../README.md](../README.md)** - Main project documentation

## Support

For issues or questions:
1. Check the logs in `logs/mcp/`
2. Review tool documentation in `TOOLS.md`
3. Verify configuration in `config.json`
4. Check integration-specific documentation

