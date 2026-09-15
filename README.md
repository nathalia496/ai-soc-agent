# SamiGPT

**SamiGPT** is an AI-powered security investigation and incident response platform that provides security operations teams with intelligent automation for case management, SIEM analysis, and CTI enrichment through the Model Context Protocol (MCP).

> **Note:** This project is currently under active development. Features, APIs, and documentation may change as development progresses.

## Demo

Watch the demo video to see SamiGPT in action:

[Demo Video](https://youtu.be/usd8ed-7AQg)

### Performance & Cost

**Key Metrics:**
- ~ $0.18 per alert
- ~ 50 seconds to investigate an alert per agent/tab

For detailed cost and usage data, see: [Cost Data CSV](usage-events/cost_all.csv)

For detailed documentation and presentation materials:

[AI Agents Presentation PDF](demo/BHMEA25_AI_Agents.pdf)

### Quick Start

SamiGPT can be used in two ways:

#### Method 1: AI Controller (Web Interface)

The AI Controller provides a web-based interface and uses the Cursor IDE `cursor-agent` binary for command execution.

**Prerequisites:**
- Cursor IDE must be installed (download from [cursor.sh](https://cursor.sh))
- Verify `cursor-agent` binary is available:
  ```bash
  which cursor-agent
  # Should show path like: /usr/local/bin/cursor-agent or ~/.local/bin/cursor-agent
  ```

**Steps:**

1. **Activate virtual environment:**
   ```bash
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. **Start the AI Controller web interface:**
   ```bash
   python3 cursor_agent.py --web --port 8081 --host 127.0.0.1
   ```

3. **Open your browser:**
   Navigate to `http://127.0.0.1:8081` to access the web interface.

#### Method 2: MCP Server (Direct Integration)

Use the MCP server directly to connect SamiGPT tools to Cursor, Claude Desktop, or other MCP-compatible tools.

**Steps:**

1. **Activate virtual environment:**
   ```bash
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. **Start the MCP server:**
   ```bash
   python -m src.mcp.mcp_server
   ```

3. **Configure your AI tool** (see "Connect MCP Server to AI Tools" section below for detailed instructions)

**Note:** The MCP server method doesn't require the Cursor IDE `cursor-agent` binary - it works directly with any MCP-compatible tool.

## Overview

SamiGPT acts as an MCP server that exposes security investigation and response capabilities as tools that can be used by AI agents, LLM tools, and automated workflows. It provides a unified, vendor-neutral API layer that connects to:

- **Case Management Systems** (TheHive, IRIS)
- **SIEM Platforms** (Elastic)
- **EDR Solutions** (Elastic Defend)
- **Threat Intelligence** (OpenCTI, Local TIP)

The platform enables automated triage, investigation, correlation, and response workflows through intelligent agent profiles organized by SOC tier (SOC1, SOC2).

## Features

### Core Capabilities

- **Automated Alert Triage**: Intelligent initial assessment and classification of security alerts
- **Case Management**: Create, update, and manage security cases with observables, comments, and timeline tracking
- **SIEM Integration**: Search security events, pivot on indicators, and correlate activities across environments
- **EDR Investigation (read-only)**: Endpoint and detection lookup for context/enrichment. SamiGPT does **not** isolate endpoints, kill processes, or trigger forensic collection — see [Active response actions removed](#active-response-actions-removed).
- **Threat Intelligence**: IOC enrichment and reputation analysis
- **Multi-Tier SOC Workflows**: Structured workflows for SOC1 (triage), SOC2 (investigation), and SOC3 (IR-level analysis and recommendations)

### Agent Profiles & Runbooks

SamiGPT includes pre-configured agent profiles with specialized runbooks:

- **SOC1 Agents**: Initial alert triage, enrichment, and false positive identification
- **SOC2 Agents**: Deep investigation, correlation, and case analysis
- **SOC3 Agents**: IR-level analysis that produces containment/forensics **recommendations** for a human analyst to execute — it never performs the response action itself (see [Active response actions removed](#active-response-actions-removed))

## Active response actions removed

**SamiGPT is a read-only/advisory agent.** It investigates, enriches, and documents findings and recommendations — it must never take an active response action on a production system by itself (isolating a host, killing a process, blocking an IP, triggering forensic collection, etc.). This is enforced as a platform policy, not just a prompt instruction.

### What was removed/disabled and why

The EDR (Elastic Defend) integration previously exposed four "response action" tools that could change state on a live endpoint. They have been removed or disabled across every layer of the stack so the agent can no longer reach them, even indirectly:

| Removed/disabled tool | What it did | Where it was removed/disabled |
| --- | --- | --- |
| `isolate_endpoint` | Disconnected a host from the network (quarantine) | Tool removed from `src/orchestrator/tools_edr.py` and from the MCP tool registry/dispatcher in `src/mcp/mcp_server.py`; underlying method disabled (raises an error) in `src/integrations/edr/elastic_defend/elastic_defend_client.py` |
| `release_endpoint_isolation` | Restored network connectivity to a previously isolated host | Same as above |
| `kill_process_on_endpoint` | Terminated a running process on an endpoint by PID | Same as above |
| `collect_forensic_artifacts` | Triggered the EDR agent to collect forensic artifacts (processes, network, filesystem, etc.) from an endpoint | Same as above |

Concretely, the change spans:

- **`src/integrations/edr/elastic_defend/elastic_defend_client.py`** — the four methods no longer call the Elastic Defend API. They immediately raise an `IntegrationError` explaining the policy, so even a direct/future caller cannot reach the vendor endpoint. This is the last line of defense.
- **`src/api/edr.py`** — the generic `EDRClient` interface (`Protocol`) no longer declares these methods; it only defines read operations (`get_endpoint_summary`, `list_endpoints`, `get_detection_details`, `list_detections`).
- **`src/orchestrator/tools_edr.py`** — the LLM-callable wrapper functions for these four actions were deleted entirely. Only `get_endpoint_summary` and `get_detection_details` remain.
- **`src/mcp/mcp_server.py`** — the four tools are no longer registered in the MCP tool list (`_register_edr_tools`) and their dispatch branches were removed from the tool-execution switch. An MCP client (Claude Desktop, Cursor, etc.) connected to this server will not see these tools at all.
- **`config/agent_profiles.json`**, **`src/mcp/agent_profiles.py`**, **`src/mcp/flow_agent_profiles.py`** — the SOC3 agent profile ("SOC3 Response Agent") no longer lists these tools, and its `decision_authority.containment_actions` / `decision_authority.forensic_collection` flags are now `false`. Its capabilities were renamed from `containment_execution`/`forensic_collection` to `containment_recommendations`/`forensic_collection_recommendations` to reflect that it recommends, not executes.
- **`run_books/soc3/`** — the SOC3 runbooks and guidelines (`guidelines.md`, `response/endpoint_isolation.md`, `response/process_termination.md`, `forensics/artifact_collection.md`) were rewritten so the agent's workflow ends at producing a documented recommendation and a case task assigned to a human analyst, instead of instructing it to call an action tool.

### Why

An autonomous agent that can disconnect a production host, kill an arbitrary process by PID, or trigger data collection on an endpoint is a significant blast-radius risk if it misclassifies an alert, hallucinates a tool call, or is manipulated via prompt injection from ingested alert/log data. Keeping SamiGPT strictly read-only + advisory means:

- A wrong decision produces a wrong **recommendation**, which a human reviews before anything happens on a real system.
- There is no code path — not the LLM prompt, not a runbook, not a tool schema — through which the agent can reach a destructive EDR action.

### What still works

- Full investigation/enrichment: case management, SIEM search/pivoting, CTI hash lookups, and **read-only** EDR lookups (`get_endpoint_summary`, `get_detection_details`).
- SOC3 still exists as an IR-level expert tier: it reviews evidence and produces a clearly documented isolation / process-termination / forensic-collection **recommendation** and case task — a human analyst always performs the actual action.

## Workflows

SamiGPT uses structured workflows organized by SOC tier. The following diagrams illustrate the execution flow:

### Agent Profiles Flow

This diagram shows how agent profiles are organized and how routing rules direct cases to the appropriate SOC tier agents.

![Agent Profiles Flow](execution_flow/agent_profiles_flow.svg)

### Initial Alert Triage (SOC1)

The initial alert triage workflow handles new security alerts, performs quick assessment, enrichment, and determines whether to create a case or close as false positive.

![Initial Alert Triage](execution_flow/initial_alert_triage.svg)

### Case Analysis (SOC2)

The SOC2 case analysis workflow performs deep investigation, SIEM analysis, CTI enrichment, correlation, and prepares cases for SOC3 escalation.

![Case Analysis](execution_flow/case_analysis.svg)

## Installation

### Prerequisites

- Python 3.9 or higher
- pip package manager

### Setup

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd SamiGPT
   ```

2. **Create and activate virtual environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

4. **Configure integrations** (see Configuration section below)

### Connect MCP Server to AI Tools

If you're using **Method 2: MCP Server** (see Quick Start above), configure your AI tool to connect to the MCP server:

#### Cursor Integration

1. Open Cursor Settings → Features → Model Context Protocol
2. Add SamiGPT server configuration:
   ```json
   {
     "mcpServers": {
       "sami-gpt": {
         "command": "python",
         "args": ["-m", "src.mcp.mcp_server"],
         "cwd": "/absolute/path/to/SamiGPT"
       }
     }
   }
   ```
3. Restart Cursor and start using SamiGPT tools in chat

#### Claude Desktop Integration

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "sami-gpt": {
      "command": "python",
      "args": ["-m", "src.mcp.mcp_server"],
      "cwd": "/absolute/path/to/SamiGPT"
    }
  }
}
```

#### Other MCP-Compatible Tools

The MCP server can also be connected to:
- **Open WebUI** (via MCP configuration)
- **Other LLM tools** that support the Model Context Protocol

## Architecture

### Infrastructure Overview

![Infrastructure Diagram](execution_flow/infrastructure_diagram.png)

### Directory Structure

```
SamiGPT/
├── src/
│   ├── api/              # Generic interfaces (CaseManagementClient, SIEMClient, EDRClient)
│   ├── core/             # Configuration, logging, errors, DTOs
│   ├── integrations/     # Vendor-specific implementations
│   │   ├── case_management/  # TheHive, IRIS integrations
│   │   ├── siem/             # Elastic integration
│   │   ├── edr/              # EDR platform integrations
│   │   ├── cti/              # Threat intelligence integrations
│   │   └── eng/              # Engineering board integrations
│   ├── mcp/              # MCP server, runbook manager, agent profiles
│   ├── orchestrator/     # Workflow orchestration
│   └── web/              # Web UI for configuration
├── run_books/            # SOC tier runbooks and workflows
├── config/               # Agent profiles and configuration
└── client_env/           # Client-specific infrastructure data
```

### Design Principles

- **Vendor-Neutral APIs**: All integrations implement generic interfaces, allowing easy swapping of security tools
- **Separation of Concerns**: AI/orchestrator layer only interacts with generic APIs, never vendor-specific code
- **Modular Integration**: Each vendor integration is self-contained with HTTP client, models, mappers, and client implementation

## Configuration

Most integrations (case management, EDR, CTI, engineering) are managed through `config.json` and can be edited via the web interface or directly. **The SIEM (Elastic/OpenSearch) integration is the exception** — it is always configured via environment variables / a `.env` file, and always takes priority over any `elastic` section in `config.json`.

### SIEM (Elastic/OpenSearch) via `.env`

Copy `.env.example` to `.env` (already gitignored) and set at least `SAMIGPT_ELASTIC_URL`. This works against Elasticsearch or OpenSearch — OpenSearch implements the same Elasticsearch-compatible REST/query-DSL API. For a local OpenSearch instance:

```bash
cp .env.example .env
```

```dotenv
# .env
SAMIGPT_ELASTIC_URL=http://localhost:9200
# DEV-ONLY: local OpenSearch has no TLS — never disable verification against
# a real production/staging endpoint.
SAMIGPT_ELASTIC_VERIFY_SSL=false
```

The URL is never hardcoded in source — see `src/core/config.py` (`load_elastic_config_from_env`) and `src/mcp/mcp_server.py`, which reads it at startup. If `SAMIGPT_ELASTIC_URL` is unset, the SIEM tools are simply not registered.

### Configuration File Structure

See `config.json.example` for the complete configuration schema of the remaining sections:

- `iris` / `thehive`: Case management configuration
- `edr`: EDR platform configuration
- `cti`: Threat intelligence configuration
- `eng`: Engineering board configuration (ClickUp, Trello, GitHub)
- `ai_controller`: AI controller web interface settings
- `logging`: Logging configuration

(`config.json` also has an `elastic` section for backward compatibility with the web UI's configuration manager, but the running MCP server ignores it in favor of `.env` — see above.)

## Usage Examples

### Basic Case Operations

```python
# List all open cases
cases = list_cases(status="open")

# Review a specific case
case = review_case(case_id="123")

# Add an observable to a case
attach_observable_to_case(
    case_id="123",
    observable_type="ip",
    observable_value="192.168.1.100",
    description="Suspicious source IP"
)
```

### SIEM Investigation

```python
# Search for security events
events = search_security_events(
    query="source.ip: 192.168.1.100",
    hours_back=24
)

# Get file report
report = get_file_report(file_hash="abc123...")

# Pivot on an indicator
related_events = pivot_on_indicator("192.168.1.100")
```

### EDR Investigation (read-only)

```python
# Get endpoint summary
endpoint = get_endpoint_summary(endpoint_id="host-123")

# Get detection details
detection = get_detection_details(detection_id="detection-456")
```

> There is no `isolate_endpoint`, `release_endpoint_isolation`, `kill_process_on_endpoint`, or
> `collect_forensic_artifacts` tool. Active response actions were removed — see
> [Active response actions removed](#active-response-actions-removed).

### Agent Profile Execution

```python
# Execute as SOC1 triage agent
execute_as_agent(
    agent_id="soc1_triage_agent",
    alert_id="alert-123"
)

# Execute specific runbook
execute_runbook(
    runbook_name="initial_alert_triage",
    alert_id="alert-123",
    case_id="case-456"
)
```

## Logging

SamiGPT provides comprehensive logging:

- **MCP Server Logs**: `logs/mcp/mcp_all.log`, `mcp_requests.log`, `mcp_responses.log`, `mcp_errors.log`
- **Application Logs**: `logs/debug.log`, `logs/error.log`, `logs/warning.log`

## Development

### Adding a New Integration

1. **Create integration directory** under `src/integrations/`
2. **Implement generic interface** from `src/api/`
3. **Add HTTP client, models, and mappers**
4. **Register in configuration**

Example structure:
```
src/integrations/case_management/new_vendor/
├── __init__.py
├── client.py          # HTTP client
├── models.py          # Vendor-specific models
├── mapper.py          # Vendor ↔ Generic DTO mapping
└── case_client.py     # Implements CaseManagementClient
```

### Running Tests

```bash
# Run all tests
pytest tests/

# Run specific integration tests
pytest tests/integrations/case_management/
```

## Contributing

When contributing:

1. Keep all vendor-specific code under `src/integrations/`
2. Ensure all integrations implement the generic APIs in `src/api/`
3. Add tests for new integrations
4. Update documentation as needed

## License

MIT

## Support

For issues, questions, or contributions, please open an issue on the repository.

## Acknowledgments

The following projects helped and inspired us during the literature review:

- [AI-Powered SOC Detection System](https://github.com/cyberarber/ai-soc-detection-system/tree/main) - ML-powered SOC platform with autonomous threat detection
- [ADK Runbooks](https://github.com/dandye/adk_runbooks/tree/main) - Security investigation runbooks and workflows
