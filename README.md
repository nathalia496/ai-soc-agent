# AttackLens

**AttackLens** is an AI-powered security investigation and incident response platform that provides security operations teams with intelligent automation for case management, SIEM analysis, and CTI enrichment through the Model Context Protocol (MCP).

> **Note:** This project is currently under active development. Features, APIs, and documentation may change as development progresses.

## Demo

Watch the demo video to see AttackLens in action:

[Demo Video](https://youtu.be/usd8ed-7AQg)

### Performance & Cost

> **Note:** The metrics below come from this project's original demo flow (Cursor IDE + paid LLM, see the AI Controller section below) and predate the free/local `investigate_alert()` pipeline. They have not been re-measured against the current pipeline and should not be read as its cost or latency.

**Key Metrics (original demo flow):**
- ~ $0.18 per alert
- ~ 50 seconds to investigate an alert per agent/tab

For detailed cost and usage data, see: [Cost Data CSV](usage-events/cost_all.csv)

For detailed documentation and presentation materials:

[AI Agents Presentation PDF](demo/BHMEA25_AI_Agents.pdf)

### Quick Start

AttackLens is built around the **MCP Server** - that's the project's primary, supported way to run it, and the one its design goals (free, local, human-in-the-loop) and core deliverable (the `investigate_alert()` pipeline) are built on. A minimal **Investigation API** also exposes that same pipeline over plain HTTP, for callers that aren't MCP clients. An **AI Controller** web interface also exists, inherited from this project's original demo; it depends on a paid, proprietary tool and sits outside the project's core scope. See the notes under "Optional" below before reaching for either.

#### Recommended: MCP Server (Direct Integration)

Use the MCP server directly to connect AttackLens tools to Claude Desktop, Cursor, or any other MCP-compatible client. No paid tooling required - everything runs locally.

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

#### Optional: Investigation API (HTTP)

A minimal FastAPI server that exposes `investigate_alert()` directly over HTTP, for cases where an MCP client isn't practical (e.g. calling it from a script, a webhook, or another service). It is not a replacement for the MCP server - it wraps the same pipeline, with the same investigation-only, human-in-the-loop contract (it returns a report; it never takes remediation action).

**Steps:**

1. **Activate virtual environment:**
   ```bash
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. **Start the API server:**
   ```bash
   uvicorn src.web.investigation_api:app --host 0.0.0.0 --port 8000
   ```

3. **Run an investigation:**
   ```bash
   curl -X POST http://localhost:8000/investigate/<alert_id> \
     -H "X-Admin-Secret: $ATTACKLENS_ADMIN_SECRET"
   ```
   `POST /investigate/{alert_id}` returns the same report/warnings structure `investigate_alert()` produces directly. `GET /health` reports which optional integrations (SIEM, CTI, MISP, ATT&CK mapper, LLM, case management, storage) are actually configured.

   `/investigate/{alert_id}` requires the `X-Admin-Secret` header to match `ATTACKLENS_ADMIN_SECRET` (same shared-secret, constant-time-compared auth as the configuration web UI below, adapted to a header since there's no login page here). `/health` is left unauthenticated, since it only reports booleans, not configuration values - treat it as local-only if that's not acceptable in your environment.

#### Optional: AI Controller (Web Interface)

> **Not part of the project's core scope.** The AI Controller is a web dashboard inherited from this project's original demo. It doesn't run its own AI - it shells out to the Cursor IDE's `cursor-agent` binary (see `src/ai_controller/agent_executor.py`), a paid, proprietary tool. Using it means every investigation depends on that external dependency, which is at odds with this project's free/local design goal. It's kept here for continuity, but new work should go through the MCP Server above; `investigate_alert()` and the rest of the project's core tools are only reachable that way.

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

## Overview

AttackLens acts as an MCP server that exposes security investigation and response capabilities as tools that can be used by AI agents, LLM tools, and automated workflows. It provides a unified, vendor-neutral API layer that connects to:

- **Case Management Systems** (TheHive, IRIS)
- **SIEM Platforms** (Elastic)
- **EDR Solutions** (Elastic Defend)
- **Threat Intelligence** (OpenCTI, Local TIP, MISP)
- **MITRE ATT&CK** - keyword-based mapping of alerts to techniques

Its core deliverable is the `investigate_alert()` pipeline: given an alert ID, it pulls the related SIEM events, enriches with CTI and MITRE ATT&CK context, generates an LLM-written report (via a local Ollama model), persists it to PostgreSQL, and posts it as a case comment - all human-in-the-loop, with no automated containment or remediation.

The platform enables automated triage, investigation, correlation, and response workflows through intelligent agent profiles organized by SOC tier (SOC1, SOC2, SOC3).

## Features

### Core Capabilities

- **Automated Alert Triage**: Intelligent initial assessment and classification of security alerts
- **End-to-End Investigation Pipeline**: `investigate_alert()` orchestrates SIEM, CTI, and ATT&CK enrichment into an LLM-generated report, persisted to PostgreSQL and posted back to the case - investigation-only, with every optional enrichment stage degrading gracefully (best-effort, non-fatal) if an integration is unavailable
- **Case Management**: Create, update, and manage security cases with observables, comments, and timeline tracking
- **SIEM Integration**: Search security events, pivot on indicators, and correlate activities across environments
- **EDR Investigation**: Endpoint summaries and forensic artifact collection - no isolation or process termination tooling exists; see [EDR Investigation](#edr-investigation) below
- **Threat Intelligence**: IOC enrichment and reputation analysis (OpenCTI, Local TIP, MISP)
- **MITRE ATT&CK Mapping**: Keyword/TF-IDF matching of alert content to ATT&CK techniques
- **Multi-Tier SOC Workflows**: Structured workflows for SOC1 (triage), SOC2 (investigation), and SOC3 (escalation)

### Agent Profiles & Runbooks

AttackLens includes pre-configured agent profiles with specialized runbooks:

- **SOC1 Agents**: Initial alert triage, enrichment, and false positive identification
- **SOC2 Agents**: Deep investigation, correlation, and case analysis
- **SOC3 Agents**: Escalation handling for cases that SOC2 analysis flags as needing senior review

## Workflows

AttackLens uses structured workflows organized by SOC tier. The following diagrams illustrate the execution flow:

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

- Python 3.12 (the version this project's CI tests against)
- pip package manager

### Setup

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd ai-soc-agent
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

4. **Create your configuration file**:
   ```bash
   cp config.json.example config.json
   ```
   Then edit `config.json` with your own integration credentials (see Configuration section below).

5. **Start PostgreSQL** (used to persist investigation reports):
   ```bash
   docker compose up -d postgres
   ```

6. **Configure integrations** (see Configuration section below)

### Connect MCP Server to AI Tools

If you're using the **MCP Server** (see Quick Start above), configure your AI tool to connect to the MCP server:

#### Cursor Integration

1. Open Cursor Settings → Features → Model Context Protocol
2. Add AttackLens server configuration:
   ```json
   {
     "mcpServers": {
       "attack-lens": {
         "command": "python",
         "args": ["-m", "src.mcp.mcp_server"],
         "cwd": "/absolute/path/to/ai-soc-agent"
       }
     }
   }
   ```
3. Restart Cursor and start using AttackLens tools in chat

#### Claude Desktop Integration

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "attack-lens": {
      "command": "python",
      "args": ["-m", "src.mcp.mcp_server"],
      "cwd": "/absolute/path/to/ai-soc-agent"
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
ai-soc-agent/
├── src/
│   ├── api/              # Generic interfaces (CaseManagementClient, SIEMClient, EDRClient)
│   ├── core/             # Configuration, logging, errors, DTOs
│   ├── integrations/     # Vendor-specific implementations
│   │   ├── case_management/  # TheHive, IRIS integrations
│   │   ├── siem/             # Elastic integration
│   │   ├── edr/              # EDR platform integrations
│   │   ├── cti/              # Threat intelligence integrations (OpenCTI, Local TIP, MISP)
│   │   ├── attack/           # MITRE ATT&CK mapper
│   │   ├── llm/              # LLM client (Ollama) for report generation
│   │   ├── storage/          # PostgreSQL persistence for investigation reports
│   │   └── eng/              # Engineering board integrations
│   ├── mcp/              # MCP server, runbook manager, agent profiles
│   ├── orchestrator/     # Workflow orchestration, including investigate_alert()
│   ├── ai_controller/    # Optional web dashboard (see Quick Start above) - not core scope
│   └── web/              # Web UI for configuration
├── run_books/            # SOC tier runbooks and workflows
├── config/               # Agent profiles and configuration
├── client_env/           # Client-specific infrastructure data
└── .github/workflows/    # CI: tests, coverage, lint (ruff), CodeQL
```

### Design Principles

- **Vendor-Neutral APIs**: All integrations implement generic interfaces, allowing easy swapping of security tools
- **Separation of Concerns**: AI/orchestrator layer only interacts with generic APIs, never vendor-specific code
- **Modular Integration**: Each vendor integration is self-contained with HTTP client, models, mappers, and client implementation

## Configuration

Configuration is managed through `config.json` and can be edited via the web interface or directly.


### Configuration File Structure

See `config.json.example` for the complete configuration schema. Key sections:

- `iris` / `thehive`: Case management configuration
- `elastic`: SIEM configuration
- `edr`: EDR platform configuration
- `cti`: Threat intelligence configuration
- `misp`: MISP threat intelligence configuration
- `ollama`: Local LLM configuration used by `investigate_alert()` to generate reports
- `eng`: Engineering board configuration (ClickUp, Trello, GitHub)
- `postgres`: PostgreSQL connection settings for persisting investigation reports (defaults match `docker-compose.yml`)
- `ai_controller`: AI controller web interface settings (optional, see Quick Start above)
- `logging`: Logging configuration

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

### EDR Investigation

Investigation-only: there is no tool to isolate an endpoint or kill a process. Endpoint isolation
and process termination are always performed by a human analyst directly in the EDR platform.

```python
# Get endpoint summary
endpoint = get_endpoint_summary(endpoint_id="host-123")

# Collect forensic artifacts (evidence gathering, not remediation)
collect_forensic_artifacts(
    endpoint_id="host-123",
    artifact_types=["processes", "network", "filesystem"]
)

# If containment looks warranted, draft a recommendation for a human analyst instead of
# attempting to act:
add_case_comment(case_id="123", content="Recommend isolating host-123: ...")
add_case_task(case_id="123", title="Human approval required: isolate host-123", ...)
```

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

AttackLens provides comprehensive logging:

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

Install the dev dependencies first:

```bash
pip install -r requirements-dev.txt
```

```bash
# Run all tests with coverage
pytest tests/ --cov=src --cov-report=term-missing

# Run specific integration tests
pytest tests/integrations/case_management/

# Lint
ruff check src/ tests/
```

Every pull request runs this same test suite, lint, a coverage check, and CodeQL security scanning via GitHub Actions (see `.github/workflows/`).

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
