# SOC3: Forensic Artifact Collection Recommendation Runbook

Produce a documented, actionable **recommendation** for which forensic artifacts should be collected from an endpoint, for a human analyst/IT operator to trigger manually in the EDR console. This runbook guides SOC3 (IR-level expert) analysts in scoping comprehensive forensic data collection. SOC3 reviews case context from SOC1 and SOC2 before making the recommendation.

> **IMPORTANT — read-only/advisory agent:** SamiGPT does **not** trigger forensic artifact collection itself. There is no `collect_forensic_artifacts` tool available to the agent anymore — active response actions were intentionally removed (see project `README.md`, section "Active response actions removed"). This runbook's output is a **recommendation and a case task**, never a triggered collection.

## Scope

This runbook covers:
*   Reviewing case context to determine which artifact types are relevant.
*   Producing a clear, auditable collection **recommendation**.
*   Creating a case task for a human analyst to trigger the collection.

## SOC Tier

**Tier:** SOC3 (Tier 3)
**Authority:** SOC3 may only **recommend** which artifacts to collect. It has no authority or tooling to trigger collection itself.

## Inputs

*   `${ENDPOINT_ID}`: The endpoint ID to recommend collecting artifacts from.
*   `${CASE_ID}`: The relevant case ID for documentation.
*   `${ARTIFACT_TYPES}`: List of artifact types recommended for collection (default: ["processes", "network", "filesystem"]).
    *   Available types: `processes`, `network`, `filesystem`, `registry`, `memory`, `logs`

## Outputs

*   `${RECOMMENDATION_STATUS}`: Whether a recommendation was produced and documented.
*   `${ARTIFACT_TYPES}`: The recommended artifact types.
*   `${DOCUMENTATION_STATUS}`: Status of documentation.

## Tools

*   **EDR Tools (read-only):** `get_endpoint_summary`
*   **Case Management Tools:** `review_case`, `add_case_comment`, `add_case_task`, `update_case_status`, `list_case_tasks`, `update_case_task_status`
*   **Knowledge Base Tools:** `kb_list_clients`, `kb_get_client_infra`

## Workflow Steps

1.  **Receive Case & Review Context (MANDATORY):**
    *   Obtain `${ENDPOINT_ID}`, `${CASE_ID}`, and `${ARTIFACT_TYPES}` (if provided).
    *   **MUST use `review_case` with `case_id=${CASE_ID}` as the FIRST action.**
    *   **Read ALL case details:**
        *   Case title, description, status, priority, tags
        *   ALL case comments from SOC1 and SOC2
        *   ALL observables, assets, evidence
        *   Review SOC1 alert details and SOC2 investigation findings
    *   **Review case timeline**: Use `list_case_timeline_events` to understand case history.
    *   If `${ARTIFACT_TYPES}` not provided, use default: `["processes", "network", "filesystem"]`.
    *   **Determine artifact types based on case context**: Review SOC1 and SOC2 findings to determine what artifacts are most relevant.
    *   **Knowledge Base Context:**
        *   Use `kb_list_clients` to list available client environments.
        *   If client name is known from case context, use `kb_get_client_infra` with `client_name=<CLIENT_NAME>` to get infrastructure knowledge.
        *   Use knowledge base to understand endpoint context/criticality, expected artifact locations, and infrastructure-specific considerations.

2.  **Get Endpoint Information (read-only):**
    *   Use `get_endpoint_summary` with `endpoint_id=${ENDPOINT_ID}`.
    *   Verify endpoint details: hostname, platform, current status.

3.  **Determine Recommended Artifact Types:**
    *   Based on case requirements, select appropriate artifact types:
        *   **processes**: Running processes and process trees
        *   **network**: Network connections and DNS queries
        *   **filesystem**: File system artifacts and modifications
        *   **registry**: Windows registry keys and modifications
        *   **memory**: Memory dumps and process memory
        *   **logs**: System logs and event logs
    *   Store selected types in `${ARTIFACT_TYPES}`.

4.  **Produce the Collection Recommendation:**
    *   Do **not** call any artifact-collection tool — none exists for this agent.
    *   Create a case task describing exactly what a human operator should collect, e.g. `SOC3 – RECOMMENDATION: Collect Forensic Artifacts (${ARTIFACT_TYPES}) from ${ENDPOINT_ID}`, using `add_case_task` with `assignee` set to the human on-call analyst/forensics team (not SamiGPT).
    *   Set `${RECOMMENDATION_STATUS}` = "Collection recommended, pending human execution".

5.  **Document the Recommendation:**
    *   Prepare recommendation comment: `RECOMMENDATION_COMMENT = "SOC3 (IR Expert) Forensic Artifact Collection RECOMMENDATION for Case ${CASE_ID}: Endpoint ID: ${ENDPOINT_ID}. Recommended Artifact Types: ${ARTIFACT_TYPES}. **Case Context Reviewed:** [summary of SOC1/SOC2 findings that informed artifact selection]. Infrastructure Context (KB): [...]. **This is a recommendation only — SamiGPT does not trigger artifact collection. A human analyst must initiate collection manually via the EDR console and attach the resulting artifacts as case evidence.**"`
    *   Include knowledge base findings (endpoint context, infrastructure considerations) in the comment.
    *   Use `add_case_comment` with `case_id=${CASE_ID}` and `content=${RECOMMENDATION_COMMENT}`.
    *   Set `${DOCUMENTATION_STATUS}` = "Documented".

6.  **Next Steps:**
    *   **Note:** After the recommendation is documented, a human analyst should:
        *   Trigger the collection manually via the EDR console.
        *   Attach the collected artifacts to the case using `add_case_evidence`.
        *   Proceed with artifact analysis, timeline reconstruction, and attack chain analysis.

## Completion Criteria

A recommendation has been successfully produced:
*   Endpoint information has been verified (read-only).
*   Artifact types have been determined and justified from case context.
*   A clear, evidence-backed collection recommendation has been documented in the case.
*   A case task has been created assigning the manual collection to a human analyst.
*   No collection tool was called by the agent.

## Artifact Type Selection Guide

*   **For Malware Investigation:**
    *   Recommended: `["processes", "network", "filesystem", "registry"]`
*   **For Account Compromise:**
    *   Recommended: `["processes", "network", "logs"]`
*   **For Data Exfiltration:**
    *   Recommended: `["network", "filesystem", "logs"]`
*   **For Comprehensive Investigation:**
    *   Recommended: `["processes", "network", "filesystem", "registry", "memory", "logs"]`

## Notes

*   **SOC3 acts as IR-level expert, in an advisory capacity only**: it reviews case context from SOC1 and SOC2 to recommend appropriate artifact types — it does not trigger collection itself.
*   **Review ALL case details first**: Read SOC1 and SOC2 findings to understand what artifacts are most relevant.
*   Document what case context informed artifact selection decisions.
*   **Provide guidance if needed**: If the case needs additional investigation before a collection recommendation can be made, provide guidance to SOC1/SOC2.
