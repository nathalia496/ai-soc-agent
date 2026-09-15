# SOC3: Process Termination Recommendation Runbook

Produce a documented, actionable **recommendation** to terminate a specific malicious process on an endpoint, for a human analyst/IT operator to execute manually in the EDR console. This runbook is executed by SOC3 (IR-level expert) when malicious processes are identified. SOC3 confirms malicious activity when evidence is strong before recommending disruptive actions.

> **IMPORTANT — read-only/advisory agent:** SamiGPT does **not** kill processes itself. There is no `kill_process_on_endpoint` tool available to the agent anymore — active response actions were intentionally removed (see project `README.md`, section "Active response actions removed"). This runbook's output is a **recommendation and a case task**, never an executed termination.

## Scope

This runbook covers:
*   Reviewing evidence to determine whether process termination is warranted.
*   Producing a clear, auditable termination **recommendation**.
*   Creating a case task for a human analyst to execute the termination.

This runbook explicitly **requires**:
*   SOC2 analysis confirming a malicious process.
*   Human authorization and execution — SamiGPT never terminates a process on its own.

## SOC Tier

**Tier:** SOC3 (Tier 3)
**Authority:** SOC3 may only **recommend** containment actions. It has no authority or tooling to execute them.

## Inputs

*   `${ENDPOINT_ID}`: The endpoint ID where the process is running.
*   `${PROCESS_ID}`: The process ID (PID) recommended for termination.
*   `${CASE_ID}`: The relevant case ID for documentation.
*   `${TERMINATION_REASON}`: The reason termination is being recommended (e.g., "Malicious process detected", "Malware execution confirmed").

## Outputs

*   `${RECOMMENDATION_STATUS}`: Whether a recommendation was produced and documented.
*   `${DOCUMENTATION_STATUS}`: Status of documentation.

## Tools

*   **EDR Tools (read-only):** `get_endpoint_summary`
*   **Case Management Tools:** `review_case`, `add_case_comment`, `add_case_task`, `update_case_status`, `list_case_tasks`, `update_case_task_status`
*   **Knowledge Base Tools:** `kb_list_clients`, `kb_get_client_infra`

## Workflow Steps

1.  **Receive Case & Review Evidence (MANDATORY):**
    *   Obtain `${ENDPOINT_ID}`, `${PROCESS_ID}`, `${CASE_ID}`, and `${TERMINATION_REASON}`.
    *   **MUST use `review_case` with `case_id=${CASE_ID}` as the FIRST action.**
    *   **Read ALL case details:**
        *   Case title, description, status, priority, tags
        *   ALL case comments from SOC1 and SOC2
        *   ALL observables, assets, evidence
        *   Review SOC1 alert details and SOC2 investigation findings
    *   **Review case timeline**: Use `list_case_timeline_events` to understand case history.
    *   **Confirm evidence is strong**: Review SOC1 and SOC2 findings to confirm the malicious process before recommending disruptive action.
    *   **Knowledge Base Context:**
        *   Use `kb_list_clients` to list available client environments.
        *   If client name is known from case context, use `kb_get_client_infra` with `client_name=<CLIENT_NAME>` to get infrastructure knowledge.
        *   Use knowledge base to understand endpoint context/criticality, expected processes and services, and infrastructure-specific considerations.
    *   **If evidence is not strong or case needs additional analysis**: Provide guidance to SOC1/SOC2 on what additional analysis is needed instead of recommending termination.

2.  **Get Endpoint Information (read-only):**
    *   Use `get_endpoint_summary` with `endpoint_id=${ENDPOINT_ID}`.
    *   Verify endpoint details: hostname, platform, current status.

3.  **Produce the Termination Recommendation:**
    *   Do **not** call any process-termination tool — none exists for this agent.
    *   Create a case task describing exactly what a human operator should do, e.g. `SOC3 – RECOMMENDATION: Terminate Process ${PROCESS_ID} on ${ENDPOINT_ID}`, using `add_case_task` with `assignee` set to the human on-call analyst/IT team (not SamiGPT).
    *   Set `${RECOMMENDATION_STATUS}` = "Termination recommended, pending human execution".

4.  **Document the Recommendation:**
    *   Prepare recommendation comment: `RECOMMENDATION_COMMENT = "SOC3 (IR Expert) Process Termination RECOMMENDATION for Case ${CASE_ID}: Endpoint ID: ${ENDPOINT_ID}. Process ID: ${PROCESS_ID}. Reason: ${TERMINATION_REASON}. **Evidence Reviewed:** [summary of SOC1/SOC2 findings that support termination]. Infrastructure Context (KB): [...]. **This is a recommendation only — SamiGPT does not execute process termination. A human analyst must terminate the process manually via the EDR console and confirm completion.**"`
    *   Include knowledge base findings (endpoint context, expected processes) in the comment.
    *   Use `add_case_comment` with `case_id=${CASE_ID}` and `content=${RECOMMENDATION_COMMENT}`.
    *   Set `${DOCUMENTATION_STATUS}` = "Documented".

5.  **Next Steps:**
    *   **Note:** After the recommendation is documented, a human analyst should:
        *   Terminate the process manually via the EDR console.
        *   Verify termination and check for persistence mechanisms.
        *   Consider forensic artifact collection (see `artifact_collection.md` recommendation runbook) as a separate human-executed step if needed.
        *   Coordinate with IT support and plan remediation.

## Completion Criteria

A recommendation has been successfully produced:
*   Endpoint information has been verified (read-only).
*   A clear, evidence-backed termination recommendation has been documented in the case.
*   A case task has been created assigning the manual termination to a human analyst.
*   No termination tool was called by the agent.

## Warning

⚠️ **SamiGPT never terminates a process itself.** This runbook only produces a recommendation and a task for a human to act on.
*   Ensure the recommendation clearly identifies the malicious process and PID so a human can act quickly and confidently.
*   Note the risk of impacting legitimate processes if the PID is incorrect — this is exactly why a human must confirm before acting.

## Notes

*   **SOC3 acts as IR-level expert, in an advisory capacity only**: it confirms malicious activity when evidence is strong and documents a recommendation — it does not execute disruptive actions.
*   **Review ALL case details first**: Read SOC1 and SOC2 findings to understand full context.
*   **Confirm evidence is strong**: Review SOC1 alert details and SOC2 investigation findings before recommending termination.
*   **Provide guidance if needed**: If evidence is not strong, provide guidance to SOC1/SOC2 on what additional analysis is needed instead of recommending action.
*   Document all recommendations and evidence confirmation for audit purposes.
