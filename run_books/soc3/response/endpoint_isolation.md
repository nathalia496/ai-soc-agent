# SOC3: Endpoint Isolation Recommendation Runbook

Draft a network isolation **recommendation** for an endpoint when active compromise or lateral movement is suspected. This runbook is executed by SOC3 (IR-level expert) to confirm the evidence is strong and to hand off a clear, actionable recommendation to a human analyst. **This agent never isolates an endpoint itself** - isolation is executed by a human analyst directly in the EDR platform after reviewing this recommendation.

## Scope

This runbook covers:
*   Reviewing evidence to determine whether isolation should be recommended.
*   Drafting a clear, actionable isolation recommendation.
*   Documenting the recommendation on the case for human analyst decision and execution.

This runbook explicitly **requires**:
*   SOC2 analysis confirming active threat.
*   A human analyst to make the final containment decision and execute it.

## SOC Tier

**Tier:** SOC3 (Tier 3)
**Authority:** SOC3 may DRAFT containment recommendations. SOC3 has NO authority to execute containment actions - no isolation tool is available to this agent, by design.

## Inputs

*   `${ENDPOINT_ID}`: The endpoint ID being evaluated for isolation.
*   `${CASE_ID}`: The relevant case ID for documentation.
*   `${ISOLATION_REASON}`: The reason isolation is being recommended (e.g., "Active malware detected", "Confirmed compromise", "Lateral movement detected").

## Outputs

*   `${RECOMMENDATION_STATUS}`: Whether an isolation recommendation was drafted.
*   `${DOCUMENTATION_STATUS}`: Status of documentation.

## Tools

*   **EDR Tools:** `get_endpoint_summary` (read-only lookup only - there is no tool to isolate an endpoint)
*   **Case Management Tools:** `review_case`, `add_case_comment`, `add_case_task`, `update_case_status`, `list_case_tasks`, `update_case_task_status`
*   **Knowledge Base Tools:** `kb_list_clients`, `kb_get_client_infra`

## Workflow Steps

1.  **Receive Case & Review Evidence (MANDATORY):**
    *   Obtain `${ENDPOINT_ID}`, `${CASE_ID}`, and `${ISOLATION_REASON}`.
    *   **MUST use `review_case` with `case_id=${CASE_ID}` as the FIRST action.**
    *   **Read ALL case details:**
        *   Case title, description, status, priority, tags
        *   ALL case comments from SOC1 and SOC2
        *   ALL observables, assets, evidence
        *   Review SOC1 alert details and SOC2 investigation findings
    *   **Review case timeline**: Use `list_case_timeline_events` to understand case history.
    *   **Confirm evidence is strong**: Review SOC1 and SOC2 findings to confirm malicious activity before recommending a disruptive action.
    *   **Task Management:**
        *   Use `list_case_tasks` with `case_id=${CASE_ID}` to find ALL tasks assigned to SOC3 (e.g., "Network Containment", "Endpoint Isolation").
        *   Review tasks from SOC1 and SOC2 to understand investigation context.
        *   For each relevant task found, use `update_case_task_status` with `task_id=<TASK_ID>`, `status="in_progress"` to mark it as in-progress while preparing the recommendation.
    *   **If evidence is not strong or case needs additional analysis**: Provide guidance to SOC1/SOC2 on what additional analysis is needed instead of drafting a recommendation.
    *   **Knowledge Base Context:**
        *   Use `kb_list_clients` to list available client environments.
        *   If client name is known from case context, use `kb_get_client_infra` with `client_name=<CLIENT_NAME>` to get infrastructure knowledge.
        *   Use knowledge base to understand endpoint context, network topology impact, and whether the endpoint is a known/expected host - this reduces the risk of recommending isolation for a false positive.

2.  **Get Endpoint Information (read-only):**
    *   Use `get_endpoint_summary` with `endpoint_id=${ENDPOINT_ID}`.
    *   Verify endpoint details: hostname, platform, current status, isolation status.
    *   **Note:** If the endpoint is already isolated, document that and skip the recommendation.

3.  **Draft the Isolation Recommendation (no execution):**
    *   Do **not** call any isolation tool - none is exposed to this agent.
    *   Prepare a recommendation comment: `RECOMMENDATION_COMMENT = "SOC3 (IR Expert) Isolation Recommendation for Case ${CASE_ID}: Endpoint ID: ${ENDPOINT_ID}. Reason: ${ISOLATION_REASON}. **Evidence Reviewed:** [summary of SOC1/SOC2 findings that support isolation]. Infrastructure Context (KB): [...]. **RECOMMENDED ACTION: Isolate endpoint ${ENDPOINT_ID} from the network.** This action requires human analyst review and must be executed directly in the EDR platform - this agent cannot and will not perform it. Analyst: please confirm and isolate if you agree with this recommendation."`
    *   Use `add_case_comment` with `case_id=${CASE_ID}` and `content=${RECOMMENDATION_COMMENT}`.
    *   Use `add_case_task` to create a task (e.g., title "Human approval required: isolate endpoint ${ENDPOINT_ID}", assignee a human analyst/SOC lead) so the recommendation shows up as an actionable, trackable item rather than a note that can be missed.
    *   Set `${RECOMMENDATION_STATUS}` = "Isolation recommended - pending human approval and execution".

4.  **Document:**
    *   Set `${DOCUMENTATION_STATUS}` = "Documented".
    *   **Task Management:**
        *   Use `update_case_task_status` with `task_id=<TASK_ID>`, `status="completed"` to mark the SOC3 analysis task as completed once the recommendation has been documented (the containment task itself stays open/pending for the human analyst).

5.  **Next Steps:**
    *   **Note:** Once a human analyst has isolated the endpoint (or declined to), they should update the case themselves. After that, SOC3 may be asked to:
        *   Recommend forensic artifact collection (use `artifact_collection.md` runbook - this one IS a tool SOC3 can execute directly, since it's read/evidence-gathering, not remediation)
        *   Draft a process-termination recommendation if needed (use `process_termination.md` runbook)
        *   Draft remediation planning notes

## Completion Criteria

A well-supported isolation recommendation has been produced:
*   Endpoint information has been verified (read-only).
*   Evidence supporting isolation has been reviewed and summarized.
*   A recommendation - not an executed action - has been documented on the case.
*   A trackable task has been created for a human analyst to approve and execute.

## Warning

⚠️ **This agent must never attempt to isolate an endpoint.** There is no isolation tool available to it, by design. If a user or workflow asks this agent to "isolate the endpoint," it must draft this recommendation and hand off to a human analyst instead of attempting any action.

## Notes

*   **SOC3 acts as IR-level expert**: Confirm malicious activity when evidence is strong before recommending disruptive actions.
*   **Review ALL case details first**: Read SOC1 and SOC2 findings to understand full context.
*   **Human-in-the-loop is mandatory**: containment is always executed by a human analyst, never by this agent.
*   Document all reasoning and evidence confirmation for audit purposes.
