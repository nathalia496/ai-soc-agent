"""
End-to-end alert investigation pipeline.

Chains the individual investigation stages that already exist in this
project - SIEM alert + nearby logs, CTI/MISP enrichment, MITRE ATT&CK
technique mapping, and LLM report generation - into a single
"alert in, report out" flow, reusing the existing ``tools_*`` wrapper
functions instead of talking to the raw client classes directly.

This is strictly an investigation pipeline: it only ever reads data and,
optionally, adds a comment to an existing case. It never isolates an
endpoint, kills a process, or performs any other containment/remediation
action - see src/mcp/README.md's "Human-in-the-loop by design" section.
Enrichment stages (logs, CTI, ATT&CK) are best-effort: if one of them
fails or isn't configured, the pipeline records a warning and keeps
going, because the report can still be useful without it. Only a missing
SIEM/LLM client, a non-existent alert, or an LLM failure stop the
pipeline outright, since there is no report to produce without them.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..core.errors import IntegrationError
from ..core.logging import get_logger
from . import tools_attack, tools_case, tools_cti, tools_llm, tools_siem, tools_storage

logger = get_logger("sami.orchestrator.investigate_alert")

# Caps how many indicators of a given type get sent to CTI lookups per
# investigation, so one noisy alert with dozens of related entities can't
# turn into dozens of outbound lookups.
_MAX_ENTITIES_PER_TYPE = 5


def investigate_alert(
    alert_id: str,
    siem_client: Any = None,
    cti_clients: Optional[List[Any]] = None,
    misp_client: Any = None,
    attack_mapper: Any = None,
    llm_client: Any = None,
    case_client: Any = None,
    case_id: Optional[str] = None,
    storage_client: Any = None,
    minutes_before: int = 30,
    minutes_after: int = 30,
    attack_top_n: int = 5,
    comment_author: str = "SamiGPT",
) -> Dict[str, Any]:
    """
    Investigate a SIEM alert end-to-end and produce a structured report.

    Pipeline: fetch alert -> fetch nearby logs -> enrich related hash/IP
    entities via CTI (OpenCTI/local TIP for hashes, MISP for hashes/IPs)
    -> map findings to MITRE ATT&CK techniques -> generate the final
    recommendation-only report. If both ``case_client`` and ``case_id``
    are given, the report is also attached to that case as a comment.

    Args:
        alert_id: The SIEM alert ID to investigate.
        siem_client: SIEM client (required).
        cti_clients: List of CTI clients for hash lookups (OpenCTI/local TIP).
            Optional - hash enrichment is skipped (with a warning) if not given.
        misp_client: MISP client for hash/IP lookups. Optional - MISP
            enrichment is skipped (with a warning) if not given.
        attack_mapper: AttackMapper instance. Optional - ATT&CK mapping is
            skipped (with a warning) if not given.
        llm_client: Report-generation LLM client, e.g. OllamaClient (required).
        case_client: Case management client. Optional - only used to attach
            the report as a comment, and only if ``case_id`` is also given.
        case_id: Case to attach the report to as a comment. The alert and the
            case are different ID spaces (SIEM vs. case management), so this
            must be passed explicitly rather than inferred from alert_id.
        storage_client: Storage client (e.g. PostgresClient). Optional - if
            given, the generated report is persisted so it can be looked up
            later via get_investigation_report/list_investigation_reports.
        minutes_before: Minutes before the alert's timestamp to search for
            nearby logs.
        minutes_after: Minutes after the alert's timestamp to search for
            nearby logs.
        attack_top_n: Maximum number of ATT&CK technique matches to request.
        comment_author: Author name used when attaching the report comment.

    Returns:
        Dictionary with the final report plus every intermediate artifact
        (alert, logs, CTI results, ATT&CK matches, case comment result,
        stored report record) and a list of non-fatal warnings encountered
        along the way, for auditability.

    Raises:
        IntegrationError: If siem_client/llm_client are missing, the alert
            can't be found, or report generation fails. Enrichment-stage
            failures (logs, CTI, ATT&CK) are recorded as warnings instead
            of raised, since the pipeline can still produce a useful report
            without them.
    """
    if siem_client is None:
        raise IntegrationError("SIEM client not provided")
    if llm_client is None:
        raise IntegrationError("LLM client not provided")

    warnings: List[str] = []

    # 1. Fetch the alert.
    alert = tools_siem.get_security_alert_by_id(alert_id=alert_id, client=siem_client)["alert"]

    # 2. Fetch nearby logs/evidence (best-effort).
    try:
        logs_result = tools_siem.get_logs_for_alert(
            alert_id=alert_id,
            minutes_before=minutes_before,
            minutes_after=minutes_after,
            client=siem_client,
        )
    except Exception as e:
        logger.warning(f"Failed to fetch nearby logs for alert {alert_id}: {e}")
        warnings.append(f"Failed to fetch nearby logs: {e}")
        logs_result = {"success": False, "events": [], "returned_count": 0}

    # 3. Reuse the related_entities the alert document already carries
    # (extracted by ElasticSIEMClient._extract_entities_from_alert) instead
    # of re-implementing entity extraction here.
    entities_by_type = _group_entities(alert.get("related_entities") or [])

    # 4. CTI enrichment for hash/IP entities (best-effort).
    cti_results = _enrich_with_cti(entities_by_type, cti_clients, misp_client, warnings)

    # 5. Map alert + logs + CTI findings to likely ATT&CK techniques (best-effort).
    enrichment_text = _build_summary_text(alert, logs_result, cti_results)
    attack_matches: List[Dict[str, Any]] = []
    if attack_mapper is not None:
        try:
            attack_matches = tools_attack.map_to_attack(
                enrichment_text, mapper=attack_mapper, top_n=attack_top_n,
            ).get("matches", [])
        except Exception as e:
            logger.warning(f"ATT&CK mapping failed for alert {alert_id}: {e}")
            warnings.append(f"ATT&CK mapping failed: {e}")
    else:
        warnings.append("ATT&CK mapper not configured; skipping technique mapping")

    # 6. Generate the final structured report from alert + logs + CTI + ATT&CK.
    report_context = _build_summary_text(alert, logs_result, cti_results, attack_matches)
    report = tools_llm.generate_investigation_report(context=report_context, client=llm_client)["report"]

    # 7. Optionally persist the report for later retrieval (best-effort).
    stored_report = None
    if storage_client is not None:
        try:
            stored_report = tools_storage.save_investigation_report(
                alert_id=alert_id,
                case_id=case_id,
                report=report,
                warnings=warnings,
                client=storage_client,
            )
        except Exception as e:
            logger.warning(f"Failed to persist investigation report for alert {alert_id}: {e}")
            warnings.append(f"Failed to persist investigation report: {e}")

    # 8. Optionally attach the report to a case for human review. Never any
    # containment/remediation tool call - investigation-only, by design.
    case_comment_result = None
    if case_client is not None and case_id is not None:
        try:
            case_comment_result = tools_case.add_case_comment(
                case_id=case_id,
                content=_format_case_comment(report, attack_matches),
                author=comment_author,
                client=case_client,
            )
        except Exception as e:
            logger.warning(f"Failed to attach report to case {case_id}: {e}")
            warnings.append(f"Failed to attach report to case {case_id}: {e}")
    elif case_client is not None and case_id is None:
        warnings.append("case_client provided but no case_id given; report was not attached to a case")

    return {
        "success": True,
        "alert_id": alert_id,
        "alert": alert,
        "logs": logs_result,
        "cti_results": cti_results,
        "attack_matches": attack_matches,
        "report": report,
        "stored_report": stored_report,
        "case_comment": case_comment_result,
        "warnings": warnings,
    }


def _group_entities(related_entities: List[str]) -> Dict[str, List[str]]:
    """
    Group ``related_entities`` strings (e.g. "ip:1.2.3.4", "hash:abc123")
    by their type prefix, as produced by
    ElasticSIEMClient._extract_entities_from_alert.
    """
    grouped: Dict[str, List[str]] = {}
    for entity in related_entities:
        entity_type, sep, value = entity.partition(":")
        if not sep:
            entity_type, value = "other", entity
        grouped.setdefault(entity_type, []).append(value)
    return grouped


def _enrich_with_cti(
    entities_by_type: Dict[str, List[str]],
    cti_clients: Optional[List[Any]],
    misp_client: Any,
    warnings: List[str],
) -> Dict[str, Any]:
    """
    Look up hash entities via lookup_hash_ti (OpenCTI/local TIP) and both
    hash and IP entities via lookup_ioc_misp (MISP), capped at
    _MAX_ENTITIES_PER_TYPE per type. Missing clients or individual lookup
    failures are recorded as warnings rather than raised, so one bad
    indicator or a missing integration doesn't stop the whole investigation.
    """
    hash_lookups: List[Dict[str, Any]] = []
    ioc_lookups: List[Dict[str, Any]] = []

    hash_values = entities_by_type.get("hash", [])[:_MAX_ENTITIES_PER_TYPE]
    ip_values = entities_by_type.get("ip", [])[:_MAX_ENTITIES_PER_TYPE]

    if hash_values and not cti_clients:
        warnings.append(
            f"{len(hash_values)} hash indicator(s) found but no CTI client (OpenCTI/local TIP) configured"
        )
    for hash_value in (hash_values if cti_clients else []):
        try:
            hash_lookups.append(tools_cti.lookup_hash_ti(hash_value, clients=cti_clients))
        except Exception as e:
            logger.warning(f"CTI hash lookup failed for {hash_value}: {e}")
            warnings.append(f"CTI hash lookup failed for {hash_value}: {e}")

    misp_targets = hash_values + ip_values
    if misp_targets and misp_client is None:
        warnings.append(f"{len(misp_targets)} indicator(s) found but no MISP client configured")
    for indicator in (misp_targets if misp_client is not None else []):
        try:
            ioc_lookups.append(tools_cti.lookup_ioc_misp(indicator, client=misp_client))
        except Exception as e:
            logger.warning(f"MISP lookup failed for {indicator}: {e}")
            warnings.append(f"MISP lookup failed for {indicator}: {e}")

    return {"hash_lookups": hash_lookups, "ioc_lookups": ioc_lookups}


def _build_summary_text(
    alert: Dict[str, Any],
    logs_result: Dict[str, Any],
    cti_results: Dict[str, Any],
    attack_matches: Optional[List[Dict[str, Any]]] = None,
) -> str:
    """
    Build a plain-text summary of the alert, nearby logs, and CTI findings
    (and, once available, ATT&CK matches) - used both as the input text for
    map_to_attack() and, with attack_matches filled in, as the final context
    for generate_investigation_report().
    """
    lines = [
        f"Alert: {alert.get('title') or alert.get('id')}",
        f"Severity: {alert.get('severity', 'unknown')} | Status: {alert.get('status', 'unknown')}",
    ]
    if alert.get("description"):
        lines.append(f"Description: {alert['description']}")
    related = alert.get("related_entities") or []
    if related:
        lines.append(f"Related entities: {', '.join(related)}")

    events = logs_result.get("events") or []
    if events:
        lines.append(f"\nNearby events ({len(events)}):")
        for event in events[:20]:
            detail_bits = [
                f"{field}={event[field]}"
                for field in ("host", "username", "ip", "process_name", "file_hash")
                if event.get(field)
            ]
            detail = f" ({', '.join(detail_bits)})" if detail_bits else ""
            lines.append(f"- [{event.get('timestamp', '')}] {event.get('message', '')}{detail}")

    hash_lookups = cti_results.get("hash_lookups") or []
    ioc_lookups = cti_results.get("ioc_lookups") or []
    if hash_lookups or ioc_lookups:
        lines.append("\nThreat intelligence findings:")
        for result in hash_lookups:
            assessment = (result.get("threat_assessment") or {}).get("summary")
            lines.append(f"- hash {result.get('hash_value')}: {assessment or 'no assessment available'}")
        for result in ioc_lookups:
            ti = result.get("threat_intelligence") or {}
            lines.append(
                f"- {result.get('indicator')} (MISP): found={ti.get('found', False)}, "
                f"tags={ti.get('tags') or []}, {len(ti.get('events') or [])} related event(s)"
            )

    if attack_matches:
        lines.append("\nLikely MITRE ATT&CK techniques:")
        for match in attack_matches:
            lines.append(
                f"- {match.get('technique_id')} {match.get('technique_name')} "
                f"(tactics: {', '.join(match.get('tactics') or [])}, score: {match.get('score')})"
            )

    return "\n".join(lines)


def _format_case_comment(report: Dict[str, Any], attack_matches: List[Dict[str, Any]]) -> str:
    """Format the generated report as a human-readable case comment."""
    lines = [
        "**SamiGPT investigation report (recommendation only - requires human review)**",
        "",
        f"Hypothesis: {report.get('hypothesis', 'N/A')}",
    ]
    if attack_matches:
        technique_ids = ", ".join(m.get("technique_id", "") for m in attack_matches)
        lines.append(f"Likely ATT&CK techniques: {technique_ids}")
    next_steps = report.get("next_steps") or []
    if next_steps:
        lines.append("\nRecommended next steps:")
        lines.extend(f"- {step}" for step in next_steps)
    return "\n".join(lines)
