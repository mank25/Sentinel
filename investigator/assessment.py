"""Deterministic composition of the Sentinel investigation pipeline.

This module wires the existing layers together:

    login evidence -> analyzer -> risk engine -> report

It is transport-agnostic on purpose. Callers supply the raw login data and a
``network_lookup`` callable, so the same composition serves the MCP tool, the
stdio runner, and the tests without any of them importing each other.

No HTTP, no MCP, and no LLM appear here -- and risk scoring stays in
:mod:`investigator.risk`.
"""

from investigator.analyzer import (
    analyze_login_history,
    correlate_network_data,
)
from investigator.report import generate_report
from investigator.risk import calculate_risk


def assess(login_data: dict, network_lookup) -> dict:
    """Run the full deterministic pipeline over ``login_data``.

    ``network_lookup`` is called once per suspicious IP and must return a
    ``get_network_activity``-shaped dict. A raised exception is captured as a
    structured lookup error rather than aborting the investigation.
    """

    login_evidence = analyze_login_history(login_data)

    if not login_evidence.get("found"):
        return {
            "found": False,
            "error": login_evidence.get(
                "error",
                "Login evidence unavailable",
            ),
        }

    network_results = []

    for ip_address in login_evidence.get("suspicious_ips", []):
        try:
            network_results.append(network_lookup(ip_address))

        except Exception as exc:  # noqa: BLE001 - surfaced as evidence
            network_results.append({
                "found": False,
                "ip_address": ip_address,
                "error": f"Network intelligence lookup failed: {exc}",
            })

    investigation = correlate_network_data(
        login_evidence,
        network_results,
    )

    investigation["risk"] = calculate_risk(investigation)
    investigation["report"] = generate_report(investigation)

    return investigation


def summarize(investigation: dict) -> dict:
    """Reduce an investigation to a compact, agent-friendly verdict.

    The full investigation carries the whole login timeline, which is far too
    large for a small model context. This keeps only what the agent needs to
    reason about and quote -- and every number here is produced by the
    deterministic engine, never by the model.
    """

    if not investigation.get("found"):
        return {
            "found": False,
            "error": investigation.get("error", "Investigation unavailable"),
        }

    risk = investigation.get("risk", {})

    return {
        "found": True,
        "username": investigation.get("username"),
        "role": investigation.get("role"),
        "threat_level": risk.get("threat_level"),
        "risk_score": risk.get("risk_score"),
        "risk_factors": risk.get("risk_factors", []),
        "incomplete_evidence": risk.get("incomplete_evidence", False),
        "evidence_summary": {
            "failed_logins": investigation.get("failed_logins"),
            "successful_logins": investigation.get("successful_logins"),
            "mfa_failures": investigation.get("mfa_failures"),
            "unknown_device_events": investigation.get(
                "unknown_device_events"
            ),
            "unknown_location_events": investigation.get(
                "unknown_location_events"
            ),
            "successful_login_after_failures": investigation.get(
                "successful_login_after_failures"
            ),
            "successful_login_after_failures_detail": investigation.get(
                "successful_login_after_failures_detail"
            ),
        },
        "suspicious_ips": investigation.get("suspicious_ips", []),
        "suspicious_ip_details": investigation.get(
            "suspicious_ip_details", []
        ),
        "network_matches": investigation.get("network_matches", []),
        "network_not_found": investigation.get("network_not_found", []),
        "network_errors": investigation.get("network_errors", []),
        "report": investigation.get("report"),
    }
