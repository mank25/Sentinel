"""Deterministic correlation of raw security evidence.

No LLM is involved in this layer: it turns the raw, read-only output of the
MCP tools into compact, explainable evidence for the risk engine.
"""

from collections import Counter

# Authentication contexts that make an IP eligible as a suspicious candidate.
# A plain repeated *successful* login from a known device/location is not one
# of them.
MIN_REPEATED_FAILURES = 2


def _event_sort_key(event: dict) -> tuple:
    """Chronological sort key for a login event.

    Timestamps are ISO-8601 strings, which sort lexicographically in
    chronological order. Events without a timestamp keep their original
    relative order (the sort is stable) and are treated as oldest-first.
    """

    timestamp = event.get("timestamp")
    return (timestamp is None, timestamp or "")


def _order_events(events: list) -> list:
    """Return the events oldest-first.

    The MCP layer returns newest-first; chronology matters for the risk
    engine, so ordering is normalised here rather than in the tool.
    """

    return sorted(events, key=_event_sort_key)


def _find_success_after_failures(ordered_events: list) -> dict | None:
    """Return details of the first success that follows a failed attempt.

    Walks the events oldest-first and returns the earliest successful login
    that has at least one failed login attempt before it. Returns ``None``
    when no such sequence exists, so a success that merely *coexists* with
    failures never counts.
    """

    preceding_failures = 0

    for event in ordered_events:
        if event.get("success") == 0:
            preceding_failures += 1
            continue

        if event.get("success") == 1 and preceding_failures > 0:
            return {
                "timestamp": event.get("timestamp"),
                "source_ip": event.get("source_ip"),
                "preceding_failures": preceding_failures,
            }

    return None


def _ip_signals(ip: str, events: list, user: dict) -> dict:
    """Collect the explicit security signals observed for one source IP."""

    ip_events = [
        event for event in events
        if event.get("source_ip") == ip
    ]

    failed_logins = sum(
        1 for event in ip_events
        if event.get("success") == 0
    )

    mfa_failures = sum(
        1 for event in ip_events
        if event.get("mfa_status") == "failed"
    )

    unknown_device_and_location = sum(
        1 for event in ip_events
        if event.get("device") != user.get("normal_device")
        and event.get("location") != user.get("normal_location")
    )

    reasons = []

    if failed_logins >= MIN_REPEATED_FAILURES:
        reasons.append(
            f"{failed_logins} failed login attempts from this IP"
        )

    if mfa_failures:
        reasons.append(
            f"{mfa_failures} MFA failures from this IP"
        )

    if unknown_device_and_location:
        reasons.append(
            f"{unknown_device_and_location} events from an unknown "
            "device and an unknown location"
        )

    return {
        "ip_address": ip,
        "events": len(ip_events),
        "failed_logins": failed_logins,
        "mfa_failures": mfa_failures,
        "unknown_device_and_location_events": unknown_device_and_location,
        "reasons": reasons,
    }


def analyze_login_history(login_data: dict) -> dict:
    """
    Convert raw login-history data into compact security evidence.

    This function does deterministic analysis only.
    No LLM is involved here.
    """

    if not login_data.get("found"):
        return {
            "found": False,
            "error": login_data.get("error", "Login history unavailable"),
        }

    user = login_data["user"]
    events = _order_events(login_data.get("login_events", []))

    failed_logins = sum(
        1 for event in events
        if event.get("success") == 0
    )

    successful_logins = sum(
        1 for event in events
        if event.get("success") == 1
    )

    mfa_failures = sum(
        1 for event in events
        if event.get("mfa_status") == "failed"
    )

    unknown_devices = sum(
        1 for event in events
        if event.get("device") != user.get("normal_device")
    )

    unknown_locations = sum(
        1 for event in events
        if event.get("location") != user.get("normal_location")
    )

    ip_counts = Counter(
        event.get("source_ip")
        for event in events
        if event.get("source_ip")
    )

    # An IP is a suspicious candidate only when the events from it carry an
    # explicit security signal. Simply appearing more than once is not one.
    suspicious_ip_details = []

    for ip in ip_counts:
        signals = _ip_signals(ip, events, user)

        if signals["reasons"]:
            suspicious_ip_details.append(signals)

    suspicious_ips = [
        signals["ip_address"]
        for signals in suspicious_ip_details
    ]

    successful_events = [
        event for event in events
        if event.get("success") == 1
    ]

    success_after_failures = _find_success_after_failures(events)

    return {
        "found": True,
        "username": user["username"],
        "role": user["role"],
        "normal_device": user.get("normal_device"),
        "normal_location": user.get("normal_location"),
        "total_events": len(events),
        "failed_logins": failed_logins,
        "successful_logins": successful_logins,
        "mfa_failures": mfa_failures,
        "unknown_device_events": unknown_devices,
        "unknown_location_events": unknown_locations,
        "source_ips": dict(ip_counts),
        "suspicious_ips": suspicious_ips,
        "suspicious_ip_details": suspicious_ip_details,
        "successful_events": successful_events,
        # Ordered, machine-readable chronology handed to the risk engine.
        "login_timeline": events,
        "successful_login_after_failures": success_after_failures is not None,
        "successful_login_after_failures_detail": success_after_failures,
    }


def _normalise_network_results(network_results) -> list:
    """Accept a single network result, a list of them, or nothing."""

    if not network_results:
        return []

    if isinstance(network_results, dict):
        return [network_results]

    return list(network_results)


def correlate_network_data(
    login_evidence: dict,
    network_results=None,
) -> dict:
    """
    Correlate login evidence with network intelligence.

    ``network_results`` is the collection of :func:`get_network_activity`
    responses gathered for the suspicious IPs. Every response is preserved:
    a lookup that failed is never folded into a successful match, and never
    silently dropped.
    """

    if not login_evidence.get("found"):
        return {
            "found": False,
            "error": login_evidence.get(
                "error",
                "Login evidence unavailable",
            ),
        }

    suspicious_ips = login_evidence.get(
        "suspicious_ips",
        [],
    )

    lookups = _normalise_network_results(network_results)

    network_matches = []
    network_errors = []
    network_not_found = []
    resolved_ips = set()

    for result in lookups:
        ip = result.get("ip_address")

        if ip is not None:
            resolved_ips.add(ip)

        if result.get("error"):
            # An unavailable lookup is evidence we do not have -- never a
            # clean result.
            network_errors.append({
                "ip_address": ip,
                "error": result["error"],
            })
            continue

        if result.get("found"):
            network_matches.append(result)
            continue

        network_not_found.append(ip)

    # A suspicious IP we never got any answer for is also a gap.
    unqueried_ips = [
        ip for ip in suspicious_ips
        if ip not in resolved_ips
    ]

    incomplete = bool(network_errors or unqueried_ips)

    return {
        "found": True,
        "username": login_evidence["username"],
        "role": login_evidence["role"],
        "failed_logins": login_evidence["failed_logins"],
        "successful_logins": login_evidence["successful_logins"],
        "mfa_failures": login_evidence["mfa_failures"],
        "unknown_device_events": login_evidence[
            "unknown_device_events"
        ],
        "unknown_location_events": login_evidence[
            "unknown_location_events"
        ],
        "successful_login_after_failures": login_evidence.get(
            "successful_login_after_failures",
            False,
        ),
        "successful_login_after_failures_detail": login_evidence.get(
            "successful_login_after_failures_detail"
        ),
        "suspicious_ips": suspicious_ips,
        "suspicious_ip_details": login_evidence.get(
            "suspicious_ip_details",
            [],
        ),
        "network_lookups": lookups,
        "network_matches": network_matches,
        "network_not_found": network_not_found,
        "network_errors": network_errors,
        "network_unqueried_ips": unqueried_ips,
        "incomplete_network_evidence": incomplete,
    }
