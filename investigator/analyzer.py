from collections import Counter


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
    events = login_data.get("login_events", [])

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

    suspicious_ips = [
        ip for ip, count in ip_counts.items()
        if count > 1
    ]

    successful_events = [
        event for event in events
        if event.get("success") == 1
    ]

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
        "successful_events": successful_events,
    }


def correlate_network_data(
    login_evidence: dict,
    network_data: dict,
) -> dict:
    """
    Correlate login evidence with network intelligence.
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

    network_matches = []

    for ip in suspicious_ips:
        if (
            network_data.get("found")
            and network_data.get("ip_address") == ip
        ):
            network_matches.append(network_data)

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
        "suspicious_ips": suspicious_ips,
        "network_matches": network_matches,
    }