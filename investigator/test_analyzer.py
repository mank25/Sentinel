from investigator.analyzer import (
    analyze_login_history,
    correlate_network_data,
)

USER = {
    "username": "admin",
    "role": "administrator",
    "normal_device": "MacBook",
    "normal_location": "Delhi",
}


def _event(
    timestamp,
    ip="10.10.1.20",
    device="MacBook",
    location="Delhi",
    success=1,
    mfa_status="passed",
):
    return {
        "timestamp": timestamp,
        "source_ip": ip,
        "device": device,
        "location": location,
        "success": success,
        "mfa_status": mfa_status,
    }


def _history(events, user=None):
    return {
        "found": True,
        "user": dict(user or USER),
        "login_events": events,
    }


# ------------------------------------------------------------------
# Baseline seeded-style scenario
# ------------------------------------------------------------------

def test_security_investigation():
    login_data = _history([
        _event(
            "2026-08-25T02:10:00",
            ip="185.123.45.67",
            device="Unknown",
            location="Unknown",
            success=0,
            mfa_status="failed",
        ),
        _event(
            "2026-08-25T02:14:00",
            ip="185.123.45.67",
            device="Unknown",
            location="Unknown",
            success=1,
            mfa_status="failed",
        ),
    ])

    evidence = analyze_login_history(login_data)

    assert evidence["failed_logins"] == 1
    assert evidence["successful_logins"] == 1
    assert evidence["mfa_failures"] == 2
    assert "185.123.45.67" in evidence["suspicious_ips"]

    network_data = {
        "found": True,
        "ip_address": "185.123.45.67",
        "reputation": "suspicious",
        "known": False,
        "connection_count": 58,
    }

    result = correlate_network_data(
        evidence,
        [network_data],
    )

    assert len(result["network_matches"]) == 1
    assert result["incomplete_network_evidence"] is False


# ------------------------------------------------------------------
# Issue 6 -- suspicious IP identification
# ------------------------------------------------------------------

def test_repeated_normal_success_is_not_suspicious():
    """A trusted user logging in five times is not an attacker."""

    evidence = analyze_login_history(_history([
        _event(f"2026-08-2{day}T09:00:00")
        for day in range(1, 6)
    ]))

    assert evidence["source_ips"]["10.10.1.20"] == 5
    assert evidence["suspicious_ips"] == []


def test_repeated_failed_logins_are_suspicious():
    evidence = analyze_login_history(_history([
        _event("2026-08-25T02:10:00", ip="203.0.113.9", success=0),
        _event("2026-08-25T02:11:00", ip="203.0.113.9", success=0),
    ]))

    assert evidence["suspicious_ips"] == ["203.0.113.9"]


def test_single_failed_login_is_not_suspicious():
    """One fat-fingered password is not a security signal."""

    evidence = analyze_login_history(_history([
        _event("2026-08-25T02:10:00", success=0),
        _event("2026-08-25T02:11:00"),
    ]))

    assert evidence["suspicious_ips"] == []


def test_failed_mfa_makes_ip_suspicious():
    evidence = analyze_login_history(_history([
        _event("2026-08-25T02:10:00", ip="198.51.100.4", mfa_status="failed"),
    ]))

    assert evidence["suspicious_ips"] == ["198.51.100.4"]
    reasons = evidence["suspicious_ip_details"][0]["reasons"]
    assert any("MFA" in reason for reason in reasons)


def test_unknown_device_and_location_is_suspicious():
    evidence = analyze_login_history(_history([
        _event(
            "2026-08-25T02:10:00",
            ip="198.51.100.7",
            device="Windows PC",
            location="Berlin",
        ),
    ]))

    assert evidence["suspicious_ips"] == ["198.51.100.7"]


def test_known_device_from_new_location_alone_is_not_suspicious():
    """Travelling with the usual laptop is not an authentication anomaly."""

    evidence = analyze_login_history(_history([
        _event("2026-08-25T02:10:00", ip="198.51.100.8", location="Mumbai"),
        _event("2026-08-25T03:10:00", ip="198.51.100.8", location="Mumbai"),
    ]))

    assert evidence["suspicious_ips"] == []


def test_multiple_suspicious_ips():
    evidence = analyze_login_history(_history([
        _event("2026-08-25T01:00:00", ip="203.0.113.9", success=0),
        _event("2026-08-25T01:01:00", ip="203.0.113.9", success=0),
        _event("2026-08-25T01:02:00", ip="198.51.100.4", mfa_status="failed"),
        _event("2026-08-25T01:03:00"),
    ]))

    assert set(evidence["suspicious_ips"]) == {"203.0.113.9", "198.51.100.4"}
    assert "10.10.1.20" not in evidence["suspicious_ips"]


# ------------------------------------------------------------------
# Issue 2 -- chronology
# ------------------------------------------------------------------

def _chronology(events):
    return analyze_login_history(_history(events))[
        "successful_login_after_failures"
    ]


def test_chronology_failure_failure_success():
    assert _chronology([
        _event("2026-08-25T01:00:00", success=0),
        _event("2026-08-25T01:01:00", success=0),
        _event("2026-08-25T01:02:00", success=1),
    ]) is True


def test_chronology_success_then_failures():
    assert _chronology([
        _event("2026-08-25T01:00:00", success=1),
        _event("2026-08-25T01:01:00", success=0),
        _event("2026-08-25T01:02:00", success=0),
    ]) is False


def test_chronology_success_only():
    assert _chronology([
        _event("2026-08-25T01:00:00", success=1),
    ]) is False


def test_chronology_failure_only():
    assert _chronology([
        _event("2026-08-25T01:00:00", success=0),
    ]) is False


def test_chronology_later_success_after_failures():
    """An earlier clean success must not mask a later post-failure success."""

    evidence = analyze_login_history(_history([
        _event("2026-08-24T09:00:00", success=1),
        _event("2026-08-25T01:00:00", success=0),
        _event("2026-08-25T01:01:00", success=0),
        _event("2026-08-25T01:02:00", success=1),
    ]))

    assert evidence["successful_login_after_failures"] is True

    detail = evidence["successful_login_after_failures_detail"]
    assert detail["timestamp"] == "2026-08-25T01:02:00"
    assert detail["preceding_failures"] == 2


def test_events_are_reordered_chronologically():
    """The MCP tool returns newest-first; the analyzer must not be fooled."""

    newest_first = [
        _event("2026-08-25T01:02:00", success=0),
        _event("2026-08-25T01:01:00", success=0),
        _event("2026-08-25T01:00:00", success=1),
    ]

    evidence = analyze_login_history(_history(newest_first))

    timestamps = [
        event["timestamp"]
        for event in evidence["login_timeline"]
    ]

    assert timestamps == sorted(timestamps)
    # Chronologically this is success -> failure -> failure.
    assert evidence["successful_login_after_failures"] is False


# ------------------------------------------------------------------
# Issue 3 -- network correlation and error handling
# ------------------------------------------------------------------

def _evidence_for(ips):
    return {
        "found": True,
        "username": "admin",
        "role": "administrator",
        "failed_logins": 2,
        "successful_logins": 0,
        "mfa_failures": 0,
        "unknown_device_events": 0,
        "unknown_location_events": 0,
        "suspicious_ips": list(ips),
    }


def test_network_lookup_success():
    result = correlate_network_data(
        _evidence_for(["185.123.45.67"]),
        [{
            "found": True,
            "ip_address": "185.123.45.67",
            "reputation": "suspicious",
            "known": False,
        }],
    )

    assert len(result["network_matches"]) == 1
    assert result["network_errors"] == []
    assert result["incomplete_network_evidence"] is False


def test_network_ip_not_found_is_not_an_error():
    result = correlate_network_data(
        _evidence_for(["203.0.113.9"]),
        [{"found": False, "ip_address": "203.0.113.9"}],
    )

    assert result["network_matches"] == []
    assert result["network_not_found"] == ["203.0.113.9"]
    assert result["network_errors"] == []
    # A queried IP with no record is complete evidence: we know there is none.
    assert result["incomplete_network_evidence"] is False


def test_network_error_is_preserved_and_flagged():
    result = correlate_network_data(
        _evidence_for(["203.0.113.9"]),
        [{
            "found": False,
            "ip_address": "203.0.113.9",
            "error": "Unable to read network security data.",
        }],
    )

    assert result["network_matches"] == []
    assert result["network_not_found"] == []
    assert result["network_errors"] == [{
        "ip_address": "203.0.113.9",
        "error": "Unable to read network security data.",
    }]
    assert result["incomplete_network_evidence"] is True


def test_network_partial_success_and_failure():
    result = correlate_network_data(
        _evidence_for(["185.123.45.67", "203.0.113.9"]),
        [
            {
                "found": True,
                "ip_address": "185.123.45.67",
                "reputation": "suspicious",
                "known": False,
            },
            {
                "found": False,
                "ip_address": "203.0.113.9",
                "error": "Unable to read network security data.",
            },
        ],
    )

    assert len(result["network_matches"]) == 1
    assert result["network_matches"][0]["ip_address"] == "185.123.45.67"
    assert len(result["network_errors"]) == 1
    assert result["incomplete_network_evidence"] is True
    # Nothing is dropped.
    assert len(result["network_lookups"]) == 2


def test_missing_lookup_for_suspicious_ip_is_incomplete():
    result = correlate_network_data(
        _evidence_for(["185.123.45.67", "203.0.113.9"]),
        [{
            "found": True,
            "ip_address": "185.123.45.67",
            "reputation": "clean",
            "known": True,
        }],
    )

    assert result["network_unqueried_ips"] == ["203.0.113.9"]
    assert result["incomplete_network_evidence"] is True


def test_correlation_without_suspicious_ips():
    result = correlate_network_data(_evidence_for([]), [])

    assert result["found"] is True
    assert result["network_matches"] == []
    assert result["incomplete_network_evidence"] is False


def test_correlation_propagates_login_failure():
    result = correlate_network_data(
        {"found": False, "error": "User 'nobody' was not found."},
        [],
    )

    assert result["found"] is False
    assert "nobody" in result["error"]


if __name__ == "__main__":
    from investigator.testkit import main

    main(dict(globals()))
