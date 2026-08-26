from investigator.risk import calculate_risk


def _evidence(**overrides):
    evidence = {
        "found": True,
        "username": "alice",
        "role": "user",
        "failed_logins": 0,
        "successful_logins": 0,
        "mfa_failures": 0,
        "unknown_device_events": 0,
        "unknown_location_events": 0,
        "successful_login_after_failures": False,
        "successful_login_after_failures_detail": None,
        "network_matches": [],
    }
    evidence.update(overrides)
    return evidence


def _factor_names(result):
    return {factor["factor"] for factor in result["risk_factors"]}


# ------------------------------------------------------------------
# Seeded scenario
# ------------------------------------------------------------------

def test_critical_admin_attack():
    evidence = _evidence(
        username="admin",
        role="administrator",
        failed_logins=47,
        successful_logins=2,
        mfa_failures=48,
        unknown_device_events=48,
        unknown_location_events=48,
        successful_login_after_failures=True,
        successful_login_after_failures_detail={
            "timestamp": "2026-08-25T02:14:00",
            "source_ip": "185.123.45.67",
            "preceding_failures": 47,
        },
        network_matches=[
            {
                "ip_address": "185.123.45.67",
                "reputation": "suspicious",
                "known": False,
            }
        ],
    )

    result = calculate_risk(evidence)

    assert result["threat_level"] == "CRITICAL"
    assert result["risk_score"] == 100
    assert len(result["risk_factors"]) >= 5
    assert "Successful login after failures" in _factor_names(result)


# ------------------------------------------------------------------
# Issue 2 -- the chronology factor is driven by the timeline, not counts
# ------------------------------------------------------------------

def test_success_after_failures_awarded_when_chronology_supports_it():
    result = calculate_risk(_evidence(
        failed_logins=3,
        successful_logins=1,
        successful_login_after_failures=True,
        successful_login_after_failures_detail={
            "timestamp": "2026-08-25T01:02:00",
            "source_ip": "203.0.113.9",
            "preceding_failures": 3,
        },
    ))

    assert "Successful login after failures" in _factor_names(result)

    reason = next(
        factor["reason"]
        for factor in result["risk_factors"]
        if factor["factor"] == "Successful login after failures"
    )
    assert "2026-08-25T01:02:00" in reason
    assert "3 failed login attempts" in reason


def test_success_before_failures_is_not_awarded():
    """Counts alone would award this factor; chronology must veto it."""

    result = calculate_risk(_evidence(
        failed_logins=3,
        successful_logins=1,
        successful_login_after_failures=False,
    ))

    assert "Successful login after failures" not in _factor_names(result)


# ------------------------------------------------------------------
# Issue 3 -- incomplete evidence
# ------------------------------------------------------------------

def test_incomplete_network_evidence_is_flagged_without_points():
    result = calculate_risk(_evidence(
        role="administrator",
        incomplete_network_evidence=True,
        network_errors=[{
            "ip_address": "203.0.113.9",
            "error": "Unable to read network security data.",
        }],
        network_unqueried_ips=[],
    ))

    assert result["incomplete_evidence"] is True
    assert "Incomplete network evidence" in _factor_names(result)

    gap = next(
        factor for factor in result["risk_factors"]
        if factor["factor"] == "Incomplete network evidence"
    )
    assert gap["points"] == 0
    assert "203.0.113.9" in gap["reason"]

    # The gap must not inflate the score: privileged account only.
    assert result["risk_score"] == 30


def test_complete_evidence_is_not_flagged():
    result = calculate_risk(_evidence(incomplete_network_evidence=False))

    assert result["incomplete_evidence"] is False
    assert "Incomplete network evidence" not in _factor_names(result)


# ------------------------------------------------------------------
# Threat levels
# ------------------------------------------------------------------

def test_clean_user_is_low_with_no_factors():
    result = calculate_risk(_evidence())

    assert result["threat_level"] == "LOW"
    assert result["risk_score"] == 0
    assert result["risk_factors"] == []


def test_unavailable_evidence_is_unknown():
    result = calculate_risk({"found": False, "error": "no data"})

    assert result["threat_level"] == "UNKNOWN"
    assert result["risk_score"] == 0
    assert result["incomplete_evidence"] is True


if __name__ == "__main__":
    from investigator.testkit import main

    main(dict(globals()))
