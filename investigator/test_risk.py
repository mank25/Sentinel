from investigator.risk import calculate_risk


def test_critical_admin_attack():
    evidence = {
        "found": True,
        "username": "admin",
        "role": "administrator",
        "failed_logins": 47,
        "successful_logins": 2,
        "mfa_failures": 48,
        "unknown_device_events": 48,
        "unknown_location_events": 48,
        "network_matches": [
            {
                "ip_address": "185.123.45.67",
                "reputation": "suspicious",
                "known": False,
            }
        ],
    }

    result = calculate_risk(evidence)

    assert result["threat_level"] == "CRITICAL"
    assert result["risk_score"] == 100
    assert len(result["risk_factors"]) >= 5
    