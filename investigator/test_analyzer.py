from investigator.analyzer import (
    analyze_login_history,
    correlate_network_data,
)


def test_security_investigation():
    login_data = {
        "found": True,
        "user": {
            "username": "admin",
            "role": "administrator",
            "normal_device": "MacBook",
            "normal_location": "Delhi",
        },
        "login_events": [
            {
                "source_ip": "185.123.45.67",
                "device": "Unknown",
                "location": "Unknown",
                "success": 0,
                "mfa_status": "failed",
            },
            {
                "source_ip": "185.123.45.67",
                "device": "Unknown",
                "location": "Unknown",
                "success": 1,
                "mfa_status": "failed",
            },
        ],
    }

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
        network_data,
    )

    assert len(result["network_matches"]) == 1
