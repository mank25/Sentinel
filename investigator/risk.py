"""Deterministic Sentinel risk scoring engine."""


def calculate_risk(evidence: dict) -> dict:
    """
    Calculate a transparent risk score from correlated evidence.

    No LLM is used here. Every point should be explainable.
    """

    if not evidence.get("found"):
        return {
            "risk_score": 0,
            "threat_level": "UNKNOWN",
            "risk_factors": [],
            "error": evidence.get(
                "error",
                "Investigation evidence unavailable",
            ),
        }

    score = 0
    factors = []

    # --------------------------------------------------
    # Privileged account
    # --------------------------------------------------

    if evidence.get("role") in {
        "administrator",
        "admin",
        "superadmin",
    }:
        score += 30
        factors.append({
            "factor": "Privileged account",
            "points": 30,
            "reason": "The affected account has administrative privileges.",
        })

    # --------------------------------------------------
    # Brute-force behavior
    # --------------------------------------------------

    failed_logins = evidence.get("failed_logins", 0)

    if failed_logins >= 20:
        score += 25
        factors.append({
            "factor": "Brute-force pattern",
            "points": 25,
            "reason": f"{failed_logins} failed login attempts were detected.",
        })

    elif failed_logins >= 5:
        score += 15
        factors.append({
            "factor": "Repeated login failures",
            "points": 15,
            "reason": f"{failed_logins} failed login attempts were detected.",
        })

    # --------------------------------------------------
    # Successful authentication
    # --------------------------------------------------

    if (
        failed_logins > 0
        and evidence.get("successful_logins", 0) > 0
    ):
        score += 20
        factors.append({
            "factor": "Successful login after failures",
            "points": 20,
            "reason": (
                "A successful authentication occurred in an account "
                "with repeated preceding failures."
            ),
        })

    # --------------------------------------------------
    # MFA failure
    # --------------------------------------------------

    if evidence.get("mfa_failures", 0) > 0:
        score += 15
        factors.append({
            "factor": "MFA failure",
            "points": 15,
            "reason": "One or more authentication attempts failed MFA.",
        })

    # --------------------------------------------------
    # Unknown device
    # --------------------------------------------------

    if evidence.get("unknown_device_events", 0) > 0:
        score += 10
        factors.append({
            "factor": "Unknown device",
            "points": 10,
            "reason": "Authentication activity came from an unfamiliar device.",
        })

    # --------------------------------------------------
    # Unknown location
    # --------------------------------------------------

    if evidence.get("unknown_location_events", 0) > 0:
        score += 10
        factors.append({
            "factor": "Unknown location",
            "points": 10,
            "reason": "Authentication activity came from an unfamiliar location.",
        })

    # --------------------------------------------------
    # Network intelligence
    # --------------------------------------------------

    for network in evidence.get("network_matches", []):

        if network.get("reputation") == "suspicious":
            score += 20
            factors.append({
                "factor": "Suspicious IP reputation",
                "points": 20,
                "reason": (
                    f"IP {network.get('ip_address')} has a suspicious reputation."
                ),
            })

        if not network.get("known", True):
            score += 10
            factors.append({
                "factor": "Unknown network source",
                "points": 10,
                "reason": (
                    f"IP {network.get('ip_address')} is not a known "
                    "trusted network source."
                ),
            })

    # --------------------------------------------------
    # Cap score at 100
    # --------------------------------------------------

    score = min(score, 100)

    # --------------------------------------------------
    # Threat classification
    # --------------------------------------------------

    if score >= 80:
        threat_level = "CRITICAL"
    elif score >= 60:
        threat_level = "HIGH"
    elif score >= 30:
        threat_level = "MEDIUM"
    else:
        threat_level = "LOW"

    return {
        "risk_score": score,
        "threat_level": threat_level,
        "risk_factors": factors,
    }