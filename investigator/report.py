"""Render an investigation result as human-readable text.

The report never recalculates risk. It only describes what the risk engine
already decided.
"""

# Assessment wording per threat level. The report states what the evidence
# supports and no more.
_ASSESSMENTS = {
    "CRITICAL": (
        "The evidence is strongly consistent with a potential account "
        "compromise and requires urgent attention."
    ),
    "HIGH": (
        "Significant suspicious activity was identified. This account "
        "should be investigated and its recent access reviewed."
    ),
    "MEDIUM": (
        "Some noteworthy activity was identified. It is not sufficient to "
        "conclude that the account was compromised."
    ),
    "LOW": (
        "Only minor findings were identified. Nothing observed indicates "
        "that the account was compromised."
    ),
    "UNKNOWN": (
        "The investigation could not be completed, so no assessment of "
        "this account can be made."
    ),
}

_NO_FINDINGS = (
    "No significant indicators were identified for this account."
)


def _assessment(risk: dict) -> str:
    threat_level = risk.get("threat_level", "UNKNOWN")

    # Factors worth 0 points (e.g. evidence gaps) are not findings against
    # the account.
    scoring_factors = [
        factor for factor in risk.get("risk_factors", [])
        if factor.get("points", 0) > 0
    ]

    if threat_level == "LOW" and not scoring_factors:
        return _NO_FINDINGS

    return _ASSESSMENTS.get(threat_level, _ASSESSMENTS["UNKNOWN"])


def generate_report(investigation: dict) -> str:
    risk = investigation["risk"]

    lines = [
        f"THREAT LEVEL: {risk['threat_level']}",
        f"RISK SCORE: {risk['risk_score']}/100",
        "",
        "KEY INDICATORS:",
    ]

    if risk["risk_factors"]:
        for factor in risk["risk_factors"]:
            lines.append(
                f"- {factor['factor']}: {factor['reason']}"
            )
    else:
        lines.append("- None identified.")

    lines.extend([
        "",
        "ASSESSMENT:",
        _assessment(risk),
    ])

    if risk.get("incomplete_evidence"):
        lines.extend([
            "",
            "EVIDENCE GAPS:",
            (
                "Network intelligence was incomplete for this "
                "investigation; the findings above may be partial."
            ),
        ])

    return "\n".join(lines)
