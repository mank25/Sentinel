def generate_report(investigation: dict) -> str:
    risk = investigation["risk"]

    lines = [
        f"THREAT LEVEL: {risk['threat_level']}",
        f"RISK SCORE: {risk['risk_score']}/100",
        "",
        "KEY INDICATORS:",
    ]

    for factor in risk["risk_factors"]:
        lines.append(
            f"- {factor['factor']}: {factor['reason']}"
        )

    lines.extend([
        "",
        "ASSESSMENT:",
        (
            "The investigation identified multiple indicators "
            "consistent with a potential account compromise."
        ),
    ])

    return "\n".join(lines)