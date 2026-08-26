from investigator.report import generate_report


def _report(threat_level, score, factors, incomplete=False):
    return generate_report({
        "risk": {
            "threat_level": threat_level,
            "risk_score": score,
            "risk_factors": factors,
            "incomplete_evidence": incomplete,
        }
    })


COMPROMISE_CLAIM = "consistent with a potential account compromise"


def test_low_with_no_factors_states_nothing_was_found():
    report = _report("LOW", 0, [])

    assert "No significant indicators were identified" in report
    assert COMPROMISE_CLAIM not in report
    assert "- None identified." in report


def test_low_with_minor_factor_does_not_claim_compromise():
    report = _report("LOW", 10, [{
        "factor": "Unknown device",
        "points": 10,
        "reason": "Authentication activity came from an unfamiliar device.",
    }])

    assert COMPROMISE_CLAIM not in report
    assert "Unknown device" in report
    assert "No significant indicators" not in report


def test_medium_describes_findings_without_claiming_compromise():
    report = _report("MEDIUM", 45, [{
        "factor": "Repeated login failures",
        "points": 15,
        "reason": "8 failed login attempts were detected.",
    }])

    assert COMPROMISE_CLAIM not in report
    assert "not sufficient to conclude" in report


def test_high_recommends_investigation_without_claiming_compromise():
    report = _report("HIGH", 65, [{
        "factor": "Brute-force pattern",
        "points": 25,
        "reason": "47 failed login attempts were detected.",
    }])

    assert "Significant suspicious activity" in report
    assert "should be investigated" in report
    assert COMPROMISE_CLAIM not in report


def test_critical_states_probable_compromise():
    report = _report("CRITICAL", 100, [{
        "factor": "Privileged account",
        "points": 30,
        "reason": "The affected account has administrative privileges.",
    }])

    assert COMPROMISE_CLAIM in report
    assert "urgent attention" in report


def test_zero_point_factor_alone_is_still_no_findings():
    """An evidence gap is not a finding against the account."""

    report = _report("LOW", 0, [{
        "factor": "Incomplete network evidence",
        "points": 0,
        "reason": "Network intelligence could not be retrieved for 1.2.3.4.",
    }], incomplete=True)

    assert "No significant indicators were identified" in report
    assert "EVIDENCE GAPS:" in report


def test_evidence_gap_is_surfaced_in_the_report():
    report = _report("CRITICAL", 100, [], incomplete=True)

    assert "EVIDENCE GAPS:" in report
    assert "incomplete" in report


def test_complete_evidence_has_no_gap_section():
    report = _report("CRITICAL", 100, [], incomplete=False)

    assert "EVIDENCE GAPS:" not in report


def test_unknown_makes_no_assessment():
    report = _report("UNKNOWN", 0, [])

    assert "could not be completed" in report
    assert COMPROMISE_CLAIM not in report


if __name__ == "__main__":
    from investigator.testkit import main

    main(dict(globals()))
