"""Tests for the Sentinel agent's system prompt.

The prompt is the agent's behaviour specification, so it is tested like any
other contract. These assert on properties we rely on -- not on prose -- and
run without a model or a network.
"""

from investigator.prompts import (
    SENTINEL_SYSTEM_PROMPT,
    investigation_request,
)

PROMPT = SENTINEL_SYSTEM_PROMPT
LOWER = PROMPT.lower()

TOOLS = ["get_login_history", "get_network_activity", "assess_user_risk"]

# Accounts that exist in the seeded demo database. The prompt must not name
# any of them: the username under investigation is supplied per run.
SEEDED_USERNAMES = ["admin"]


# ------------------------------------------------------------------
# Role
# ------------------------------------------------------------------

def test_defines_sentinel_as_an_evidence_driven_investigator():
    assert "you are sentinel" in LOWER
    assert "investigator" in LOWER
    # The framing must be evidence-first, not conclusion-first.
    assert "evidence" in LOWER


def test_states_that_claims_must_trace_back_to_tool_results():
    assert "traced back" in LOWER or "traceable" in LOWER


# ------------------------------------------------------------------
# Tool understanding: when and why
# ------------------------------------------------------------------

def test_documents_every_tool():
    for tool in TOOLS:
        assert tool in PROMPT, f"{tool} is not described in the prompt"


def test_each_tool_has_a_stated_purpose():
    """Naming a tool is not enough; the agent needs to know why it exists."""

    # get_login_history is the baseline/first call.
    assert "first call" in LOWER
    assert "baseline" in LOWER

    # get_network_activity corroborates a suspicion.
    assert "corroborate" in LOWER or "refute" in LOWER

    # assess_user_risk is the scoring system of record.
    assert "system of record" in LOWER or "authoritative" in LOWER


def test_network_lookups_are_restricted_to_observed_ips():
    assert "appeared in the login evidence" in LOWER


def test_prompt_contains_no_hardcoded_ip_addresses():
    """Suspicious IPs must be discovered from evidence, never memorised.

    A literal IP in the prompt would let the agent 'investigate' the seeded
    scenario without reading the login history at all.
    """

    import re

    found = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", PROMPT)

    assert found == [], f"prompt hardcodes IP addresses: {found}"


def test_prompt_contains_no_hardcoded_usernames_from_the_seed():
    """The account under investigation arrives as input, never as prose.

    A literal seeded username would let the agent act on a remembered
    account instead of the one it was asked about. Matched as a
    case-insensitive whole word so quoting and capitalisation cannot slip
    past -- `admin`, `ADMIN`, `'admin'`, `"admin"`, `the admin user` -- while
    unrelated words that merely contain the substring, such as
    "administrative" or "administrator", are left alone.
    """

    import re

    for username in SEEDED_USERNAMES:
        found = re.findall(
            rf"\b{re.escape(username)}\b",
            PROMPT,
            flags=re.IGNORECASE,
        )

        assert found == [], (
            f"prompt hardcodes the seeded username {username!r}: {found}"
        )


# ------------------------------------------------------------------
# Method: derivation and correlation
# ------------------------------------------------------------------

def test_requires_suspicious_ips_to_be_derived_from_evidence():
    assert "derive these ips from the evidence" in LOWER
    assert "never assume, guess" in LOWER


def test_rejects_frequency_alone_as_a_suspicion_signal():
    assert "frequency alone is not a signal" in LOWER


def test_names_the_real_security_signals():
    for signal in ["failed authentication", "failed mfa", "unknown device"]:
        assert signal in LOWER


def test_requires_correlation_across_tools_before_concluding():
    assert "correlate before concluding" in LOWER
    assert "isolation" in LOWER
    # Multi-source corroboration must be explicitly valued.
    assert "two independent" in LOWER or "more than one source" in LOWER


def test_requires_reconciling_own_reading_with_the_engine():
    assert "reconcile" in LOWER


def test_handles_the_no_suspicious_ips_case():
    assert "no suspicious ips" in LOWER


# ------------------------------------------------------------------
# Evidence discipline
# ------------------------------------------------------------------

def test_forbids_inventing_evidence():
    assert "never invent evidence" in LOWER


def test_separates_observation_from_inference():
    assert "separate observation from inference" in LOWER
    assert "belongs in evidence" in LOWER
    assert "belongs in assessment" in LOWER


def test_requires_chronology_to_be_read_not_inferred():
    assert "chronology" in LOWER
    assert "do not infer it from counts" in LOWER


def test_forbids_treating_failed_lookups_as_clean():
    assert "failed lookups are not clean results" in LOWER


def test_handles_a_missing_user():
    assert "does not exist" in LOWER


# ------------------------------------------------------------------
# The deterministic engine stays authoritative
# ------------------------------------------------------------------

def test_score_must_come_from_the_engine_verbatim():
    assert "the score is not yours" in LOWER
    assert "verbatim" in LOWER
    assert "never estimate, adjust, round or recompute" in LOWER


def test_prompt_contains_no_scoring_rules():
    """Risk points live in investigator/risk.py, never in the prompt."""

    import re

    banned_phrases = [
        "+30", "+25", "+20", "+15", "+10",
        "score +=", "points", "add 30", "weight",
    ]

    for phrase in banned_phrases:
        assert phrase not in LOWER, f"prompt leaks scoring rule: {phrase!r}"

    # No numeric thresholds that would let the model derive a score.
    assert not re.search(r"\bscore\s*(>=|>|<)\s*\d", LOWER)


def test_prompt_does_not_define_threat_level_thresholds():
    """The engine maps score -> level; the prompt must not duplicate that.

    Matches threshold-shaped constructs rather than bare digits, since
    legitimate text such as "ISO-8601" contains numbers.
    """

    import re

    threshold_patterns = [
        r"\b(?:score|level)\b[^.]{0,40}\b\d{2,3}\s*(?:or above|or more|\+)",
        r"(?:>=|<=|>|<)\s*\d{2,3}",
        r"\b\d{2,3}\s*(?:-|to|and above|or higher)\s*\d{0,3}\s*(?:=|means|is)\s*"
        r"(?:critical|high|medium|low)",
        r"\b(?:critical|high|medium|low)\b\s*(?:=|:)\s*\d{2,3}",
    ]

    for pattern in threshold_patterns:
        match = re.search(pattern, LOWER)
        assert match is None, (
            f"prompt appears to define a scoring threshold: {match.group(0)!r}"
        )


# ------------------------------------------------------------------
# Calibration -- the agent must not over-claim
# ------------------------------------------------------------------

def test_calibration_covers_every_threat_level():
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        assert level in PROMPT, f"no calibration guidance for {level}"


def test_forbids_asserting_compromise_below_critical():
    assert "do not assert that compromise occurred" in LOWER
    assert "not sufficient to conclude" in LOWER


def test_critical_language_is_still_hedged():
    """Even at CRITICAL the agent says 'consistent with', not 'was'."""

    assert "consistent with" in LOWER
    assert 'not "the account was compromised"' in LOWER


def test_low_with_no_factors_must_not_manufacture_concern():
    assert "no significant indicators" in LOWER
    assert "manufacture concern" in LOWER


def test_distinguishes_authentication_from_malicious_action():
    assert "not proof of malicious action" in LOWER


# ------------------------------------------------------------------
# Output contract
# ------------------------------------------------------------------

def test_output_format_defines_the_required_sections():
    for section in [
        "THREAT LEVEL:",
        "RISK SCORE:",
        "INDICATORS",
        "EVIDENCE",
        "ASSESSMENT",
        "RECOMMENDED NEXT ACTIONS",
    ]:
        assert section in PROMPT


def test_evidence_gaps_section_is_conditional():
    assert "EVIDENCE GAPS" in PROMPT
    assert "only if" in LOWER


def test_agent_is_told_evidence_tools_cannot_change_anything():
    """Read-only is now a property of the evidence tools, not the agent."""

    assert "cannot change anything" in LOWER
    assert "run only after a" in LOWER and "human approves them" in LOWER
    assert "recommendation for a human operator" in LOWER


# ------------------------------------------------------------------
# Containment -- proposed by the agent, decided by a human
# ------------------------------------------------------------------

def test_documents_the_containment_tools():
    for tool in ["contain_account", "block_ip", "get_account_status"]:
        assert tool in PROMPT


def test_containment_is_separated_from_evidence_gathering():
    assert "your containment tools" in LOWER
    assert "everything above only reads" in LOWER


def test_states_that_a_human_must_approve_containment():
    assert "a human must approve every containment call before it" in LOWER
    assert "proposing an action, not performing one" in LOWER


def test_explains_why_containment_is_disruptive():
    """The agent should understand the cost of being wrong."""

    assert "lock a legitimate operator out" in LOWER
    assert "shared vpn or nat egress" in LOWER


def test_requires_an_evidence_based_justification():
    assert "justification" in LOWER
    assert '"suspicious activity" is not a justification' in LOWER


def test_containment_is_restricted_to_high_and_critical():
    assert "only when the threat level is high or critical" in LOWER
    assert "at medium or low, recommend in" in LOWER


def test_containment_targets_must_be_implicated_by_evidence():
    assert "a target the evidence implicates" in LOWER


def test_a_denial_must_be_respected():
    assert "that decision stands" in LOWER
    assert "do not retry it or work around it" in LOWER


def test_requires_containment_to_be_verified_by_read_back():
    """A tool call that returned is an attempt, not an outcome."""

    assert "verify containment" in LOWER
    assert "an attempt, not an outcome" in LOWER
    assert "read the resulting state back" in LOWER


def test_names_the_read_back_tool_for_each_containment_action():
    assert "`get_account_status` after" in PROMPT
    assert "`get_ip_status` after" in PROMPT


def test_verification_verdict_is_a_fixed_two_way_choice():
    """The report must commit to CONFIRMED or FAILED, not hedge."""

    assert "VERIFICATION: CONFIRMED" in PROMPT
    assert "VERIFICATION: FAILED" in PROMPT


def test_success_may_not_be_claimed_from_the_call_itself():
    assert "never write confirmed on the strength of the containment call" in LOWER
    assert "only the read-back can confirm it" in LOWER


def test_verification_is_skipped_when_nothing_was_approved():
    """Nothing ran, so there is no outcome -- and nothing to report."""

    assert "skip this step entirely when nothing was approved" in LOWER


def test_containment_outcome_must_be_reported_honestly():
    assert "CONTAINMENT" in PROMPT
    assert "never describe a denied or unapproved action as though it" in LOWER


# ------------------------------------------------------------------
# Request builder
# ------------------------------------------------------------------

def test_investigation_request_names_the_account():
    request = investigation_request("alice")

    assert "alice" in request


def test_investigation_request_does_not_prejudge_the_outcome():
    """The opening message must not tell the agent what it will find."""

    request = investigation_request("alice").lower()

    for leading in ["critical", "compromised", "attack", "breach", "100"]:
        assert leading not in request


def test_investigation_request_asks_for_tool_use():
    assert "tools" in investigation_request("alice").lower()


if __name__ == "__main__":
    from investigator.testkit import main

    main(dict(globals()))
