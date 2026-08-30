"""Console tests: the approval gate must hold the run until a human answers.

These use a fake agent, so they need neither TrueForge nor a model.
"""

import threading
import time

import pytest
from starlette.testclient import TestClient

import ui.runner
import ui.server
from ui.runner import (
    DECISION_ACCEPTED,
    DECISION_NO_GATE,
    DECISION_STALE_GATE,
    InvestigationRun,
    RunRegistry,
    parse_assessment,
)
from ui.server import app, main, registry, set_console_token


class FakeAgent:
    """A SentinelAgent stand-in that always proposes containment."""

    # Shaped exactly like extract_trace() output, so the runner's mapping is
    # exercised against the real vocabulary rather than an invented one.
    TRACE = [
        {
            "step": "mcp.initialize",
            "server": "sentinel-security",
            "transport": "remote",
            "created_at": "2026-08-29T10:00:00Z",
        },
        {
            "step": "tool.call",
            "tool": "get_login_history",
            "arguments": {"username": "admin"},
            "tool_call_id": "t1",
            "created_at": "2026-08-29T10:00:01Z",
        },
        {
            "step": "tool.response",
            "tool": "get_login_history",
            "tool_call_id": "t1",
            "content": '{"found": true, "login_events": []}',
            "created_at": "2026-08-29T10:00:03Z",
        },
        {
            "step": "tool.call",
            "tool": "assess_user_risk",
            "arguments": {"username": "admin"},
            "tool_call_id": "t2",
            "created_at": "2026-08-29T10:00:04Z",
        },
        {
            "step": "tool.response",
            "tool": "assess_user_risk",
            "tool_call_id": "t2",
            "content": (
                '{"found": true, "username": "admin", '
                '"threat_level": "CRITICAL", "risk_score": 100, '
                '"risk_factors": [{"factor": "Privileged account", '
                '"points": 30, "reason": "admin"}], '
                '"incomplete_evidence": false}'
            ),
            "created_at": "2026-08-29T10:00:05Z",
        },
    ]

    def __init__(self, deny_reason_seen=None):
        self.seen = deny_reason_seen

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False

    def provision(self):
        return {
            "model": "test/model",
            "tools": ["get_login_history", "contain_account"],
        }

    def investigate(
        self, username, provision=True, on_approval=None, on_trace=None
    ):
        if on_trace:
            on_trace(self.TRACE)

        pending = [{
            "thread_id": "main",
            "tool_call_id": "call_1",
            "tool": "contain_account",
            "arguments": {"username": username},
        }]

        decisions = on_approval(pending) if on_approval else []
        approval = decisions[0]["approval"] if decisions else {}

        return {
            "username": username,
            "response": "CRITICAL - impossible travel.",
            "trace": [],
            "approvals": [{
                "tool": "contain_account",
                "arguments": {"username": username},
                "allowed": approval.get("status") == "allow",
                "reason": approval.get("reason"),
            }],
        }


def _wait(run, status, timeout=5.0):
    deadline = time.time() + timeout

    while time.time() < deadline:
        if run.status == status:
            return True

        time.sleep(0.02)

    return False


def _wait_for_event(run, kind, timeout=5.0):
    """Return the first event of ``kind``, or fail once the deadline passes."""

    deadline = time.time() + timeout

    while time.time() < deadline:
        for event in run.history():
            if event["kind"] == kind:
                return event

        time.sleep(0.02)

    raise AssertionError(f"no {kind!r} event within {timeout}s")


def _wait_any(run, statuses, timeout=5.0):
    deadline = time.time() + timeout

    while time.time() < deadline:
        if run.status in statuses:
            return run.status

        time.sleep(0.02)

    return run.status


def test_run_pauses_until_a_human_decides():
    """Nothing is auto-approved: the run blocks on the gate."""

    run = InvestigationRun("admin", agent_factory=FakeAgent)
    run.start()

    assert _wait(run, "awaiting-approval"), "run did not pause for approval"
    assert run.result is None, "the run finished without a decision"
    assert run.pending[0]["tool"] == "contain_account"

    assert run.decide(run.gate_id, False, "False positive.") == (
        DECISION_ACCEPTED
    )

    assert _wait_any(run, {"done", "error"}) == "done"
    assert run.result["approvals"][0]["allowed"] is False


def test_denial_reason_reaches_the_agent():
    run = InvestigationRun("admin", agent_factory=FakeAgent)
    run.start()

    assert _wait(run, "awaiting-approval")
    run.decide(run.gate_id, False, "VPN, not travel.")

    assert _wait_any(run, {"done", "error"}) == "done"
    assert run.result["approvals"][0]["reason"] == "VPN, not travel."


def test_approval_executes_the_action():
    run = InvestigationRun("admin", agent_factory=FakeAgent)
    run.start()

    assert _wait(run, "awaiting-approval")
    run.decide(run.gate_id, True, "")

    assert _wait_any(run, {"done", "error"}) == "done"
    assert run.result["approvals"][0]["allowed"] is True


def test_decision_is_rejected_when_not_paused():
    """A stray decision cannot slip in before or after the gate."""

    run = InvestigationRun("admin", agent_factory=FakeAgent)

    assert run.gate_id is None
    assert run.decide("anything", True, "") == DECISION_NO_GATE


def test_history_replays_for_a_late_follower():
    run = InvestigationRun("admin", agent_factory=FakeAgent)
    run.start()

    assert _wait(run, "awaiting-approval")

    kinds = [event["kind"] for event in run.history()]

    assert "provisioned" in kinds
    assert "approval_required" in kinds


def test_agent_failure_is_reported_not_swallowed():
    class Broken(FakeAgent):
        def provision(self):
            raise RuntimeError("TrueForge is down")

    run = InvestigationRun("admin", agent_factory=Broken)
    run.start()

    assert _wait_any(run, {"done", "error"}) == "error"
    assert "TrueForge is down" in run.error


# ---------------------------------------------------------------------
# HTTP surface
# ---------------------------------------------------------------------

def _client(monkeyed_factory=FakeAgent):
    original = registry.create
    registry.create = lambda username, agent_factory=None: original(
        username, agent_factory=monkeyed_factory
    )
    return TestClient(app), original


def test_investigation_endpoints():
    client, original = _client()

    try:
        started = client.post(
            "/api/investigations", json={"username": "admin"}
        )
        assert started.status_code == 200

        run_id = started.json()["id"]
        run = registry.get(run_id)

        assert _wait(run, "awaiting-approval")

        decided = client.post(
            f"/api/investigations/{run_id}/decision",
            json={
                "gate_id": run.gate_id,
                "allowed": False,
                "reason": "Not compromised.",
            },
        )
        assert decided.status_code == 200

        assert _wait_any(run, {"done", "error"}) == "done"

    finally:
        registry.create = original


def test_endpoint_validation():
    client, original = _client()

    try:
        assert client.post(
            "/api/investigations", json={"username": "  "}
        ).status_code == 400

        assert client.post(
            "/api/investigations/missing/decision", json={"allowed": True}
        ).status_code == 404

    finally:
        registry.create = original


def test_registry_isolates_runs():
    registry_ = RunRegistry()
    first = registry_.create("admin", agent_factory=FakeAgent)
    second = registry_.create("root", agent_factory=FakeAgent)

    assert first.id != second.id
    assert registry_.get(first.id) is first
    assert registry_.get("nope") is None


# ---------------------------------------------------------------------
# Repeated gates, concurrent followers, and the token guard
# ---------------------------------------------------------------------

class TwoGateAgent(FakeAgent):
    """An agent that pauses twice, as a multi-round investigation does."""

    def investigate(
        self, username, provision=True, on_approval=None, on_trace=None
    ):
        rounds = []

        for call_id in ("call_1", "call_2"):
            pending = [{
                "thread_id": "main",
                "tool_call_id": call_id,
                "tool": "contain_account",
                "arguments": {"username": username, "round": call_id},
            }]
            rounds.append(on_approval(pending))

        return {
            "username": username,
            "response": "CRITICAL - impossible travel.",
            "trace": [],
            "approvals": [],
            "rounds": rounds,
        }


def test_a_second_gate_waits_for_its_own_decision():
    """The first answer must not resume a containment call nobody saw."""

    run = InvestigationRun("admin", agent_factory=TwoGateAgent)
    run.start()

    assert _wait(run, "awaiting-approval")
    assert run.pending[0]["tool_call_id"] == "call_1"

    first_gate = run.gate_id
    assert run.decide(first_gate, False, "First.") == DECISION_ACCEPTED

    # The agent opens a second gate; it must pause again rather than reuse
    # the decision just made.
    assert _wait(run, "awaiting-approval"), "the second gate did not pause"
    assert run.pending[0]["tool_call_id"] == "call_2"
    assert run.result is None, "the run finished on one decision"

    second_gate = run.gate_id
    assert second_gate != first_gate, "the second gate reused the first id"

    assert run.decide(second_gate, True, "") == DECISION_ACCEPTED
    assert _wait_any(run, {"done", "error"}) == "done"

    first, second = run.result["rounds"]

    # Each round carries its own tool_call_id and its own answer.
    assert first[0]["tool_call_id"] == "call_1"
    assert first[0]["approval"]["status"] == "deny"
    assert second[0]["tool_call_id"] == "call_2"
    assert second[0]["approval"]["status"] == "allow"


# ---------------------------------------------------------------------
# Gate binding
#
# A decision answers one specific containment request. These tests exist
# because the previous contract -- "release whichever gate is open" -- let a
# duplicated answer land on a containment call the operator never saw.
# ---------------------------------------------------------------------

def test_a_gate1_decision_cannot_approve_gate2():
    """The Phase 0 vulnerability, as a test.

    Approve gate 1, let the run advance to gate 2, then replay the gate-1
    answer. It must be refused, gate 2 must still be pending, and no second
    containment may have been authorised.
    """

    run = InvestigationRun("admin", agent_factory=TwoGateAgent)
    run.start()

    assert _wait(run, "awaiting-approval")

    gate_1 = run.gate_id
    assert run.pending[0]["tool_call_id"] == "call_1"

    assert run.decide(gate_1, True, "Confirmed malicious.") == (
        DECISION_ACCEPTED
    )

    # The run advances and opens a second, different gate.
    assert _wait(run, "awaiting-approval"), "the second gate did not pause"

    gate_2 = run.gate_id
    assert gate_2 != gate_1
    assert run.pending[0]["tool_call_id"] == "call_2"

    # The duplicated gate-1 answer: a second click, a second tab, a retried
    # request. It must not authorise the action now on the table.
    assert run.decide(gate_1, True, "Confirmed malicious.") == (
        DECISION_STALE_GATE
    )

    # Gate 2 is untouched -- still open, still holding the run.
    assert run.status == "awaiting-approval"
    assert run.gate_id == gate_2
    assert run.pending[0]["tool_call_id"] == "call_2"
    assert run.result is None

    # Only one decision was ever recorded.
    decisions = [
        event for event in run.history() if event["kind"] == "decision"
    ]
    assert len(decisions) == 1
    assert decisions[0]["gate_id"] == gate_1

    # Answering the gate actually on the table still works.
    assert run.decide(gate_2, False, "Shared VPN.") == DECISION_ACCEPTED
    assert _wait_any(run, {"done", "error"}) == "done"

    first, second = run.result["rounds"]
    assert first[0]["approval"]["status"] == "allow"
    assert second[0]["approval"]["status"] == "deny"


def test_an_unknown_gate_id_is_refused():
    """A guessed or fabricated gate id authorises nothing."""

    run = InvestigationRun("admin", agent_factory=TwoGateAgent)
    run.start()

    assert _wait(run, "awaiting-approval")

    assert run.decide("not-a-real-gate", True, "") == DECISION_STALE_GATE
    assert run.decide("", True, "") == DECISION_STALE_GATE
    assert run.decide(run.id, True, "") == DECISION_STALE_GATE

    # The gate still holds the run.
    assert run.status == "awaiting-approval"
    assert run.result is None
    assert not [e for e in run.history() if e["kind"] == "decision"]


def test_a_duplicate_decision_at_the_same_gate_is_refused():
    """Answering twice does not answer twice."""

    run = InvestigationRun("admin", agent_factory=TwoGateAgent)
    run.start()

    assert _wait(run, "awaiting-approval")

    gate_1 = run.gate_id

    assert run.decide(gate_1, False, "First.") == DECISION_ACCEPTED
    assert run.decide(gate_1, True, "Second.") in (
        DECISION_NO_GATE,
        DECISION_STALE_GATE,
    )

    decisions = [e for e in run.history() if e["kind"] == "decision"]
    assert len(decisions) == 1
    assert decisions[0]["allowed"] is False


def test_concurrent_decisions_produce_exactly_one():
    """Two operators hitting Approve at the same instant produce one answer.

    Both threads answer the gate they were shown, so at most one can win --
    and the loser must not be carried forward to the next gate.
    """

    run = InvestigationRun("admin", agent_factory=TwoGateAgent)
    run.start()

    assert _wait(run, "awaiting-approval")

    gate_1 = run.gate_id
    outcomes = []
    barrier = threading.Barrier(2)

    def answer(allowed, reason):
        barrier.wait()
        outcomes.append(run.decide(gate_1, allowed, reason))

    threads = [
        threading.Thread(target=answer, args=(True, "approve")),
        threading.Thread(target=answer, args=(False, "deny")),
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    assert outcomes.count(DECISION_ACCEPTED) == 1, outcomes

    # Whatever the loser answered, it did not become a second decision --
    # and in particular it did not resolve gate 2.
    assert _wait(run, "awaiting-approval"), "gate 2 did not open"
    assert run.gate_id != gate_1

    gate_1_decisions = [
        e for e in run.history()
        if e["kind"] == "decision" and e["gate_id"] == gate_1
    ]
    assert len(gate_1_decisions) == 1


def test_a_timed_out_gate_cannot_be_answered_afterwards(monkeypatch):
    """Timeout is a denial, and the retracted gate stays unanswerable."""

    monkeypatch.setattr(ui.runner, "APPROVAL_TIMEOUT", 0.05)

    run = InvestigationRun("admin", agent_factory=TwoGateAgent)
    run.start()

    assert _wait(run, "awaiting-approval")

    gate_1 = run.gate_id

    # Let the gate lapse, then try to answer it.
    assert _wait_any(run, {"awaiting-approval"}, timeout=1.0)

    timed_out = _wait_for_event(run, "approval_timeout")
    assert timed_out["gate_id"] == gate_1

    assert run.decide(gate_1, True, "late") in (
        DECISION_NO_GATE,
        DECISION_STALE_GATE,
    )

    # Nothing was approved by the lapse.
    approvals = [
        e for e in run.history()
        if e["kind"] == "decision" and e["gate_id"] == gate_1
    ]
    assert approvals == []


def test_every_follower_sees_every_event():
    """Two open tabs both get the run; they do not divide it between them."""

    run = InvestigationRun("admin", agent_factory=FakeAgent)

    first = run.follow(timeout=0.05)
    second = run.follow(timeout=0.05)

    # Registering is lazy: pull one idle tick so both generators subscribe.
    assert next(first) is None
    assert next(second) is None

    run.emit("phase", phase="investigating", message="one")
    run.emit("phase", phase="investigating", message="two")

    for follower in (first, second):
        seen = [event for event in (next(follower), next(follower))]
        assert [event["message"] for event in seen] == ["one", "two"]

    first.close()
    second.close()


def test_backlog_is_replayed_exactly_once():
    """A late follower gets the history, and not a second copy of it."""

    run = InvestigationRun("admin", agent_factory=FakeAgent)
    run.emit("phase", phase="investigating", message="before")

    follower = run.follow(timeout=0.05)

    assert next(follower)["message"] == "before"

    run.emit("phase", phase="investigating", message="after")

    assert next(follower)["message"] == "after"

    # Nothing left over: the backlog was not also queued.
    assert next(follower) is None

    follower.close()


def test_a_closed_follower_is_deregistered():
    run = InvestigationRun("admin", agent_factory=FakeAgent)

    follower = run.follow(timeout=0.05)
    assert next(follower) is None
    follower.close()

    run.emit("phase", phase="investigating", message="orphan")

    assert run._followers == []


def test_allowed_must_be_a_real_boolean():
    """The JSON string "false" is not an approval to contain an account."""

    client, original = _client()

    try:
        started = client.post(
            "/api/investigations", json={"username": "admin"}
        )
        run_id = started.json()["id"]
        run = registry.get(run_id)

        assert _wait(run, "awaiting-approval")

        gate_id = run.gate_id

        for value in ("false", "true", 1, "yes", None):
            rejected = client.post(
                f"/api/investigations/{run_id}/decision",
                json={"gate_id": gate_id, "allowed": value},
            )
            assert rejected.status_code == 400, f"{value!r} was accepted"

        # The gate is untouched: still waiting for a real answer.
        assert run.status == "awaiting-approval"

        assert client.post(
            f"/api/investigations/{run_id}/decision",
            json={
                "gate_id": gate_id,
                "allowed": False,
                "reason": "Not compromised.",
            },
        ).status_code == 200

        assert _wait_any(run, {"done", "error"}) == "done"

    finally:
        registry.create = original


def test_token_guard_rejects_unauthenticated_requests():
    """A console bound beyond loopback demands its token on every route."""

    client, original = _client()
    set_console_token("s3cret")

    try:
        assert client.post(
            "/api/investigations", json={"username": "admin"}
        ).status_code == 401

        assert client.get("/api/investigations/anything/events").status_code == 401
        assert client.get("/").status_code == 401

        # A header works, and so does the query string EventSource needs.
        started = client.post(
            "/api/investigations",
            json={"username": "admin"},
            headers={"authorization": "Bearer s3cret"},
        )
        assert started.status_code == 200

        run = registry.get(started.json()["id"])

        assert _wait(run, "awaiting-approval")

        gate_id = run.gate_id

        assert client.post(
            f"/api/investigations/{run.id}/decision?token=wrong",
            json={"gate_id": gate_id, "allowed": True},
        ).status_code == 401

        assert client.post(
            f"/api/investigations/{run.id}/decision?token=s3cret",
            json={"gate_id": gate_id, "allowed": False},
        ).status_code == 200

    finally:
        set_console_token(None)
        registry.create = original


def test_remote_binding_requires_a_token(monkeypatch):
    """Exposing containment approval to the network is not a default."""

    # Cleared so a token in the developer's own environment cannot let this
    # test fall through parser.error() and actually start a server.
    monkeypatch.delenv("SENTINEL_CONSOLE_TOKEN", raising=False)

    with pytest.raises(SystemExit):
        main(["--host", "0.0.0.0"])

    assert ui.server.CONSOLE_TOKEN is None, "a refused bind must not set a token"


# ---------------------------------------------------------------------
# Gate binding over HTTP
# ---------------------------------------------------------------------

def test_decision_endpoint_requires_a_gate_id():
    """The route will not accept "approve whatever is open"."""

    client, original = _client()

    try:
        started = client.post(
            "/api/investigations", json={"username": "admin"}
        )
        run_id = started.json()["id"]
        run = registry.get(run_id)

        assert _wait(run, "awaiting-approval")

        for body in (
            {"allowed": True},
            {"allowed": True, "gate_id": None},
            {"allowed": True, "gate_id": ""},
            {"allowed": True, "gate_id": "   "},
            {"allowed": True, "gate_id": 12345},
        ):
            refused = client.post(
                f"/api/investigations/{run_id}/decision", json=body
            )
            assert refused.status_code == 400, body
            assert "gate_id" in refused.json()["error"]

        # None of that touched the gate.
        assert run.status == "awaiting-approval"
        assert run.result is None

    finally:
        registry.create = original


def test_decision_endpoint_refuses_an_unknown_gate_id():
    client, original = _client()

    try:
        started = client.post(
            "/api/investigations", json={"username": "admin"}
        )
        run_id = started.json()["id"]
        run = registry.get(run_id)

        assert _wait(run, "awaiting-approval")

        refused = client.post(
            f"/api/investigations/{run_id}/decision",
            json={"gate_id": "deadbeef" * 4, "allowed": True},
        )

        assert refused.status_code == 409
        assert refused.json()["outcome"] == DECISION_STALE_GATE
        assert run.status == "awaiting-approval"

    finally:
        registry.create = original


def test_decision_endpoint_refuses_a_stale_gate_id():
    """The Phase 0 vulnerability, at the HTTP boundary."""

    def two_gates(*args, **kwargs):
        return TwoGateAgent()

    client, original = _client(monkeyed_factory=two_gates)

    try:
        started = client.post(
            "/api/investigations", json={"username": "admin"}
        )
        run_id = started.json()["id"]
        run = registry.get(run_id)

        assert _wait(run, "awaiting-approval")
        gate_1 = run.gate_id

        assert client.post(
            f"/api/investigations/{run_id}/decision",
            json={"gate_id": gate_1, "allowed": True},
        ).status_code == 200

        assert _wait(run, "awaiting-approval"), "gate 2 did not open"
        assert run.gate_id != gate_1

        # Replaying the gate-1 approval must not approve gate 2.
        replayed = client.post(
            f"/api/investigations/{run_id}/decision",
            json={"gate_id": gate_1, "allowed": True},
        )

        assert replayed.status_code == 409
        assert replayed.json()["outcome"] == DECISION_STALE_GATE
        assert run.status == "awaiting-approval"
        assert run.pending[0]["tool_call_id"] == "call_2"

        decisions = [
            e for e in run.history() if e["kind"] == "decision"
        ]
        assert len(decisions) == 1

    finally:
        registry.create = original


# ---------------------------------------------------------------------
# The live event pipeline
# ---------------------------------------------------------------------

def test_tool_activity_is_emitted_while_the_run_is_in_flight():
    """Tool calls reach the console during the run, not only at the end."""

    run = InvestigationRun("admin", agent_factory=FakeAgent)
    run.start()

    # The gate is still open -- the run has not returned a result yet.
    assert _wait(run, "awaiting-approval")
    assert run.result is None

    kinds = [event["kind"] for event in run.history()]

    assert "mcp_ready" in kinds
    assert kinds.count("tool_call") == 2
    assert kinds.count("tool_result") == 2
    assert "assessment" in kinds
    assert "complete" not in kinds, "activity arrived only at the end"


def test_tool_calls_and_results_correlate_by_tool_call_id():
    run = InvestigationRun("admin", agent_factory=FakeAgent)
    run.start()

    assert _wait(run, "awaiting-approval")

    calls = {
        e["tool_call_id"]: e
        for e in run.history() if e["kind"] == "tool_call"
    }
    results = {
        e["tool_call_id"]: e
        for e in run.history() if e["kind"] == "tool_result"
    }

    assert set(calls) == set(results) == {"t1", "t2"}
    assert calls["t1"]["tool"] == "get_login_history"
    assert calls["t1"]["arguments"] == {"username": "admin"}
    assert results["t1"]["tool"] == "get_login_history"
    assert calls["t2"]["tool"] == "assess_user_risk"


def test_the_assessment_is_the_engines_verdict_verbatim():
    """The console's threat level comes from the engine, not from prose."""

    run = InvestigationRun("admin", agent_factory=FakeAgent)
    run.start()

    assert _wait(run, "awaiting-approval")

    verdict = _wait_for_event(run, "assessment")

    assert verdict["threat_level"] == "CRITICAL"
    assert verdict["risk_score"] == 100
    assert verdict["username"] == "admin"
    assert verdict["risk_factors"][0]["factor"] == "Privileged account"
    assert verdict["incomplete_evidence"] is False
    assert run.assessment["risk_score"] == 100


def test_parse_assessment_rejects_anything_that_is_not_a_verdict():
    """A malformed or incomplete payload yields no score at all."""

    assert parse_assessment(None) is None
    assert parse_assessment("not json") is None
    assert parse_assessment("[]") is None
    assert parse_assessment('{"found": false, "error": "no such user"}') is None
    # found, but the engine produced no numbers -- never invent them.
    assert parse_assessment('{"found": true, "username": "admin"}') is None

    # A list of MCP content blocks is unwrapped.
    parsed = parse_assessment([
        {"text": '{"found": true, "threat_level": "LOW", "risk_score": 0}'}
    ])
    assert parsed["threat_level"] == "LOW"
    assert parsed["risk_score"] == 0


def test_approval_required_carries_its_gate_id():
    run = InvestigationRun("admin", agent_factory=FakeAgent)
    run.start()

    assert _wait(run, "awaiting-approval")

    event = _wait_for_event(run, "approval_required")

    assert event["gate_id"] == run.gate_id
    assert event["pending"][0]["tool"] == "contain_account"

    run.decide(run.gate_id, False, "No.")

    decision = _wait_for_event(run, "decision")

    assert decision["gate_id"] == event["gate_id"]
    assert decision["allowed"] is False
    assert decision["reason"] == "No."


def test_events_are_sequenced_and_ordered():
    """seq is monotonic, gapless and consistent across followers."""

    run = InvestigationRun("admin", agent_factory=FakeAgent)
    run.start()

    assert _wait_any(run, {"awaiting-approval"})
    run.decide(run.gate_id, False, "")
    assert _wait_any(run, {"done", "error"}) == "done"

    seqs = [event["seq"] for event in run.history()]

    assert seqs == list(range(1, len(seqs) + 1))


def test_replay_after_reconnect_yields_no_duplicates():
    """A follower that drops and replays sees each event exactly once.

    This is the server half of the browser's reconnect: the backlog is the
    whole run, and `seq` is what lets the client discard what it already
    rendered.
    """

    run = InvestigationRun("admin", agent_factory=FakeAgent)
    run.start()

    assert _wait(run, "awaiting-approval")

    # First connection: read part of the run, then "drop".
    first = run.follow(timeout=0.05)
    seen = []

    for _ in range(3):
        event = next(first)

        if event is not None:
            seen.append(event)

    first.close()

    last_seq = seen[-1]["seq"]

    run.decide(run.gate_id, False, "")
    assert _wait_any(run, {"done", "error"}) == "done"

    # Reconnect: replay everything, drop what was already rendered.
    second = run.follow(timeout=0.05)
    replayed = []

    while True:
        event = next(second)

        if event is None:
            break

        replayed.append(event)

    second.close()

    fresh = [e for e in replayed if e["seq"] > last_seq]
    combined = seen + fresh

    # Every event, exactly once, in order.
    assert [e["seq"] for e in combined] == list(
        range(1, len(run.history()) + 1)
    )
    assert len(combined) == len(run.history())


def test_tool_events_carry_the_thread_that_made_the_call():
    """The console correlates on (thread_id, tool_call_id), so the runner
    must publish the thread alongside the id."""

    run = InvestigationRun("admin", agent_factory=FakeAgent)

    run._on_trace([
        {
            "step": "tool.call",
            "tool": "get_login_history",
            "arguments": {"username": "admin"},
            "thread_id": "main",
            "tool_call_id": "call_123",
            "created_at": "2026-08-30T10:00:00Z",
        },
        {
            "step": "tool.call",
            "tool": "get_network_activity",
            "arguments": {"ip_address": "185.123.45.67"},
            "thread_id": "subagent-abc",
            "tool_call_id": "call_123",
            "created_at": "2026-08-30T10:00:01Z",
        },
        {
            "step": "tool.response",
            "tool": "get_network_activity",
            "thread_id": "subagent-abc",
            "tool_call_id": "call_123",
            "content": '{"found": true}',
            "created_at": "2026-08-30T10:00:02Z",
        },
    ])

    calls = [e for e in run.history() if e["kind"] == "tool_call"]
    results = [e for e in run.history() if e["kind"] == "tool_result"]

    # The same tool_call_id on two threads stays distinguishable downstream.
    assert [(c["thread_id"], c["tool_call_id"]) for c in calls] == [
        ("main", "call_123"),
        ("subagent-abc", "call_123"),
    ]
    assert results[0]["thread_id"] == "subagent-abc"
    assert results[0]["tool_call_id"] == "call_123"


# ------------------------------------------------------------------
# Delegated investigations on the event stream
#
# A subagent's work must reach the console attributed to the thread that
# did it. These use the runner's trace callback directly, which is the
# seam TrueForge's events arrive through.
# ------------------------------------------------------------------

def test_thread_lifecycle_reaches_the_console():
    run = InvestigationRun("admin", agent_factory=_never_called)

    run._on_trace([
        {"step": "thread.created", "thread_id": "t1",
         "name": "Identity Analyst", "parent_thread_id": "main",
         "created_at": "2026-08-26T02:24:18"},
        {"step": "thread.done", "thread_id": "t1",
         "created_at": "2026-08-26T02:24:20"},
    ])

    kinds = [event["kind"] for event in run.history()]

    assert kinds == ["thread_started", "thread_finished"]

    started = run.history()[0]

    assert started["thread_id"] == "t1"
    assert started["name"] == "Identity Analyst"
    assert started["parent_thread_id"] == "main"


def test_a_linear_run_publishes_no_thread_events():
    """Nothing about the console changes when there are no subagents."""

    run = InvestigationRun("admin", agent_factory=_never_called)

    run._on_trace([
        {"step": "tool.call", "thread_id": "main", "tool_call_id": "call_1",
         "tool": "get_login_history", "arguments": {"username": "admin"}},
    ])

    kinds = [event["kind"] for event in run.history()]

    assert "thread_started" not in kinds
    assert kinds == ["tool_call"]


def test_tool_events_carry_the_thread_that_made_them():
    """Correlation in the browser depends on this field being present."""

    run = InvestigationRun("admin", agent_factory=_never_called)

    run._on_trace([
        {"step": "tool.call", "thread_id": "t1", "tool_call_id": "call_7",
         "tool": "get_network_activity", "arguments": {}},
        {"step": "tool.response", "thread_id": "t1", "tool_call_id": "call_7",
         "tool": "get_network_activity", "content": "{}"},
    ])

    for event in run.history():
        assert event["thread_id"] == "t1"
        assert event["tool_call_id"] == "call_7"


def test_the_same_tool_call_id_on_two_threads_stays_distinguishable():
    """The bug this branch exists to fix, at the console's own boundary.

    Two threads can mint the same tool_call_id. If the console's event
    stream dropped the thread, the browser could not tell the two results
    apart -- and would attach a subagent's answer to the lead's question.
    """

    run = InvestigationRun("admin", agent_factory=_never_called)

    run._on_trace([
        {"step": "tool.call", "thread_id": "A", "tool_call_id": "call_123",
         "tool": "get_login_history", "arguments": {}},
        {"step": "tool.call", "thread_id": "B", "tool_call_id": "call_123",
         "tool": "get_network_activity", "arguments": {}},
        {"step": "tool.response", "thread_id": "B", "tool_call_id": "call_123",
         "tool": "get_network_activity", "content": '{"found": true}'},
    ])

    events = run.history()

    assert [event["thread_id"] for event in events] == ["A", "B", "B"]

    response = events[-1]

    assert response["kind"] == "tool_result"
    assert response["thread_id"] == "B"


def test_an_agent_message_carries_its_thread():
    run = InvestigationRun("admin", agent_factory=_never_called)

    run._on_trace([
        {"step": "model.message", "thread_id": "t1", "content": "findings"},
    ])

    assert run.history()[0]["thread_id"] == "t1"


def _never_called():
    raise AssertionError("these tests drive the trace callback directly")
