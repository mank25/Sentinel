"""Console tests: the approval gate must hold the run until a human answers.

These use a fake agent, so they need neither TrueForge nor a model.
"""

import time

import pytest
from starlette.testclient import TestClient

import ui.server
from ui.runner import InvestigationRun, RunRegistry
from ui.server import app, main, registry, set_console_token


class FakeAgent:
    """A SentinelAgent stand-in that always proposes containment."""

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

    def investigate(self, username, provision=True, on_approval=None):
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

    run.decide(False, "False positive.")

    assert _wait_any(run, {"done", "error"}) == "done"
    assert run.result["approvals"][0]["allowed"] is False


def test_denial_reason_reaches_the_agent():
    run = InvestigationRun("admin", agent_factory=FakeAgent)
    run.start()

    assert _wait(run, "awaiting-approval")
    run.decide(False, "VPN, not travel.")

    assert _wait_any(run, {"done", "error"}) == "done"
    assert run.result["approvals"][0]["reason"] == "VPN, not travel."


def test_approval_executes_the_action():
    run = InvestigationRun("admin", agent_factory=FakeAgent)
    run.start()

    assert _wait(run, "awaiting-approval")
    run.decide(True, "")

    assert _wait_any(run, {"done", "error"}) == "done"
    assert run.result["approvals"][0]["allowed"] is True


def test_decision_is_rejected_when_not_paused():
    """A stray decision cannot slip in before or after the gate."""

    run = InvestigationRun("admin", agent_factory=FakeAgent)

    assert run.decide(True, "") is False


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
            json={"allowed": False, "reason": "Not compromised."},
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

    def investigate(self, username, provision=True, on_approval=None):
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
    assert run.decide(False, "First.")

    # The agent opens a second gate; it must pause again rather than reuse
    # the decision just made.
    assert _wait(run, "awaiting-approval"), "the second gate did not pause"
    assert run.pending[0]["tool_call_id"] == "call_2"
    assert run.result is None, "the run finished on one decision"

    assert run.decide(True, "")
    assert _wait_any(run, {"done", "error"}) == "done"

    first, second = run.result["rounds"]

    # Each round carries its own tool_call_id and its own answer.
    assert first[0]["tool_call_id"] == "call_1"
    assert first[0]["approval"]["status"] == "deny"
    assert second[0]["tool_call_id"] == "call_2"
    assert second[0]["approval"]["status"] == "allow"


def test_a_decision_is_recorded_once():
    """Two operators answering at the same gate produce one decision."""

    run = InvestigationRun("admin", agent_factory=TwoGateAgent)
    run.start()

    assert _wait(run, "awaiting-approval")
    assert run.decide(False, "First.") is True
    assert run.decide(True, "Second.") is False


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

        for value in ("false", "true", 1, "yes", None):
            rejected = client.post(
                f"/api/investigations/{run_id}/decision",
                json={"allowed": value},
            )
            assert rejected.status_code == 400, f"{value!r} was accepted"

        # The gate is untouched: still waiting for a real answer.
        assert run.status == "awaiting-approval"

        assert client.post(
            f"/api/investigations/{run_id}/decision",
            json={"allowed": False, "reason": "Not compromised."},
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

        assert client.post(
            f"/api/investigations/{run.id}/decision?token=s3cret",
            json={"allowed": False},
        ).status_code == 200

        assert client.post(
            f"/api/investigations/{run.id}/decision?token=wrong",
            json={"allowed": True},
        ).status_code == 401

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
