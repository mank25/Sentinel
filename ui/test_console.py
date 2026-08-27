"""Console tests: the approval gate must hold the run until a human answers.

These use a fake agent, so they need neither TrueForge nor a model.
"""

import time

from starlette.testclient import TestClient

from ui.runner import InvestigationRun, RunRegistry
from ui.server import app, registry


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
