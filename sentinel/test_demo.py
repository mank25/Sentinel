"""Tests for the demo orchestration layer.

Two things are worth holding here, and neither is about security logic --
this package has none.

* **Readiness answers are actionable.** A failing check must name a fix, not
  raise. The whole point of the module is that an operator never meets a
  traceback first.
* **The demo never invents anything.** The narration prints only what the
  trace carried, and the report reads its verdict out of the risk engine's
  own tool result rather than out of the agent's prose.

These run under pytest (they use ``tmp_path`` and ``monkeypatch``)::

    pytest sentinel -q
"""

import json
import sqlite3

import pytest

from sentinel import preflight
from sentinel.demo import _clock, _verdict_from_trace, narrate, reset_demo_state
from trueforge.config import SENTINEL_TOOLS, TrueForgeConfig


# ------------------------------------------------------------------
# Readiness: every negative answer carries a fix
# ------------------------------------------------------------------

def test_a_missing_evidence_database_names_the_command_that_builds_it(
    tmp_path,
):
    check = preflight.check_evidence_database(tmp_path / "absent.db")

    assert check.ok is False
    assert "init_db" in check.fix


def test_an_empty_evidence_database_is_not_ready(tmp_path):
    """Schema without rows is not a seeded incident."""

    db = tmp_path / "security.db"

    with sqlite3.connect(db) as connection:
        connection.execute("CREATE TABLE users (id INTEGER PRIMARY KEY)")
        connection.execute("CREATE TABLE login_events (id INTEGER PRIMARY KEY)")
        connection.execute(
            "CREATE TABLE network_events (id INTEGER PRIMARY KEY)"
        )

    check = preflight.check_evidence_database(db)

    assert check.ok is False
    assert "--reset" in check.fix


def test_a_corrupt_evidence_database_is_reported_not_raised(tmp_path):
    db = tmp_path / "security.db"
    db.write_bytes(b"this is not a database")

    check = preflight.check_evidence_database(db)

    assert check.ok is False
    assert check.fix


def test_the_readiness_check_never_creates_the_evidence_database(tmp_path):
    """A check that builds what it is checking is not a check."""

    absent = tmp_path / "absent.db"

    preflight.check_evidence_database(absent)

    assert not absent.exists()


def test_unreachable_trueforge_is_reported_with_a_fix():
    config = TrueForgeConfig(base_url="http://127.0.0.1:1")

    check = preflight.check_trueforge(config)

    assert check.ok is False
    assert "unreachable" in check.detail
    assert check.fix


def test_an_unconfigured_model_lists_the_alternatives(monkeypatch):
    class Response:
        status_code = 200

        @staticmethod
        def raise_for_status():
            return None

        @staticmethod
        def json():
            return {"data": [{"name": "provider/other-model"}]}

    monkeypatch.setattr(preflight.httpx2, "get", lambda *a, **k: Response())

    config = TrueForgeConfig(model="provider/absent-model")
    check = preflight.check_model(config)

    assert check.ok is False
    assert "provider/other-model" in check.fix


def test_a_stale_mcp_server_is_caught_before_the_investigation(monkeypatch):
    """A server from an older checkout pings fine and then fails a turn.

    Catching it here is the difference between "restart the MCP server" and
    an opaque provisioning error in the middle of a demo.
    """

    incomplete = [
        tool for tool in SENTINEL_TOOLS if tool != SENTINEL_TOOLS[-1]
    ]

    monkeypatch.setattr(preflight, "resolve_token", lambda: "token")
    monkeypatch.setattr(
        preflight, "_list_mcp_tools",
        lambda url, token: _immediately(incomplete),
    )

    check = preflight.check_mcp_server(TrueForgeConfig())

    assert check.ok is False
    assert SENTINEL_TOOLS[-1] in check.detail
    assert "Restart it" in check.fix


def test_a_complete_mcp_server_is_ready(monkeypatch):
    monkeypatch.setattr(preflight, "resolve_token", lambda: "token")
    monkeypatch.setattr(
        preflight, "_list_mcp_tools",
        lambda url, token: _immediately(list(SENTINEL_TOOLS)),
    )

    check = preflight.check_mcp_server(TrueForgeConfig())

    assert check.ok is True
    assert str(len(SENTINEL_TOOLS)) in check.detail


async def _immediately(value):
    return value


def test_a_missing_console_build_does_not_block_the_cli_demo(tmp_path):
    """The terminal demo needs no frontend; refusing to run would be wrong."""

    check = preflight.check_console_build(tmp_path / "index.html")

    assert check.ok is False
    assert preflight.blocking([check]) == []


def test_formatting_shows_the_fix_under_a_failure():
    checks = [
        preflight.Check("Thing", False, "is broken", "do the thing"),
        preflight.Check("Other", True, "is fine"),
    ]

    rendered = preflight.format_checks(checks)

    assert "FAIL" in rendered
    assert "-> do the thing" in rendered
    # A passing check has nothing to fix, so nothing is suggested for it.
    assert rendered.count("->") == 1


# ------------------------------------------------------------------
# Reset: the demo is repeatable
# ------------------------------------------------------------------

def test_reset_clears_containment_so_the_demo_can_be_rerun(monkeypatch,
                                                           tmp_path):
    """An account left contained by the last run changes the next one."""

    from investigator import containment

    store = tmp_path / "containment.db"
    monkeypatch.setattr(containment, "DB_PATH", store)

    containment.record_action(
        containment.ACTION_CONTAIN_ACCOUNT, "admin", "earlier demo run",
        db_path=store,
    )
    assert containment.account_status("admin", db_path=store)["contained"]

    reset_demo_state("admin", evidence_db=tmp_path / "security.db")

    assert containment.account_status("admin", db_path=store)["contained"] is (
        False
    )


def test_reset_is_idempotent(monkeypatch, tmp_path):
    """Running it twice must be as safe as running it once."""

    from investigator import containment

    monkeypatch.setattr(containment, "DB_PATH", tmp_path / "containment.db")

    evidence = tmp_path / "security.db"

    reset_demo_state("admin", evidence_db=evidence)
    reset_demo_state("admin", evidence_db=evidence)

    assert containment.list_actions() == []


# ------------------------------------------------------------------
# Narration and reporting: nothing is invented
# ------------------------------------------------------------------

def test_an_event_without_a_timestamp_gets_no_invented_one():
    """Blank, not now(). A made-up time is a false claim about the trace."""

    assert _clock(None).strip() == ""
    assert _clock("not a timestamp").strip() == ""
    assert _clock("2026-08-26T02:24:18") == "02:24:18"


def test_narration_prints_only_recognised_steps(capsys):
    narrate([
        {"step": "tool.call", "tool": "get_login_history",
         "arguments": {"username": "admin"},
         "created_at": "2026-08-26T02:24:18"},
        {"step": "a.step.from.a.future.trueforge", "payload": "ignored"},
    ])

    printed = capsys.readouterr().out

    assert "get_login_history" in printed
    assert "future" not in printed


def test_narration_labels_a_subagent_thread_but_not_the_main_one(capsys):
    narrate([
        {"step": "tool.call", "tool": "assess_user_risk", "arguments": {},
         "thread_id": "main"},
        {"step": "tool.call", "tool": "get_login_history", "arguments": {},
         "thread_id": "aeea3c28-97f0-44bf-9c9b-9592da2afc0e"},
    ])

    lines = capsys.readouterr().out.strip().splitlines()

    assert "[" not in lines[0]
    assert "[aeea3c28]" in lines[1]


def test_the_report_verdict_comes_from_the_engines_tool_result():
    """Never parsed out of the agent's prose."""

    trace = [
        {"step": "model.message",
         "content": "THREAT LEVEL: LOW\nRISK SCORE: 3/100"},
        {"step": "tool.response", "tool": "assess_user_risk",
         "content": json.dumps({
             "found": True, "threat_level": "CRITICAL", "risk_score": 100,
             "risk_factors": [{"factor": "Privileged account", "points": 30}],
         })},
    ]

    verdict = _verdict_from_trace(trace)

    assert verdict["threat_level"] == "CRITICAL"
    assert verdict["risk_score"] == 100


def test_no_assessment_means_no_verdict_rather_than_a_guess():
    trace = [
        {"step": "model.message", "content": "THREAT LEVEL: CRITICAL"},
        {"step": "tool.response", "tool": "get_login_history",
         "content": '{"found": true}'},
    ]

    assert _verdict_from_trace(trace) is None


def test_an_unparsable_assessment_is_dropped_not_half_read():
    trace = [
        {"step": "tool.response", "tool": "assess_user_risk",
         "content": "not json at all"},
    ]

    assert _verdict_from_trace(trace) is None


def test_a_failed_assessment_is_not_treated_as_a_verdict():
    trace = [
        {"step": "tool.response", "tool": "assess_user_risk",
         "content": json.dumps({"found": False, "error": "unavailable"})},
    ]

    assert _verdict_from_trace(trace) is None


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
