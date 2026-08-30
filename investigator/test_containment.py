"""Tests for Sentinel's only write path.

Two things are under test: that containment actions are recorded and
readable, and -- more importantly -- that adding a write path did not make
the evidence store writable.

These use pytest fixtures (``tmp_path``) for store isolation, so unlike the
other investigator suites they run under pytest only::

    pytest investigator/test_containment.py -q
"""

import sqlite3
import sys
from pathlib import Path

import pytest

from investigator import containment
from investigator.containment import (
    ACTION_BLOCK_IP,
    ACTION_CONTAIN_ACCOUNT,
    account_status,
    ip_status,
    list_actions,
    record_action,
)

sys.path.insert(
    0,
    str(Path(__file__).resolve().parent.parent / "mcp" / "sentinel_mcp"),
)


@pytest.fixture
def store(tmp_path):
    return tmp_path / "containment.db"


# ------------------------------------------------------------------
# Recording
# ------------------------------------------------------------------

def test_recording_an_action_returns_an_audit_record(store):
    result = record_action(
        ACTION_CONTAIN_ACCOUNT,
        "admin",
        "47 failed logins then a success from a suspicious IP",
        threat_level="CRITICAL",
        risk_score=100,
        db_path=store,
    )

    assert result["ok"] is True
    assert result["action"] == ACTION_CONTAIN_ACCOUNT
    assert result["target"] == "admin"
    assert result["threat_level"] == "CRITICAL"
    assert result["risk_score"] == 100
    assert result["status"] == "active"
    assert result["timestamp"]


def test_the_store_is_created_on_first_use(store):
    assert not store.exists()

    record_action(ACTION_BLOCK_IP, "203.0.113.9", "brute force source",
                  db_path=store)

    assert store.exists()


def test_actions_are_append_only(store):
    for i in range(3):
        record_action(ACTION_BLOCK_IP, f"203.0.113.{i}", "reason",
                      db_path=store)

    assert len(list_actions(db_path=store)) == 3


def test_justification_is_required(store):
    result = record_action(ACTION_CONTAIN_ACCOUNT, "admin", "   ",
                           db_path=store)

    assert result["ok"] is False
    assert "justification" in result["error"].lower()
    assert list_actions(db_path=store) == []


def test_target_is_required(store):
    result = record_action(ACTION_CONTAIN_ACCOUNT, "", "reason",
                           db_path=store)

    assert result["ok"] is False
    assert list_actions(db_path=store) == []


def test_unknown_actions_are_refused(store):
    result = record_action("delete_everything", "admin", "reason",
                           db_path=store)

    assert result["ok"] is False
    assert "unknown containment action" in result["error"].lower()
    assert list_actions(db_path=store) == []


# ------------------------------------------------------------------
# Reading state back -- the write must be observable
# ------------------------------------------------------------------

def test_account_status_is_clear_before_any_action(store):
    status = account_status("admin", db_path=store)

    assert status["contained"] is False
    assert status["containment_actions"] == []


def test_account_status_reflects_containment(store):
    record_action(ACTION_CONTAIN_ACCOUNT, "admin", "brute force",
                  threat_level="CRITICAL", risk_score=100, db_path=store)

    status = account_status("admin", db_path=store)

    assert status["contained"] is True
    assert status["containment_actions"][0]["justification"] == "brute force"
    assert status["containment_actions"][0]["threat_level"] == "CRITICAL"


def test_containment_is_scoped_to_its_target(store):
    record_action(ACTION_CONTAIN_ACCOUNT, "admin", "brute force",
                  db_path=store)

    assert account_status("bob", db_path=store)["contained"] is False


def test_blocking_an_ip_does_not_contain_an_account(store):
    """The two action types must not bleed into each other."""

    record_action(ACTION_BLOCK_IP, "admin", "reason", db_path=store)

    assert account_status("admin", db_path=store)["contained"] is False
    assert ip_status("admin", db_path=store)["blocked"] is True


def test_ip_status_reflects_a_block(store):
    record_action(ACTION_BLOCK_IP, "185.10.10.10", "suspicious reputation",
                  db_path=store)

    status = ip_status("185.10.10.10", db_path=store)

    assert status["blocked"] is True
    assert status["containment_actions"][0]["action"] == ACTION_BLOCK_IP


def test_status_reads_do_not_create_the_store(tmp_path):
    missing = tmp_path / "nope.db"

    assert account_status("admin", db_path=missing)["contained"] is False
    assert not missing.exists()


# ------------------------------------------------------------------
# The security boundary -- this is the point of the whole design
# ------------------------------------------------------------------

def test_containment_store_is_not_the_evidence_store():
    import server as sentinel_server

    assert containment.DB_PATH != sentinel_server.DB_PATH
    assert containment.DB_PATH.name != sentinel_server.DB_PATH.name


def test_evidence_database_is_still_opened_read_only(tmp_path):
    """Adding a write path must not have loosened the evidence store."""

    import server as sentinel_server

    evidence = tmp_path / "security.db"

    with sqlite3.connect(evidence) as setup:
        setup.execute("CREATE TABLE users (id INTEGER PRIMARY KEY)")

    connection = sentinel_server._connect_read_only(evidence)

    try:
        with pytest.raises(sqlite3.OperationalError):
            connection.execute("INSERT INTO users (id) VALUES (1)")

    finally:
        connection.close()


def test_containment_never_writes_to_the_evidence_database(tmp_path):
    """A containment write must land in the containment store, nowhere else."""

    evidence = tmp_path / "security.db"
    store = tmp_path / "containment.db"

    with sqlite3.connect(evidence) as setup:
        setup.execute("CREATE TABLE users (id INTEGER PRIMARY KEY)")

    before = evidence.read_bytes()

    record_action(ACTION_CONTAIN_ACCOUNT, "admin", "reason", db_path=store)

    assert evidence.read_bytes() == before
    assert store.exists()


def test_containment_tools_are_annotated_destructive():
    """The annotations are what make a host gate these tools."""

    import asyncio

    import server as sentinel_server

    tools = {
        tool.name: tool
        for tool in asyncio.run(sentinel_server.server.list_tools())
    }

    for name in ["contain_account", "block_ip"]:
        annotations = tools[name].annotations
        assert annotations.read_only_hint is False, name
        assert annotations.destructive_hint is True, name


def test_evidence_tools_remain_annotated_read_only():
    import asyncio

    import server as sentinel_server

    tools = {
        tool.name: tool
        for tool in asyncio.run(sentinel_server.server.list_tools())
    }

    for name in [
        "get_login_history",
        "get_network_activity",
        "assess_user_risk",
        "get_account_status",
    ]:
        annotations = tools[name].annotations
        assert annotations.read_only_hint is True, name
        assert annotations.destructive_hint is False, name


def test_status_lookup_matches_a_padded_target(tmp_path):
    """Qodo #4: the write path strips the target, so the read path must too.

    Without this, containing " admin " stores "admin" and then reports the
    account as uncontained -- which would let it be contained twice.
    """

    db = tmp_path / "containment.db"

    containment.record_action(
        containment.ACTION_CONTAIN_ACCOUNT,
        "  admin  ",
        "Confirmed compromise.",
        db_path=db,
    )

    assert containment.account_status("  admin  ", db_path=db)["contained"]
    assert containment.account_status("admin", db_path=db)["contained"]


def test_ip_status_lookup_matches_a_padded_target(tmp_path):
    db = tmp_path / "containment.db"

    containment.record_action(
        containment.ACTION_BLOCK_IP,
        " 185.123.45.67 ",
        "Suspicious reputation.",
        db_path=db,
    )

    assert containment.ip_status(" 185.123.45.67 ", db_path=db)["blocked"]
    assert containment.ip_status("185.123.45.67", db_path=db)["blocked"]


# ------------------------------------------------------------------
# Verification -- reading the outcome back
#
# A containment call returning without raising is an *attempt*. These
# tests hold the line that the read-back, not the call, is what makes an
# action confirmable -- and that a failed attempt can never read back as a
# success.
# ------------------------------------------------------------------

def test_a_rejected_action_leaves_nothing_to_verify(store):
    """A refused write must not read back as containment in force."""

    result = record_action(
        ACTION_BLOCK_IP,
        "185.123.45.67",
        "",                      # no justification -- rejected
        db_path=store,
    )

    assert result["ok"] is False
    assert ip_status("185.123.45.67", db_path=store)["blocked"] is False
    assert list_actions(db_path=store) == []


def test_an_unknown_action_is_rejected_and_records_nothing(store):
    result = record_action("delete_everything", "admin", "why", db_path=store)

    assert result["ok"] is False
    assert account_status("admin", db_path=store)["contained"] is False
    assert list_actions(db_path=store) == []


def test_verification_reads_a_different_target_as_uncontained(store):
    """Containing one target must never verify a different one."""

    record_action(
        ACTION_BLOCK_IP, "185.123.45.67", "Suspicious.", db_path=store
    )

    assert ip_status("185.123.45.67", db_path=store)["blocked"] is True
    assert ip_status("10.10.1.20", db_path=store)["blocked"] is False


def test_verification_of_an_absent_store_is_negative_not_an_error(tmp_path):
    """No containment store means nothing is contained -- not a crash.

    The read-back runs on a fresh machine too, and a missing file has to
    answer 'no' rather than raise: an exception here would surface to the
    agent as an unavailable tool, which is not the same claim as 'this
    action is not in force'.
    """

    absent = tmp_path / "never-created.db"

    assert account_status("admin", db_path=absent)["contained"] is False
    assert ip_status("185.123.45.67", db_path=absent)["blocked"] is False
    assert not absent.exists()


def test_the_status_tools_are_annotated_read_only():
    """Verification must not itself require an approval gate."""

    import server as sentinel_server

    for tool in ("get_account_status", "get_ip_status"):
        assert hasattr(sentinel_server, tool), f"{tool} is not exposed"

    annotations = sentinel_server.READ_ONLY

    assert annotations.read_only_hint is True
    assert annotations.destructive_hint is False


def test_get_ip_status_reports_the_containment_store(monkeypatch, store):
    """The MCP verification tool reads the audit log, not a guess."""

    import asyncio

    import server as sentinel_server

    monkeypatch.setattr(containment, "DB_PATH", store)

    before = asyncio.run(sentinel_server.get_ip_status("185.123.45.67"))
    assert before["blocked"] is False

    record_action(
        ACTION_BLOCK_IP, "185.123.45.67", "Suspicious.", db_path=store
    )

    after = asyncio.run(sentinel_server.get_ip_status("185.123.45.67"))
    assert after["blocked"] is True
    assert after["containment_actions"][0]["justification"] == "Suspicious."
