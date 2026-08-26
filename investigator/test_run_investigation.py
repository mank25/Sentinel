"""Orchestration tests for the investigation runner.

These drive :func:`run_pipeline` against a fake MCP session so the whole
pipeline is exercised without a live server.
"""

import asyncio
import json
import subprocess
import sys
from pathlib import Path

from investigator.run_investigation import run_pipeline

PROJECT_ROOT = Path(__file__).resolve().parent.parent

USER = {
    "username": "admin",
    "role": "administrator",
    "normal_device": "MacBook",
    "normal_location": "Delhi",
}


class _Content:
    def __init__(self, payload):
        self.text = json.dumps(payload)


class _ToolResult:
    def __init__(self, payload):
        self.content = [_Content(payload)]


class FakeSession:
    """Records every tool call and replays canned responses."""

    def __init__(self, login_payload, network_payloads=None):
        self.login_payload = login_payload
        self.network_payloads = network_payloads or {}
        self.network_calls = []

    async def call_tool(self, name, arguments):
        if name == "get_login_history":
            return _ToolResult(self.login_payload)

        if name == "get_network_activity":
            ip = arguments["ip_address"]
            self.network_calls.append(ip)

            payload = self.network_payloads.get(ip)

            if isinstance(payload, Exception):
                raise payload

            if payload is None:
                payload = {"found": False, "ip_address": ip}

            return _ToolResult(payload)

        raise AssertionError(f"unexpected tool call: {name}")


def _failures(ip, count, start=0):
    return [
        {
            "timestamp": f"2026-08-25T01:{start + i:02d}:00",
            "source_ip": ip,
            "device": "Unknown",
            "location": "Unknown",
            "success": 0,
            "mfa_status": "failed",
        }
        for i in range(count)
    ]


def _login_payload(events):
    return {
        "found": True,
        "user": dict(USER),
        "login_events": events,
    }


def _run(session, username="admin"):
    return asyncio.run(run_pipeline(session, username, verbose=False))


# ------------------------------------------------------------------
# Issue 1 -- every suspicious IP is investigated
# ------------------------------------------------------------------

def test_zero_suspicious_ips_skips_network_lookups():
    session = FakeSession(_login_payload([
        {
            "timestamp": "2026-08-24T09:00:00",
            "source_ip": "10.10.1.20",
            "device": "MacBook",
            "location": "Delhi",
            "success": 1,
            "mfa_status": "passed",
        },
    ]))

    result = _run(session)

    assert session.network_calls == []
    assert result["suspicious_ips"] == []
    assert result["network_matches"] == []
    assert result["incomplete_network_evidence"] is False
    assert result["risk"]["threat_level"] in {"LOW", "MEDIUM"}


def test_single_suspicious_ip_is_looked_up():
    session = FakeSession(
        _login_payload(_failures("185.123.45.67", 3)),
        {
            "185.123.45.67": {
                "found": True,
                "ip_address": "185.123.45.67",
                "reputation": "suspicious",
                "known": False,
            }
        },
    )

    result = _run(session)

    assert session.network_calls == ["185.123.45.67"]
    assert len(result["network_matches"]) == 1


def test_all_suspicious_ips_are_looked_up():
    events = (
        _failures("185.123.45.67", 3, start=0)
        + _failures("203.0.113.9", 3, start=10)
        + _failures("198.51.100.4", 3, start=20)
    )

    session = FakeSession(
        _login_payload(events),
        {
            "185.123.45.67": {
                "found": True,
                "ip_address": "185.123.45.67",
                "reputation": "suspicious",
                "known": False,
            },
            "203.0.113.9": {
                "found": True,
                "ip_address": "203.0.113.9",
                "reputation": "suspicious",
                "known": False,
            },
            "198.51.100.4": {"found": False, "ip_address": "198.51.100.4"},
        },
    )

    result = _run(session)

    assert sorted(session.network_calls) == sorted(result["suspicious_ips"])
    assert len(session.network_calls) == 3
    # Nothing is dropped: two matches, one no-record, three lookups.
    assert len(result["network_lookups"]) == 3
    assert len(result["network_matches"]) == 2
    assert result["network_not_found"] == ["198.51.100.4"]
    assert result["incomplete_network_evidence"] is False


def test_one_failing_lookup_does_not_destroy_the_investigation():
    events = (
        _failures("185.123.45.67", 3, start=0)
        + _failures("203.0.113.9", 3, start=10)
    )

    session = FakeSession(
        _login_payload(events),
        {
            "185.123.45.67": {
                "found": True,
                "ip_address": "185.123.45.67",
                "reputation": "suspicious",
                "known": False,
            },
            "203.0.113.9": RuntimeError("stdio transport closed"),
        },
    )

    result = _run(session)

    # Both IPs were still attempted.
    assert len(session.network_calls) == 2
    assert len(result["network_matches"]) == 1
    assert len(result["network_errors"]) == 1
    assert result["network_errors"][0]["ip_address"] == "203.0.113.9"
    assert result["incomplete_network_evidence"] is True
    assert result["risk"]["incomplete_evidence"] is True
    assert result["found"] is True


def test_tool_reported_network_error_is_preserved():
    session = FakeSession(
        _login_payload(_failures("203.0.113.9", 3)),
        {
            "203.0.113.9": {
                "found": False,
                "ip_address": "203.0.113.9",
                "error": "Unable to read network security data.",
            }
        },
    )

    result = _run(session)

    assert result["network_matches"] == []
    assert result["network_errors"] == [{
        "ip_address": "203.0.113.9",
        "error": "Unable to read network security data.",
    }]
    assert result["risk"]["incomplete_evidence"] is True


def test_missing_user_short_circuits():
    session = FakeSession({
        "found": False,
        "error": "User 'nobody' was not found.",
    })

    result = _run(session, username="nobody")

    assert result["found"] is False
    assert session.network_calls == []


# ------------------------------------------------------------------
# Issue 4 -- both invocation styles work
# ------------------------------------------------------------------

def _run_cli(args):
    return subprocess.run(
        [sys.executable, *args],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )


def test_module_execution_works():
    completed = _run_cli(["-m", "investigator.run_investigation"])

    assert completed.returncode == 0, completed.stderr
    assert "SENTINEL REPORT" in completed.stdout


def test_direct_script_execution_works():
    completed = _run_cli(["investigator/run_investigation.py"])

    assert completed.returncode == 0, completed.stderr
    assert "SENTINEL REPORT" in completed.stdout


if __name__ == "__main__":
    from investigator.testkit import main

    main(dict(globals()))
