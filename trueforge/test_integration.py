"""Integration tests against a live TrueForge + Sentinel MCP stack.

Skipped by default -- ``pytest -q`` excludes the ``integration`` marker (see
pyproject.toml). Run them deliberately:

    python mcp/sentinel_mcp/http_server.py &
    pytest -m integration -q

Skip policy
-----------
A test skips only when a *prerequisite is genuinely absent* -- TrueForge is
not running, the Sentinel MCP server is not running, or the configured model
is not registered. Those are checked once, up front, by the ``stack``
fixture.

Once the prerequisites are present, nothing skips. A failure to register the
MCP server, provision the agent, execute a turn or orchestrate the tools is a
real regression and fails the suite. The single concession is a bounded retry
for transient upstream provider errors (HTTP 503 / rate limiting), which
retries and then *fails* -- it never skips.
"""

import time

import httpx2
import pytest

from trueforge.agent import SentinelAgent, deny_all
from trueforge.client import TrueForgeClient, TrueForgeError
from trueforge.config import TrueForgeConfig

pytestmark = pytest.mark.integration

# Substrings identifying a temporary provider-side outage rather than a
# defect in Sentinel or in the TrueForge wiring.
TRANSIENT_MARKERS = (
    "high demand",
    "currently overloaded",
    "(503)",
    "(429)",
    "rate limit",
    "temporarily unavailable",
)

MAX_TURN_ATTEMPTS = 3


def _is_transient(message: str) -> bool:
    lowered = (message or "").lower()

    return any(marker in lowered for marker in TRANSIENT_MARKERS)


@pytest.fixture(scope="module")
def config():
    return TrueForgeConfig.from_env()


@pytest.fixture(scope="module")
def stack(config):
    """Verify every prerequisite, skipping only if one is truly missing."""

    # 1. TrueForge itself.
    client = TrueForgeClient(config)

    try:
        client.ping()

    except TrueForgeError as exc:
        client.close()
        pytest.skip(f"TrueForge is not running at {config.base_url}: {exc}")

    # 2. The Sentinel MCP HTTP server. Any HTTP status proves it is
    #    listening -- 401 included, since that is the auth layer answering.
    try:
        httpx2.post(config.mcp_url, timeout=5.0, content=b"{}")

    except httpx2.ConnectError:
        client.close()
        pytest.skip(
            f"Sentinel MCP server is not running at {config.mcp_url}. "
            "Start it: python mcp/sentinel_mcp/http_server.py"
        )

    except httpx2.HTTPError:
        # Reached it; the protocol complaint is irrelevant here.
        pass

    # 3. The configured model.
    available = [model["name"] for model in client.list_models()]

    if config.model not in available:
        client.close()
        pytest.skip(
            f"Model {config.model} is not configured in TrueForge "
            f"(available: {available})"
        )

    yield client

    client.close()


# ------------------------------------------------------------------
# Wiring -- these must fail, not skip, once the stack is up
# ------------------------------------------------------------------

def test_trueforge_is_reachable(stack):
    assert stack.ping() is True


def test_configured_model_is_available(stack, config):
    names = [model["name"] for model in stack.list_models()]

    assert config.model in names


def test_mcp_server_registers_and_exposes_sentinel_tools(stack, config):
    """TrueForge must actually connect to the Sentinel MCP server."""

    with SentinelAgent(config, client=stack) as agent:
        tools = agent.ensure_mcp_server()

    for expected in config.tools:
        assert expected in tools


def test_mcp_registration_carries_bearer_auth(stack, config):
    """The MCP server must be registered with header auth, not anonymously."""

    with SentinelAgent(config, client=stack) as agent:
        agent.ensure_mcp_server()

    registered = {
        server["name"]: server
        for server in stack.list_mcp_servers()
    }[config.mcp_server_name]

    auth = registered["manifest"].get("auth")

    assert auth is not None, "MCP server registered without authentication"
    assert auth["type"] == "header"
    assert "Authorization" in auth["headers"]
    assert registered["auth_status"]["status"] == "authenticated"


def test_mcp_server_rejects_unauthenticated_requests(stack, config):
    """The HTTP transport must not serve security data anonymously."""

    response = httpx2.post(
        config.mcp_url,
        timeout=5.0,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        },
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "pytest", "version": "1"},
            },
        },
    )

    assert response.status_code == 401


def test_agent_can_be_provisioned(stack, config):
    with SentinelAgent(config, client=stack) as agent:
        provisioned = agent.provision()

    assert provisioned["agent"]["name"] == config.agent_name
    assert provisioned["agent"]["manifest"]["model"]["name"] == config.model
    assert provisioned["model"] == config.model


def test_unknown_model_is_rejected_with_alternatives(stack, config):
    from trueforge.agent import SentinelAgentError

    broken = TrueForgeConfig.from_env()
    broken.model = "nonexistent/model-that-is-not-configured"

    with SentinelAgent(broken, client=stack) as agent:
        with pytest.raises(SentinelAgentError) as excinfo:
            agent.ensure_model()

    assert "not configured" in str(excinfo.value)
    assert config.model in str(excinfo.value)


# ------------------------------------------------------------------
# End-to-end
# ------------------------------------------------------------------

DENIAL_REASON = "Integration test: denied so nothing is executed."


def _deny_everything(pending):
    """Refuse every containment request, and record that one was made.

    Denial rather than approval is the right default for a test that runs
    against the real stack: it exercises the whole gate -- pause, decision,
    resume -- while executing nothing and leaving no state behind, so the
    suite is repeatable and never writes to the containment audit log.
    """

    _deny_everything.seen.extend(pending)

    return deny_all(pending, DENIAL_REASON)


_deny_everything.seen = []


def _investigate_with_retry(config, username, on_approval=_deny_everything):
    """Run the investigation, retrying only transient provider outages.

    A decision callback is supplied by default. Without one, an
    investigation of a CRITICAL account pauses at the containment gate and
    reports that it is waiting -- which is correct behaviour and used to
    read here as a failed turn. The end-to-end tests want the whole journey
    including the decision, so they answer the gate.
    """

    last_error = None

    for attempt in range(MAX_TURN_ATTEMPTS):
        _deny_everything.seen = []

        with SentinelAgent(config) as agent:
            result = agent.investigate(username, on_approval=on_approval)

        if not result.get("error"):
            return result

        last_error = result["error"]

        if not _is_transient(last_error):
            # A real failure. Fail now rather than retrying into a green run.
            pytest.fail(f"Investigation turn failed: {last_error}")

        time.sleep(2 * (attempt + 1))

    pytest.fail(
        f"Investigation still failing after {MAX_TURN_ATTEMPTS} attempts "
        f"against transient provider errors: {last_error}"
    )


def test_end_to_end_investigation_of_seeded_admin(stack, config):
    """A full agent-run investigation of the seeded ``admin`` scenario.

    Asserts the whole architecture: TrueForge orchestrates, the MCP tools
    supply evidence, and the deterministic engine -- not the model -- decides
    the verdict.
    """

    result = _investigate_with_retry(config, "admin")

    assert result["status"] == "done"

    # TrueForge really called the Sentinel MCP tools.
    assert "get_login_history" in result["tool_calls"]
    assert "assess_user_risk" in result["tool_calls"]

    # The trace is built from recorded events, including the MCP handshake.
    steps = [entry["step"] for entry in result["trace"]]
    assert "mcp.initialize" in steps
    assert steps.count("tool.call") == len(result["tool_calls"])

    # The deterministic verdict reached the agent's answer verbatim.
    response = result["response"]
    assert "CRITICAL" in response
    assert "100" in response

    # Nothing is left paused: the gate was answered and the turn finished.
    assert result["pending_approvals"] == []


def test_the_containment_gate_really_fires_against_a_live_harness(
    stack, config
):
    """The safety property, asserted end to end rather than in a fake.

    A CRITICAL account is exactly the case where the agent should propose
    containment -- and TrueForge should stop it. This asserts the pause
    happened, that it was for a destructive tool, and that denying it
    executed nothing.
    """

    from investigator import containment

    before = containment.list_actions()

    result = _investigate_with_retry(config, "admin")

    requested = _deny_everything.seen

    assert requested, (
        "The agent never proposed containment against a CRITICAL account, "
        "so the approval gate was not exercised."
    )

    for item in requested:
        assert item["tool"] in {"contain_account", "block_ip"}
        # The operator has to be able to see what they are deciding on.
        assert item["arguments"].get("justification"), (
            f"{item['tool']} was proposed with no justification"
        )
        assert item["thread_id"]
        assert item["tool_call_id"]

    # Every decision was recorded as a denial, and reached the agent.
    assert result["approvals"], "no decision was recorded"
    assert all(not a["allowed"] for a in result["approvals"])
    assert all(a["reason"] == DENIAL_REASON for a in result["approvals"])

    # The point of a denial: the environment is unchanged.
    assert containment.list_actions() == before


def test_end_to_end_matches_the_deterministic_engine(stack, config):
    """The agent must not invent a score that differs from the engine."""

    import json
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "mcp" / "sentinel_mcp"))
    import server as sentinel_server

    truth = sentinel_server._assess_user_risk_sync("admin")

    result = _investigate_with_retry(config, "admin")

    assert truth["threat_level"] == "CRITICAL"
    assert truth["risk_score"] == 100

    # Whatever the model wrote, the authoritative numbers came from the
    # deterministic engine via the MCP tool.
    tool_payloads = [
        entry["content"]
        for entry in result["trace"]
        if entry.get("step") == "tool.response"
        and entry.get("tool") == "assess_user_risk"
    ]

    assert tool_payloads, "assess_user_risk returned no evidence"

    payload = json.loads(tool_payloads[0])

    assert payload["threat_level"] == truth["threat_level"]
    assert payload["risk_score"] == truth["risk_score"]
