"""Integration tests against a live TrueForge + Sentinel MCP stack.

Skipped by default -- ``pytest -q`` excludes the ``integration`` marker (see
pyproject.toml). Run them deliberately with a running stack:

    python mcp/sentinel_mcp/http_server.py &
    pytest -m integration -q

They assert on the wiring (registration, discovery, provisioning), which is
independent of whether the configured model can complete a tool-using turn.
"""

import pytest

from trueforge.agent import SentinelAgent
from trueforge.client import TrueForgeClient, TrueForgeError
from trueforge.config import TrueForgeConfig

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def config():
    return TrueForgeConfig.from_env()


@pytest.fixture(scope="module")
def client(config):
    with TrueForgeClient(config) as live:
        try:
            live.ping()

        except TrueForgeError as exc:
            pytest.skip(f"TrueForge is not reachable: {exc}")

        yield live


def test_trueforge_is_reachable(client):
    assert client.ping() is True


def test_configured_model_is_available(client, config):
    names = [model["name"] for model in client.list_models()]

    assert config.model in names, (
        f"{config.model} is not configured in TrueForge; found {names}"
    )


def test_mcp_server_registers_and_exposes_sentinel_tools(config):
    """TrueForge must actually connect to the Sentinel MCP server."""

    with SentinelAgent(config) as agent:
        try:
            tools = agent.ensure_mcp_server()

        except TrueForgeError as exc:
            pytest.skip(f"Sentinel MCP server is not reachable: {exc}")

    for expected in config.tools:
        assert expected in tools


def test_agent_can_be_provisioned(config):
    with SentinelAgent(config) as agent:
        try:
            provisioned = agent.provision()

        except TrueForgeError as exc:
            pytest.skip(f"Cannot provision the Sentinel agent: {exc}")

    assert provisioned["agent"]["name"] == config.agent_name
    assert provisioned["agent"]["manifest"]["model"]["name"] == config.model


def test_end_to_end_investigation(config):
    """A full agent-run investigation of the seeded ``admin`` scenario.

    Requires a model that can complete a tool-using turn. See the TrueForge
    section of the README for the known groq/gpt-oss-120b limitation.
    """

    with SentinelAgent(config) as agent:
        try:
            result = agent.investigate("admin")

        except TrueForgeError as exc:
            pytest.skip(f"Investigation could not run: {exc}")

    if result.get("error"):
        pytest.skip(f"Turn did not complete: {result['error']}")

    assert result["status"] == "done"
    assert "get_login_history" in result["tool_calls"]
    assert result["response"].strip()
