"""Unit tests for the TrueForge integration.

These run entirely against a fake transport -- no TrueForge server, no MCP
server and no network. The integration tests that do need a live stack live
in ``trueforge/test_integration.py`` and are skipped by default.
"""

import json

import pytest

from investigator.prompts import SENTINEL_SYSTEM_PROMPT
from trueforge.agent import (
    SentinelAgent,
    SentinelAgentError,
    build_agent_spec,
    diagnose_turn_error,
    extract_trace,
    summarize_tool_calls,
)
from trueforge.client import (
    TrueForgeClient,
    TrueForgeHTTPError,
    TrueForgeProtocolError,
    TrueForgeTimeout,
    TrueForgeUnavailable,
)
from trueforge.config import TrueForgeConfig

import httpx2


# ------------------------------------------------------------------
# Fake transport
# ------------------------------------------------------------------

class FakeResponse:
    def __init__(self, status_code=200, payload=None, text=None):
        self.status_code = status_code
        self._payload = payload
        self.text = text if text is not None else json.dumps(payload)
        self.content = self.text.encode()

    def json(self):
        if self._payload is None:
            raise ValueError("not json")

        return self._payload


class FakeHTTP:
    """Records requests and replays queued or routed responses."""

    def __init__(self, routes=None, error=None):
        self.routes = routes or {}
        self.error = error
        self.requests = []

    def request(self, method, url, **kwargs):
        self.requests.append({"method": method, "url": url, **kwargs})

        if self.error is not None:
            raise self.error

        path = url.split("/api/v1", 1)[-1].split("?")[0]
        key = f"{method} {path}"

        handler = self.routes.get(key)

        if handler is None:
            raise AssertionError(f"unexpected request: {key}")

        if callable(handler):
            return handler(self.requests[-1])

        if isinstance(handler, list):
            return handler.pop(0)

        return handler

    def close(self):
        pass


def _config():
    return TrueForgeConfig(
        base_url="http://localhost:8790",
        model="groq/gpt-oss-120b",
        mcp_server_name="sentinel-security",
        mcp_url="http://127.0.0.1:8791/mcp",
        agent_name="sentinel-investigator",
        timeout=5.0,
    )


def _ok(payload):
    return FakeResponse(200, payload)


# ------------------------------------------------------------------
# Config
# ------------------------------------------------------------------

def test_config_api_path():
    assert _config().api == "http://localhost:8790/api/v1"


def test_config_from_env_overrides(monkeypatch):
    monkeypatch.setenv("TRUEFORGE_BASE_URL", "http://example:9999/")
    monkeypatch.setenv("TRUEFORGE_MODEL", "groq/other")
    monkeypatch.setenv("TRUEFORGE_TIMEOUT", "12.5")

    config = TrueForgeConfig.from_env()

    assert config.base_url == "http://example:9999"
    assert config.api == "http://example:9999/api/v1"
    assert config.model == "groq/other"
    assert config.timeout == 12.5


def test_config_rejects_non_numeric_timeout(monkeypatch):
    monkeypatch.setenv("TRUEFORGE_TIMEOUT", "soon")

    with pytest.raises(ValueError):
        TrueForgeConfig.from_env()


# ------------------------------------------------------------------
# Request construction
# ------------------------------------------------------------------

def test_register_mcp_server_builds_remote_manifest():
    http = FakeHTTP({
        "PUT /settings/mcp-servers": _ok({"data": {"name": "sentinel"}}),
    })

    client = TrueForgeClient(_config(), http=http)
    client.register_mcp_server("sentinel", "http://127.0.0.1:8791/mcp", "desc")

    sent = http.requests[0]

    assert sent["method"] == "PUT"
    assert sent["url"].endswith("/api/v1/settings/mcp-servers")
    # TrueForge v0.1.4 only supports remote MCP servers.
    assert sent["json"] == {
        "manifest": {
            "type": "remote",
            "name": "sentinel",
            "url": "http://127.0.0.1:8791/mcp",
            "description": "desc",
        }
    }


def test_register_mcp_server_attaches_header_auth():
    http = FakeHTTP({
        "PUT /settings/mcp-servers": _ok({"data": {"name": "sentinel"}}),
    })

    client = TrueForgeClient(_config(), http=http)
    client.register_mcp_server(
        "sentinel",
        "http://127.0.0.1:8791/mcp",
        "desc",
        headers={"Authorization": "Bearer secret-token"},
    )

    manifest = http.requests[0]["json"]["manifest"]

    assert manifest["auth"] == {
        "type": "header",
        "headers": {"Authorization": "Bearer secret-token"},
    }


def test_provisioning_registers_the_mcp_server_with_a_bearer_token():
    """The HTTP transport must never be registered anonymously."""

    http = FakeHTTP(_provision_routes([
        "get_login_history",
        "get_network_activity",
        "assess_user_risk",
    ]))

    config = _config()
    config.mcp_token = "unit-test-token"

    agent = SentinelAgent(config, client=TrueForgeClient(config, http))
    agent.ensure_mcp_server()

    register = next(
        req for req in http.requests
        if req["method"] == "PUT"
    )
    auth = register["json"]["manifest"]["auth"]

    assert auth["type"] == "header"
    assert auth["headers"]["Authorization"] == "Bearer unit-test-token"


def test_create_session_references_agent_by_name():
    http = FakeHTTP({
        "POST /sessions": _ok({"data": {"id": "sess-1"}}),
    })

    client = TrueForgeClient(_config(), http=http)
    session = client.create_session("sentinel-investigator")

    assert session["id"] == "sess-1"
    assert http.requests[0]["json"] == {
        "agent": {"name": "sentinel-investigator"}
    }


def test_create_turn_builds_user_message():
    http = FakeHTTP({
        "POST /sessions/sess-1/turns": _ok({"data": {"id": "turn-1"}}),
    })

    client = TrueForgeClient(_config(), http=http)
    client.create_turn("sess-1", "investigate admin", stream=False)

    assert http.requests[0]["json"] == {
        "input": [{"type": "user.message", "content": "investigate admin"}],
        "stream": False,
    }


def test_list_turn_events_follows_pagination():
    pages = [
        _ok({
            "data": [{"type": "turn.created"}],
            "pagination": {"limit": 100, "next_page_token": "t2"},
        }),
        _ok({
            "data": [{"type": "turn.done"}],
            "pagination": {"limit": 100},
        }),
    ]

    http = FakeHTTP({"GET /sessions/s/turns/t/events": pages})

    client = TrueForgeClient(_config(), http=http)
    events = client.list_turn_events("s", "t")

    assert [event["type"] for event in events] == [
        "turn.created",
        "turn.done",
    ]
    assert http.requests[1]["params"]["page_token"] == "t2"


# ------------------------------------------------------------------
# Agent configuration
# ------------------------------------------------------------------

def test_default_model_is_not_the_known_broken_one():
    """groq/gpt-oss-120b cannot complete a tool-using turn (see README)."""

    from trueforge.config import DEFAULT_MODEL

    assert DEFAULT_MODEL == "google-gemini/gemini-3-6-flash"
    assert DEFAULT_MODEL != "groq/gpt-oss-120b"


def test_agent_spec_follows_the_configured_model():
    """Switching provider/model must need no code change."""

    config = _config()
    config.model = "openai/gpt-5.5"

    assert build_agent_spec(config)["model"]["name"] == "openai/gpt-5.5"


def test_agent_spec_uses_configured_model_and_prompt():
    spec = build_agent_spec(_config())

    assert spec["model"]["name"] == "groq/gpt-oss-120b"
    assert spec["instructions"] == SENTINEL_SYSTEM_PROMPT


def test_agent_spec_attaches_sentinel_mcp_tools_only():
    spec = build_agent_spec(_config())

    server = spec["mcp_servers"][0]

    assert server["name"] == "sentinel-security"
    assert server["enable_tools"] == [
        "get_login_history",
        "get_network_activity",
        "assess_user_risk",
    ]
    # Read-only tools never need human approval.
    assert server["require_approval_for_tools"] == []


def test_agent_spec_does_not_leak_scoring_into_the_prompt():
    """Risk points must live in investigator/risk.py, not the prompt."""

    instructions = build_agent_spec(_config())["instructions"]

    assert "assess_user_risk" in instructions
    for banned in ["+30", "+25", "score += ", "30 points"]:
        assert banned not in instructions


def test_upsert_agent_creates_when_absent():
    http = FakeHTTP({
        "GET /agents": _ok({"data": []}),
        "POST /agents": _ok({"data": {"id": "a1", "name": "sentinel"}}),
    })

    client = TrueForgeClient(_config(), http=http)
    agent = client.upsert_agent("sentinel", {"model": {"name": "m"}})

    assert agent["id"] == "a1"
    assert http.requests[1]["json"]["name"] == "sentinel"


def test_upsert_agent_updates_when_present():
    http = FakeHTTP({
        "GET /agents": _ok({"data": [{"id": "a9", "name": "sentinel"}]}),
        "PUT /agents/a9": _ok({"data": {"id": "a9", "name": "sentinel"}}),
    })

    client = TrueForgeClient(_config(), http=http)
    client.upsert_agent("sentinel", {"model": {"name": "m"}})

    assert http.requests[1]["method"] == "PUT"
    assert "manifest" in http.requests[1]["json"]


# ------------------------------------------------------------------
# MCP provisioning
# ------------------------------------------------------------------

def _provision_routes(tools):
    return {
        "GET /capabilities": _ok({"data": {}}),
        "GET /models": _ok({"data": [{"name": "groq/gpt-oss-120b"}]}),
        "PUT /settings/mcp-servers": _ok({"data": {"name": "sentinel"}}),
        "GET /mcp-servers/sentinel-security/tools": _ok({
            "data": [{"name": name} for name in tools]
        }),
        "GET /agents": _ok({"data": []}),
        "POST /agents": _ok({"data": {"id": "a1"}}),
    }


def test_ensure_mcp_server_returns_discovered_tools():
    http = FakeHTTP(_provision_routes([
        "get_login_history",
        "get_network_activity",
        "assess_user_risk",
    ]))

    agent = SentinelAgent(_config(), client=TrueForgeClient(_config(), http))

    assert agent.ensure_mcp_server() == [
        "get_login_history",
        "get_network_activity",
        "assess_user_risk",
    ]


def test_ensure_mcp_server_reports_missing_tools():
    http = FakeHTTP(_provision_routes(["get_login_history"]))

    agent = SentinelAgent(_config(), client=TrueForgeClient(_config(), http))

    with pytest.raises(SentinelAgentError) as excinfo:
        agent.ensure_mcp_server()

    assert "assess_user_risk" in str(excinfo.value)


def test_ensure_mcp_server_explains_unreachable_mcp_server():
    routes = _provision_routes([])
    routes["GET /mcp-servers/sentinel-security/tools"] = FakeResponse(
        502, None, "upstream unreachable"
    )

    http = FakeHTTP(routes)
    agent = SentinelAgent(_config(), client=TrueForgeClient(_config(), http))

    with pytest.raises(SentinelAgentError) as excinfo:
        agent.ensure_mcp_server()

    assert "http_server.py" in str(excinfo.value)


def test_ensure_model_accepts_a_configured_model():
    routes = _provision_routes([])
    routes["GET /models"] = _ok({
        "data": [{"name": "groq/gpt-oss-120b"}, {"name": "other/model"}]
    })

    http = FakeHTTP(routes)
    agent = SentinelAgent(_config(), client=TrueForgeClient(_config(), http))

    assert agent.ensure_model() == "groq/gpt-oss-120b"


def test_ensure_model_rejects_an_unconfigured_model_with_alternatives():
    routes = _provision_routes([])
    routes["GET /models"] = _ok({"data": [{"name": "other/model"}]})

    http = FakeHTTP(routes)
    config = _config()
    config.model = "missing/model"

    agent = SentinelAgent(config, client=TrueForgeClient(config, http))

    with pytest.raises(SentinelAgentError) as excinfo:
        agent.ensure_model()

    message = str(excinfo.value)

    assert "missing/model" in message
    assert "other/model" in message


# ------------------------------------------------------------------
# Error handling
# ------------------------------------------------------------------

def test_trueforge_unavailable_is_actionable():
    http = FakeHTTP(error=httpx2.ConnectError("refused"))
    client = TrueForgeClient(_config(), http=http)

    with pytest.raises(TrueForgeUnavailable) as excinfo:
        client.ping()

    assert "Is it running?" in str(excinfo.value)


def test_timeout_is_reported_as_timeout():
    http = FakeHTTP(error=httpx2.TimeoutException("slow"))
    client = TrueForgeClient(_config(), http=http)

    with pytest.raises(TrueForgeTimeout):
        client.ping()


def test_http_error_carries_status_and_body():
    http = FakeHTTP({
        "GET /capabilities": FakeResponse(500, None, "boom"),
    })

    client = TrueForgeClient(_config(), http=http)

    with pytest.raises(TrueForgeHTTPError) as excinfo:
        client.ping()

    assert excinfo.value.status == 500
    assert "boom" in str(excinfo.value)


def test_malformed_json_is_a_protocol_error():
    http = FakeHTTP({
        "GET /capabilities": FakeResponse(200, None, "<html>nope</html>"),
    })

    client = TrueForgeClient(_config(), http=http)

    with pytest.raises(TrueForgeProtocolError):
        client.ping()


def test_missing_data_envelope_is_a_protocol_error():
    http = FakeHTTP({
        "GET /agents": _ok({"unexpected": []}),
    })

    client = TrueForgeClient(_config(), http=http)

    with pytest.raises(TrueForgeProtocolError):
        client.list_agents()


def test_turn_without_status_is_a_protocol_error():
    http = FakeHTTP({
        "GET /sessions/s/turns/t": _ok({"data": {"id": "t"}}),
    })

    client = TrueForgeClient(_config(), http=http)

    with pytest.raises(TrueForgeProtocolError):
        client.wait_for_turn("s", "t", timeout=1)


def test_wait_for_turn_times_out_while_running():
    http = FakeHTTP({
        "GET /sessions/s/turns/t": lambda req: _ok(
            {"data": {"id": "t", "state": {"status": "running"}}}
        ),
    })

    client = TrueForgeClient(_config(), http=http)

    with pytest.raises(TrueForgeTimeout):
        client.wait_for_turn("s", "t", timeout=0.01, poll_interval=0.001)


def test_diagnose_turn_error_explains_reasoning_replay():
    message = (
        "Request failed (400): 'messages.2' : for 'role:assistant' the "
        "following must be satisfied[('messages.2' : property "
        "'reasoning_content' is unsupported)]"
    )

    diagnosed = diagnose_turn_error(message)

    assert "TrueForge/provider incompatibility" in diagnosed
    assert "python -m investigator.run_investigation" in diagnosed


def test_diagnose_turn_error_passes_other_messages_through():
    assert diagnose_turn_error("iteration limit reached") == (
        "iteration limit reached"
    )


# ------------------------------------------------------------------
# Event parsing
# ------------------------------------------------------------------

TRACE_EVENTS = [
    {
        "type": "mcp.initialize",
        "created_at": "t0",
        "mcp_servers": [
            {"name": "sentinel-security", "transport_type": "streamable-http"}
        ],
    },
    {
        "type": "model.message",
        "created_at": "t1",
        "tool_calls": [
            {
                "id": "call-1",
                "function": {
                    "name": "get_login_history",
                    "arguments": '{"username": "admin"}',
                },
            }
        ],
    },
    {
        "type": "tool.response",
        "created_at": "t2",
        "tool_call_id": "call-1",
        "content": '{"found": true}',
    },
    {
        "type": "model.message",
        "created_at": "t3",
        "tool_calls": [
            {
                "id": "call-2",
                "function": {
                    "name": "get_network_activity",
                    "arguments": '{"ip_address": "185.123.45.67"}',
                },
            }
        ],
    },
    {
        "type": "tool.response",
        "created_at": "t4",
        "tool_call_id": "call-2",
        "content": '{"reputation": "suspicious"}',
    },
    {
        "type": "model.message",
        "created_at": "t5",
        "content": "THREAT LEVEL: CRITICAL",
    },
    {"type": "turn.done", "created_at": "t6", "state": {"status": "done"}},
]


def test_extract_trace_builds_the_investigation_journey():
    trace = extract_trace(TRACE_EVENTS)
    steps = [entry["step"] for entry in trace]

    assert steps == [
        "mcp.initialize",
        "tool.call",
        "tool.response",
        "tool.call",
        "tool.response",
        "model.message",
        "turn.done",
    ]


def test_extract_trace_parses_tool_arguments():
    trace = extract_trace(TRACE_EVENTS)
    call = trace[1]

    assert call["tool"] == "get_login_history"
    assert call["arguments"] == {"username": "admin"}


def test_extract_trace_pairs_responses_with_their_call():
    trace = extract_trace(TRACE_EVENTS)
    response = trace[4]

    assert response["tool_call_id"] == "call-2"
    assert response["tool"] == "get_network_activity"


def test_extract_trace_handles_session_event_envelope():
    wrapped = [{"turn_id": "t1", "event": event} for event in TRACE_EVENTS]

    assert extract_trace(wrapped) == extract_trace(TRACE_EVENTS)


def test_extract_trace_tolerates_unparsable_arguments():
    trace = extract_trace([
        {
            "type": "model.message",
            "tool_calls": [
                {"id": "c", "function": {"name": "t", "arguments": "{oops"}}
            ],
        }
    ])

    assert trace[0]["arguments"] == {"_raw": "{oops"}


def test_summarize_tool_calls_lists_tools_in_order():
    assert summarize_tool_calls(extract_trace(TRACE_EVENTS)) == [
        "get_login_history",
        "get_network_activity",
    ]


# ------------------------------------------------------------------
# Full investigation flow
# ------------------------------------------------------------------

def _investigation_routes(turn_state, events=None):
    routes = _provision_routes([
        "get_login_history",
        "get_network_activity",
        "assess_user_risk",
    ])

    routes.update({
        "POST /sessions": _ok({"data": {"id": "sess-1"}}),
        "POST /sessions/sess-1/turns": _ok({"data": {"id": "turn-1"}}),
        "GET /sessions/sess-1/turns/turn-1": _ok({
            "data": {"id": "turn-1", "state": turn_state}
        }),
        "GET /sessions/sess-1/turns/turn-1/events": _ok({
            "data": events if events is not None else TRACE_EVENTS,
            "pagination": {"limit": 100},
        }),
    })

    return routes


def test_successful_investigation_returns_response_and_trace():
    state = {
        "status": "done",
        "output": {"content": "THREAT LEVEL: CRITICAL"},
        "required_actions": [],
        "completed_at": "t6",
    }

    http = FakeHTTP(_investigation_routes(state))
    agent = SentinelAgent(_config(), client=TrueForgeClient(_config(), http))

    result = agent.investigate("admin")

    assert result["status"] == "done"
    assert result["response"] == "THREAT LEVEL: CRITICAL"
    assert result["tool_calls"] == [
        "get_login_history",
        "get_network_activity",
    ]
    assert result["session_id"] == "sess-1"
    assert not result.get("error")


def test_investigation_flattens_structured_output_content():
    state = {
        "status": "done",
        "output": {"content": [{"type": "text", "text": "CRITICAL"}]},
        "required_actions": [],
        "completed_at": "t6",
    }

    http = FakeHTTP(_investigation_routes(state))
    agent = SentinelAgent(_config(), client=TrueForgeClient(_config(), http))

    assert agent.investigate("admin")["response"] == "CRITICAL"


def test_failed_turn_surfaces_the_error_and_keeps_the_trace():
    state = {
        "status": "error",
        "message": "provider exploded",
        "completed_at": "t6",
    }

    http = FakeHTTP(_investigation_routes(state))
    agent = SentinelAgent(_config(), client=TrueForgeClient(_config(), http))

    result = agent.investigate("admin")

    assert result["status"] == "error"
    assert "provider exploded" in result["error"]
    # The partial journey is still available for the UI.
    assert result["tool_calls"] == [
        "get_login_history",
        "get_network_activity",
    ]


def test_paused_turn_reports_required_actions():
    state = {
        "status": "done",
        "output": None,
        "required_actions": [{"type": "tool.approval_required"}],
        "completed_at": "t6",
    }

    http = FakeHTTP(_investigation_routes(state))
    agent = SentinelAgent(_config(), client=TrueForgeClient(_config(), http))

    result = agent.investigate("admin")

    assert "tool.approval_required" in result["error"]


def test_investigation_reports_unreachable_trueforge():
    http = FakeHTTP(error=httpx2.ConnectError("refused"))
    agent = SentinelAgent(_config(), client=TrueForgeClient(_config(), http))

    with pytest.raises(TrueForgeUnavailable):
        agent.investigate("admin")
