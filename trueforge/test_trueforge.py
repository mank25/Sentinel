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
    allow_all,
    build_agent_spec,
    deny_all,
    diagnose_turn_error,
    extract_trace,
    pending_approvals,
    summarize_tool_calls,
)
from trueforge.client import (
    TrueForgeClient,
    approval_item,
    TrueForgeHTTPError,
    TrueForgeProtocolError,
    TrueForgeTimeout,
    TrueForgeUnavailable,
)
from trueforge.config import SENTINEL_TOOLS, TrueForgeConfig

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


# Derived from the config rather than restated, so adding a tool to the
# agent cannot leave the fake MCP server behind: it would otherwise report
# the new tool as missing in every test that provisions.
ALL_TOOLS = list(SENTINEL_TOOLS)


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

    http = FakeHTTP(_provision_routes(ALL_TOOLS))

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
    assert server["enable_tools"] == ALL_TOOLS


def test_agent_spec_does_not_leak_scoring_into_the_prompt():
    """Risk points must live in investigator/risk.py, not the prompt.

    investigator/test_prompts.py covers the prompt's content in depth; this
    guards the wiring, i.e. that the spec ships that prompt.
    """

    instructions = build_agent_spec(_config())["instructions"]

    assert "assess_user_risk" in instructions
    for banned in ["+30", "+25", "score += ", "30 points"]:
        assert banned not in instructions


def test_agent_spec_keeps_the_execution_trace_linear():
    """Sub-agents would move tool calls into a thread the trace hides.

    TrueForge's visible tool execution is the demonstrable part of a run, so
    the spec must not enable anything that relocates it.
    """

    config = build_agent_spec(_config())["config"]

    assert config["dynamic_sub_agents"]["enabled"] is False
    assert config["generative_ui"]["enabled"] is False
    # Non-interactive runs must never block waiting on a human.
    assert config["ask_user_questions"]["enabled"] is False


def test_agent_spec_caps_the_agent_loop():
    """iteration_limit is both a runaway guard and a cost ceiling."""

    config = build_agent_spec(_config())["config"]

    assert 1 <= config["iteration_limit"] <= 32


def test_agent_spec_preloads_the_tool_schemas():
    """Deferred discovery spends a model call on list_tools before any work."""

    server = build_agent_spec(_config())["mcp_servers"][0]

    assert server["preload"] is True


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
    http = FakeHTTP(_provision_routes(ALL_TOOLS))

    agent = SentinelAgent(_config(), client=TrueForgeClient(_config(), http))

    assert agent.ensure_mcp_server() == ALL_TOOLS


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
    routes = _provision_routes(ALL_TOOLS)

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


# ------------------------------------------------------------------
# Containment approval gate
# ------------------------------------------------------------------

CONTAINMENT_EVENTS = [
    {
        "type": "model.message",
        "created_at": "t1",
        "tool_calls": [
            {
                "id": "call-c1",
                "function": {
                    "name": "contain_account",
                    "arguments": '{"username": "admin", '
                                 '"justification": "brute force"}',
                },
            }
        ],
    },
    {
        "type": "tool.approval_required",
        "created_at": "t2",
        "thread_id": "main",
        "tool_calls": [{"id": "call-c1", "source_event_id": "e1"}],
    },
]

PAUSED_STATE = {
    "status": "done",
    "output": None,
    "required_actions": [
        {
            "type": "tool.approval_required",
            "thread_id": "main",
            "tool_calls": [{"id": "call-c1", "source_event_id": "e1"}],
        }
    ],
    "completed_at": "t3",
}


def test_paused_turn_reports_what_approval_is_needed():
    """Without a decision callback the run stops -- never auto-approves."""

    http = FakeHTTP(_investigation_routes(PAUSED_STATE, CONTAINMENT_EVENTS))
    agent = SentinelAgent(_config(), client=TrueForgeClient(_config(), http))

    result = agent.investigate("admin")

    pending = result["pending_approvals"]

    assert len(pending) == 1
    assert pending[0]["tool"] == "contain_account"
    assert pending[0]["arguments"]["username"] == "admin"
    assert pending[0]["arguments"]["justification"] == "brute force"
    assert "contain_account" in result["error"]
    # Nothing was decided, so nothing was recorded as approved.
    assert result["approvals"] == []


def test_pending_approvals_joins_ids_to_their_arguments():
    turn = {"state": PAUSED_STATE}
    trace = extract_trace(CONTAINMENT_EVENTS)

    pending = pending_approvals(turn, trace)

    assert pending == [{
        "thread_id": "main",
        "tool_call_id": "call-c1",
        "tool": "contain_account",
        "arguments": {"username": "admin", "justification": "brute force"},
    }]


def test_approval_required_appears_in_the_trace():
    steps = [e["step"] for e in extract_trace(CONTAINMENT_EVENTS)]

    assert "tool.approval_required" in steps


def _approval_flow_routes(second_state, second_events):
    """Turn 1 pauses for approval; turn 2 is the resumed turn."""

    routes = _provision_routes(ALL_TOOLS)
    routes.update({
        "POST /sessions": _ok({"data": {"id": "sess-1"}}),
        "POST /sessions/sess-1/turns": [
            _ok({"data": {"id": "turn-1"}}),
            _ok({"data": {"id": "turn-2"}}),
        ],
        "GET /sessions/sess-1/turns/turn-1": _ok({
            "data": {"id": "turn-1", "state": PAUSED_STATE}
        }),
        "GET /sessions/sess-1/turns/turn-1/events": _ok({
            "data": CONTAINMENT_EVENTS,
            "pagination": {"limit": 100},
        }),
        "GET /sessions/sess-1/turns/turn-2": _ok({
            "data": {"id": "turn-2", "state": second_state}
        }),
        "GET /sessions/sess-1/turns/turn-2/events": _ok({
            "data": second_events,
            "pagination": {"limit": 100},
        }),
    })

    return routes


RESUMED_DONE = {
    "status": "done",
    "output": {"content": "Containment applied."},
    "required_actions": [],
    "completed_at": "t9",
}

RESUMED_EVENTS = [
    {
        "type": "tool.response",
        "created_at": "t4",
        "tool_call_id": "call-c1",
        "content": '{"ok": true, "action_id": 1}',
    },
    {"type": "model.message", "created_at": "t5",
     "content": "Containment applied."},
    {"type": "turn.done", "created_at": "t6", "state": RESUMED_DONE},
]


def test_allowing_containment_resumes_the_turn():
    http = FakeHTTP(_approval_flow_routes(RESUMED_DONE, RESUMED_EVENTS))
    agent = SentinelAgent(_config(), client=TrueForgeClient(_config(), http))

    result = agent.investigate("admin", on_approval=allow_all)

    assert result["status"] == "done"
    assert result["pending_approvals"] == []
    assert not result.get("error")
    assert result["approvals"] == [{
        "tool": "contain_account",
        "arguments": {"username": "admin", "justification": "brute force"},
        "tool_call_id": "call-c1",
        "allowed": True,
        "reason": None,
    }]
    assert result["response"] == "Containment applied."


def test_allow_sends_a_user_tool_approval_item():
    http = FakeHTTP(_approval_flow_routes(RESUMED_DONE, RESUMED_EVENTS))
    agent = SentinelAgent(_config(), client=TrueForgeClient(_config(), http))

    agent.investigate("admin", on_approval=allow_all)

    resume = [
        req for req in http.requests
        if req["method"] == "POST"
        and req["url"].endswith("/sessions/sess-1/turns")
    ][1]

    assert resume["json"]["input"] == [{
        "type": "user.tool_approval",
        "thread_id": "main",
        "tool_call_id": "call-c1",
        "approval": {"status": "allow"},
    }]
    assert resume["json"]["previous_turn_id"] == "turn-1"


def test_denying_containment_is_recorded_and_reported():
    denied_done = {
        "status": "done",
        "output": {"content": "Containment was declined; no action taken."},
        "required_actions": [],
        "completed_at": "t9",
    }

    http = FakeHTTP(_approval_flow_routes(denied_done, RESUMED_EVENTS))
    agent = SentinelAgent(_config(), client=TrueForgeClient(_config(), http))

    result = agent.investigate("admin", on_approval=deny_all)

    assert result["status"] == "done"
    assert result["approvals"][0]["allowed"] is False
    assert result["approvals"][0]["reason"] == "Denied by operator."


def test_deny_sends_a_reason_to_the_agent():
    http = FakeHTTP(_approval_flow_routes(RESUMED_DONE, RESUMED_EVENTS))
    agent = SentinelAgent(_config(), client=TrueForgeClient(_config(), http))

    agent.investigate("admin", on_approval=deny_all)

    resume = [
        req for req in http.requests
        if req["method"] == "POST"
        and req["url"].endswith("/sessions/sess-1/turns")
    ][1]

    approval = resume["json"]["input"][0]["approval"]

    assert approval["status"] == "deny"
    assert approval["reason"] == "Denied by operator."


def test_allow_decision_carries_no_reason_field():
    """TrueForge's ApprovalAllow schema has no reason property."""

    item = approval_item("main", "call-1", True, "should be dropped")

    assert item["approval"] == {"status": "allow"}


def test_approval_loop_is_bounded():
    """A server that keeps re-pausing must not loop forever."""

    routes = _provision_routes(ALL_TOOLS)
    routes.update({
        "POST /sessions": _ok({"data": {"id": "sess-1"}}),
        "POST /sessions/sess-1/turns": lambda req: _ok(
            {"data": {"id": "turn-1"}}
        ),
        "GET /sessions/sess-1/turns/turn-1": lambda req: _ok(
            {"data": {"id": "turn-1", "state": PAUSED_STATE}}
        ),
        "GET /sessions/sess-1/turns/turn-1/events": lambda req: _ok({
            "data": CONTAINMENT_EVENTS,
            "pagination": {"limit": 100},
        }),
    })

    http = FakeHTTP(routes)
    agent = SentinelAgent(_config(), client=TrueForgeClient(_config(), http))

    result = agent.investigate(
        "admin", on_approval=allow_all, max_approval_rounds=2
    )

    assert len(result["approvals"]) == 2


def test_investigation_reports_unreachable_trueforge():
    http = FakeHTTP(error=httpx2.ConnectError("refused"))
    agent = SentinelAgent(_config(), client=TrueForgeClient(_config(), http))

    with pytest.raises(TrueForgeUnavailable):
        agent.investigate("admin")


# ------------------------------------------------------------------
# CLI approval rendering and decisions
# ------------------------------------------------------------------

from trueforge import run_agent  # noqa: E402

PENDING_ITEM = {
    "thread_id": "main",
    "tool_call_id": "call-c1",
    "tool": "contain_account",
    "arguments": {
        "username": "admin",
        "justification": "47 failed logins from 185.123.45.67",
    },
}


def test_describe_request_shows_action_target_and_reason():
    rendered = run_agent.describe_request(PENDING_ITEM)

    assert "CONTAINMENT APPROVAL REQUIRED" in rendered
    assert "contain_account" in rendered
    assert "admin" in rendered
    assert "47 failed logins" in rendered


def test_describe_request_separates_justification_from_target():
    """The reason is the case being made, not part of the target."""

    rendered = run_agent.describe_request(PENDING_ITEM)
    target_line = next(
        line for line in rendered.splitlines() if "target:" in line
    )

    assert "justification" not in target_line


def test_prompt_approves_on_yes(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda *_: "y")

    decisions = run_agent.prompt_for_approval([PENDING_ITEM], "no")

    assert decisions[0]["approval"] == {"status": "allow"}


def test_prompt_denies_on_no(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda *_: "n")

    decisions = run_agent.prompt_for_approval([PENDING_ITEM], "too risky")

    assert decisions[0]["approval"]["status"] == "deny"
    assert decisions[0]["approval"]["reason"] == "too risky"


def test_empty_answer_defaults_to_deny(monkeypatch):
    """Silence is not consent."""

    monkeypatch.setattr("builtins.input", lambda *_: "")

    decisions = run_agent.prompt_for_approval([PENDING_ITEM], "no")

    assert decisions[0]["approval"]["status"] == "deny"


def test_non_interactive_stdin_denies(monkeypatch):
    """A closed stdin must never be read as approval."""

    def raise_eof(*_):
        raise EOFError

    monkeypatch.setattr("builtins.input", raise_eof)

    decisions = run_agent.prompt_for_approval([PENDING_ITEM], "no")

    assert decisions[0]["approval"]["status"] == "deny"


def test_approve_and_deny_flags_are_mutually_exclusive():
    parser = run_agent.build_parser()

    with pytest.raises(SystemExit):
        parser.parse_args(["--approve", "--deny"])


def test_no_approval_flag_means_interactive():
    args = run_agent.build_parser().parse_args([])

    assert args.approve is False
    assert args.deny is False


# ---------------------------------------------------------------------
# Regressions for the Qodo review on PR #5
# ---------------------------------------------------------------------

def test_resumed_response_still_pairs_with_its_call():
    """Qodo #2: a tool.response in the resumed turn belongs to a
    tool.call recorded before the pause.

    Extracting each turn separately left the response with tool=None,
    breaking the documented call/response pairing in --trace and in the
    console, which renders the same trace.
    """

    http = FakeHTTP(_approval_flow_routes(RESUMED_DONE, RESUMED_EVENTS))
    agent = SentinelAgent(_config(), client=TrueForgeClient(_config(), http))

    result = agent.investigate("admin", on_approval=allow_all)

    responses = [
        entry for entry in result["trace"]
        if entry.get("step") == "tool.response"
        and entry.get("tool_call_id") == "call-c1"
    ]

    assert responses, "the resumed tool.response is missing from the trace"

    for response in responses:
        assert response.get("tool") == "contain_account", (
            "the resumed response lost its tool name"
        )


def test_raw_events_span_every_turn():
    """Qodo #3: --json advertises the full raw history.

    events was overwritten on each resume, so the original tool request
    and the approval-required event vanished from the JSON output.
    """

    http = FakeHTTP(_approval_flow_routes(RESUMED_DONE, RESUMED_EVENTS))
    agent = SentinelAgent(_config(), client=TrueForgeClient(_config(), http))

    result = agent.investigate("admin", on_approval=allow_all)
    events = result["events"]

    assert len(events) >= len(CONTAINMENT_EVENTS) + len(RESUMED_EVENTS), (
        "events lost the turns before the resume"
    )

    types = [event.get("type") for event in events]

    assert "tool.response" in types
    assert any(
        event.get("type") == "model.message"
        and "Containment applied." in str(event.get("content", ""))
        for event in events
    ), "the resumed turn's events are missing"


# ------------------------------------------------------------------
# Live trace streaming
#
# The console renders the investigation while it is running, so the agent
# must hand out trace entries as TrueForge records them -- each one once,
# in order, and identical to what the finished run reports.
# ------------------------------------------------------------------

def _streaming_routes(reveals, statuses):
    """Reveal events progressively, one step per poll of the turn."""

    routes = _provision_routes(ALL_TOOLS)
    poll = {"n": 0}

    def turn(_request):
        index = min(poll["n"], len(statuses) - 1)
        return _ok({
            "data": {
                "id": "turn-1",
                "state": {
                    "status": statuses[index],
                    "output": {"content": "THREAT LEVEL: CRITICAL"},
                    "required_actions": [],
                },
            }
        })

    def events(_request):
        index = min(poll["n"], len(reveals) - 1)
        payload = _ok({
            "data": reveals[index],
            "pagination": {"limit": 100},
        })
        poll["n"] += 1
        return payload

    routes.update({
        "POST /sessions": _ok({"data": {"id": "sess-1"}}),
        "POST /sessions/sess-1/turns": _ok({"data": {"id": "turn-1"}}),
        "GET /sessions/sess-1/turns/turn-1": turn,
        "GET /sessions/sess-1/turns/turn-1/events": events,
    })

    return routes


def test_on_trace_streams_entries_as_they_are_recorded(monkeypatch):
    """Trace entries reach the caller mid-turn, once each, in order."""

    monkeypatch.setattr("trueforge.agent.POLL_INTERVAL", 0.001)

    reveals = [
        TRACE_EVENTS[:1],
        TRACE_EVENTS[:3],
        TRACE_EVENTS,
    ]
    statuses = ["running", "running", "done"]

    http = FakeHTTP(_streaming_routes(reveals, statuses))
    agent = SentinelAgent(_config(), client=TrueForgeClient(_config(), http))

    batches = []
    result = agent.investigate("admin", on_trace=batches.append)

    # More than one batch: the caller saw the run unfold, not just its end.
    assert len(batches) > 1

    streamed = [entry for batch in batches for entry in batch]

    # Every entry exactly once, and the same journey the run finally reports.
    assert streamed == result["trace"]

    # The first batch arrived before the tool calls existed.
    assert [entry["step"] for entry in batches[0]] == ["mcp.initialize"]

    # No entry was delivered twice.
    ids = [
        entry.get("tool_call_id")
        for entry in streamed
        if entry["step"] == "tool.call"
    ]
    assert len(ids) == len(set(ids))


def test_on_trace_batches_never_overlap(monkeypatch):
    """A slow turn that reveals nothing new emits nothing."""

    monkeypatch.setattr("trueforge.agent.POLL_INTERVAL", 0.001)

    reveals = [TRACE_EVENTS[:1], TRACE_EVENTS[:1], TRACE_EVENTS]
    statuses = ["running", "running", "done"]

    http = FakeHTTP(_streaming_routes(reveals, statuses))
    agent = SentinelAgent(_config(), client=TrueForgeClient(_config(), http))

    batches = []
    agent.investigate("admin", on_trace=batches.append)

    # The idle poll produced no batch at all -- not an empty one, and not a
    # repeat of what was already sent.
    assert all(batch for batch in batches)

    streamed = [entry for batch in batches for entry in batch]
    steps = [entry["step"] for entry in streamed]

    assert steps.count("mcp.initialize") == 1


def test_without_on_trace_the_turn_is_read_once():
    """The CLI path keeps its original single-fetch behaviour."""

    http = FakeHTTP(_investigation_routes({
        "status": "done",
        "output": {"content": "CRITICAL"},
        "required_actions": [],
    }))
    agent = SentinelAgent(_config(), client=TrueForgeClient(_config(), http))

    result = agent.investigate("admin")

    event_reads = [
        request for request in http.requests
        if request["url"].endswith("/events")
    ]

    assert len(event_reads) == 1
    assert result["trace"]


def test_streaming_survives_an_approval_pause(monkeypatch):
    """Entries recorded after a resume continue the same stream."""

    monkeypatch.setattr("trueforge.agent.POLL_INTERVAL", 0.001)

    paused = {
        "status": "awaiting_approval",
        "output": {"content": ""},
        "required_actions": [{
            "type": "tool.approval_required",
            "thread_id": "main",
            "tool_calls": [{"id": "call-9"}],
        }],
    }
    finished = {
        "status": "done",
        "output": {"content": "CRITICAL"},
        "required_actions": [],
    }

    first_events = TRACE_EVENTS + [{
        "type": "model.message",
        "created_at": "t5",
        "tool_calls": [{
            "id": "call-9",
            "function": {
                "name": "contain_account",
                "arguments": '{"username": "admin"}',
            },
        }],
    }]
    resumed_events = [{
        "type": "tool.response",
        "created_at": "t7",
        "tool_call_id": "call-9",
        "content": '{"ok": true}',
    }]

    routes = _provision_routes(ALL_TOOLS)
    turns = {"n": 0}

    def create_turn(_request):
        turns["n"] += 1
        return _ok({"data": {"id": f"turn-{turns['n']}"}})

    routes.update({
        "POST /sessions": _ok({"data": {"id": "sess-1"}}),
        "POST /sessions/sess-1/turns": create_turn,
        "GET /sessions/sess-1/turns/turn-1": _ok({
            "data": {"id": "turn-1", "state": paused}
        }),
        "GET /sessions/sess-1/turns/turn-1/events": _ok({
            "data": first_events, "pagination": {"limit": 100},
        }),
        "GET /sessions/sess-1/turns/turn-2": _ok({
            "data": {"id": "turn-2", "state": finished}
        }),
        "GET /sessions/sess-1/turns/turn-2/events": _ok({
            "data": resumed_events, "pagination": {"limit": 100},
        }),
    })

    http = FakeHTTP(routes)
    agent = SentinelAgent(_config(), client=TrueForgeClient(_config(), http))

    batches = []
    result = agent.investigate(
        "admin", on_approval=allow_all, on_trace=batches.append
    )

    streamed = [entry for batch in batches for entry in batch]

    # The whole journey, across the pause, exactly once.
    assert streamed == result["trace"]

    responses = [
        entry for entry in streamed
        if entry["step"] == "tool.response"
        and entry["tool_call_id"] == "call-9"
    ]

    # The response recorded after the resume is paired with the call made
    # before the pause.
    assert len(responses) == 1
    assert responses[0]["tool"] == "contain_account"


# ------------------------------------------------------------------
# Thread-aware trace correlation
#
# A tool_call_id is minted per conversation by the model provider, so once a
# turn can run more than one thread the id alone is not a unique identity.
# These tests pin the identity to (thread_id, tool_call_id).
# ------------------------------------------------------------------

# The same tool_call_id, used by two different threads in one turn. This is
# the case the old implementation got wrong.
COLLIDING_THREAD_EVENTS = [
    {
        "type": "model.message",
        "created_at": "t1",
        "thread_id": "main",
        "tool_calls": [
            {
                "id": "call_123",
                "function": {
                    "name": "get_login_history",
                    "arguments": '{"username": "admin"}',
                },
            }
        ],
    },
    {
        "type": "thread.created",
        "created_at": "t2",
        "thread_id": "subagent-abc",
        "agent_info": {
            "type": "dynamic",
            "name": "corroborate-ip",
            "input": "Check 185.123.45.67",
        },
        "parent": {"thread_id": "main", "tool_call_id": "call_999"},
    },
    {
        "type": "model.message",
        "created_at": "t3",
        "thread_id": "subagent-abc",
        "tool_calls": [
            {
                "id": "call_123",
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
        "thread_id": "main",
        "tool_call_id": "call_123",
        "content": "LOGIN RESULT",
    },
    {
        "type": "tool.response",
        "created_at": "t5",
        "thread_id": "subagent-abc",
        "tool_call_id": "call_123",
        "content": "NETWORK RESULT",
    },
    {
        "type": "thread.done",
        "created_at": "t6",
        "thread_id": "subagent-abc",
        "parent": {"thread_id": "main", "tool_call_id": "call_999"},
    },
]


def _responses(trace):
    return [e for e in trace if e["step"] == "tool.response"]


def test_the_same_tool_call_id_in_two_threads_never_cross_correlates():
    """The core regression: identity is (thread_id, tool_call_id).

    `main` and `subagent-abc` both use `call_123`. Each response must resolve
    to the tool its own thread called, and to nothing else. Correlating on
    tool_call_id alone attaches the network result to the login lookup.
    """

    trace = extract_trace(COLLIDING_THREAD_EVENTS)

    main_response, sub_response = _responses(trace)

    # The pairing itself, asserted first: correlating on tool_call_id alone
    # resolves both responses to whichever call was recorded last, so the
    # login result comes back labelled get_network_activity.
    assert main_response["content"] == "LOGIN RESULT"
    assert main_response["tool"] == "get_login_history"

    assert sub_response["content"] == "NETWORK RESULT"
    assert sub_response["tool"] == "get_network_activity"

    # Neither response was attributed to the other thread's tool.
    assert main_response["tool"] != sub_response["tool"]

    # Each is still stamped with the thread it belongs to, and the provider's
    # id is unchanged.
    assert main_response["thread_id"] == "main"
    assert main_response["tool_call_id"] == "call_123"
    assert sub_response["thread_id"] == "subagent-abc"
    assert sub_response["tool_call_id"] == "call_123"


def test_each_thread_keeps_its_own_tool_call():
    """Both calls survive with their own thread and identical id."""

    trace = extract_trace(COLLIDING_THREAD_EVENTS)
    calls = [e for e in trace if e["step"] == "tool.call"]

    assert [(c["thread_id"], c["tool_call_id"], c["tool"]) for c in calls] == [
        ("main", "call_123", "get_login_history"),
        ("subagent-abc", "call_123", "get_network_activity"),
    ]

    # The id is recorded exactly as TrueForge produced it -- never rewritten
    # or namespaced into a synthetic value.
    assert all(c["tool_call_id"] == "call_123" for c in calls)


def test_thread_id_is_preserved_on_trace_entries():
    trace = extract_trace(COLLIDING_THREAD_EVENTS)

    for entry in trace:
        assert "thread_id" in entry, entry["step"]

    by_step = {}
    for entry in trace:
        by_step.setdefault(entry["step"], []).append(entry["thread_id"])

    assert by_step["tool.call"] == ["main", "subagent-abc"]
    assert by_step["tool.response"] == ["main", "subagent-abc"]
    assert by_step["thread.created"] == ["subagent-abc"]
    assert by_step["thread.done"] == ["subagent-abc"]


def test_thread_lifecycle_events_are_recorded_with_their_parent():
    trace = extract_trace(COLLIDING_THREAD_EVENTS)

    created = next(e for e in trace if e["step"] == "thread.created")

    assert created["thread_id"] == "subagent-abc"
    assert created["name"] == "corroborate-ip"
    assert created["parent_thread_id"] == "main"
    assert created["parent_tool_call_id"] == "call_999"

    done = next(e for e in trace if e["step"] == "thread.done")

    assert done["thread_id"] == "subagent-abc"
    assert done["parent_thread_id"] == "main"


def test_interleaved_threads_pair_across_the_interleaving():
    """A response is matched to its call even with another thread between."""

    events = [
        {
            "type": "model.message",
            "created_at": "t1",
            "thread_id": "main",
            "tool_calls": [{
                "id": "dup",
                "function": {"name": "get_login_history", "arguments": "{}"},
            }],
        },
        {
            "type": "model.message",
            "created_at": "t2",
            "thread_id": "sub-1",
            "tool_calls": [{
                "id": "dup",
                "function": {"name": "get_network_activity", "arguments": "{}"},
            }],
        },
        {
            "type": "model.message",
            "created_at": "t3",
            "thread_id": "sub-2",
            "tool_calls": [{
                "id": "dup",
                "function": {"name": "get_account_status", "arguments": "{}"},
            }],
        },
        # Responses arrive in a different order than the calls were made.
        {
            "type": "tool.response", "created_at": "t4",
            "thread_id": "sub-2", "tool_call_id": "dup", "content": "C",
        },
        {
            "type": "tool.response", "created_at": "t5",
            "thread_id": "main", "tool_call_id": "dup", "content": "A",
        },
        {
            "type": "tool.response", "created_at": "t6",
            "thread_id": "sub-1", "tool_call_id": "dup", "content": "B",
        },
    ]

    resolved = [
        (e["thread_id"], e["content"], e["tool"])
        for e in _responses(extract_trace(events))
    ]

    assert resolved == [
        ("sub-2", "C", "get_account_status"),
        ("main", "A", "get_login_history"),
        ("sub-1", "B", "get_network_activity"),
    ]


def test_a_response_from_an_unknown_thread_resolves_to_no_tool():
    """A stray response is reported, not silently attached to someone else."""

    events = [
        {
            "type": "model.message",
            "created_at": "t1",
            "thread_id": "main",
            "tool_calls": [{
                "id": "call_123",
                "function": {"name": "get_login_history", "arguments": "{}"},
            }],
        },
        {
            "type": "tool.response", "created_at": "t2",
            "thread_id": "ghost-thread", "tool_call_id": "call_123",
            "content": "orphan",
        },
    ]

    orphan = _responses(extract_trace(events))[0]

    assert orphan["thread_id"] == "ghost-thread"
    assert orphan["content"] == "orphan"
    assert orphan["tool"] is None, "an orphan borrowed another thread's tool"


def test_events_without_a_thread_id_are_read_as_the_main_thread():
    """Traces recorded before subagents existed still correlate."""

    trace = extract_trace(TRACE_EVENTS)

    assert all(
        entry["thread_id"] == "main"
        for entry in trace
        if "thread_id" in entry
    )

    # And the pairing is unchanged from the single-thread behaviour.
    assert [e["step"] for e in trace] == [
        "mcp.initialize",
        "tool.call",
        "tool.response",
        "tool.call",
        "tool.response",
        "model.message",
        "turn.done",
    ]
    assert trace[4]["tool"] == "get_network_activity"


def test_a_null_thread_id_does_not_become_an_invented_thread():
    """Run-level events carry thread_id: null; they read as main, not as a
    fabricated thread name."""

    trace = extract_trace([{
        "type": "mcp.initialize",
        "created_at": "t0",
        "thread_id": None,
        "mcp_servers": [{"name": "sentinel-security", "transport_type": "remote"}],
    }])

    assert trace[0]["thread_id"] == "main"


def test_wrapped_events_keep_their_thread_id():
    """The session-listing envelope must not hide the thread."""

    wrapped = [
        {"turn_id": "turn-1", "event": event}
        for event in COLLIDING_THREAD_EVENTS
    ]

    assert extract_trace(wrapped) == extract_trace(COLLIDING_THREAD_EVENTS)


def test_unknown_event_types_are_ignored():
    """A new TrueForge event type must never break a trace."""

    events = [
        {"type": "sandbox.created", "created_at": "t0", "thread_id": None},
        {"type": "model.message.delta", "created_at": "t1", "thread_id": "main"},
        {"type": "some.future.event", "created_at": "t2", "thread_id": "main"},
        {"type": "mcp.auth_required", "created_at": "t3", "thread_id": None},
        {},
    ]

    assert extract_trace(events) == []

    # And they do not disturb the events around them.
    mixed = [events[0]] + list(TRACE_EVENTS) + [events[2]]

    assert extract_trace(mixed) == extract_trace(TRACE_EVENTS)


def test_extract_trace_is_prefix_stable_across_interleaved_threads():
    """The invariant streaming depends on, now with several threads.

    `_advance_turn` emits `trace[emitted:]` on every poll. That is only
    correct while the trace of a prefix of the events is a prefix of the
    trace of all of them -- including when threads interleave.
    """

    full = extract_trace(COLLIDING_THREAD_EVENTS)

    for size in range(len(COLLIDING_THREAD_EVENTS) + 1):
        partial = extract_trace(COLLIDING_THREAD_EVENTS[:size])

        assert partial == full[:len(partial)], (
            f"trace of the first {size} events is not a prefix of the whole"
        )


def test_pending_approvals_resolves_within_the_right_thread():
    """An approval shows the arguments of the call it actually names.

    Both threads have a pending call id `call_x`; only the subagent's is
    awaiting approval. Resolving on the id alone would show the operator the
    parent's arguments for an action the subagent requested.
    """

    # The subagent's containment request is recorded first and the parent's
    # unrelated call second, so a lookup keyed on the id alone resolves to
    # the parent's get_login_history -- the wrong action entirely.
    events = [
        {
            "type": "model.message",
            "created_at": "t1",
            "thread_id": "subagent-abc",
            "tool_calls": [{
                "id": "call_x",
                "function": {
                    "name": "contain_account",
                    "arguments": (
                        '{"username": "root", "justification": "47 failures"}'
                    ),
                },
            }],
        },
        {
            "type": "model.message",
            "created_at": "t2",
            "thread_id": "main",
            "tool_calls": [{
                "id": "call_x",
                "function": {
                    "name": "get_login_history",
                    "arguments": '{"username": "admin"}',
                },
            }],
        },
    ]

    turn = {"state": {
        "status": "done",
        "required_actions": [{
            "type": "tool.approval_required",
            "thread_id": "subagent-abc",
            "tool_calls": [{"id": "call_x", "source_event_id": "e2"}],
        }],
    }}

    pending = pending_approvals(turn, extract_trace(events))

    assert pending == [{
        "thread_id": "subagent-abc",
        "tool_call_id": "call_x",
        "tool": "contain_account",
        "arguments": {"username": "root", "justification": "47 failures"},
    }]


def test_pending_approvals_still_resolves_a_single_thread_turn():
    """The existing main-thread behaviour is untouched."""

    turn = {"state": PAUSED_STATE}

    assert pending_approvals(turn, extract_trace(CONTAINMENT_EVENTS)) == [{
        "thread_id": "main",
        "tool_call_id": "call-c1",
        "tool": "contain_account",
        "arguments": {"username": "admin", "justification": "brute force"},
    }]


def test_approval_decisions_carry_the_requesting_thread():
    """allow_all/deny_all send the decision back to the thread that asked.

    TrueForge's user.tool_approval payload is (thread_id, tool_call_id), so
    a subagent's request must be answered on the subagent's thread.
    """

    pending = [{
        "thread_id": "subagent-abc",
        "tool_call_id": "call_x",
        "tool": "contain_account",
        "arguments": {},
    }]

    allowed = allow_all(pending)
    denied = deny_all(pending, "Shared VPN.")

    assert allowed[0]["thread_id"] == "subagent-abc"
    assert allowed[0]["tool_call_id"] == "call_x"
    assert allowed[0]["approval"] == {"status": "allow"}

    assert denied[0]["thread_id"] == "subagent-abc"
    assert denied[0]["approval"]["reason"] == "Shared VPN."


# ---------------------------------------------------------------------
# Delegated investigation
#
# Delegation changes who gathers the evidence. These hold that it changes
# nothing about what anything is permitted to do -- and that the two shapes
# stay distinct resources in TrueForge rather than overwriting each other.
# ---------------------------------------------------------------------

def _delegated_config():
    config = _config()
    config.delegate = True
    return config


def test_delegation_is_off_by_default():
    """The reliable path is the default path."""

    assert _config().delegate is False

    spec = build_agent_spec(_config())

    assert spec["config"]["dynamic_sub_agents"]["enabled"] is False


def test_delegation_enables_dynamic_subagents():
    spec = build_agent_spec(_delegated_config())

    assert spec["config"]["dynamic_sub_agents"]["enabled"] is True


def test_delegation_does_not_widen_the_approval_gate():
    """A subagent must be gated exactly as the lead is.

    The selector lives on the MCP server attachment, so it binds the tools
    rather than the thread calling them. If this ever became thread-scoped,
    a specialist could contain an account without a human.
    """

    for config in (_config(), _delegated_config()):
        server = build_agent_spec(config)["mcp_servers"][0]

        assert server["require_approval_for_tools"] == [
            "@write", "@destructive"
        ]


def test_delegation_does_not_widen_the_tool_set():
    linear = build_agent_spec(_config())["mcp_servers"][0]
    delegated = build_agent_spec(_delegated_config())["mcp_servers"][0]

    assert linear["enable_tools"] == delegated["enable_tools"]


def test_delegated_prompt_extends_the_investigator_contract():
    """The lead is still bound by every rule the linear agent has."""

    from investigator.prompts import (
        DELEGATED_LEAD_PROMPT,
        SENTINEL_SYSTEM_PROMPT,
    )

    assert DELEGATED_LEAD_PROMPT.startswith(SENTINEL_SYSTEM_PROMPT)

    spec = build_agent_spec(_delegated_config())

    assert spec["instructions"] == DELEGATED_LEAD_PROMPT


def test_delegated_prompt_still_hardcodes_no_ip_address():
    """The delegation brief must not leak the answer either."""

    import re

    from investigator.prompts import DELEGATION_BRIEF

    found = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", DELEGATION_BRIEF)

    assert found == [], f"delegation brief hardcodes IPs: {found}"


def test_delegated_prompt_carries_no_scoring_rules():
    import re

    from investigator.prompts import DELEGATION_BRIEF

    lower = DELEGATION_BRIEF.lower()

    assert "points" not in lower
    assert not re.search(r"\bscore\s*(>=|>|<)\s*\d", lower)


def test_specialists_are_told_not_to_propose_containment():
    from investigator.prompts import DELEGATION_BRIEF

    lower = DELEGATION_BRIEF.lower()

    assert "a specialist reports; it does not act" in lower
    assert "no subagent may propose or call" in lower


def test_the_brief_does_not_claim_instructions_are_the_control():
    """Honesty about where the guarantee actually lives.

    The brief tells specialists not to contain. If the project ever starts
    presenting that sentence as the safety mechanism, the claim in the
    README stops being true.
    """

    from investigator.prompts import DELEGATION_BRIEF

    lower = DELEGATION_BRIEF.lower()

    assert "it is not what makes containment safe" in lower
    assert "approval gate is attached to the containment tools" in lower


def test_delegation_raises_the_iteration_ceiling_but_keeps_one():
    linear = build_agent_spec(_config())["config"]["iteration_limit"]
    delegated = build_agent_spec(_delegated_config())["config"][
        "iteration_limit"
    ]

    assert delegated > linear
    assert delegated <= 1024, "TrueForge caps iteration_limit at 1024"


def test_sandbox_stays_disabled_in_both_shapes():
    """No sandbox provider is configured on this deployment.

    Enabling it would fail the turn rather than add a capability, so the
    honest setting is off -- in both shapes.
    """

    for config in (_config(), _delegated_config()):
        assert build_agent_spec(config)["config"]["sandbox"] == {
            "enabled": False
        }


def test_the_two_shapes_are_separate_trueforge_agents():
    """Provisioning is create-or-replace; a shared name would clobber."""

    assert _config().effective_agent_name != (
        _delegated_config().effective_agent_name
    )


def test_an_explicit_agent_name_is_never_overridden():
    """A caller who named the agent gets the agent they named."""

    config = _delegated_config()
    config.agent_name = "my-own-agent"

    assert config.effective_agent_name == "my-own-agent"
