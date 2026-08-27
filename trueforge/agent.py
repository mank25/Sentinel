"""Sentinel's TrueForge agent: configuration, execution and trace extraction.

Layering:

    TrueForgeClient      -- HTTP only
        v
    build_agent_spec     -- what the agent is
        v
    SentinelAgent        -- ensure MCP + agent, run a session/turn
        v
    extract_trace        -- the investigation journey, from real events

TrueForge orchestrates the agent loop and the MCP tool calls. All security
scoring stays in :mod:`investigator.risk`, reachable only through the
``assess_user_risk`` MCP tool.
"""

import json

from investigator.prompts import (
    SENTINEL_SYSTEM_PROMPT,
    investigation_request,
)
from trueforge.client import TrueForgeClient, TrueForgeError
from trueforge.config import TrueForgeConfig
from trueforge.mcp_auth import authorization_header

MCP_SERVER_DESCRIPTION = (
    "Read-only Sentinel security investigation tools: login history, "
    "network intelligence, and deterministic risk assessment."
)

# TrueForge v0.1.4 persists a model's reasoning as `thinking_blocks` and
# replays it to the provider as `reasoning_content` on the assistant message.
# Groq's OpenAI-compatible endpoint rejects that property on input, so the
# turn dies on the second provider call -- the moment any tool is used.
# Nothing in Sentinel triggers this; it is a provider/runtime incompatibility.
_REASONING_REPLAY_MARKER = "property 'reasoning_content' is unsupported"

REASONING_REPLAY_HELP = """\
The model provider rejected TrueForge's replay of the assistant message.

TrueForge stores the model's reasoning and sends it back as
'reasoning_content'; Groq's OpenAI-compatible API rejects that field on
input, so the turn fails as soon as the agent calls its first tool.

This is a TrueForge/provider incompatibility, not a Sentinel fault: the
Sentinel MCP server, its tools and the deterministic pipeline all work.

Workarounds:
  - Configure a non-reasoning model, or a provider whose API tolerates
    'reasoning_content' on input (Settings -> Model Providers).
  - Or run the deterministic investigation directly, which needs no LLM:
        python -m investigator.run_investigation
"""


def diagnose_turn_error(message: str) -> str:
    """Attach actionable guidance to known TrueForge failure modes."""

    if message and _REASONING_REPLAY_MARKER in message:
        return f"{message}\n\n{REASONING_REPLAY_HELP}"

    return message


class SentinelAgentError(TrueForgeError):
    """The Sentinel agent could not complete an investigation."""


def build_agent_spec(config: TrueForgeConfig) -> dict:
    """The TrueForge ``AgentSpec`` for the Sentinel investigator.

    Every Sentinel tool is read-only and annotated as such, so none of them
    require human approval. Sub-agents and generative UI are off to keep the
    execution trace linear and the context small -- the configured model has
    an 8192-token window.
    """

    return {
        "model": {"name": config.model},
        "instructions": SENTINEL_SYSTEM_PROMPT,
        "mcp_servers": [
            {
                "name": config.mcp_server_name,
                # Named explicitly rather than "@all" so a new tool on the
                # server cannot silently widen the agent's reach.
                "enable_tools": list(config.tools),
                "require_approval_for_tools": [],
                "preload": True,
            }
        ],
        "config": {
            "iteration_limit": 12,
            "sandbox": {"enabled": False},
            "dynamic_sub_agents": {"enabled": False},
            "generative_ui": {"enabled": False},
            "ask_user_questions": {"enabled": False},
        },
    }


# ---------------------------------------------------------------------
# Trace extraction
# ---------------------------------------------------------------------

def _parse_arguments(raw):
    """Tool-call arguments arrive as a JSON string; keep it readable."""

    if isinstance(raw, dict):
        return raw

    if not raw:
        return {}

    try:
        return json.loads(raw)

    except (json.JSONDecodeError, TypeError, ValueError):
        return {"_raw": raw}


def extract_trace(events: list) -> list:
    """Turn raw TrueForge turn events into an ordered investigation journey.

    Nothing here is synthesised: every entry comes from an event TrueForge
    actually recorded. Tool calls are read from ``model.message.tool_calls``
    and paired with their ``tool.response`` by ``tool_call_id``.
    """

    trace = []
    pending = {}

    for event in events:
        # Session-level listings wrap events as {"turn_id", "event"}.
        if "event" in event and "type" not in event:
            event = event["event"]

        kind = event.get("type")

        if kind == "mcp.initialize":
            for info in event.get("mcp_servers", []):
                trace.append({
                    "step": "mcp.initialize",
                    "server": info.get("name"),
                    "transport": info.get("transport_type"),
                    "created_at": event.get("created_at"),
                })

        elif kind == "model.message":
            for call in event.get("tool_calls") or []:
                function = call.get("function", {})
                call_id = call.get("id")

                entry = {
                    "step": "tool.call",
                    "tool": function.get("name"),
                    "arguments": _parse_arguments(function.get("arguments")),
                    "tool_call_id": call_id,
                    "created_at": event.get("created_at"),
                }

                trace.append(entry)

                if call_id:
                    pending[call_id] = entry

            content = event.get("content")

            if content and not (event.get("tool_calls") or []):
                trace.append({
                    "step": "model.message",
                    "content": content,
                    "created_at": event.get("created_at"),
                })

        elif kind == "tool.response":
            call_id = event.get("tool_call_id")
            call = pending.get(call_id, {})

            trace.append({
                "step": "tool.response",
                "tool": call.get("tool"),
                "tool_call_id": call_id,
                "content": event.get("content"),
                "created_at": event.get("created_at"),
            })

        elif kind == "turn.done":
            state = event.get("state", {})

            trace.append({
                "step": "turn.done",
                "status": state.get("status"),
                "created_at": event.get("created_at"),
            })

    return trace


def _message_text(message) -> str:
    """Flatten a ``model.message`` content field to plain text."""

    if message is None:
        return ""

    content = message.get("content") if isinstance(message, dict) else message

    if content is None:
        return ""

    if isinstance(content, str):
        return content

    if isinstance(content, list):
        return "".join(
            part.get("text", "")
            for part in content
            if isinstance(part, dict)
        )

    return str(content)


def summarize_tool_calls(trace: list) -> list:
    """The tool names actually invoked, in order."""

    return [
        entry["tool"]
        for entry in trace
        if entry.get("step") == "tool.call" and entry.get("tool")
    ]


# ---------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------

class SentinelAgent:
    """Configures and runs the Sentinel investigator on TrueForge."""

    def __init__(
        self,
        config: TrueForgeConfig | None = None,
        client: TrueForgeClient | None = None,
    ):
        self.config = config or TrueForgeConfig.from_env()
        self._owns_client = client is None
        self.client = client or TrueForgeClient(self.config)

    def close(self) -> None:
        if self._owns_client:
            self.client.close()

    def __enter__(self) -> "SentinelAgent":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    # -----------------------------------------------------------------
    # Provisioning
    # -----------------------------------------------------------------

    def ensure_mcp_server(self) -> list:
        """Register the Sentinel MCP server and confirm its tools load.

        Returns the tool names TrueForge could actually see, which proves the
        registration points at a live server.
        """

        try:
            self.client.register_mcp_server(
                name=self.config.mcp_server_name,
                url=self.config.mcp_url,
                description=MCP_SERVER_DESCRIPTION,
                headers=authorization_header(
                    self.config.require_mcp_token()
                ),
            )

        except TrueForgeError as exc:
            raise SentinelAgentError(
                f"Could not register the Sentinel MCP server "
                f"({self.config.mcp_url}) with TrueForge: {exc}"
            ) from exc

        try:
            tools = self.client.list_mcp_tools(self.config.mcp_server_name)

        except TrueForgeError as exc:
            hint = (
                "Start it with: python mcp/sentinel_mcp/http_server.py"
            )

            if "401" in str(exc) or "unauthorized" in str(exc).lower():
                hint = (
                    "The MCP server rejected TrueForge's bearer token. Make "
                    "sure both sides resolve the same token: either export "
                    "SENTINEL_MCP_TOKEN for both, or let both use the "
                    "generated .sentinel-mcp-token file."
                )

            raise SentinelAgentError(
                f"TrueForge could not load tools from the Sentinel MCP "
                f"server at {self.config.mcp_url}: {exc}\n{hint}"
            ) from exc

        names = [tool.get("name") for tool in tools]
        missing = [tool for tool in self.config.tools if tool not in names]

        if missing:
            raise SentinelAgentError(
                f"The Sentinel MCP server is missing expected tools: "
                f"{missing}. Found: {names}"
            )

        return names

    def ensure_agent(self) -> dict:
        """Create or update the Sentinel agent definition."""

        try:
            return self.client.upsert_agent(
                self.config.agent_name,
                build_agent_spec(self.config),
            )

        except TrueForgeError as exc:
            raise SentinelAgentError(
                f"Could not create the Sentinel agent "
                f"'{self.config.agent_name}': {exc}"
            ) from exc

    def ensure_model(self) -> str:
        """Verify the configured model exists on this TrueForge instance.

        A model that is not configured fails deep inside the turn with an
        opaque provider error, so check it up front and name the
        alternatives.
        """

        try:
            available = [model["name"] for model in self.client.list_models()]

        except TrueForgeError as exc:
            raise SentinelAgentError(
                f"Could not list TrueForge models: {exc}"
            ) from exc

        if self.config.model in available:
            return self.config.model

        raise SentinelAgentError(
            f"Model '{self.config.model}' is not configured in TrueForge.\n"
            f"Available: {available or '(none)'}\n"
            "Add a provider under Settings -> Model Providers, or choose one "
            "of the above with --model / $TRUEFORGE_MODEL."
        )

    def provision(self) -> dict:
        """Make TrueForge ready to run an investigation."""

        self.client.ping()

        model = self.ensure_model()
        tools = self.ensure_mcp_server()
        agent = self.ensure_agent()

        return {"model": model, "tools": tools, "agent": agent}

    # -----------------------------------------------------------------
    # Execution
    # -----------------------------------------------------------------

    def investigate(self, username: str, provision: bool = True) -> dict:
        """Run one investigation and return the response plus its trace."""

        if provision:
            self.provision()

        try:
            session = self.client.create_session(self.config.agent_name)

        except TrueForgeError as exc:
            raise SentinelAgentError(
                f"Could not create a TrueForge session: {exc}"
            ) from exc

        session_id = session["id"]

        try:
            turn = self.client.create_turn(
                session_id,
                investigation_request(username),
                stream=False,
            )

        except TrueForgeError as exc:
            raise SentinelAgentError(
                f"Could not start an investigation turn in session "
                f"{session_id}: {exc}"
            ) from exc

        turn_id = turn["id"]

        turn = self.client.wait_for_turn(session_id, turn_id)

        state = turn.get("state", {})
        status = state.get("status")

        events = self.client.list_turn_events(session_id, turn_id)
        trace = extract_trace(events)

        result = {
            "username": username,
            "session_id": session_id,
            "turn_id": turn_id,
            "status": status,
            "response": "",
            "tool_calls": summarize_tool_calls(trace),
            "trace": trace,
            "events": events,
        }

        if status == "error":
            result["error"] = diagnose_turn_error(
                state.get("message", "Turn failed")
            )
            return result

        if status == "cancelled":
            result["error"] = "Turn was cancelled"
            return result

        required = state.get("required_actions") or []

        if required:
            result["error"] = (
                "Turn paused awaiting "
                f"{[action.get('type') for action in required]}"
            )
            result["required_actions"] = required

        result["response"] = _message_text(state.get("output"))

        return result
