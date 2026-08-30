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
import time

from investigator.prompts import (
    DELEGATED_LEAD_PROMPT,
    SENTINEL_SYSTEM_PROMPT,
    investigation_request,
)
from trueforge.client import (
    TrueForgeClient,
    TrueForgeError,
    TrueForgeProtocolError,
    TrueForgeTimeout,
    approval_item,
)
from trueforge.config import TrueForgeConfig
from trueforge.mcp_auth import authorization_header

# How often a running turn is re-read while streaming its trace. This is
# the same cadence TrueForgeClient.wait_for_turn polls at; the difference
# is that each tick also collects the events recorded so far, so an
# operator watching the console sees a tool call within a second of
# TrueForge recording it rather than at the end of the run.
POLL_INTERVAL = 1.0

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

    Two shapes, selected by ``config.delegate``:

    * **Linear** (default) -- one thread. Subagents are off, so the trace is
      a single readable investigation and every tool call is visible in it.
    * **Delegated** -- a lead analyst that commissions specialist subagents
      and correlates their findings. TrueForge gives each subagent its own
      thread, which is precisely why tool results are correlated on
      ``(thread_id, tool_call_id)`` rather than on the id alone.

    What does **not** change between them is what anything is allowed to do.
    ``require_approval_for_tools`` is attached to the MCP server, so it binds
    the *tools* rather than the thread that calls them: a subagent invoking
    ``block_ip`` is paused for a human exactly as the lead would be. The
    delegation brief also tells specialists not to propose containment, but
    that is about keeping the investigation coherent -- the gate is what
    makes it safe, and the gate is in the harness.

    Generative UI and user questions stay off in both shapes: they would put
    turn-blocking interactions in front of the operator that are not the
    containment decision, which is the one interaction this console exists
    to present.

    ``iteration_limit`` doubles as a cost ceiling. A linear investigation
    uses four or five model calls; delegation needs materially more, because
    each specialist runs its own loop, so the ceiling is raised only in that
    shape and still caps a runaway loop well before it becomes expensive.
    """

    return {
        "model": {"name": config.model},
        "instructions": (
            DELEGATED_LEAD_PROMPT if config.delegate
            else SENTINEL_SYSTEM_PROMPT
        ),
        "mcp_servers": [
            {
                "name": config.mcp_server_name,
                # Named explicitly rather than "@all" so a new tool on the
                # server cannot silently widen the agent's reach.
                "enable_tools": list(config.tools),
                # TrueForge's own default, stated explicitly so it cannot be
                # lost in a refactor. The evidence tools are annotated
                # read-only and run freely; contain_account and block_ip are
                # annotated destructive and therefore pause for a human.
                # The gate is enforced by the harness, not by the prompt --
                # rewriting the instructions cannot bypass it.
                "require_approval_for_tools": ["@write", "@destructive"],
                "preload": True,
            }
        ],
        "config": {
            "iteration_limit": 30 if config.delegate else 12,
            # Sandbox execution is unavailable on this deployment: TrueForge
            # v0.1.4 sandboxes are Daytona-backed and no sandbox provider is
            # configured (GET /api/v1/settings/sandbox-providers returns
            # "No sandbox provider configured"). Enabling it here would fail
            # the turn rather than add a capability.
            "sandbox": {"enabled": False},
            "dynamic_sub_agents": {"enabled": bool(config.delegate)},
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


# The root agent's thread. TrueForge stamps `thread_id` on every
# thread-scoped event and names the root thread "main"; each subagent gets a
# minted id. Events recorded before subagents existed carry no field at all,
# so reading a missing one as the main thread keeps old traces correct.
DEFAULT_THREAD_ID = "main"


def _thread_of(event: dict) -> str:
    """The thread an event belongs to.

    Falls back to :data:`DEFAULT_THREAD_ID` only when the event carries no
    usable id -- an older event without the field, or a run-level event whose
    ``thread_id`` is explicitly null. No id is ever invented for an event that
    has one.
    """

    thread_id = event.get("thread_id")

    if isinstance(thread_id, str) and thread_id:
        return thread_id

    return DEFAULT_THREAD_ID


def extract_trace(events: list) -> list:
    """Turn raw TrueForge turn events into an ordered investigation journey.

    Nothing here is synthesised: every entry comes from an event TrueForge
    actually recorded.

    Tool calls are read from ``model.message.tool_calls`` and paired with
    their ``tool.response`` by **(thread_id, tool_call_id)**, never by
    ``tool_call_id`` alone. Once more than one thread can run in a turn, the
    id is no longer unique: it is minted per conversation by the model
    provider (observed values are short counters like ``call_2394998``), so
    two threads can independently produce the same one. Pairing on the id
    alone would attach a subagent's result to the parent's tool call. The
    thread is what makes the identity unique; the id is kept exactly as
    TrueForge recorded it.
    """

    trace = []
    pending = {}

    for event in events:
        # Session-level listings wrap events as {"turn_id", "event"}.
        if "event" in event and "type" not in event:
            event = event["event"]

        kind = event.get("type")
        thread_id = _thread_of(event)

        if kind == "mcp.initialize":
            for info in event.get("mcp_servers", []):
                trace.append({
                    "step": "mcp.initialize",
                    "server": info.get("name"),
                    "transport": info.get("transport_type"),
                    "thread_id": thread_id,
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
                    "thread_id": thread_id,
                    "tool_call_id": call_id,
                    "created_at": event.get("created_at"),
                }

                trace.append(entry)

                if call_id:
                    pending[(thread_id, call_id)] = entry

            content = event.get("content")

            if content and not (event.get("tool_calls") or []):
                trace.append({
                    "step": "model.message",
                    "content": content,
                    "thread_id": thread_id,
                    "created_at": event.get("created_at"),
                })

        elif kind == "tool.response":
            call_id = event.get("tool_call_id")
            call = pending.get((thread_id, call_id), {})

            trace.append({
                "step": "tool.response",
                "tool": call.get("tool"),
                "thread_id": thread_id,
                "tool_call_id": call_id,
                "content": event.get("content"),
                "created_at": event.get("created_at"),
            })

        elif kind == "tool.approval_required":
            for call in event.get("tool_calls") or []:
                trace.append({
                    "step": "tool.approval_required",
                    "thread_id": thread_id,
                    "tool_call_id": call.get("id"),
                    "created_at": event.get("created_at"),
                })

        elif kind == "thread.created":
            parent = event.get("parent") or {}
            agent_info = event.get("agent_info") or {}

            trace.append({
                "step": "thread.created",
                "thread_id": event.get("thread_id"),
                "name": agent_info.get("name"),
                "parent_thread_id": parent.get("thread_id"),
                "parent_tool_call_id": parent.get("tool_call_id"),
                "created_at": event.get("created_at"),
            })

        elif kind == "thread.done":
            parent = event.get("parent") or {}

            trace.append({
                "step": "thread.done",
                "thread_id": event.get("thread_id"),
                "parent_thread_id": parent.get("thread_id"),
                "parent_tool_call_id": parent.get("tool_call_id"),
                "created_at": event.get("created_at"),
            })

        elif kind == "turn.done":
            state = event.get("state", {})

            trace.append({
                "step": "turn.done",
                "status": state.get("status"),
                "created_at": event.get("created_at"),
            })

        # Any other event type is ignored. New TrueForge event types must
        # never break an investigation trace.

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


def pending_approvals(turn: dict, trace: list) -> list:
    """The containment calls a turn is paused on, with their arguments.

    ``required_actions`` names the tool-call ids; the arguments live on the
    ``model.message`` that requested them, which the trace already carries.
    Joining the two gives a human enough to decide on.
    """

    state = turn.get("state", {})

    # Keyed by (thread_id, tool_call_id) for the same reason extract_trace
    # pairs on it: with more than one thread the id alone is ambiguous, and
    # resolving it wrongly would show the operator the arguments of a
    # different call than the one they are being asked to approve.
    calls_by_id = {
        (
            entry.get("thread_id", DEFAULT_THREAD_ID),
            entry.get("tool_call_id"),
        ): entry
        for entry in trace
        if entry.get("step") == "tool.call"
    }

    pending = []

    for action in state.get("required_actions") or []:
        if action.get("type") != "tool.approval_required":
            continue

        thread_id = action.get("thread_id", DEFAULT_THREAD_ID)

        for call in action.get("tool_calls") or []:
            call_id = call.get("id")
            requested = calls_by_id.get((thread_id, call_id), {})

            pending.append({
                "thread_id": thread_id,
                "tool_call_id": call_id,
                "tool": requested.get("tool"),
                "arguments": requested.get("arguments", {}),
            })

    return pending


def deny_all(pending: list, reason: str = "Denied by operator.") -> list:
    """A decision callback that refuses every containment request."""

    return [
        approval_item(
            item["thread_id"], item["tool_call_id"], False, reason
        )
        for item in pending
    ]


def allow_all(pending: list) -> list:
    """A decision callback that approves every containment request."""

    return [
        approval_item(item["thread_id"], item["tool_call_id"], True)
        for item in pending
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
                self.config.effective_agent_name,
                build_agent_spec(self.config),
            )

        except TrueForgeError as exc:
            raise SentinelAgentError(
                f"Could not create the Sentinel agent "
                f"'{self.config.effective_agent_name}': {exc}"
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

    def _advance_turn(
        self,
        session_id: str,
        turn_id: str,
        prior_events: list,
        emitted: int,
        on_trace,
    ) -> tuple:
        """Wait for a turn to settle, streaming its trace as it is recorded.

        Returns ``(turn, events, trace, emitted)``.

        ``extract_trace`` is a prefix-stable function of the event list: it
        walks events in order and appends entries, so the trace of a prefix
        of the events is a prefix of the trace of all of them. That is what
        makes incremental emission safe -- ``trace[emitted:]`` is exactly the
        journey the operator has not seen yet, never a re-ordering of what
        they have.

        With no ``on_trace`` callback this collapses to the original
        behaviour: wait for the turn, then read its events once.
        """

        if on_trace is None:
            turn = self.client.wait_for_turn(session_id, turn_id)
            events = prior_events + self.client.list_turn_events(
                session_id, turn_id
            )
            trace = extract_trace(events)

            return turn, events, trace, len(trace)

        deadline = time.monotonic() + self.config.timeout

        while True:
            turn = self.client.get_turn(session_id, turn_id)
            status = turn.get("state", {}).get("status")

            if status is None:
                raise TrueForgeProtocolError(
                    f"Turn {turn_id} has no state.status: {str(turn)[:200]!r}"
                )

            events = prior_events + self.client.list_turn_events(
                session_id, turn_id
            )
            trace = extract_trace(events)

            if len(trace) > emitted:
                on_trace(trace[emitted:])
                emitted = len(trace)

            if status != "running":
                return turn, events, trace, emitted

            if time.monotonic() >= deadline:
                raise TrueForgeTimeout(
                    f"Turn {turn_id} was still running after "
                    f"{self.config.timeout}s"
                )

            time.sleep(POLL_INTERVAL)

    def investigate(
        self,
        username: str,
        provision: bool = True,
        on_approval=None,
        max_approval_rounds: int = 4,
        on_trace=None,
    ) -> dict:
        """Run one investigation and return the response plus its trace.

        If the agent proposes a containment action, TrueForge pauses the turn
        and ``on_approval`` is called with the pending calls. It must return
        ``user.tool_approval`` items (see :func:`allow_all` / :func:`deny_all`
        / :func:`approval_item`). With no callback the run stops at the pause
        and reports what was requested -- nothing is ever auto-approved.

        ``on_trace`` is called with each batch of newly-recorded trace
        entries while the turn is still running, so a console can render the
        investigation as it happens. The entries are the same ones the
        returned ``trace`` contains -- nothing is synthesised for the live
        view that is absent from the final one.
        """

        if provision:
            self.provision()

        try:
            session = self.client.create_session(
                self.config.effective_agent_name
            )

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

        # Accumulated across every turn in this investigation. A resumed
        # turn carries the tool.response for a tool.call made in the turn
        # that paused, so the trace must be extracted from all of them
        # together or the pairing is lost.
        turn, events, trace, emitted = self._advance_turn(
            session_id, turn_id, [], 0, on_trace
        )
        approvals = []

        # ------------------------------------------------------------
        # Containment approval loop
        # ------------------------------------------------------------
        rounds = 0

        while True:
            pending = pending_approvals(turn, trace)

            if not pending or on_approval is None:
                break

            if rounds >= max_approval_rounds:
                break

            rounds += 1

            decisions = on_approval(pending)

            if not decisions:
                break

            for item, decision in zip(pending, decisions):
                approvals.append({
                    "tool": item["tool"],
                    "arguments": item["arguments"],
                    "tool_call_id": item["tool_call_id"],
                    "allowed": (
                        decision.get("approval", {}).get("status") == "allow"
                    ),
                    "reason": decision.get("approval", {}).get("reason"),
                })

            try:
                turn = self.client.resume_turn_with_approval(
                    session_id,
                    decisions,
                    previous_turn_id=turn_id,
                )

            except TrueForgeError as exc:
                raise SentinelAgentError(
                    f"Could not resume session {session_id} after a "
                    f"containment decision: {exc}"
                ) from exc

            turn_id = turn["id"]

            # Re-extract from the whole event history rather than appending
            # a per-turn trace: a tool.response in this turn belongs to a
            # tool.call recorded before the pause.
            turn, events, trace, emitted = self._advance_turn(
                session_id, turn_id, events, emitted, on_trace
            )

        state = turn.get("state", {})
        status = state.get("status")

        result = {
            "username": username,
            "session_id": session_id,
            "turn_id": turn_id,
            "status": status,
            "response": "",
            "tool_calls": summarize_tool_calls(trace),
            "approvals": approvals,
            "pending_approvals": pending_approvals(turn, trace),
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

        if result["pending_approvals"]:
            requested = [
                item["tool"] for item in result["pending_approvals"]
            ]
            result["error"] = (
                f"Turn is paused awaiting human approval for {requested}. "
                "Supply an on_approval callback (or use --approve/--deny) "
                "to decide."
            )

        result["response"] = _message_text(state.get("output"))

        return result
