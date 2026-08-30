"""Run an investigation in the background and publish it as events.

:class:`SentinelAgent.investigate` is synchronous and blocks on the human
decision through its ``on_approval`` callback. The console needs the opposite
shape: a request returns immediately, the browser follows along over SSE, and
the decision arrives later on a separate request.

:class:`InvestigationRun` bridges the two. The investigation runs on a worker
thread; ``on_approval`` blocks that thread on an :class:`threading.Event`
until the browser posts a decision. Nothing is ever auto-approved -- if the
operator never answers, the run stays paused until the gate times out, and
containment is not executed.

Two properties this module exists to guarantee:

* **A decision applies to the gate it was made at, and to no other one.**
  Every pause mints a fresh ``gate_id``; a decision must name it. See
  :meth:`InvestigationRun.decide`.
* **Every follower sees every event, exactly once, in order.** Events carry
  a monotonic ``seq`` so a reconnecting browser can replay the run and drop
  what it has already rendered.
"""

import json
import queue
import threading
import uuid

from trueforge.agent import SentinelAgent, SentinelAgentError
from trueforge.client import TrueForgeError, approval_item

# How long a paused run waits for a human before giving up, in seconds.
APPROVAL_TIMEOUT = 600.0

# Outcomes of InvestigationRun.decide. Three, not a boolean: "no gate is
# open" and "you answered a gate that has already closed" are different
# failures, and conflating them is what let a stale answer through before.
DECISION_ACCEPTED = "accepted"
DECISION_NO_GATE = "no-open-gate"
DECISION_STALE_GATE = "stale-gate"

# The MCP tool that runs Sentinel's deterministic risk engine. Its result is
# the authoritative verdict, so the runner lifts it out of the raw trace and
# republishes it structurally -- the console must never have to read a
# threat level out of the model's prose.
ASSESSMENT_TOOL = "assess_user_risk"


def parse_assessment(content) -> dict | None:
    """Extract the deterministic verdict from an ``assess_user_risk`` result.

    Returns the engine's own fields, unchanged, or ``None`` if the payload is
    not a completed assessment. Nothing here computes, adjusts or infers a
    score: every number is read verbatim from what
    :mod:`investigator.risk` produced, and a payload that lacks one is
    dropped rather than filled in.
    """

    if isinstance(content, str):
        try:
            content = json.loads(content)

        except (json.JSONDecodeError, ValueError):
            return None

    # An MCP result may arrive as a list of content blocks.
    if isinstance(content, list):
        for block in content:
            if isinstance(block, dict) and "text" in block:
                parsed = parse_assessment(block["text"])

                if parsed is not None:
                    return parsed

        return None

    if not isinstance(content, dict):
        return None

    if not content.get("found"):
        return None

    if "threat_level" not in content or "risk_score" not in content:
        return None

    return {
        "username": content.get("username"),
        "threat_level": content.get("threat_level"),
        "risk_score": content.get("risk_score"),
        "risk_factors": content.get("risk_factors", []),
        "incomplete_evidence": content.get("incomplete_evidence", False),
    }


class InvestigationRun:
    """One investigation, observable as a stream of events."""

    def __init__(self, username: str, agent_factory=SentinelAgent):
        self.id = uuid.uuid4().hex[:12]
        self.username = username
        self.status = "starting"

        self._agent_factory = agent_factory
        self._history: list = []
        self._followers: list[queue.Queue] = []
        self._lock = threading.Lock()
        self._seq = 0

        # Non-None only while a gate is open, and replaced for every gate.
        # An investigation can pause more than once, so a decision must
        # never outlive the gate it was made at.
        self._gate: threading.Event | None = None
        self._gate_id: str | None = None
        self._decisions: list | None = None

        self.pending: list = []
        self.result: dict | None = None
        self.error: str | None = None
        self.assessment: dict | None = None

    @property
    def gate_id(self) -> str | None:
        """The id of the currently open approval gate, if any."""

        with self._lock:
            return self._gate_id

    # -----------------------------------------------------------------
    # Event plumbing
    # -----------------------------------------------------------------

    def emit(self, kind: str, **payload) -> None:
        """Publish one event to every follower and to the replay history.

        Each event carries a monotonic ``seq``. A browser that reconnects
        replays the run from the start and skips anything at or below the
        last sequence it rendered, so a dropped connection costs neither a
        duplicate event nor a missing one.
        """

        # Appending to history and fanning out happen under one lock, so a
        # follower registering concurrently sees the event on exactly one
        # side of the boundary. The queues are unbounded; put never blocks.
        with self._lock:
            self._seq += 1
            event = {"seq": self._seq, "kind": kind, **payload}

            self._history.append(event)

            for follower in self._followers:
                follower.put(event)

    def history(self) -> list:
        """Events already emitted, so a late follower sees the whole run."""

        with self._lock:
            return list(self._history)

    def follow(self, timeout: float = 1.0):
        """Yield this run's events -- the backlog first, then live ones.

        Every follower gets its own queue. A shared queue would divide live
        events between two open tabs (or between a stale connection and the
        one that replaced it) instead of delivering each event to both, and
        a console that missed an ``approval_required`` would sit blank while
        the run waited on it.

        Registration happens under the same lock that appends to history, so
        each event arrives exactly once: in the backlog or on the queue,
        never both. ``None`` is yielded on idle so SSE can ping.
        """

        mine: queue.Queue = queue.Queue()

        with self._lock:
            backlog = list(self._history)
            self._followers.append(mine)

        try:
            yield from backlog

            while True:
                try:
                    yield mine.get(timeout=timeout)

                except queue.Empty:
                    yield None

        finally:
            with self._lock:
                if mine in self._followers:
                    self._followers.remove(mine)

    # -----------------------------------------------------------------
    # Live investigation activity
    # -----------------------------------------------------------------

    def _on_trace(self, entries: list) -> None:
        """Publish newly-recorded trace entries as they arrive.

        Called from the agent thread while the turn is still running. Every
        entry here came from an event TrueForge actually recorded -- this
        maps them onto the console's event vocabulary and adds nothing.

        ``thread_id`` rides along on the tool events because the console
        correlates a result to its call exactly the way
        :func:`trueforge.agent.extract_trace` does -- on
        ``(thread_id, tool_call_id)``, never on the id alone.
        """

        for entry in entries:
            step = entry.get("step")

            if step == "mcp.initialize":
                self.emit(
                    "mcp_ready",
                    server=entry.get("server"),
                    transport=entry.get("transport"),
                    created_at=entry.get("created_at"),
                )

            elif step == "tool.call":
                self.emit(
                    "tool_call",
                    thread_id=entry.get("thread_id"),
                    tool_call_id=entry.get("tool_call_id"),
                    tool=entry.get("tool"),
                    arguments=entry.get("arguments", {}),
                    created_at=entry.get("created_at"),
                )

            elif step == "tool.response":
                self.emit(
                    "tool_result",
                    thread_id=entry.get("thread_id"),
                    tool_call_id=entry.get("tool_call_id"),
                    tool=entry.get("tool"),
                    content=entry.get("content"),
                    created_at=entry.get("created_at"),
                )

                if entry.get("tool") == ASSESSMENT_TOOL:
                    self._publish_assessment(entry.get("content"))

            elif step == "model.message":
                self.emit(
                    "agent_message",
                    content=entry.get("content"),
                    created_at=entry.get("created_at"),
                )

    def _publish_assessment(self, content) -> None:
        """Republish the risk engine's verdict as structured data."""

        assessment = parse_assessment(content)

        if assessment is None:
            return

        self.assessment = assessment

        self.emit("assessment", **assessment)

    # -----------------------------------------------------------------
    # The approval gate
    # -----------------------------------------------------------------

    def _on_approval(self, pending: list) -> list:
        """Called by the agent thread when TrueForge pauses the turn.

        Each pause mints a fresh gate with its own id. The event, the id and
        the decision slot are all per-gate rather than per-run: an
        investigation can pause several times, and a decision that only had
        to find *some* open gate could be applied to a containment call the
        operator never saw.
        """

        gate = threading.Event()
        gate_id = uuid.uuid4().hex

        with self._lock:
            self.pending = list(pending)
            self._decisions = None
            self._gate = gate
            self._gate_id = gate_id
            self.status = "awaiting-approval"

        self.emit("approval_required", gate_id=gate_id, pending=pending)

        if not gate.wait(timeout=APPROVAL_TIMEOUT):
            with self._lock:
                # Retract the gate only if it is still this one.
                if self._gate is gate:
                    self._gate = None
                    self._gate_id = None
                    self.pending = []
                    self.status = "investigating"

            self.emit(
                "approval_timeout",
                gate_id=gate_id,
                message=(
                    "No decision within "
                    f"{int(APPROVAL_TIMEOUT / 60)} minutes; "
                    "containment was not executed."
                ),
            )

            return []

        with self._lock:
            decisions = self._decisions or []
            self._decisions = None

        return decisions

    def decide(self, gate_id: str, allowed: bool, reason: str = "") -> str:
        """Record the operator's decision and release the agent thread.

        ``gate_id`` must name the gate that is currently open. A decision is
        an answer to one specific containment request, not a standing
        instruction to approve whatever the agent asks next: if the gate the
        operator was looking at has already closed -- because they answered
        it a moment ago, or it timed out -- the answer is refused rather
        than applied to its successor.

        Returns :data:`DECISION_ACCEPTED`, :data:`DECISION_NO_GATE` or
        :data:`DECISION_STALE_GATE`.
        """

        with self._lock:
            gate = self._gate

            if gate is None:
                return DECISION_NO_GATE

            if gate_id != self._gate_id:
                return DECISION_STALE_GATE

            actions = [
                {"tool": item["tool"], "arguments": item["arguments"]}
                for item in self.pending
            ]

            self._decisions = [
                approval_item(
                    item["thread_id"],
                    item["tool_call_id"],
                    allowed,
                    reason or None,
                )
                for item in self.pending
            ]

            # Closing the gate under the same lock that read it means two
            # operators answering at once produce one decision, not two: the
            # second finds no open gate, or a different one.
            self._gate = None
            self._gate_id = None
            self.pending = []
            self.status = "resuming"

        self.emit(
            "decision",
            gate_id=gate_id,
            allowed=allowed,
            reason=reason,
            actions=actions,
        )

        gate.set()

        return DECISION_ACCEPTED

    # -----------------------------------------------------------------
    # Execution
    # -----------------------------------------------------------------

    def start(self) -> None:
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self) -> None:
        try:
            with self._agent_factory() as agent:
                self.status = "provisioning"
                self.emit(
                    "phase",
                    phase="provisioning",
                    message="Connecting to TrueForge",
                )

                details = agent.provision()

                self.emit(
                    "provisioned",
                    model=details["model"],
                    tools=details["tools"],
                )

                self.status = "investigating"
                self.emit(
                    "phase",
                    phase="investigating",
                    message=f"Investigating {self.username}",
                )

                result = agent.investigate(
                    self.username,
                    provision=False,
                    on_approval=self._on_approval,
                    on_trace=self._on_trace,
                )

            self.result = result
            self.status = "done"

            self.emit(
                "complete",
                response=result.get("response", ""),
                trace=result.get("trace", []),
                approvals=result.get("approvals", []),
            )

        except (SentinelAgentError, TrueForgeError) as exc:
            self.error = str(exc)
            self.status = "error"
            self.emit("error", message=str(exc))

        except Exception as exc:  # noqa: BLE001 - surface anything to the UI
            self.error = f"{type(exc).__name__}: {exc}"
            self.status = "error"
            self.emit("error", message=self.error)


class RunRegistry:
    """The console's in-memory set of investigations."""

    def __init__(self):
        self._runs: dict = {}
        self._lock = threading.Lock()

    def create(self, username: str, agent_factory=SentinelAgent):
        run = InvestigationRun(username, agent_factory=agent_factory)

        with self._lock:
            self._runs[run.id] = run

        return run

    def get(self, run_id: str):
        with self._lock:
            return self._runs.get(run_id)
