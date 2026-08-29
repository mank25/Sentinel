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
"""

import queue
import threading
import uuid

from trueforge.agent import SentinelAgent, SentinelAgentError
from trueforge.client import TrueForgeError, approval_item

# How long a paused run waits for a human before giving up, in seconds.
APPROVAL_TIMEOUT = 600.0


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

        # Non-None only while a gate is open, and replaced for every gate.
        # An investigation can pause more than once, so a decision must
        # never outlive the gate it was made at.
        self._gate: threading.Event | None = None
        self._decisions: list | None = None

        self.pending: list = []
        self.result: dict | None = None
        self.error: str | None = None

    # -----------------------------------------------------------------
    # Event plumbing
    # -----------------------------------------------------------------

    def emit(self, kind: str, **payload) -> None:
        """Publish one event to every follower and to the replay history."""

        event = {"kind": kind, **payload}

        # Appending to history and fanning out happen under one lock, so a
        # follower registering concurrently sees the event on exactly one
        # side of the boundary. The queues are unbounded; put never blocks.
        with self._lock:
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
    # The approval gate
    # -----------------------------------------------------------------

    def _on_approval(self, pending: list) -> list:
        """Called by the agent thread when TrueForge pauses the turn.

        Each pause opens a fresh gate. The event and the decision slot are
        per-gate rather than per-run: an investigation can pause several
        times, and reusing them would let the first answer resume a later
        gate immediately, carrying the earlier round's tool call ids.
        """

        gate = threading.Event()

        with self._lock:
            self.pending = list(pending)
            self._decisions = None
            self._gate = gate
            self.status = "awaiting-approval"

        self.emit("approval_required", pending=pending)

        if not gate.wait(timeout=APPROVAL_TIMEOUT):
            with self._lock:
                # Retract the gate only if it is still this one.
                if self._gate is gate:
                    self._gate = None
                    self.pending = []
                    self.status = "investigating"

            self.emit(
                "approval_timeout",
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

    def decide(self, allowed: bool, reason: str = "") -> bool:
        """Record the operator's decision and release the agent thread.

        False means no gate was open. A stray decision is dropped rather
        than held, so it can never be applied to a later containment call
        the operator has not seen.
        """

        with self._lock:
            gate = self._gate

            if gate is None:
                return False

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
            # operators answering at once produce one decision, not two.
            self._gate = None
            self.pending = []
            self.status = "resuming"

        self.emit("decision", allowed=allowed, reason=reason, actions=actions)

        gate.set()

        return True

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
