"""Run an investigation in the background and publish it as events.

:class:`SentinelAgent.investigate` is synchronous and blocks on the human
decision through its ``on_approval`` callback. The console needs the opposite
shape: a request returns immediately, the browser follows along over SSE, and
the decision arrives later on a separate request.

:class:`InvestigationRun` bridges the two. The investigation runs on a worker
thread; ``on_approval`` blocks that thread on an :class:`threading.Event`
until the browser posts a decision. Nothing is ever auto-approved -- if the
operator never answers, the run stays paused until it is cancelled.
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
        self._events: queue.Queue = queue.Queue()
        self._history: list = []
        self._lock = threading.Lock()

        # Set when the operator decides; carries the decision items.
        self._decided = threading.Event()
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

        with self._lock:
            self._history.append(event)

        self._events.put(event)

    def history(self) -> list:
        """Events already emitted, so a late follower sees the whole run."""

        with self._lock:
            return list(self._history)

    def follow(self, timeout: float = 1.0):
        """Yield events as they arrive; ``None`` on idle so SSE can ping."""

        while True:
            try:
                yield self._events.get(timeout=timeout)

            except queue.Empty:
                yield None

    # -----------------------------------------------------------------
    # The approval gate
    # -----------------------------------------------------------------

    def _on_approval(self, pending: list) -> list:
        """Called by the agent thread when TrueForge pauses the turn."""

        self.pending = pending
        self.status = "awaiting-approval"
        self.emit("approval_required", pending=pending)

        # Block the investigation until a human answers.
        if not self._decided.wait(timeout=APPROVAL_TIMEOUT):
            self.emit(
                "approval_timeout",
                message=(
                    "No decision within "
                    f"{int(APPROVAL_TIMEOUT / 60)} minutes; "
                    "containment was not executed."
                ),
            )
            return []

        return self._decisions or []

    def decide(self, allowed: bool, reason: str = "") -> bool:
        """Record the operator's decision and release the agent thread."""

        if self.status != "awaiting-approval":
            return False

        self._decisions = [
            approval_item(
                item["thread_id"],
                item["tool_call_id"],
                allowed,
                reason or None,
            )
            for item in self.pending
        ]

        self.status = "resuming"
        self.emit(
            "decision",
            allowed=allowed,
            reason=reason,
            actions=[
                {"tool": item["tool"], "arguments": item["arguments"]}
                for item in self.pending
            ],
        )

        self._decided.set()

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
