import { useCallback, useEffect, useRef, useState } from "react";
import { followRun, sendDecision, startInvestigation } from "./api";
import { initialState, reduce, type ConsoleState } from "./correlate";
import { ApprovalGate } from "./components/ApprovalGate";
import { Timeline } from "./components/Timeline";
import { Verdict } from "./components/Verdict";
import type { Link, RunEvent, Status } from "./types";

const DOT: Record<Status, string> = {
  idle: "",
  provisioning: "busy",
  investigating: "busy",
  "awaiting-approval": "wait",
  resuming: "busy",
  done: "on",
  error: "bad",
};

const LABEL: Record<Status, string> = {
  idle: "idle",
  provisioning: "provisioning",
  investigating: "investigating",
  "awaiting-approval": "awaiting approval",
  resuming: "resuming",
  done: "complete",
  error: "error",
};

const ACTIVE: Status[] = [
  "provisioning",
  "investigating",
  "awaiting-approval",
  "resuming",
];

export default function App() {
  const [username, setUsername] = useState("admin");
  const [state, setState] = useState<ConsoleState>(initialState);
  const [link, setLink] = useState<Link>("closed");
  const [deciding, setDeciding] = useState(false);

  const runId = useRef<string | null>(null);
  const close = useRef<(() => void) | null>(null);
  const bottom = useRef<HTMLDivElement>(null);

  const busy = ACTIVE.includes(state.status);

  // Follow the run while it is live; stop pulling the view down once it is
  // finished, so the operator can read the timeline without fighting it.
  useEffect(() => {
    if (!busy) return;
    bottom.current?.scrollIntoView({ behavior: "smooth" });
  }, [state.items, state.pending, state.status, busy]);

  useEffect(() => () => close.current?.(), []);

  const onEvent = useCallback((event: RunEvent) => {
    setState((current) => reduce(current, event));
  }, []);

  const run = async () => {
    if (!username.trim()) return;

    close.current?.();
    setState({ ...initialState(), status: "provisioning" });
    setLink("closed");

    try {
      const started = await startInvestigation(username.trim());
      runId.current = started.id;
      close.current = followRun(started.id, { onEvent, onLink: setLink });
    } catch (exc) {
      setState((current) => ({
        ...current,
        status: "error",
        error: (exc as Error).message,
      }));
    }
  };

  const decide = async (allowed: boolean, reason: string) => {
    if (!runId.current || !state.gateId) return;

    setDeciding(true);

    try {
      await sendDecision(runId.current, state.gateId, allowed, reason);
    } catch (exc) {
      setState((current) => ({
        ...current,
        error: (exc as Error).message,
      }));
    } finally {
      setDeciding(false);
    }
  };

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <h1>Sentinel</h1>
          <span>AI Security Investigator</span>
        </div>

        <div className="pills">
          <span className="pill">
            <span className={`dot ${DOT[state.status]}`} />
            {LABEL[state.status]}
          </span>
          {link === "reconnecting" && (
            <span className="pill warn">
              <span className="dot wait" />
              reconnecting…
            </span>
          )}
          {state.model && <span className="pill">{state.model}</span>}
          {state.tools.length > 0 && (
            <span className="pill">
              <span className="dot on" />
              {state.tools.length} MCP tools
            </span>
          )}
        </div>
      </header>

      <div className="launcher">
        <label htmlFor="username">Investigate</label>
        <input
          id="username"
          type="text"
          value={username}
          onChange={(event) => setUsername(event.target.value)}
          onKeyDown={(event) => event.key === "Enter" && !busy && run()}
          placeholder="username"
          disabled={busy}
        />
        <button className="btn-primary" onClick={run} disabled={busy}>
          {busy ? "Running…" : "Run investigation"}
        </button>
      </div>

      <main className="main">
        {state.error && <div className="banner">{state.error}</div>}

        {state.items.length === 0 && !state.error && (
          <div className="empty">
            <h2>No investigation running</h2>
            <p>
              Enter a username and run an investigation. Sentinel reads
              evidence through read-only MCP tools and pauses for your
              approval before any containment action.
            </p>
          </div>
        )}

        <Timeline items={state.items} />

        {state.pending.length > 0 && (
          <ApprovalGate
            pending={state.pending}
            gateId={state.gateId}
            onDecide={decide}
            busy={deciding}
          />
        )}

        {(state.response || state.assessment) && state.status === "done" && (
          <Verdict
            username={username}
            assessment={state.assessment}
            response={state.response}
            approvals={state.approvals}
          />
        )}

        <div ref={bottom} />
      </main>
    </div>
  );
}
