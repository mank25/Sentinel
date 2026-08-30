import { useCallback, useEffect, useRef, useState } from "react";
import { followRun, sendDecision, startInvestigation } from "./api";
import { initialState, reduce, type ConsoleState } from "./correlate";
import { Landing } from "./components/Landing";
import { IncidentHeader } from "./components/IncidentHeader";
import { ReportPane } from "./components/ReportPane";
import { Timeline } from "./components/Timeline";
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

/** The only account in data/security.db. See data/init_db.py. */
const SEEDED_USER = "admin";

const ACTIVE: Status[] = [
  "provisioning",
  "investigating",
  "awaiting-approval",
  "resuming",
];

/** The console lives at `#console`; everything else is the landing page.
 *
 * Hash routing, not paths: ui/server.py serves the built app from `/` alone,
 * so a deep path would 404 on reload. The `?token=` query the console needs
 * survives a hash change untouched. */
function useView(): "landing" | "console" {
  const read = () =>
    window.location.hash === "#console" ? "console" : "landing";

  const [view, setView] = useState<"landing" | "console">(read);

  useEffect(() => {
    const onHash = () => setView(read());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  return view;
}

export default function App() {
  const view = useView();
  const [username, setUsername] = useState("admin");
  const [state, setState] = useState<ConsoleState>(initialState);
  const [link, setLink] = useState<Link>("closed");
  const [deciding, setDeciding] = useState(false);

  const runId = useRef<string | null>(null);
  const close = useRef<(() => void) | null>(null);
  const bottom = useRef<HTMLDivElement>(null);
  const report = useRef<HTMLDivElement>(null);

  const busy = ACTIVE.includes(state.status);

  // The demo evidence database seeds exactly one account. Any other name
  // reaches the tools and comes back empty, which looks like a broken run
  // rather than an empty one -- so say so before the button is pressed.
  const unseeded = username.trim().toLowerCase() !== SEEDED_USER;

  // Follow the run while it is live; stop pulling the view down once it is
  // finished, so the operator can read the timeline without fighting it.
  useEffect(() => {
    if (!busy) return;
    bottom.current?.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }, [state.items, state.pending, state.status, busy]);

  // A gate that opens while the report pane is scrolled down would be asked
  // silently. Put it back at the top, where the request now lives.
  useEffect(() => {
    if (state.gateId) report.current?.scrollTo({ top: 0, behavior: "smooth" });
  }, [state.gateId]);

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

  if (view === "landing") {
    return (
      <Landing
        onEnter={() => {
          window.location.hash = "console";
          window.scrollTo({ top: 0 });
        }}
      />
    );
  }

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <h1>Sentinel</h1>
          <span>AI Security Investigator</span>
          <a className="topnav-back" href="#">
            ← overview
          </a>
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

        {unseeded ? (
          <p className="launcher-note warn">
            Only <code>admin</code> has evidence in this database.{" "}
            <button
              type="button"
              className="linkish"
              onClick={() => setUsername(SEEDED_USER)}
              disabled={busy}
            >
              Use admin
            </button>
          </p>
        ) : (
          <p className="launcher-note">
            The seeded incident — 47 failed logins, then one success from a
            flagged IP.
          </p>
        )}
      </div>

      {state.error && <div className="banner">{state.error}</div>}

      {state.status !== "idle" && (
        <IncidentHeader
          username={username}
          assessment={state.assessment}
          status={state.status}
          threads={state.threads}
        />
      )}

      {/* Two instruments side by side: what the agent is doing, and what it
          has established. The approval request lands in the report, next to
          the score it has to be judged against. */}
      <div className="console">
        <section className="pane pane-feed">
          <header className="pane-head">
            <span className="pane-title">Investigation feed</span>
            <span className="pane-meta">
              {state.items.length > 0
                ? `${state.items.length} event${state.items.length === 1 ? "" : "s"}`
                : "no activity"}
              {busy && <span className="dot busy" />}
            </span>
          </header>

          <div className="pane-body">
            {state.items.length === 0 ? (
              <div className="empty">
                <h2>Nothing under investigation</h2>
                <p>
                  Enter a username above and run it. Sentinel pulls evidence
                  through read-only MCP tools, and every tool call it makes
                  appears here as TrueForge records it.
                </p>
              </div>
            ) : (
              <Timeline items={state.items} threads={state.threads} />
            )}
            <div ref={bottom} />
          </div>
        </section>

        <section
          className={`pane pane-report${
            state.pending.length > 0 ? " holding" : ""
          }`}
        >
          <header className="pane-head">
            <span className="pane-title">Incident report</span>
            <span className="pane-meta">
              {state.pending.length > 0 ? (
                <span className="pane-hold">
                  <span className="dot wait" />
                  your decision required
                </span>
              ) : (
                LABEL[state.status]
              )}
            </span>
          </header>

          <div className="pane-body" ref={report}>
            <ReportPane
              username={username}
              assessment={state.assessment}
              response={state.response}
              approvals={state.approvals}
              status={state.status}
              pending={state.pending}
              gateId={state.gateId}
              threads={state.threads}
              onDecide={decide}
              deciding={deciding}
            />
          </div>
        </section>
      </div>
    </div>
  );
}
