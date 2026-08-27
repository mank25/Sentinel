import { useCallback, useEffect, useRef, useState } from "react";
import { followRun, sendDecision, startInvestigation } from "./api";
import { ApprovalGate } from "./components/ApprovalGate";
import {
  formatCall,
  summarize,
  Timeline,
  type TimelineItem,
} from "./components/Timeline";
import { Verdict } from "./components/Verdict";
import type { Approval, PendingAction, RunEvent, Status } from "./types";

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

export default function App() {
  const [username, setUsername] = useState("admin");
  const [status, setStatus] = useState<Status>("idle");
  const [items, setItems] = useState<TimelineItem[]>([]);
  const [pending, setPending] = useState<PendingAction[]>([]);
  const [model, setModel] = useState<string | null>(null);
  const [tools, setTools] = useState<string[]>([]);
  const [response, setResponse] = useState<string | null>(null);
  const [approvals, setApprovals] = useState<Approval[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [deciding, setDeciding] = useState(false);

  const runId = useRef<string | null>(null);
  const close = useRef<(() => void) | null>(null);
  const seq = useRef(0);
  const bottom = useRef<HTMLDivElement>(null);

  const push = useCallback((item: Omit<TimelineItem, "id">) => {
    seq.current += 1;
    setItems((current) => [...current, { ...item, id: `e${seq.current}` }]);
  }, []);

  useEffect(() => {
    bottom.current?.scrollIntoView({ behavior: "smooth" });
  }, [items, pending, response]);

  useEffect(() => () => close.current?.(), []);

  const handleEvent = useCallback(
    (event: RunEvent) => {
      switch (event.kind) {
        case "phase":
          setStatus(event.phase as Status);
          push({ kind: "phase", title: event.message });
          break;

        case "provisioned":
          setModel(event.model);
          setTools(event.tools);
          push({
            kind: "result",
            title: "TrueForge ready",
            sub: `${event.model} · ${event.tools.length} MCP tools loaded`,
            detail: event.tools.join("\n"),
          });
          break;

        case "approval_required":
          setStatus("awaiting-approval");
          setPending(event.pending);
          break;

        case "approval_timeout":
          setStatus("error");
          setPending([]);
          setError(event.message);
          break;

        case "decision":
          setPending([]);
          setStatus("resuming");
          event.actions.forEach((action) =>
            push({
              kind: "decision",
              title: `${event.allowed ? "Approved" : "Denied"}: ${action.tool}`,
              sub: event.reason || undefined,
            }),
          );
          break;

        case "complete":
          event.trace
            .filter((call) => call.step === "tool.call" && call.tool)
            .forEach((call) =>
              push({
                kind: "tool",
                title: formatCall(call),
                detail: summarize(call.result),
              }),
            );
          setResponse(event.response);
          setApprovals(event.approvals ?? []);
          setStatus("done");
          break;

        case "error":
          // Clear the gate: a dead run must not leave clickable
          // Approve/Deny buttons behind, which would only earn a 409.
          setPending([]);
          setError(event.message);
          setStatus("error");
          break;
      }
    },
    [push],
  );

  const run = async () => {
    if (!username.trim()) return;

    close.current?.();
    setItems([]);
    setPending([]);
    setResponse(null);
    setApprovals([]);
    setError(null);
    setStatus("provisioning");

    try {
      const started = await startInvestigation(username.trim());
      runId.current = started.id;
      close.current = followRun(started.id, handleEvent);
    } catch (exc) {
      setError((exc as Error).message);
      setStatus("error");
    }
  };

  const decide = async (allowed: boolean, reason: string) => {
    if (!runId.current) return;

    setDeciding(true);

    try {
      await sendDecision(runId.current, allowed, reason);
    } catch (exc) {
      setError((exc as Error).message);
    } finally {
      setDeciding(false);
    }
  };

  const busy =
    status === "provisioning" ||
    status === "investigating" ||
    status === "resuming" ||
    status === "awaiting-approval";

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <h1>Sentinel</h1>
          <span>AI Security Investigator</span>
        </div>

        <div className="pills">
          <span className="pill">
            <span className={`dot ${DOT[status]}`} />
            {LABEL[status]}
          </span>
          {model && <span className="pill">{model}</span>}
          {tools.length > 0 && (
            <span className="pill">
              <span className="dot on" />
              {tools.length} MCP tools
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
        {error && <div className="banner">{error}</div>}

        {items.length === 0 && !error && (
          <div className="empty">
            <h2>No investigation running</h2>
            <p>
              Enter a username and run an investigation. Sentinel reads
              evidence through read-only MCP tools and pauses for your
              approval before any containment action.
            </p>
          </div>
        )}

        <Timeline items={items} />

        {pending.length > 0 && (
          <ApprovalGate
            pending={pending}
            onDecide={decide}
            busy={deciding}
          />
        )}

        {response && (
          <Verdict
            username={username}
            response={response}
            approvals={approvals}
          />
        )}

        <div ref={bottom} />
      </main>
    </div>
  );
}
