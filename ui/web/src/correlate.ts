/**
 * The console's state machine: SSE events in, a rendered timeline out.
 *
 * This is deliberately a pure function of the event stream. Two consequences
 * matter:
 *
 *  - Replay is free. A reconnecting browser can re-run every event it has
 *    ever seen and land in exactly the same state, which is what makes the
 *    `seq`-based reconnect safe.
 *  - It is testable without a browser (see `tests/correlate.test.ts`).
 *
 * It computes nothing about security. The threat level and risk score are
 * copied from the `assessment` event, which the Python side lifted verbatim
 * out of the deterministic risk engine's own tool result.
 */

import type {
  Approval,
  Assessment,
  PendingAction,
  RunEvent,
  Status,
} from "./types";

/**
 * The root agent's thread, used when an event carries no id.
 *
 * Mirrors `DEFAULT_THREAD_ID` in trueforge/agent.py.
 */
export const MAIN_THREAD = "main";

export type ToolStatus = "running" | "done";

export interface ToolActivity {
  /** The TrueForge thread that made the call ("main" for the root agent). */
  threadId: string;
  toolCallId: string;
  tool: string;
  arguments: Record<string, unknown>;
  status: ToolStatus;
  /** Raw tool output, exactly as the MCP tool returned it. */
  content?: string;
  /** Key facts read out of `content`; empty when it is not JSON. */
  facts: { label: string; value: string }[];
  startedAt?: string;
  finishedAt?: string;
  durationMs?: number;
}

/**
 * One TrueForge thread. The root agent is always present; a delegated
 * investigation adds one per specialist subagent.
 *
 * This exists so the timeline can say *who* made a call. It is also why
 * tool results correlate on `(threadId, toolCallId)`: `tool_call_id` is
 * minted per conversation, so two threads can independently produce the
 * same one.
 */
export interface ThreadInfo {
  threadId: string;
  /** The subagent's display name, or null for the root agent. */
  name: string | null;
  parentThreadId: string | null;
  running: boolean;
}

export interface ApprovalRecord {
  gateId: string;
  pending: PendingAction[];
  outcome: "pending" | "approved" | "denied" | "timeout";
  reason?: string;
}

export type ItemKind =
  | "phase"
  | "tool"
  | "note"
  | "agent"
  | "approval"
  | "error";

export interface TimelineItem {
  id: string;
  kind: ItemKind;
  title: string;
  sub?: string;
  detail?: string;
  tool?: ToolActivity;
  approval?: ApprovalRecord;
  /** The thread this entry belongs to, for lane labelling. */
  threadId?: string;
}

export interface ConsoleState {
  status: Status;
  items: TimelineItem[];
  pending: PendingAction[];
  gateId: string | null;
  model: string | null;
  tools: string[];
  assessment: Assessment | null;
  response: string | null;
  approvals: Approval[];
  error: string | null;
  lastSeq: number;
  /** Threads seen so far, in the order TrueForge created them. */
  threads: ThreadInfo[];
}

export function initialState(): ConsoleState {
  return {
    status: "idle",
    items: [],
    pending: [],
    gateId: null,
    model: null,
    tools: [],
    assessment: null,
    response: null,
    approvals: [],
    error: null,
    lastSeq: 0,
    threads: [],
  };
}

/**
 * Name a thread for display.
 *
 * Falls back to a short form of the id when TrueForge gave the subagent no
 * name -- never to a role invented here. The console labels threads; it does
 * not decide what they were for.
 */
export function threadLabel(
  threads: ThreadInfo[],
  threadId: string | undefined,
): string | null {
  if (!threadId || threadId === MAIN_THREAD) return null;

  const known = threads.find((thread) => thread.threadId === threadId);

  if (known?.name) return known.name;

  return `thread ${threadId.slice(0, 8)}`;
}

/** What each tool is doing, in an operator's words rather than an API's. */
const PURPOSE: Record<string, string> = {
  get_login_history: "Reading login evidence",
  get_network_activity: "Corroborating with network intelligence",
  assess_user_risk: "Deterministic risk engine",
  get_account_status: "Verifying account containment state",
  get_ip_status: "Verifying whether the address is blocked",
  contain_account: "Proposing account containment",
  block_ip: "Proposing an IP block",
};

/** Explains, in an operator's words, what a containment tool will do. */
export const CONSEQUENCE: Record<string, string> = {
  contain_account:
    "Disables the account. The user is signed out and cannot log back in.",
  block_ip: "Blocks the address at the perimeter for all users.",
};

export function formatArguments(args: Record<string, unknown> = {}): string {
  return Object.entries(args)
    .map(([key, value]) => `${key}=${JSON.stringify(value)}`)
    .join(", ");
}

/**
 * Split a containment call's arguments into the target and the reason.
 *
 * A containment tool takes exactly one target argument plus a
 * `justification`. Separating them lets the approval card lead with *what*
 * is being acted on and give the *why* the room a full paragraph needs.
 *
 * Nothing is invented: an argument set without a justification yields an
 * empty `why`, which the card reports as a missing justification rather
 * than filling in.
 */
export function splitJustification(args: Record<string, unknown> = {}): {
  target: string;
  why: string;
} {
  const { justification, ...rest } = args;

  const target = Object.entries(rest)
    .map(([key, value]) =>
      typeof value === "string"
        ? `${key}=${value}`
        : `${key}=${JSON.stringify(value)}`,
    )
    .join(", ");

  return {
    target,
    why: typeof justification === "string" ? justification : "",
  };
}

export function formatCall(
  tool: string,
  args: Record<string, unknown> = {},
): string {
  return `${tool}(${formatArguments(args)})`;
}

/**
 * Read the notable fields out of a tool result.
 *
 * Only fields the payload actually contains are reported -- nothing is
 * inferred, defaulted or invented. A result that is not JSON yields no facts
 * at all, and the raw body is shown instead.
 */
export function describeResult(
  tool: string,
  content: string | null | undefined,
): { label: string; value: string }[] {
  if (!content) return [];

  let parsed: unknown;

  try {
    parsed = JSON.parse(content);
  } catch {
    return [];
  }

  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return [];
  }

  const body = parsed as Record<string, unknown>;
  const facts: { label: string; value: string }[] = [];

  const add = (label: string, value: unknown) => {
    if (value === undefined || value === null) return;
    facts.push({ label, value: String(value) });
  };

  if (body.error !== undefined) {
    add("error", body.error);
    return facts;
  }

  if (body.found === false) {
    add("found", "no record");
    return facts;
  }

  switch (tool) {
    case "get_login_history": {
      const user = body.user as Record<string, unknown> | undefined;
      add("user", user?.username);
      add("role", user?.role);
      add("normal device", user?.normal_device);
      add("normal location", user?.normal_location);
      if (Array.isArray(body.login_events)) {
        add("events returned", body.login_events.length);
      }
      break;
    }

    case "get_network_activity":
      add("ip", body.ip_address);
      add("reputation", body.reputation);
      add("known", body.known);
      add("country", body.country);
      add("connections", body.connection_count);
      break;

    case "assess_user_risk":
      add("threat level", body.threat_level);
      add("risk score", body.risk_score);
      if (Array.isArray(body.risk_factors)) {
        add("risk factors", body.risk_factors.length);
      }
      add("incomplete evidence", body.incomplete_evidence);
      break;

    case "get_account_status":
      add("contained", body.contained);
      if (Array.isArray(body.containment_actions)) {
        add("recorded actions", body.containment_actions.length);
      }
      break;

    // The read-back half of a containment action. `blocked` is what
    // actually confirms a block is in force -- block_ip's own return value
    // only reports what it attempted.
    case "get_ip_status":
      add("blocked", body.blocked);
      if (Array.isArray(body.containment_actions)) {
        add("recorded actions", body.containment_actions.length);
      }
      break;

    case "contain_account":
    case "block_ip":
      add("ok", body.ok);
      add("action", body.action);
      add("target", body.target);
      add("action id", body.action_id);
      add("recorded at", body.timestamp);
      break;

    default:
      break;
  }

  return facts;
}

function duration(from?: string, to?: string): number | undefined {
  if (!from || !to) return undefined;

  const start = Date.parse(from);
  const end = Date.parse(to);

  if (Number.isNaN(start) || Number.isNaN(end)) return undefined;
  if (end < start) return undefined;

  return end - start;
}

function push(
  state: ConsoleState,
  item: Omit<TimelineItem, "id">,
  seq: number,
): TimelineItem[] {
  return [...state.items, { ...item, id: `e${seq}` }];
}

/**
 * Fold one event into the console state.
 *
 * Events at or below `state.lastSeq` are ignored, which is what makes a
 * replayed backlog idempotent.
 */
export function reduce(state: ConsoleState, event: RunEvent): ConsoleState {
  if (event.seq <= state.lastSeq) return state;

  const next: ConsoleState = { ...state, lastSeq: event.seq };

  switch (event.kind) {
    case "phase":
      return {
        ...next,
        status: event.phase as Status,
        items: push(next, { kind: "phase", title: event.message }, event.seq),
      };

    case "provisioned":
      return {
        ...next,
        model: event.model,
        tools: event.tools,
        items: push(
          next,
          {
            kind: "note",
            title: "TrueForge agent ready",
            sub: `${event.model} · ${event.tools.length} MCP tools loaded`,
            detail: event.tools.join("\n"),
          },
          event.seq,
        ),
      };

    case "mcp_ready":
      return {
        ...next,
        items: push(
          next,
          {
            kind: "note",
            title: `MCP connected · ${event.server ?? "sentinel"}`,
            sub: event.transport ?? undefined,
          },
          event.seq,
        ),
      };

    case "tool_call": {
      const toolCallId = event.tool_call_id ?? `seq-${event.seq}`;
      const threadId = event.thread_id ?? MAIN_THREAD;
      const tool = event.tool ?? "(unnamed tool)";

      return {
        ...next,
        items: push(
          next,
          {
            kind: "tool",
            title: tool,
            sub: PURPOSE[tool],
            threadId,
            tool: {
              threadId,
              toolCallId,
              tool,
              arguments: event.arguments ?? {},
              status: "running",
              facts: [],
              startedAt: event.created_at,
            },
          },
          event.seq,
        ),
      };
    }

    case "tool_result": {
      const id = event.tool_call_id;
      const threadId = event.thread_id ?? MAIN_THREAD;
      let matched = false;

      const items = next.items.map((item) => {
        if (matched || !item.tool) return item;
        // A result belongs to the call with the same id *on the same
        // thread*. tool_call_id is minted per conversation, so two threads
        // can produce the same one; matching on it alone would attach a
        // subagent's result to the parent's call.
        if (id === null || item.tool.toolCallId !== id) return item;
        if (item.tool.threadId !== threadId) return item;
        if (item.tool.status === "done") return item;

        matched = true;

        return {
          ...item,
          tool: {
            ...item.tool,
            status: "done" as ToolStatus,
            content: event.content ?? undefined,
            facts: describeResult(item.tool.tool, event.content),
            finishedAt: event.created_at,
            durationMs: duration(item.tool.startedAt, event.created_at),
          },
        };
      });

      // A response with no matching call still deserves to be visible.
      if (!matched) {
        return {
          ...next,
          items: push(
            next,
            {
              kind: "tool",
              title: event.tool ?? "tool result",
              tool: {
                threadId,
                toolCallId: id ?? `seq-${event.seq}`,
                tool: event.tool ?? "(unknown)",
                arguments: {},
                status: "done",
                content: event.content ?? undefined,
                facts: describeResult(event.tool ?? "", event.content),
                finishedAt: event.created_at,
              },
            },
            event.seq,
          ),
        };
      }

      return { ...next, items };
    }

    case "agent_message":
      return {
        ...next,
        items: push(
          next,
          {
            kind: "agent",
            title: "Agent",
            detail: event.content,
            threadId: event.thread_id ?? MAIN_THREAD,
          },
          event.seq,
        ),
      };

    // A delegated investigation only. Recording the thread lets the
    // timeline attribute each call to the specialist that made it; a
    // linear run never emits these and renders exactly as before.
    case "thread_started": {
      const already = next.threads.some(
        (thread) => thread.threadId === event.thread_id,
      );

      return {
        ...next,
        threads: already
          ? next.threads
          : [
              ...next.threads,
              {
                threadId: event.thread_id,
                name: event.name,
                parentThreadId: event.parent_thread_id,
                running: true,
              },
            ],
        items: push(
          next,
          {
            kind: "note",
            title: `Specialist started · ${event.name ?? "subagent"}`,
            sub: "delegated investigation — its own TrueForge thread",
            threadId: event.thread_id,
          },
          event.seq,
        ),
      };
    }

    case "thread_finished":
      return {
        ...next,
        threads: next.threads.map((thread) =>
          thread.threadId === event.thread_id
            ? { ...thread, running: false }
            : thread,
        ),
        items: push(
          next,
          {
            kind: "note",
            title: "Specialist finished",
            threadId: event.thread_id,
          },
          event.seq,
        ),
      };

    case "assessment":
      return {
        ...next,
        assessment: {
          username: event.username,
          threat_level: event.threat_level,
          risk_score: event.risk_score,
          risk_factors: event.risk_factors,
          incomplete_evidence: event.incomplete_evidence,
        },
      };

    case "approval_required":
      return {
        ...next,
        status: "awaiting-approval",
        pending: event.pending,
        gateId: event.gate_id,
        items: push(
          next,
          {
            kind: "approval",
            title: "Human approval required",
            approval: {
              gateId: event.gate_id,
              pending: event.pending,
              outcome: "pending",
            },
          },
          event.seq,
        ),
      };

    case "decision":
      return {
        ...next,
        status: "resuming",
        pending: [],
        gateId: null,
        // The gate card stays in the timeline as the historical record of
        // what was asked and what the operator answered.
        items: next.items.map((item) =>
          item.approval?.gateId === event.gate_id
            ? {
                ...item,
                approval: {
                  ...item.approval,
                  outcome: event.allowed
                    ? ("approved" as const)
                    : ("denied" as const),
                  reason: event.reason || undefined,
                },
              }
            : item,
        ),
      };

    case "approval_timeout":
      return {
        ...next,
        status: "error",
        pending: [],
        gateId: null,
        error: event.message,
        items: next.items.map((item) =>
          item.approval?.gateId === event.gate_id
            ? {
                ...item,
                approval: { ...item.approval, outcome: "timeout" as const },
              }
            : item,
        ),
      };

    case "complete":
      return {
        ...next,
        status: "done",
        response: event.response,
        approvals: event.approvals ?? [],
      };

    case "error":
      return { ...next, status: "error", error: event.message };

    default:
      return next;
  }
}

export function reduceAll(
  state: ConsoleState,
  events: RunEvent[],
): ConsoleState {
  return events.reduce(reduce, state);
}
