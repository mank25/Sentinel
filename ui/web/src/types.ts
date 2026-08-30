/** The event stream the Python console publishes over SSE.
 *
 * Every event carries a monotonic `seq`. The browser records the highest one
 * it has rendered, so a reconnect can replay the whole run and discard the
 * part it already drew -- no duplicates, no gaps, order preserved.
 */

export interface TraceEntry {
  step: string;
  tool?: string;
  arguments?: Record<string, unknown>;
  content?: string;
  tool_call_id?: string;
  created_at?: string;
}

export interface PendingAction {
  thread_id: string;
  tool_call_id: string;
  tool: string;
  arguments: Record<string, unknown>;
}

export interface Approval {
  tool: string;
  arguments: Record<string, unknown>;
  allowed: boolean;
  reason?: string | null;
}

export interface RiskFactor {
  factor: string;
  points: number;
  reason: string;
}

/**
 * The deterministic risk engine's verdict, republished verbatim from the
 * `assess_user_risk` tool result. Never derived from the model's prose, and
 * never recomputed here.
 */
export interface Assessment {
  username: string | null;
  threat_level: string;
  risk_score: number;
  risk_factors: RiskFactor[];
  incomplete_evidence: boolean;
}

interface Seq {
  seq: number;
}

export type RunEvent = Seq &
  (
    | { kind: "phase"; phase: string; message: string }
    | { kind: "provisioned"; model: string; tools: string[] }
    | {
        kind: "mcp_ready";
        server: string | null;
        transport: string | null;
        created_at?: string;
      }
    | {
        kind: "tool_call";
        thread_id: string | null;
        tool_call_id: string | null;
        tool: string | null;
        arguments: Record<string, unknown>;
        created_at?: string;
      }
    | {
        kind: "tool_result";
        thread_id: string | null;
        tool_call_id: string | null;
        tool: string | null;
        content: string | null;
        created_at?: string;
      }
    | { kind: "agent_message"; content: string; created_at?: string }
    | ({ kind: "assessment" } & Assessment)
    | {
        kind: "approval_required";
        gate_id: string;
        pending: PendingAction[];
      }
    | { kind: "approval_timeout"; gate_id: string; message: string }
    | {
        kind: "decision";
        gate_id: string;
        allowed: boolean;
        reason: string;
        actions: { tool: string; arguments: Record<string, unknown> }[];
      }
    | {
        kind: "complete";
        response: string;
        trace: TraceEntry[];
        approvals: Approval[];
      }
    | { kind: "error"; message: string }
  );

export type Status =
  | "idle"
  | "provisioning"
  | "investigating"
  | "awaiting-approval"
  | "resuming"
  | "done"
  | "error";

/** Set when the stream drops and the browser is retrying. */
export type Link = "live" | "reconnecting" | "closed";
