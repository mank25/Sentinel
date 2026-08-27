/** The event stream the Python console publishes over SSE. */

export interface ToolCall {
  step: string;
  tool?: string;
  arguments?: Record<string, unknown>;
  result?: unknown;
  tool_call_id?: string;
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

export type RunEvent =
  | { kind: "phase"; phase: string; message: string }
  | { kind: "provisioned"; model: string; tools: string[] }
  | { kind: "approval_required"; pending: PendingAction[] }
  | { kind: "approval_timeout"; message: string }
  | {
      kind: "decision";
      allowed: boolean;
      reason: string;
      actions: { tool: string; arguments: Record<string, unknown> }[];
    }
  | {
      kind: "complete";
      response: string;
      trace: ToolCall[];
      approvals: Approval[];
    }
  | { kind: "error"; message: string };

export type Status =
  | "idle"
  | "provisioning"
  | "investigating"
  | "awaiting-approval"
  | "resuming"
  | "done"
  | "error";
