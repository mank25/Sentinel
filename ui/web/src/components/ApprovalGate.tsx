import { useState } from "react";
import type { PendingAction } from "../types";

/** Explains, in an operator's words, what a containment tool will do. */
const CONSEQUENCE: Record<string, string> = {
  contain_account:
    "Disables the account. The user is signed out and cannot log back in.",
  block_ip: "Blocks the address at the perimeter for all users.",
};

interface Props {
  pending: PendingAction[];
  onDecide: (allowed: boolean, reason: string) => void;
  busy: boolean;
}

export function ApprovalGate({ pending, onDecide, busy }: Props) {
  const [reason, setReason] = useState("");

  const format = (action: PendingAction) => {
    const args = Object.entries(action.arguments ?? {})
      .map(([key, value]) => `${key}=${JSON.stringify(value)}`)
      .join(", ");

    return `${action.tool}(${args})`;
  };

  return (
    <section className="gate" role="alertdialog" aria-live="assertive">
      <header className="gate-head">
        <span className="dot wait" />
        Approval required
      </header>

      <div className="gate-body">
        <p>
          The investigation is paused. Sentinel proposes the following
          action, which cannot be undone. It will not run unless you
          approve it.
        </p>

        {pending.map((action) => (
          <div className="action" key={action.tool_call_id}>
            <code>{format(action)}</code>
            <div className="why">
              {CONSEQUENCE[action.tool] ??
                "This action changes system state."}
            </div>
          </div>
        ))}

        <div className="gate-controls">
          <input
            type="text"
            placeholder="Reason (sent to the agent on denial)"
            value={reason}
            onChange={(event) => setReason(event.target.value)}
            disabled={busy}
          />
          <button
            className="btn-deny"
            onClick={() => onDecide(false, reason)}
            disabled={busy}
          >
            Deny
          </button>
          <button
            className="btn-approve"
            onClick={() => onDecide(true, reason)}
            disabled={busy}
          >
            Approve &amp; execute
          </button>
        </div>
      </div>
    </section>
  );
}
