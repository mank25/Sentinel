import { useState } from "react";
import { CONSEQUENCE, formatCall } from "../correlate";
import type { PendingAction } from "../types";

interface Props {
  pending: PendingAction[];
  gateId: string | null;
  onDecide: (allowed: boolean, reason: string) => void;
  busy: boolean;
}

/**
 * The live decision point.
 *
 * `gateId` identifies the exact containment request on the table. It is sent
 * with the decision, and the server refuses an answer that names any other
 * gate -- so this card can only ever approve what it is currently showing.
 */
export function ApprovalGate({ pending, gateId, onDecide, busy }: Props) {
  const [reason, setReason] = useState("");

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
            <code>{formatCall(action.tool, action.arguments)}</code>
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
            disabled={busy || !gateId}
          >
            Deny
          </button>
          <button
            className="btn-approve"
            onClick={() => onDecide(true, reason)}
            disabled={busy || !gateId}
          >
            Approve &amp; execute
          </button>
        </div>

        {gateId && <div className="gate-id">gate {gateId.slice(0, 8)}</div>}
      </div>
    </section>
  );
}
