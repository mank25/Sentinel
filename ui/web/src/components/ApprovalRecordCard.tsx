import type { ApprovalRecord } from "../correlate";
import { CONSEQUENCE, formatCall } from "../correlate";

const OUTCOME: Record<
  ApprovalRecord["outcome"],
  { label: string; className: string }
> = {
  pending: { label: "Waiting for operator decision…", className: "pending" },
  approved: { label: "APPROVED — executed", className: "approved" },
  denied: { label: "DENIED — not executed", className: "denied" },
  timeout: { label: "TIMED OUT — not executed", className: "denied" },
};

/**
 * The permanent record of one approval gate.
 *
 * It is written into the timeline the moment the gate opens and stays there
 * afterwards, so the history shows what was asked and what the human
 * answered -- not just that the run continued.
 */
export function ApprovalRecordCard({ record }: { record: ApprovalRecord }) {
  const outcome = OUTCOME[record.outcome];

  return (
    <div className={`gate-record ${outcome.className}`}>
      <div className="title">Human approval required</div>

      {record.pending.map((action) => (
        <div className="record-action" key={action.tool_call_id}>
          <code>{formatCall(action.tool, action.arguments)}</code>
          <div className="why">
            {CONSEQUENCE[action.tool] ?? "This action changes system state."}
          </div>
        </div>
      ))}

      <div className={`record-outcome ${outcome.className}`}>
        {outcome.label}
        {record.reason ? ` — ${record.reason}` : ""}
      </div>
    </div>
  );
}
