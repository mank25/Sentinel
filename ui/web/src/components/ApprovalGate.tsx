import { useState } from "react";
import { CONSEQUENCE, splitJustification, threadLabel } from "../correlate";
import type { ThreadInfo } from "../correlate";
import type { Assessment, PendingAction } from "../types";

interface Props {
  pending: PendingAction[];
  gateId: string | null;
  assessment: Assessment | null;
  threads: ThreadInfo[];
  onDecide: (allowed: boolean, reason: string) => void;
  busy: boolean;
}

/**
 * The decision point.
 *
 * This is the screen the whole project exists to put in front of a person,
 * so it shows everything a decision needs and nothing it does not: what is
 * being asked, against what target, why (the agent's own justification, in
 * full — never truncated), the deterministic engine's score, the factors
 * behind that score, and what approving will actually do.
 *
 * `gateId` identifies the exact request on the table. It is sent with the
 * decision, and the server refuses an answer naming any other gate, so this
 * card can only ever approve what it is currently showing.
 *
 * Nothing here is computed. The risk numbers come from the `assessment`
 * event, which the Python side lifted verbatim out of the risk engine's own
 * tool result; the justification is the argument the agent passed to the
 * tool.
 */
export function ApprovalGate({
  pending,
  gateId,
  assessment,
  threads,
  onDecide,
  busy,
}: Props) {
  const [reason, setReason] = useState("");

  const scoring = (assessment?.risk_factors ?? []).filter(
    (factor) => factor.points > 0,
  );

  return (
    <section className="gate" role="alertdialog" aria-live="assertive">
      <header className="gate-head">
        <span className="dot wait" />
        Action requires approval
        <span className="gate-head-note">
          The investigation is paused. Nothing runs until you decide.
        </span>
      </header>

      <div className="gate-body">
        {pending.map((action) => {
          const { target, why } = splitJustification(action.arguments);
          const lane = threadLabel(threads, action.thread_id);

          return (
            <article className="gate-action" key={action.tool_call_id}>
              <dl className="gate-fields">
                <div className="gate-field">
                  <dt>Action</dt>
                  <dd>
                    <code>{action.tool}</code>
                    {lane && <span className="gate-lane">via {lane}</span>}
                  </dd>
                </div>

                <div className="gate-field">
                  <dt>Target</dt>
                  <dd>
                    {target ? (
                      <code className="gate-target">{target}</code>
                    ) : (
                      <span className="dim">not specified</span>
                    )}
                  </dd>
                </div>

                <div className="gate-field wide">
                  <dt>Why</dt>
                  <dd>
                    {/* The agent's case, in full. A decision made on a
                        truncated reason is not an informed decision. */}
                    {why || (
                      <span className="dim">
                        The agent gave no justification. That alone is a
                        reason to deny.
                      </span>
                    )}
                  </dd>
                </div>

                {assessment && (
                  <div className="gate-field">
                    <dt>Risk</dt>
                    <dd>
                      <span className={`level ${assessment.threat_level}`}>
                        {assessment.threat_level}
                      </span>
                      <span className="gate-score">
                        {assessment.risk_score} / 100
                      </span>
                      <span className="gate-provenance">
                        investigator/risk.py
                      </span>
                    </dd>
                  </div>
                )}

                <div className="gate-field wide">
                  <dt>Effect</dt>
                  <dd>
                    {CONSEQUENCE[action.tool] ??
                      "This action changes system state."}
                  </dd>
                </div>
              </dl>

              {scoring.length > 0 && (
                <details className="gate-evidence" open>
                  <summary>
                    Evidence — {scoring.length} factor
                    {scoring.length === 1 ? "" : "s"} from the risk engine
                  </summary>
                  <ul>
                    {scoring.map((factor) => (
                      <li key={factor.factor}>
                        <span className="factor-name">{factor.factor}</span>
                        <span className="factor-reason">{factor.reason}</span>
                      </li>
                    ))}
                  </ul>
                </details>
              )}

              <p className="gate-warning">
                This action is destructive and Sentinel cannot undo it.
              </p>
            </article>
          );
        })}

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
            Approve action
          </button>
        </div>

        {gateId && (
          <div className="gate-id">
            This decision answers gate {gateId.slice(0, 8)} only.
          </div>
        )}
      </div>
    </section>
  );
}
