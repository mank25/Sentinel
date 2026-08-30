import { splitJustification } from "../correlate";
import type { ThreadInfo } from "../correlate";
import type { Approval, Assessment, PendingAction, Status } from "../types";
import { ApprovalGate } from "./ApprovalGate";

interface Props {
  username: string;
  assessment: Assessment | null;
  response: string | null;
  approvals: Approval[];
  status: Status;
  pending: PendingAction[];
  gateId: string | null;
  threads: ThreadInfo[];
  onDecide: (allowed: boolean, reason: string) => void;
  deciding: boolean;
}

/**
 * The right-hand pane: the incident report, assembled while the run happens.
 *
 * It fills in the order the facts become true — the engine's score the
 * moment the engine speaks, the authorisation request the moment the run
 * stops, the written report when the agent finishes — so the operator is
 * never asked to approve containment before the score is on screen.
 *
 * Every number here is copied from the `assessment` event, which the runner
 * lifted verbatim out of `assess_user_risk`. Nothing in this file computes,
 * rounds or infers a score.
 */
export function ReportPane({
  username,
  assessment,
  response,
  approvals,
  status,
  pending,
  gateId,
  threads,
  onDecide,
  deciding,
}: Props) {
  const scoring = (assessment?.risk_factors ?? []).filter(
    (factor) => factor.points > 0,
  );

  return (
    <div className="report">
      {/* First in the pane, always. A decision the operator has to scroll to
          find is a decision they can miss, and this is the one thing on the
          screen that stops the run. The gate carries the score and the
          evidence with it, so nothing is lost by putting it above them. */}
      {pending.length > 0 && (
        <ApprovalGate
          pending={pending}
          gateId={gateId}
          assessment={assessment}
          threads={threads}
          onDecide={onDecide}
          busy={deciding}
        />
      )}

      <section className="report-block">
        <div className="engine-label">Deterministic risk engine</div>

        {assessment ? (
          <div className="engine">
            <div className="score">
              <span className="score-value">{assessment.risk_score}</span>
              <span className="score-max">/ 100</span>
              <span className={`level ${assessment.threat_level}`}>
                {assessment.threat_level}
              </span>
            </div>

            <div className="engine-note">
              {scoring.length} evidence-backed factor
              {scoring.length === 1 ? "" : "s"} · subject{" "}
              <code>{username}</code>
            </div>

            <ul className="factors">
              {(assessment.risk_factors ?? []).map((factor) => (
                <li key={factor.factor}>
                  <span className="factor-name">{factor.factor}</span>
                  <span className="factor-points">
                    {factor.points > 0 ? `+${factor.points}` : "—"}
                  </span>
                  <span className="factor-reason">{factor.reason}</span>
                </li>
              ))}
            </ul>

            {assessment.incomplete_evidence && (
              <div className="gap">
                Evidence was incomplete; findings may be partial.
              </div>
            )}

            <div className="provenance">
              Computed by investigator/risk.py — not by the model.
            </div>
          </div>
        ) : (
          <div className="report-waiting">
            {status === "idle"
              ? "No score yet. Run an investigation."
              : "The engine scores the account once the evidence is in."}
          </div>
        )}
      </section>

      <section className="report-block">
        <div className="engine-label">
          Written report
          <span className="narrative-target">{username}</span>
        </div>

        {response ? (
          <div className="narrative">
            <div className="body">{response}</div>
          </div>
        ) : (
          <div className="report-waiting">
            {status === "idle"
              ? "The agent's report appears here."
              : status === "awaiting-approval"
                ? "The agent is paused. It writes its report after you decide."
                : "The agent is still working."}
          </div>
        )}
      </section>

      {/* A run that ends with nothing here is ambiguous: did the agent never
          ask, or did the gate go unanswered? Say which, rather than leaving a
          blank where a containment decision would have been. */}
      {status === "done" && approvals.length === 0 && (
        <section className="report-block">
          <div className="engine-label">Containment outcome</div>
          <div className="report-waiting">
            None. The agent finished without requesting a destructive action,
            so no approval was needed and nothing was changed.
          </div>
        </section>
      )}

      {approvals.length > 0 && (
        <section className="report-block">
          <div className="engine-label">Containment outcome</div>

          {approvals.map((approval, index) => {
            const { target } = splitJustification(approval.arguments);

            return (
              <div
                className={`outcome ${approval.allowed ? "allowed" : "denied"}`}
                key={index}
              >
                <span className="outcome-verdict">
                  {approval.allowed
                    ? "APPROVED — executed"
                    : "DENIED — not executed"}
                </span>
                <code className="outcome-call">
                  {approval.tool}
                  {target ? `(${target})` : ""}
                </code>
                {approval.reason && (
                  <span className="outcome-reason">{approval.reason}</span>
                )}
              </div>
            );
          })}

          {/* Whether the action took effect is a claim only the read-back can
              support, and the agent makes it in its own report. The console
              shows the human decision, which is the part it witnessed. */}
          <div className="outcome-note">
            Verification of each executed action is read back from the
            containment store by the agent — see CONTAINMENT in the report.
          </div>
        </section>
      )}
    </div>
  );
}
