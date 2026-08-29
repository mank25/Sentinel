import type { Approval, Assessment } from "../types";

interface Props {
  username: string;
  assessment: Assessment | null;
  response: string | null;
  approvals: Approval[];
}

/**
 * The verdict, in two clearly separate halves.
 *
 * Left: the deterministic risk engine's own output -- score, threat level
 * and the factors that justify them, copied verbatim from `assess_user_risk`.
 * No language model contributed to any number here, and nothing in this file
 * computes one.
 *
 * Right: the agent's narrative. It explains the evidence; it does not decide
 * the score.
 */
export function Verdict({
  username,
  assessment,
  response,
  approvals,
}: Props) {
  const scoring = (assessment?.risk_factors ?? []).filter(
    (factor) => factor.points > 0,
  );

  return (
    <section className="verdict">
      <div className="verdict-grid">
        {assessment && (
          <aside className="engine">
            <div className="engine-label">Deterministic risk engine</div>

            <div className="score">
              <span className="score-value">{assessment.risk_score}</span>
              <span className="score-max">/ 100</span>
            </div>

            <span className={`level ${assessment.threat_level}`}>
              {assessment.threat_level}
            </span>

            <div className="engine-note">
              Based on {scoring.length} evidence-backed factor
              {scoring.length === 1 ? "" : "s"}
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
          </aside>
        )}

        <div className="narrative">
          <div className="engine-label">
            AI investigator
            <span className="narrative-target">{username}</span>
          </div>

          {response ? (
            <div className="body">{response}</div>
          ) : (
            <div className="body dim">No narrative was produced.</div>
          )}
        </div>
      </div>

      {approvals.map((approval, index) => (
        <div
          className={`outcome ${approval.allowed ? "allowed" : "denied"}`}
          key={index}
        >
          {approval.allowed ? "EXECUTED" : "BLOCKED BY OPERATOR"}
          {"  "}
          {approval.tool}
          {approval.reason ? `  — ${approval.reason}` : ""}
        </div>
      ))}
    </section>
  );
}
