import type { ThreadInfo } from "../correlate";
import type { Assessment, Status } from "../types";

interface Props {
  username: string;
  assessment: Assessment | null;
  status: Status;
  threads: ThreadInfo[];
}

const STAGE: { key: string; label: string; reached: (s: Status) => boolean }[] =
  [
    {
      key: "investigate",
      label: "Investigation",
      reached: (s) => s !== "idle",
    },
    {
      key: "risk",
      label: "Risk",
      reached: (s) =>
        ["awaiting-approval", "resuming", "done"].includes(s),
    },
    {
      key: "approve",
      label: "Approval",
      reached: (s) => ["awaiting-approval", "resuming", "done"].includes(s),
    },
    { key: "resolve", label: "Resolved", reached: (s) => s === "done" },
  ];

/**
 * The incident band: who is under investigation, and what the deterministic
 * engine has said about them so far.
 *
 * It appears as soon as the engine has spoken rather than only at the end,
 * because an operator being asked to approve containment needs the score in
 * front of them at that moment, not after they have decided.
 *
 * The score and threat level are copied from the `assessment` event. Nothing
 * in this file computes, rounds or infers one, and the band renders without
 * a verdict rather than guessing at one.
 */
export function IncidentHeader({
  username,
  assessment,
  status,
  threads,
}: Props) {
  const specialists = threads.filter(
    (thread) => thread.threadId !== "main",
  );

  return (
    <section className="incident">
      <div className="incident-subject">
        <div className="incident-label">Subject</div>
        <div className="incident-name">{username}</div>
        {specialists.length > 0 && (
          <div className="incident-threads">
            {specialists.length} specialist
            {specialists.length === 1 ? "" : "s"} ·{" "}
            {specialists.filter((t) => t.running).length} running
          </div>
        )}
      </div>

      {assessment ? (
        <div className="incident-risk">
          <div className="incident-label">
            Deterministic risk engine
          </div>
          <div className="incident-score">
            <span className={`level ${assessment.threat_level}`}>
              {assessment.threat_level}
            </span>
            <span className="incident-value">{assessment.risk_score}</span>
            <span className="incident-max">/ 100</span>
          </div>
        </div>
      ) : (
        <div className="incident-risk">
          <div className="incident-label">Deterministic risk engine</div>
          <div className="incident-pending">
            awaiting the engine's verdict
          </div>
        </div>
      )}

      <ol className="incident-stages">
        {STAGE.map((stage) => (
          <li
            key={stage.key}
            className={stage.reached(status) ? "reached" : ""}
          >
            {stage.label}
          </li>
        ))}
      </ol>
    </section>
  );
}
