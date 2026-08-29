import type { Approval } from "../types";

const LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;

/** The threat level is the engine's, not the model's -- read it back out. */
export function detectLevel(text: string): string | null {
  const upper = text.toUpperCase();
  return LEVELS.find((level) => upper.includes(level)) ?? null;
}

interface Props {
  username: string;
  response: string;
  approvals: Approval[];
}

export function Verdict({ username, response, approvals }: Props) {
  const level = detectLevel(response);

  return (
    <section className="verdict">
      <div className="verdict-head">
        {level && <span className={`level ${level}`}>{level}</span>}
        <strong>Investigation complete</strong>
        <span style={{ color: "var(--dim)", fontFamily: "var(--mono)" }}>
          {username}
        </span>
      </div>

      <div className="body">{response}</div>

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
