import type { TimelineItem, ToolActivity } from "../correlate";
import { formatArguments } from "../correlate";
import { ApprovalRecordCard } from "./ApprovalRecordCard";

const ICON: Record<TimelineItem["kind"], string> = {
  phase: "○",
  tool: "▸",
  note: "✓",
  agent: "❝",
  approval: "⚠",
  error: "✗",
};

function humanDuration(ms?: number): string | null {
  if (ms === undefined) return null;
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

function ToolCard({ activity }: { activity: ToolActivity }) {
  const args = formatArguments(activity.arguments);
  const took = humanDuration(activity.durationMs);
  const running = activity.status === "running";

  return (
    <div className={`tool ${running ? "running" : "done"}`}>
      <div className="tool-head">
        <span className="tool-name">{activity.tool}</span>
        {args && <span className="tool-args">({args})</span>}
        <span className="tool-state">
          {running ? "running…" : "done"}
          {took && !running ? ` · ${took}` : ""}
        </span>
      </div>

      {activity.facts.length > 0 && (
        <dl className="facts">
          {activity.facts.map((fact) => (
            <div className="fact" key={fact.label}>
              <dt>{fact.label}</dt>
              <dd>{fact.value}</dd>
            </div>
          ))}
        </dl>
      )}

      {activity.status === "done" &&
        activity.facts.length === 0 &&
        activity.content && (
          <pre className="args">{truncate(activity.content)}</pre>
        )}
    </div>
  );
}

function truncate(text: string): string {
  return text.length > 1200 ? `${text.slice(0, 1200)}…` : text;
}

export function Timeline({ items }: { items: TimelineItem[] }) {
  return (
    <div className="timeline">
      {items.map((item) => (
        <article
          className={`event ${item.kind === "error" ? "err" : item.kind}`}
          key={item.id}
        >
          <div className="icon">{ICON[item.kind]}</div>
          <div className="event-body">
            {item.approval ? (
              <ApprovalRecordCard record={item.approval} />
            ) : (
              <>
                <div className="title">{item.title}</div>
                {item.sub && <div className="sub">{item.sub}</div>}
                {item.tool && <ToolCard activity={item.tool} />}
                {item.detail && <pre className="args">{item.detail}</pre>}
              </>
            )}
          </div>
        </article>
      ))}
    </div>
  );
}
