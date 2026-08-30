import type { ThreadInfo, TimelineItem, ToolActivity } from "../correlate";
import { formatArguments, threadLabel } from "../correlate";
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

/**
 * Render a tool result as text, whatever shape it arrived in.
 *
 * The runner forwards `content` from the TrueForge event unchanged, which
 * keeps the trace faithful but means this is not guaranteed to be a string:
 * MCP results can arrive as a list of content blocks. Passing an
 * object-containing array to React as a child throws and takes the whole
 * investigation view down with it, so coerce here rather than trusting the
 * type. Fidelity is preserved -- a non-string is serialised, not discarded.
 */
function truncate(content: unknown): string {
  if (content === null || content === undefined) return "";

  const text =
    typeof content === "string" ? content : safeStringify(content);

  return text.length > 1200 ? `${text.slice(0, 1200)}…` : text;
}

function safeStringify(value: unknown): string {
  try {
    return JSON.stringify(value, null, 2) ?? String(value);
  } catch {
    // Circular or otherwise unserialisable: show something rather than
    // crashing the timeline.
    return String(value);
  }
}

export function Timeline({
  items,
  threads = [],
}: {
  items: TimelineItem[];
  threads?: ThreadInfo[];
}) {
  return (
    <div className="timeline">
      {items.map((item) => {
        // Only labelled when the entry did not come from the root agent, so
        // a linear investigation stays uncluttered and a delegated one
        // attributes every call to the specialist that made it.
        const lane = threadLabel(threads, item.threadId);

        return (
        <article
          className={`event ${item.kind === "error" ? "err" : item.kind}${
            lane ? " delegated" : ""
          }`}
          key={item.id}
        >
          <div className="icon">{ICON[item.kind]}</div>
          <div className="event-body">
            {lane && <div className="lane">{lane}</div>}
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
        );
      })}
    </div>
  );
}
