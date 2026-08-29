import type { ToolCall } from "../types";

export interface TimelineItem {
  id: string;
  kind: "phase" | "tool" | "result" | "error" | "decision";
  title: string;
  sub?: string;
  detail?: string;
}

const ICON: Record<TimelineItem["kind"], string> = {
  phase: "○",
  tool: "▸",
  result: "✓",
  error: "✗",
  decision: "◆",
};

export function summarize(value: unknown): string {
  if (value === null || value === undefined) return "";

  const text =
    typeof value === "string" ? value : JSON.stringify(value, null, 2);

  return text.length > 1200 ? `${text.slice(0, 1200)}…` : text;
}

export function formatCall(call: ToolCall): string {
  const args = Object.entries(call.arguments ?? {})
    .map(([key, value]) => `${key}=${JSON.stringify(value)}`)
    .join(", ");

  return `${call.tool}(${args})`;
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
          <div>
            <div className="title">{item.title}</div>
            {item.sub && <div className="sub">{item.sub}</div>}
            {item.detail && <pre className="args">{item.detail}</pre>}
          </div>
        </article>
      ))}
    </div>
  );
}
