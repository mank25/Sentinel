import type { RunEvent } from "./types";

/**
 * The operator token, present only when the console was bound beyond
 * loopback and started with one. It rides in the query string rather than
 * an Authorization header because EventSource cannot set headers, and the
 * stream has to authenticate the same way every other route does.
 */
const TOKEN = new URLSearchParams(window.location.search).get("token") ?? "";

function url(path: string): string {
  return TOKEN ? `${path}?token=${encodeURIComponent(TOKEN)}` : path;
}

export interface StartedRun {
  id: string;
  username: string;
}

export async function startInvestigation(
  username: string,
): Promise<StartedRun> {
  const response = await fetch(url("/api/investigations"), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ username }),
  });

  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.error ?? `Could not start (${response.status})`);
  }

  return response.json();
}

export async function sendDecision(
  runId: string,
  allowed: boolean,
  reason: string,
): Promise<void> {
  const response = await fetch(
    url(`/api/investigations/${runId}/decision`),
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ allowed, reason }),
    },
  );

  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.error ?? `Decision failed (${response.status})`);
  }
}

/**
 * Follow a run. The server replays the events already emitted before
 * streaming live ones, so subscribing late still renders the whole run.
 */
export function followRun(
  runId: string,
  onEvent: (event: RunEvent) => void,
): () => void {
  const source = new EventSource(
    url(`/api/investigations/${runId}/events`),
  );

  source.onmessage = (message) => {
    if (!message.data) return;

    try {
      onEvent(JSON.parse(message.data) as RunEvent);
    } catch {
      // A malformed frame should not tear down the stream.
    }
  };

  source.onerror = () => source.close();

  return () => source.close();
}
