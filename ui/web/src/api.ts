import type { Link, RunEvent } from "./types";

/**
 * The operator token, present only when the console was bound beyond
 * loopback and started with one. It rides in the query string rather than
 * an Authorization header because EventSource cannot set headers, and the
 * stream has to authenticate the same way every other route does.
 */
const TOKEN = new URLSearchParams(window.location.search).get("token") ?? "";

/** Backoff between reconnect attempts, in milliseconds. */
const RETRY_DELAYS = [500, 1000, 2000, 4000, 8000];

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

/**
 * Answer one containment request.
 *
 * `gateId` names the exact gate being answered. The server refuses a
 * decision that does not match the gate currently open (409), so a stale or
 * duplicated click can never approve a containment action the operator was
 * not shown.
 */
export async function sendDecision(
  runId: string,
  gateId: string,
  allowed: boolean,
  reason: string,
): Promise<void> {
  const response = await fetch(
    url(`/api/investigations/${runId}/decision`),
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ gate_id: gateId, allowed, reason }),
    },
  );

  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.error ?? `Decision failed (${response.status})`);
  }
}

interface FollowHandlers {
  onEvent: (event: RunEvent) => void;
  onLink: (link: Link) => void;
}

/**
 * Follow a run, reconnecting through transient failures.
 *
 * The server replays a run from its first event, and every event carries a
 * monotonic `seq`. So reconnecting is simply: open the same stream again and
 * let the reducer drop anything at or below the highest seq already applied.
 * That keeps one event-stream architecture rather than two -- there is no
 * separate catch-up channel and no polling.
 */
export function followRun(
  runId: string,
  { onEvent, onLink }: FollowHandlers,
): () => void {
  let source: EventSource | null = null;
  let attempt = 0;
  let timer: number | undefined;
  let stopped = false;
  let finished = false;

  const open = () => {
    if (stopped) return;

    source = new EventSource(url(`/api/investigations/${runId}/events`));

    source.onopen = () => {
      // Deliberately does NOT reset `attempt`. A handshake only proves the
      // socket opened; a server that accepts connections and drops them
      // immediately would otherwise refill the retry budget on every cycle
      // and reconnect forever instead of surfacing the failure. The budget
      // is restored below, once a frame has actually been delivered --
      // which is the first moment the connection has demonstrably worked.
      onLink("live");
    };

    source.onmessage = (message) => {
      if (!message.data) return;

      // A delivered frame is the stability condition. Past this point the
      // connection did its job, so a later drop starts from a full budget.
      attempt = 0;

      let event: RunEvent;

      try {
        event = JSON.parse(message.data) as RunEvent;
      } catch {
        // A malformed frame should not tear down the stream.
        return;
      }

      if (event.kind === "complete" || event.kind === "error") {
        finished = true;
      }

      onEvent(event);
    };

    source.onerror = () => {
      source?.close();
      source = null;

      if (stopped) return;

      // The server closes the stream once the run is over; that is a normal
      // end, not a failure to retry.
      if (finished) {
        onLink("closed");
        return;
      }

      if (attempt >= RETRY_DELAYS.length) {
        onLink("closed");
        onEvent({
          seq: Number.MAX_SAFE_INTEGER,
          kind: "error",
          message:
            "Lost the connection to the console and could not reconnect. " +
            "The investigation may still be running on the server -- " +
            "reload to rejoin it.",
        });
        return;
      }

      onLink("reconnecting");
      timer = setTimeout(open, RETRY_DELAYS[attempt]) as unknown as number;
      attempt += 1;
    };
  };

  open();

  return () => {
    stopped = true;
    clearTimeout(timer);
    source?.close();
  };
}
