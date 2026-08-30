/**
 * Tests for the console's event->timeline transformation.
 *
 * Run with the project's own toolchain, no test framework added:
 *
 *     npm test          (node --test, using Node's native TS stripping)
 *
 * The reducer is where the browser's correctness actually lives -- tool
 * correlation, replay idempotence and the approval record -- so it is
 * separated from React precisely so it can be tested without a DOM.
 */

import assert from "node:assert/strict";
import { test } from "node:test";

import {
  describeResult,
  initialState,
  reduce,
  reduceAll,
  splitJustification,
  threadLabel,
} from "../src/correlate.ts";
import type { RunEvent } from "../src/types.ts";

let seq = 0;
const ev = (event: Omit<RunEvent, "seq">): RunEvent =>
  ({ ...event, seq: ++seq }) as RunEvent;

const reset = () => {
  seq = 0;
};

test("a tool result attaches to its call by tool_call_id", () => {
  reset();

  const state = reduceAll(initialState(), [
    ev({
      kind: "tool_call",
      tool_call_id: "c1",
      tool: "get_login_history",
      arguments: { username: "admin" },
      created_at: "2026-08-29T10:00:00.000Z",
    }),
    ev({
      kind: "tool_call",
      tool_call_id: "c2",
      tool: "get_network_activity",
      arguments: { ip_address: "185.123.45.67" },
      created_at: "2026-08-29T10:00:01.000Z",
    }),
    // Out of order on purpose: the second call answers first.
    ev({
      kind: "tool_result",
      tool_call_id: "c2",
      tool: "get_network_activity",
      content: '{"found": true, "ip_address": "185.123.45.67", "reputation": "suspicious", "known": false}',
      created_at: "2026-08-29T10:00:02.500Z",
    }),
    ev({
      kind: "tool_result",
      tool_call_id: "c1",
      tool: "get_login_history",
      content: '{"found": true, "user": {"username": "admin", "role": "administrator"}, "login_events": [1, 2, 3]}',
      created_at: "2026-08-29T10:00:04.000Z",
    }),
  ]);

  assert.equal(state.items.length, 2, "a result must not add a new row");

  const [login, network] = state.items;

  assert.equal(login.tool?.status, "done");
  assert.equal(login.tool?.durationMs, 4000);
  assert.deepEqual(
    login.tool?.facts.find((f) => f.label === "events returned"),
    { label: "events returned", value: "3" },
  );

  assert.equal(network.tool?.status, "done");
  assert.equal(network.tool?.durationMs, 1500);
  assert.deepEqual(
    network.tool?.facts.find((f) => f.label === "reputation"),
    { label: "reputation", value: "suspicious" },
  );
});

test("a call with no result yet stays visibly running", () => {
  reset();

  const state = reduce(
    initialState(),
    ev({
      kind: "tool_call",
      tool_call_id: "c1",
      tool: "assess_user_risk",
      arguments: { username: "admin" },
    }),
  );

  assert.equal(state.items[0].tool?.status, "running");
  assert.equal(state.items[0].tool?.durationMs, undefined);
  assert.equal(state.items[0].sub, "Deterministic risk engine");
});

test("replayed events are ignored, so a reconnect cannot duplicate", () => {
  reset();

  const events = [
    ev({ kind: "phase", phase: "investigating", message: "Investigating admin" }),
    ev({
      kind: "tool_call",
      tool_call_id: "c1",
      tool: "get_login_history",
      arguments: { username: "admin" },
    }),
    ev({
      kind: "tool_result",
      tool_call_id: "c1",
      tool: "get_login_history",
      content: '{"found": true, "login_events": []}',
    }),
  ];

  const once = reduceAll(initialState(), events);

  // The reconnect: the server replays the whole run from the start.
  const twice = reduceAll(once, events);

  assert.equal(twice.items.length, once.items.length);
  assert.deepEqual(
    twice.items.map((i) => i.id),
    once.items.map((i) => i.id),
  );
  assert.equal(twice.lastSeq, once.lastSeq);

  // And a genuinely new event after the replay still lands.
  const after = reduce(
    twice,
    ev({ kind: "phase", phase: "resuming", message: "Resuming" }),
  );
  assert.equal(after.items.length, once.items.length + 1);
});

test("event order is preserved through a partial replay", () => {
  reset();

  const events = [
    ev({ kind: "phase", phase: "investigating", message: "one" }),
    ev({ kind: "phase", phase: "investigating", message: "two" }),
    ev({ kind: "phase", phase: "investigating", message: "three" }),
  ];

  // Rendered the first two, dropped, then replayed everything.
  const partial = reduceAll(initialState(), events.slice(0, 2));
  const rejoined = reduceAll(partial, events);

  assert.deepEqual(
    rejoined.items.map((i) => i.title),
    ["one", "two", "three"],
  );
});

test("the approval gate is recorded in the timeline and kept there", () => {
  reset();

  const opened = reduce(
    initialState(),
    ev({
      kind: "approval_required",
      gate_id: "gate-1",
      pending: [
        {
          thread_id: "main",
          tool_call_id: "call_1",
          tool: "contain_account",
          arguments: { username: "admin" },
        },
      ],
    }),
  );

  assert.equal(opened.status, "awaiting-approval");
  assert.equal(opened.gateId, "gate-1");
  assert.equal(opened.items[0].approval?.outcome, "pending");

  const decided = reduce(
    opened,
    ev({
      kind: "decision",
      gate_id: "gate-1",
      allowed: false,
      reason: "Shared VPN.",
      actions: [{ tool: "contain_account", arguments: { username: "admin" } }],
    }),
  );

  // The card is updated in place, not removed: the history shows what was
  // asked and what the operator answered.
  assert.equal(decided.items.length, 1);
  assert.equal(decided.items[0].approval?.outcome, "denied");
  assert.equal(decided.items[0].approval?.reason, "Shared VPN.");
  assert.equal(decided.gateId, null, "the gate must close");
  assert.deepEqual(decided.pending, []);
});

test("a decision for another gate leaves this record alone", () => {
  reset();

  const opened = reduce(
    initialState(),
    ev({
      kind: "approval_required",
      gate_id: "gate-2",
      pending: [
        {
          thread_id: "main",
          tool_call_id: "call_2",
          tool: "block_ip",
          arguments: { ip_address: "185.123.45.67" },
        },
      ],
    }),
  );

  const other = reduce(
    opened,
    ev({
      kind: "decision",
      gate_id: "gate-1",
      allowed: true,
      reason: "",
      actions: [],
    }),
  );

  assert.equal(other.items[0].approval?.outcome, "pending");
});

test("the verdict comes from the engine event, never from prose", () => {
  reset();

  const state = reduceAll(initialState(), [
    ev({
      kind: "assessment",
      username: "admin",
      threat_level: "CRITICAL",
      risk_score: 100,
      risk_factors: [
        { factor: "Privileged account", points: 30, reason: "admin" },
        { factor: "Incomplete network evidence", points: 0, reason: "gap" },
      ],
      incomplete_evidence: true,
    }),
    ev({
      kind: "complete",
      response: "THREAT LEVEL: LOW ... (the model contradicting itself)",
      trace: [],
      approvals: [],
    }),
  ]);

  assert.equal(state.assessment?.threat_level, "CRITICAL");
  assert.equal(state.assessment?.risk_score, 100);
  assert.equal(state.assessment?.incomplete_evidence, true);
  assert.equal(state.status, "done");
});

test("describeResult reports only fields the payload actually has", () => {
  assert.deepEqual(describeResult("get_login_history", null), []);
  assert.deepEqual(describeResult("get_login_history", "not json"), []);
  assert.deepEqual(describeResult("anything", "[1,2,3]"), []);

  // A lookup failure is reported as such, not as a clean result.
  assert.deepEqual(
    describeResult(
      "get_network_activity",
      '{"found": false, "ip_address": "1.1.1.1", "error": "Unable to read network security data."}',
    ),
    [{ label: "error", value: "Unable to read network security data." }],
  );

  // "No record" is distinct from "the lookup failed".
  assert.deepEqual(
    describeResult("get_network_activity", '{"found": false, "ip_address": "1.1.1.1"}'),
    [{ label: "found", value: "no record" }],
  );

  // Absent optional fields are omitted rather than defaulted.
  const facts = describeResult(
    "get_network_activity",
    '{"found": true, "ip_address": "185.123.45.67", "reputation": "suspicious"}',
  );
  assert.deepEqual(facts.map((f) => f.label), ["ip", "reputation"]);
});

test("an orphan tool result is still shown", () => {
  reset();

  const state = reduce(
    initialState(),
    ev({
      kind: "tool_result",
      tool_call_id: "unknown",
      tool: "get_account_status",
      content: '{"found": true, "contained": false}',
    }),
  );

  assert.equal(state.items.length, 1);
  assert.equal(state.items[0].tool?.status, "done");
});

test("a second result cannot overwrite an already-answered call", () => {
  reset();

  const state = reduceAll(initialState(), [
    ev({
      kind: "tool_call",
      tool_call_id: "c1",
      tool: "get_account_status",
      arguments: {},
    }),
    ev({
      kind: "tool_result",
      tool_call_id: "c1",
      tool: "get_account_status",
      content: '{"found": true, "contained": false}',
    }),
    ev({
      kind: "tool_result",
      tool_call_id: "c1",
      tool: "get_account_status",
      content: '{"found": true, "contained": true}',
    }),
  ]);

  assert.equal(state.items.length, 2, "the duplicate becomes its own row");
  assert.deepEqual(state.items[0].tool?.facts, [
    { label: "contained", value: "false" },
  ]);
});

test("a result correlates on (thread_id, tool_call_id), not the id alone", () => {
  reset();

  const state = reduceAll(initialState(), [
    ev({
      kind: "tool_call",
      thread_id: "main",
      tool_call_id: "call_123",
      tool: "get_login_history",
      arguments: { username: "admin" },
    }),
    ev({
      kind: "tool_call",
      thread_id: "subagent-abc",
      tool_call_id: "call_123",
      tool: "get_network_activity",
      arguments: { ip_address: "185.123.45.67" },
    }),
    ev({
      kind: "tool_result",
      thread_id: "subagent-abc",
      tool_call_id: "call_123",
      tool: "get_network_activity",
      content: '{"found": true, "ip_address": "185.123.45.67", "reputation": "suspicious"}',
    }),
    ev({
      kind: "tool_result",
      thread_id: "main",
      tool_call_id: "call_123",
      tool: "get_login_history",
      content: '{"found": true, "login_events": [1, 2, 3]}',
    }),
  ]);

  // Two calls, two results, no extra rows: each result found its own call.
  assert.equal(state.items.length, 2);

  const [main, sub] = state.items;

  assert.equal(main.tool?.threadId, "main");
  assert.equal(main.tool?.tool, "get_login_history");
  assert.deepEqual(
    main.tool?.facts.find((f) => f.label === "events returned"),
    { label: "events returned", value: "3" },
  );

  assert.equal(sub.tool?.threadId, "subagent-abc");
  assert.equal(sub.tool?.tool, "get_network_activity");
  assert.deepEqual(
    sub.tool?.facts.find((f) => f.label === "reputation"),
    { label: "reputation", value: "suspicious" },
  );
});

test("a result from an unknown thread does not claim another thread's call", () => {
  reset();

  const state = reduceAll(initialState(), [
    ev({
      kind: "tool_call",
      thread_id: "main",
      tool_call_id: "call_123",
      tool: "get_login_history",
      arguments: {},
    }),
    ev({
      kind: "tool_result",
      thread_id: "ghost",
      tool_call_id: "call_123",
      tool: "get_login_history",
      content: '{"found": true, "login_events": []}',
    }),
  ]);

  // The main call is still running; the orphan is shown on its own row.
  assert.equal(state.items.length, 2);
  assert.equal(state.items[0].tool?.status, "running");
  assert.equal(state.items[1].tool?.threadId, "ghost");
});

test("events without a thread_id are treated as the main thread", () => {
  reset();

  const state = reduceAll(initialState(), [
    ev({
      kind: "tool_call",
      thread_id: null,
      tool_call_id: "c1",
      tool: "get_login_history",
      arguments: {},
    }),
    ev({
      kind: "tool_result",
      thread_id: null,
      tool_call_id: "c1",
      tool: "get_login_history",
      content: '{"found": true, "login_events": []}',
    }),
  ]);

  assert.equal(state.items.length, 1);
  assert.equal(state.items[0].tool?.threadId, "main");
  assert.equal(state.items[0].tool?.status, "done");
});

// ------------------------------------------------------------------
// Thread lanes
//
// A delegated investigation puts each specialist on its own TrueForge
// thread. These hold that the console attributes work to the thread that
// did it, and that a linear run is unaffected.
// ------------------------------------------------------------------

test("a linear run has no threads to label", () => {
  const state = reduceAll(initialState(), [
    { seq: 1, kind: "tool_call", thread_id: "main", tool_call_id: "call_1",
      tool: "get_login_history", arguments: { username: "admin" } },
  ] as RunEvent[]);

  assert.equal(state.threads.length, 0);
  assert.equal(threadLabel(state.threads, "main"), null);
  assert.equal(threadLabel(state.threads, undefined), null);
});

test("a started specialist is recorded and named", () => {
  const state = reduceAll(initialState(), [
    { seq: 1, kind: "thread_started", thread_id: "aeea3c28-97f0",
      name: "Identity Analyst", parent_thread_id: "main" },
  ] as RunEvent[]);

  assert.equal(state.threads.length, 1);
  assert.equal(state.threads[0].name, "Identity Analyst");
  assert.equal(state.threads[0].running, true);
  assert.equal(threadLabel(state.threads, "aeea3c28-97f0"), "Identity Analyst");
});

test("an unnamed thread falls back to its id, never an invented role", () => {
  const state = reduceAll(initialState(), [
    { seq: 1, kind: "thread_started", thread_id: "b1c2d3e4f5a6",
      name: null, parent_thread_id: "main" },
  ] as RunEvent[]);

  assert.equal(threadLabel(state.threads, "b1c2d3e4f5a6"), "thread b1c2d3e4");
});

test("a finished specialist stops being marked running", () => {
  const state = reduceAll(initialState(), [
    { seq: 1, kind: "thread_started", thread_id: "t1", name: "Network Analyst",
      parent_thread_id: "main" },
    { seq: 2, kind: "thread_finished", thread_id: "t1" },
  ] as RunEvent[]);

  assert.equal(state.threads[0].running, false);
});

test("a replayed thread_started does not duplicate the thread", () => {
  const events = [
    { seq: 1, kind: "thread_started", thread_id: "t1", name: "Identity Analyst",
      parent_thread_id: "main" },
  ] as RunEvent[];

  // Replay from scratch, the way a reconnecting browser does.
  const once = reduceAll(initialState(), events);
  const twice = reduceAll(initialState(), [...events, ...events]);

  assert.equal(once.threads.length, 1);
  assert.equal(twice.threads.length, 1);
});

test("tool activity carries the thread that made the call", () => {
  const state = reduceAll(initialState(), [
    { seq: 1, kind: "thread_started", thread_id: "t1", name: "Network Analyst",
      parent_thread_id: "main" },
    { seq: 2, kind: "tool_call", thread_id: "t1", tool_call_id: "call_9",
      tool: "get_network_activity", arguments: {} },
  ] as RunEvent[]);

  const call = state.items.find((item) => item.tool);

  assert.equal(call?.threadId, "t1");
  assert.equal(threadLabel(state.threads, call?.threadId), "Network Analyst");
});

// ------------------------------------------------------------------
// The approval card's fields
// ------------------------------------------------------------------

test("the justification is separated from the target, and never truncated", () => {
  const why =
    "IP 185.123.45.67 produced 47 failed authentication attempts followed " +
    "by a success at 2026-08-26T02:24:18 from an unknown device.";

  const { target, why: reason } = splitJustification({
    ip_address: "185.123.45.67",
    justification: why,
  });

  assert.equal(target, "ip_address=185.123.45.67");
  assert.equal(reason, why);
});

test("a missing justification yields an empty reason, not a filled-in one", () => {
  const { target, why } = splitJustification({ username: "admin" });

  assert.equal(target, "username=admin");
  assert.equal(why, "");
});
