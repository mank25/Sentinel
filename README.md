# Sentinel

### Autonomous security investigation on TrueForge — with the dangerous half under human control.

Sentinel investigates a possibly-compromised account the way a SOC analyst
does. A TrueForge agent decides what evidence to gather and pulls it through
read-only MCP tools, a deterministic engine — not the model — computes the
risk score, and when the agent wants to contain the account **TrueForge stops
it and waits for a person.**

> **The agent investigates. The engine scores. The human authorises.**

The gate is not a paragraph in a prompt. `contain_account` and `block_ip` are
annotated `destructiveHint: true` on the MCP server, the agent spec sets
`require_approval_for_tools: ["@write", "@destructive"]`, and TrueForge pauses
the turn and emits `tool.approval_required`. **Rewriting the system prompt
cannot bypass it.** The model proposes; a person decides.

---

## Quick start

Three services, one command.

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python data/init_db.py                       # seed the incident

# terminal 1 — TrueForge v0.1.4 on :8790, with a model provider configured
# terminal 2
python mcp/sentinel_mcp/http_server.py       # Sentinel MCP tools on :8791

# terminal 3 — the demo
python -m sentinel.demo
```

`python -m sentinel.demo` resets the demo state, checks every service is
ready, runs a real investigation, streams the agent's tool calls as TrueForge
records them, **stops for your decision**, executes containment if you
approve, verifies it, and prints the incident report.

Not ready yet? It tells you what to type:

```
Sentinel readiness
  [OK  ] Evidence DB       READY      1 user(s), 51 login events, 2 network records, read-only
  [FAIL] MCP server        NOT READY  running, but missing get_ip_status
                           -> It is serving an older build. Restart it: python mcp/sentinel_mcp/http_server.py
  [OK  ] TrueForge         READY      v0.1.4 API at http://localhost:8790
  [OK  ] Model             READY      google-gemini/gemini-3-6-flash
```

Run it repeatedly. `--approve`, `--deny` and `--delegate` script the paths;
`--check` runs readiness alone; `--reset-only` puts the demo back to its
starting position. Every run resets first, so approve and deny are both
watchable in one sitting.

### The browser console

```bash
python -m ui.server          # http://127.0.0.1:8792
```

That is the whole setup — `ui/web/dist` is committed, so the console runs
with Python alone. npm is needed to *change* the frontend, not to run it.

---

## Architecture

```
                            ┌──────────────────────────────┐
                            │          TRUEFORGE           │
                            │  agent loop · MCP orchestra- │
     "Investigate admin"  → │  tion · execution trace ·    │
                            │  threads · APPROVAL GATES    │
                            └───────────────┬──────────────┘
                                            │
                        ┌───────────────────┴──────────────────┐
                        ▼                                      ▼
              ┌──────────────────┐                  ┌────────────────────┐
              │  SENTINEL AGENT  │                  │  SPECIALISTS       │
              │  chooses what to │  create_sub_     │  identity/timeline │
              │  investigate     │  agent ────────► │  /network          │
              └────────┬─────────┘   (--delegate)   │  own threads       │
                       │                            └─────────┬──────────┘
                       └──────────────┬───────────────────────┘
                                      ▼
                    ┌─────────────────────────────────────┐
                    │      SENTINEL MCP SERVER            │
                    │                                     │
                    │  READ-ONLY          DESTRUCTIVE     │
                    │  get_login_history  contain_account │
                    │  get_network_activ. block_ip        │
                    │  assess_user_risk   ── gated ──     │
                    │  get_account_status                 │
                    │  get_ip_status                      │
                    └────────┬──────────────────┬─────────┘
                             ▼                  ▼
                 ┌───────────────────┐  ┌──────────────────┐
                 │  data/security.db │  │ containment.db   │
                 │  mode=ro          │  │ append-only      │
                 │  PRAGMA query_only│  │ audit log        │
                 │  NEVER WRITTEN    │  │ the only writes  │
                 └─────────┬─────────┘  └──────────────────┘
                           ▼
                 ┌───────────────────┐
                 │   RISK ENGINE     │  investigator/risk.py
                 │   DETERMINISTIC   │  every point attributable
                 └───────────────────┘  no LLM, ever
```

Who does what:

| Layer | Responsibility | Never does |
|---|---|---|
| **TrueForge** | agent loop, model, MCP orchestration, event trace, threads, approval gates | security scoring |
| **The agent (LLM)** | decides what to investigate, correlates, explains, *proposes* containment | invent a score, execute containment |
| **MCP evidence tools** | read the evidence store | write anything |
| **Analyzer** | correlate evidence deterministically | call a model |
| **Risk engine** | the authoritative score | get overridden |
| **The human** | authorise destructive actions | get bypassed |

---

## Why TrueForge

Sentinel does not use TrueForge as an HTTP wrapper around an LLM. The
investigation *runs inside the harness*, and six harness capabilities are
load-bearing:

| Capability | How Sentinel depends on it |
|---|---|
| **Agent execution** | `AgentSpec` with instructions, model, iteration ceiling. The agent loop is TrueForge's, not a hand-rolled `while` loop. |
| **MCP orchestration** | TrueForge connects to the Sentinel MCP server, discovers tools, and executes every tool call. Sentinel never calls its own tools during an investigation. |
| **Human approval gates** | `require_approval_for_tools` + destructive annotations. TrueForge *pauses the turn* and emits `tool.approval_required`; nothing runs until a `user.tool_approval` decision comes back. **This is the project's central safety property, and it is the harness's.** |
| **Execution traces** | `mcp.initialize`, `model.message`, `tool.response`, `thread.created`, `turn.done` — real recorded events. The timeline and the CLI narration are both projections of them. Nothing is synthesised. |
| **Session & turn lifecycle** | An investigation is a session; a pause-and-resume is a new turn with `previous_turn_id`. Trace correlation spans turns because a `tool.response` in the resumed turn belongs to a `tool.call` from the paused one. |
| **Thread-aware execution / subagents** | `create_sub_agent` puts each specialist on its own thread. This is why results correlate on `(thread_id, tool_call_id)` — see below. |

**Not used, and why:** sandbox execution. TrueForge v0.1.4 sandboxes are
Daytona-backed, and this deployment has no sandbox provider configured
(`GET /api/v1/settings/sandbox-providers` → *"No sandbox provider
configured"*). Enabling `config.sandbox` would fail the turn rather than add
a capability, so it stays off with the reason recorded in
`build_agent_spec`. A capability we cannot actually run is not one we claim.

---

## The safety model

```
                              SENTINEL

                   ┌──────────────────────────┐
                   │          AGENT           │
                   │  investigate · correlate │
                   │  reason · propose        │
                   └────────────┬─────────────┘
                                ▼
                   ┌──────────────────────────┐
                   │      MCP EVIDENCE        │
                   │        READ ONLY         │
                   │  mode=ro + query_only    │
                   └────────────┬─────────────┘
                                ▼
                   ┌──────────────────────────┐
                   │       RISK ENGINE        │
                   │      DETERMINISTIC       │
                   │   investigator/risk.py   │
                   └────────────┬─────────────┘
                                ▼
                   ┌──────────────────────────┐
                   │     HUMAN APPROVAL       │
                   │     TRUEFORGE GATE       │
                   └────────────┬─────────────┘
                                ▼
                   ┌──────────────────────────┐
                   │       CONTAINMENT        │
                   │       WRITE PATH         │
                   └────────────┬─────────────┘
                                ▼
                   ┌──────────────────────────┐
                   │   VERIFY BY READ-BACK    │
                   │  get_account_status /    │
                   │  get_ip_status           │
                   └──────────────────────────┘
```

### The gate is enforced by the harness, not the prompt

Four independent properties, each with tests behind it:

**1. Evidence is unwritable.** `data/security.db` is opened `mode=ro` with
`PRAGMA query_only`. Containment writes to a *different* database. An
investigation can never modify the evidence it reasons about.

| Store | Opened | Written by |
|---|---|---|
| `data/security.db` | `mode=ro` + `PRAGMA query_only` | nothing, ever |
| `data/containment.db` | read-write | `investigator/containment.py` only |

**2. The score is not the model's.** Risk points live in
`investigator/risk.py` and reach the agent only through `assess_user_risk`.
The prompt contains no scoring rules — and `investigator/test_prompts.py`
fails the build if a point value, a `score >=` construct or a threshold ever
appears in it. The console republishes the engine's numbers verbatim from the
tool result; no scoring logic is duplicated in TypeScript.

**3. Destructive tools stop the harness.** Annotated `destructiveHint: true`;
the agent spec requires approval for `@write` and `@destructive`. Approval is
attached to the *tool*, not the calling thread — so a subagent invoking
`block_ip` is paused exactly as the lead is.

**4. A decision answers one specific request.** Every pause mints a
`gate_id`. It rides out on the event, comes back with the decision, and the
server refuses anything that does not name the gate currently open:

```
POST /api/investigations/{id}/decision
{"gate_id": "a358cc9a...", "allowed": false, "reason": "Shared VPN."}

400  'allowed' is not a JSON boolean            -> nothing executes
400  gate_id missing                            -> nothing executes
409  gate_id names a gate that is not the open one
409  no gate is open at all
```

Without it, a decision would mean *"approve whatever gate happens to be open
right now"* — so a duplicated click, a second tab or a retried request could
approve the **next** containment action, which the operator never saw. An
investigation can pause more than once, and the two pauses can propose very
different things.

**Silence is never consent.** An empty answer, a closed stdin, or ten minutes
of no decision are all denials. The failure mode is "nothing happened", never
"it went ahead".

### What containment actually does

Approving records an **authorised containment order** in
`data/containment.db`, which is Sentinel's system of record for response
actions. It does not itself call an identity provider or program a firewall —
a production deployment puts provider adapters behind that same approved
interface. This is stated in the tool descriptions, on the approval card and
here, because an agent that overstates what it did is the failure this
project exists to prevent. Qodo raised exactly this on
[#5](https://github.com/mank25/Sentinel/pull/5); the fix was honesty, not
scope.

What *is* real: the authorisation, the audit record, and the read-back.

---

## The demo scenario

One coherent incident, seeded by `data/init_db.py`. Run
`python data/init_db.py --narrative` to read the story the rows describe.

```
2026-08-24 09:21   admin signs in from Delhi on their MacBook       ─┐
2026-08-24 14:02   routine sign-in                                   ├ baseline
2026-08-25 09:47   routine sign-in                                  ─┘

2026-08-26 02:11   41 password failures from 185.123.45.67           ← brute force
                   mfa_status: not_reached (MFA never challenged)
2026-08-26 02:21   6 attempts clear the password, denied at MFA      ← credentials
                   mfa_status: failed                                  compromised
2026-08-26 02:24   the 7th push is approved. Success.                ← MFA fatigue
                   Unknown device, unknown location.

network intel      185.123.45.67  suspicious · not known · 58 conns
                   10.10.1.20     clean · India · known
```

Two details that matter:

- **The corporate egress is recorded as clean.** Corroboration is only
  meaningful if a lookup could have come back the other way. An investigator
  who checks both IPs learns that one is suspicious and one is not.
- **The attacker IP appears in the evidence and nowhere else.** Not in the
  prompt, not in the risk engine, not in the UI. A test fails the build if an
  IP literal ever reaches the prompt, because an agent handed the answer is
  not investigating.

The engine's verdict on this data: **CRITICAL, 100/100**, from eight
evidence-backed factors. It is computed, not chosen.

### What the agent actually does with it

An unscripted run (the tool order is the model's, not a fixed pipeline):

```
→ get_login_history(username=admin)          establish the baseline
← 51 events, normal device MacBook, Delhi
→ get_network_activity(ip=185.123.45.67)     corroborate — IP derived from evidence
← reputation suspicious, known false
→ assess_user_risk(username=admin)           the authoritative verdict
← CRITICAL 100/100, 8 factors
→ get_account_status(username=admin)         is it already contained?
← contained: false
→ get_ip_status(ip=185.123.45.67)
← blocked: false
→ contain_account(...)
⚠ PAUSED — human approval required
                                             ← operator decides
→ get_account_status(username=admin)         verify by read-back
← contained: true

VERIFICATION: CONFIRMED
```

---

## Delegated investigation

`--delegate` runs the same investigation as a lead analyst commissioning
three specialists, each on its own TrueForge thread:

```
                      SENTINEL LEAD  (thread: main)
                             │  create_sub_agent
          ┌──────────────────┼──────────────────┐
          ▼                  ▼                  ▼
      IDENTITY           TIMELINE            NETWORK
      ANALYST            ANALYST             ANALYST
   login history      chronology,        reputation for the
   baseline, which    failure→success    IPs identity found
   IPs carry signal   sequencing         (it cannot see logins)
          └──────────────────┼──────────────────┘
                             ▼
                   CORRELATION (the lead)
                             ▼
                       RISK ENGINE
                             ▼
                     HUMAN APPROVAL
                             ▼
                  CONTAINMENT → VERIFY
```

**Off by default, deliberately.** Delegation multiplies the model calls a run
needs; a probe against this deployment had the provider rate-limit a
delegated run partway through. Reliability is the default path; delegation is
the capability demo.

**It changes who gathers evidence and nothing else.** Specialists get the
same tool set and the same gate. The brief tells them not to propose
containment — that keeps the investigation coherent, and it is explicitly
*not* what makes it safe. A test asserts the brief never claims otherwise.

### Why `(thread_id, tool_call_id)` — the bug this branch is named for

`tool_call_id` is minted **per conversation** by the model provider (observed
values are short counters like `call_2394998`). Once more than one thread can
run in a turn, two threads can independently produce the same id.

Correlating a `tool.response` by `tool_call_id` alone therefore attaches a
subagent's result to the parent's tool call — the console would show an
operator the wrong evidence under the right question. The thread is what makes
the identity unique.

This is enforced in three places and regression-tested in all three:
`trueforge/agent.py` (`extract_trace`, `pending_approvals`), `ui/runner.py`
(the event stream carries `thread_id`), and `ui/web/src/correlate.ts` (the
browser reducer). The canonical test:

```
thread A, tool_call_id call_123    response(A, call_123) → A
thread B, tool_call_id call_123    response(B, call_123) → B     never A → B
```

---

## The operator console

```bash
python -m ui.server          # http://127.0.0.1:8792
```

The console is where the gate becomes visible. A trace scrolling past in a
terminal does not show an operator what the agent wants to do to a production
account; a button next to the account name does.

- **An incident band** carrying subject, threat level and score from the
  moment the engine speaks — not after the decision has been made.
- **A live timeline** of what the agent is doing while it does it. Each tool
  call TrueForge actually made, its arguments and its result, streamed about
  a second after it happens. In a delegated run each entry is attributed to
  the specialist that made it. Every row comes from a recorded event.
- **The approval card**: the action, the target, the agent's full
  justification (never truncated — a decision made on a shortened reason is
  not an informed decision), the engine's score, the evidence factors behind
  it, and what approving will actually do. A request that arrives with no
  justification says so, and says that is itself a reason to deny.
- **The verdict, in two halves.** The engine's score and factors, visibly
  apart from the agent's narrative, labelled `Computed by
  investigator/risk.py — not by the model`.

The console holds no security logic. It starts investigations, streams what
TrueForge reports, and carries a decision back to a paused turn.

Every event carries a monotonic `seq`, and a follower is replayed the whole
run from its first event. Reconnection is therefore trivial and safe: the
browser retries with backoff, replays, and the reducer drops anything at or
below the highest `seq` it has already rendered. No duplicates, no gaps, and
no second event-stream architecture to maintain.

### Binding beyond this machine

Every route can start an investigation, read its evidence, or approve
containment. On `127.0.0.1` that is the operator's own machine; anywhere else
it is whoever can reach the port, so the console refuses to bind there
without a shared token:

```bash
python -m ui.server --host 0.0.0.0 --token "$(openssl rand -hex 24)"
```

The token is then required on every request, as `Authorization: Bearer` or
`?token=` (the query string is what the SSE stream uses, since `EventSource`
cannot set headers). This is a shared secret, not per-operator identity: put
it behind a real proxy if you need accountable, per-person access.

---

## Testing

```bash
pytest -q                 # 280 unit tests, no services required
pytest -m integration -q  # 9 more; needs TrueForge + the MCP server running
cd ui/web && npm test     # 24 frontend tests, no browser, no test framework
```

The suites are weighted toward the failure paths, because those are the ones
that matter here:

| Property | Held by |
|---|---|
| Duplicate `tool_call_id` across threads never cross-correlates | `test_trueforge.py`, `correlate.test.ts`, `test_console.py` |
| A gate-1 decision cannot approve gate 2 | `ui/test_console.py` |
| A stale or replayed decision is refused (409) | `ui/test_console.py` |
| `{"allowed": "false"}` does not approve containment | `ui/test_console.py` |
| Denial executes nothing and is reported as not-taken | `test_trueforge.py`, `test_console.py` |
| Silence and closed stdin are denials | `test_trueforge.py` |
| A failed network lookup is incomplete evidence, never a clean IP | `test_analyzer.py`, `test_risk.py` |
| A missing/corrupt database returns a structured error, not a traceback | `test_analyzer.py`, `test_demo.py` |
| A rejected containment write reads back as not-contained | `test_containment.py` |
| The evidence store is still unwritable | `test_containment.py` |
| The prompt contains no IP, no score and no threshold | `test_prompts.py` |
| Replayed events do not duplicate timeline entries | `correlate.test.ts` |
| Non-string tool content cannot crash the timeline | `correlate.test.ts` |

Integration tests skip **only** when a prerequisite is genuinely absent —
TrueForge down, MCP server down, or the model not registered. Once those are
present nothing skips: a broken registration or a tool-orchestration
regression fails the suite. The sole concession is a bounded retry for
transient provider 503s.

---

## Model choice

Default: `google-gemini/gemini-3-6-flash`, verified end-to-end. Override with
`--model` or `$TRUEFORGE_MODEL`; the runner validates against
`GET /api/v1/models` before opening a session and lists the alternatives if
it is missing.

Requirements: tool/function calling, and enough context for a full login
history.

**Known-incompatible: `groq/gpt-oss-120b`.** TrueForge persists the model's
reasoning as `thinking_blocks` and replays it to the provider as
`reasoning_content`; Groq's OpenAI-compatible API rejects that property on
input, so the turn dies on the second model call — the moment any tool is
used. Nothing in Sentinel triggers it; MCP registration, tool discovery and
the first tool call all succeed first. Sentinel detects the signature and
prints the workarounds rather than the provider's error.

The deterministic investigation always runs with no LLM at all:

```bash
python -m investigator.run_investigation
```

---

## Qodo code review evidence

Every substantive change landed through a pull request reviewed by Qodo
before merge. Nothing was pushed straight to `main`.

### Findings, fixes, and follow-up verification

| PR | Qodo finding | Severity | Outcome |
|---|---|---|---|
| [#5](https://github.com/mank25/Sentinel/pull/5) | *Containment never reaches target* — both destructive tools report success after only inserting an audit row | High | **Fixed by scoping the claim honestly.** The tools now describe what they do — record an authorised containment order in the system of record, with provider adapters going behind the same approved interface — and tell the agent to treat the return value as "the order was accepted", not "the account is locked". Step 8 of the prompt then requires a read-back before any success is reported, and `VERIFICATION: CONFIRMED` may not be written from the call's own return value. |
| [#5](https://github.com/mank25/Sentinel/pull/5) | *Resumed responses lose tool* — a resumed turn's `tool.response` gets `tool: None`, breaking call/response pairing after every approval | Medium | **Fixed.** Events accumulate across every turn in an investigation and the trace is re-extracted from all of them, so a response in the resumed turn still finds the call from the paused one. `test_resumed_response_still_pairs_with_its_call`. |
| [#6](https://github.com/mank25/Sentinel/pull/6) | *Later gates reuse approval* — after the first decision the event stayed set, so a second gate resumed with a stale decision without waiting for the operator | High | **Fixed, and it is why `gate_id` exists.** The gate, its id and the decision slot are per-pause rather than per-run. `test_a_gate1_decision_cannot_approve_gate2`. |
| [#6](https://github.com/mank25/Sentinel/pull/6) | *String `false` approves containment* — `bool(body.get("allowed"))` reads the JSON string `"false"` as an approval | High | **Fixed.** The route requires an actual JSON boolean and returns 400 otherwise. Verified live against the running console: `{"allowed": "true"}` → 400. |
| [#7](https://github.com/mank25/Sentinel/pull/7) | *Content blocks crash timeline* — MCP content-block results reach React as an object-containing array and take the investigation view down | High | **Fixed.** The display path coerces, and `describeResult` unwraps content blocks the way `parse_assessment` already did on the Python side. Three tests. |
| [#7](https://github.com/mank25/Sentinel/pull/7) | *Retry budget resets forever* — `onopen` reset the counter, so open/drop cycles never exhausted the five retries | Medium | **Fixed.** The budget resets when a frame is actually delivered — the first moment the connection has demonstrably worked — not on the handshake. |
| [#2](https://github.com/mank25/Sentinel/pull/2) | Batch / parallelise the suspicious-IP lookups | — | **Dismissed, deliberately.** Throughput optimisations for a loop that queries a 20 KB local SQLite file. The serial loop keeps the execution trace a readable, ordered narrative, which is the point of an investigator. Revisit if the evidence store moves off-box. |
| [#3](https://github.com/mank25/Sentinel/pull/3) | Unify the stdio runner and the MCP adapter on one assessment pipeline | — | **Partly accepted.** The duplicated composition wiring was real, and `investigator/assessment.py` exists because of it. Making the deterministic layers async was declined — Qodo's own recommendation agreed — because their entire value is being simple and predictable. |
| [#4](https://github.com/mank25/Sentinel/pull/4) | Enforce tool ordering in the runtime rather than in prose | — | **Dismissed, with reasoning.** Enforcing the order in code would duplicate orchestration TrueForge already owns and make the agent a fixed script rather than an investigator. The concern behind it — that prose is not a guarantee — is answered by tests instead: `test_prompts.py` fails the build if the prompt contains a literal IP or a scoring rule. |

Qodo's architectural recommendations on #5, #6 and #7 all endorsed the
existing design (keep the two-database split and the harness gate; keep the
worker-thread bridge and SSE; keep sequenced full-replay over
`Last-Event-ID`), and those designs are unchanged.

The pattern worth noting: Qodo's **defect** findings on this repo were
consistently about *the boundary between claiming and doing* — success
reported from an attempt, an approval reused across gates, a truthy string
read as consent. That is the same class of error the whole project is built
to prevent, which is a useful thing for a reviewer to keep catching.

---

## Limitations

Stated plainly, because a demo that hides them is not a security tool.

- **Containment records an authorised order; it does not enforce it.** See
  *What containment actually does*. Provider adapters are the honest
  remaining work.
- **Sandbox execution is not used.** No sandbox provider is configured on
  this TrueForge deployment, so enabling it would fail the turn.
- **Delegation is slower and more exposed to provider rate limits.** It is
  off by default for that reason.
- **The console's token is a shared secret, not per-operator identity.** It
  authenticates the console, not the person; there is no audit trail of
  *which* human approved. Put it behind a real proxy for that.
- **The evidence store is a seeded SQLite file**, not a SIEM. The MCP tool
  boundary is the seam where a real one would attach.
- **Run state is in memory.** Restarting the console loses in-flight runs;
  the containment audit log survives, since it is on disk.
- **`ui/server.py` prints the console URL with the token in it** when one is
  set, so the operator can open it. That is a terminal, not a log — but it
  is a deliberate trade, not an oversight.

## Future work

Provider adapters behind the approved containment interface (the finding from
#5 taken all the way); per-operator identity on approvals so the audit log
records *who*; collapsing the stdio runner onto `investigator/assessment.py`
(the honest remainder of #3); sandboxed analysis of the authentication
timeline once a sandbox provider is available.

---

## Repository map

```
data/init_db.py            the incident, and the only source of truth for it
mcp/sentinel_mcp/          MCP server: 5 read-only tools, 2 gated destructive
  server.py                  stdio + the tool definitions and annotations
  http_server.py             authenticated streamable HTTP (TrueForge needs remote)
investigator/              deterministic, no LLM, no HTTP
  analyzer.py                evidence correlation
  risk.py                    the authoritative score
  assessment.py              the single composition path
  containment.py             the only write path
  prompts.py                 the agent's behaviour contract (tested as one)
trueforge/                 the only package that speaks HTTP to TrueForge
  client.py                  transport
  agent.py                   agent spec, execution, trace extraction
ui/                        the operator console
  runner.py                  investigation → event stream; the gate lives here
  server.py                  four routes
  web/                       React; correlate.ts is a pure, tested reducer
sentinel/                  demo orchestration; contains no security logic
  preflight.py               readiness checks that name their own fix
  demo.py                    reset → check → investigate → gate → report
```

### Why the MCP server also speaks HTTP

TrueForge v0.1.4 accepts **remote MCP servers only** — its `MCPServerType`
enum has the single value `"remote"` and the manifest requires a `url`. The
stdio entrypoint cannot be registered with it, so `http_server.py` serves the
*same* `server` object over streamable HTTP. The tools and the read-only
model are identical. The HTTP transport is authenticated (stdio needs no
credentials — the client spawns the process; a listening socket serving login
histories does), and refuses a non-loopback bind without
`SENTINEL_MCP_ALLOW_REMOTE=1`.

Configuration is environment-driven; see `.env.example`. Everything has a
working local default, and **Sentinel never reads a model provider API key** —
those live in TrueForge's own settings.
