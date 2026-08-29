# Sentinel

AI Security Investigator — an MCP server exposing read-only security
investigation tools over a local SQLite event store.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Dependencies are declared in `pyproject.toml`.

## Database initialization

The demo security database (`data/security.db`) is **not** committed to Git.
`data/init_db.py` is the source of truth for it — recreate it after a fresh
clone with:

```bash
python data/init_db.py
```

Importing `data.init_db` has no side effects; the database is only created when
the script is run directly or `init_db()` is called explicitly.

## Running the MCP server

```bash
python mcp/sentinel_mcp/server.py
```

The server speaks MCP over stdio and exposes two read-only tools:

- `get_login_history(username)` — returns the user's profile and their most
  recent login events (newest first, with ISO-8601 timestamps).
- `get_network_activity(ip_address)` — returns network intelligence for a
  single IP address.
- `assess_user_risk(username)` — runs the deterministic pipeline (analyzer →
  risk engine → report) and returns the authoritative threat level, risk
  score and risk factors. Scoring stays in `investigator/risk.py`; this tool
  is a thin read-only adapter over it.

All three are annotated `readOnlyHint: true`. The same tools are also served
over streamable HTTP for TrueForge — see the TrueForge section below:

```bash
python mcp/sentinel_mcp/http_server.py
```

The HTTP transport is **authenticated**. stdio needs no credentials (the
client spawns the process), but a listening socket serving login histories
and network intelligence does, so every request must carry
`Authorization: Bearer <token>`. The token comes from `$SENTINEL_MCP_TOKEN`,
or is generated once into `.sentinel-mcp-token` (mode 0600, gitignored). The
server also refuses to bind to a non-loopback interface unless
`SENTINEL_MCP_ALLOW_REMOTE=1` is set.

`get_network_activity` distinguishes two negative outcomes, and the
investigator keeps them apart:

```json
{"found": false, "ip_address": "203.0.113.9"}
{"found": false, "ip_address": "203.0.113.9", "error": "Unable to read network security data."}
```

The first means the IP was queried and has no record. The second means the
lookup itself failed — the investigation then reports incomplete network
evidence rather than treating the IP as clean.

The database is opened strictly read-only (`mode=ro` + `PRAGMA query_only`), so
the tool can never create or modify `data/security.db`. If the database is
missing or invalid, the tool returns a structured error rather than raising:

```json
{"found": false, "error": "Security database is unavailable or invalid"}
```

## Smoke test

```bash
python mcp/test_client.py
```

This starts the server, lists its tools, and calls
`get_login_history("admin")`.

## Running an investigation

Both invocations are supported and behave identically:

```bash
python -m investigator.run_investigation   # preferred
python investigator/run_investigation.py
```

The pipeline keeps its layers separate:

```
MCP tools (read-only)  ->  analyzer (correlation)  ->  risk engine (scoring)  ->  report (wording)
```

The risk engine is deterministic — every point is attributable to a listed
factor — and the report never recalculates risk.

## Tests

The suites are plain functions, so they run either way:

```bash
pytest -q     # investigator + trueforge unit tests

# or, without pytest installed:
python -m investigator.test_analyzer
python -m investigator.test_risk
python -m investigator.test_report
python -m investigator.test_run_investigation
```

## TrueForge agent integration

### Architecture

```
                        TrueForge  (agent loop, model, MCP orchestration)
                             |
                      Sentinel Agent
                             |
              +--------------+--------------+
              v              v              v
     get_login_history  get_network_activity  assess_user_risk
              |              |              |
              +--------------+--------------+
                             v
                     Sentinel MCP server  (read-only SQLite)
                             v
                          Analyzer      <- correlates evidence
                             v
                         Risk Engine    <- deterministic scoring
                             v
                           Report
                             v
                      Agent response
```

Who does what:

- **TrueForge** runs the agent loop: it holds the model, decides which tool to
  call next, executes MCP tool calls and records every event. It is the
  orchestrator, and it does no security scoring.
- **MCP tools** are the evidence layer. They are strictly read-only
  (`mode=ro` + `PRAGMA query_only`) and annotated `readOnlyHint: true`.
- **Analyzer / risk engine / report** stay deterministic and unchanged. The
  agent reaches them through the `assess_user_risk` tool, so the threat level
  and risk score are computed by `investigator/risk.py` and never invented by
  the model. The prompt in `investigator/prompts.py` contains no scoring
  rules for exactly this reason.

`trueforge/` is the only package that speaks HTTP to TrueForge. The
deterministic modules never import it.

### Why the MCP server also speaks HTTP

TrueForge v0.1.4 accepts **remote MCP servers only** -- its `MCPServerType`
enum has the single value `"remote"` and the manifest requires a `url`. The
stdio entrypoint therefore cannot be registered with it. `http_server.py`
serves the *same* `server` object over streamable HTTP; the tools and the
read-only model are identical.

### Setup

1. Start TrueForge (v0.1.4) on `http://localhost:8790` and configure a model
   provider under **Settings -> Model Providers**. Sentinel never reads a
   provider API key -- TrueForge stores it. Do not put one in this repo.

2. Start the Sentinel MCP server over HTTP:

   ```bash
   python mcp/sentinel_mcp/http_server.py
   # Sentinel MCP (streamable-http) listening on http://127.0.0.1:8791/mcp
   ```

3. Run an investigation. Registration and agent creation happen
   programmatically -- no browser configuration required:

   ```bash
   python -m trueforge.run_agent --username admin --trace
   ```

Configuration is environment-driven; see `.env.example`. Everything has a
working local default.

### What the runner does

1. `GET /api/v1/capabilities` - confirm TrueForge is up
2. `PUT /api/v1/settings/mcp-servers` - register `sentinel-security`
   (create-or-replace, so it is idempotent)
3. `GET /api/v1/mcp-servers/{name}/tools` - make TrueForge connect to the MCP
   server and confirm all three tools load
4. `GET /api/v1/agents` + `POST`/`PUT /api/v1/agents/{id}` - create or update
   the `sentinel-investigator` agent
5. `POST /api/v1/sessions` - open a session against the agent
6. `POST /api/v1/sessions/{id}/turns` - send the investigation request
7. `GET /api/v1/sessions/{id}/turns/{turn_id}` - poll until the turn ends
8. `GET /api/v1/sessions/{id}/turns/{turn_id}/events` - collect the real
   execution trace

### Containment and the approval gate

Sentinel's evidence tools only read. Containment is the one write path, and
it is gated on a human.

Two stores, one direction each:

| Store | Opened | Written by |
|---|---|---|
| `data/security.db` | `mode=ro` + `PRAGMA query_only` | nothing, ever |
| `data/containment.db` | read-write | `investigator/containment.py` only |

An investigation can therefore never modify the evidence it reasons about.

**The gate is enforced by the harness, not the prompt.** `contain_account`
and `block_ip` are annotated `readOnlyHint: false, destructiveHint: true` on
the MCP server, and the agent spec sets
`require_approval_for_tools: ["@write", "@destructive"]`. TrueForge pauses the
turn and emits `tool.approval_required`; nothing runs until a
`user.tool_approval` decision comes back. Rewriting the system prompt cannot
bypass this — the model proposes, a person decides.

Containment writes are observable: `get_account_status` reads the audit log
back, so a later investigation sees that a response action was taken and why.

Running it:

```bash
python -m trueforge.run_agent --username admin --trace   # prompts you to decide
python -m trueforge.run_agent --username admin --approve # scripted demo: approve
python -m trueforge.run_agent --username admin --deny    # scripted demo: deny
```

Interactively the run stops and shows what is being requested:

```
====================================================================
  CONTAINMENT APPROVAL REQUIRED
====================================================================
  action:  contain_account
  target:  username='admin'
  reason:  47 failed logins then a success from 185.123.45.67
====================================================================
  Approve this action? [y/N]
```

An empty answer, or a closed stdin, is a **denial** — silence is never
consent. On denial the decision is final: the agent reports that the action
was not taken and may not retry it.

### The investigator prompt

`investigator/prompts.py` is the agent's behaviour specification, and it is
tested like one (`investigator/test_prompts.py`). It is what makes the agent
an investigator rather than a wrapper around one function.

It contains, deliberately:

- **A role and a standard.** Sentinel is a SOC analyst whose credibility
  rests on every claim tracing back to a tool result.
- **Purpose, not just names, for each tool** — why `get_login_history` is
  always first (it establishes the *baseline* device and location everything
  else is judged against), why `get_network_activity` exists (to corroborate
  or *refute* a suspicion the login history alone cannot settle), and that
  `assess_user_risk` is the scoring system of record.
- **A method with an explicit correlation stage.** Findings must be tied
  together across tools before any conclusion; a finding backed by two
  independent sources is called out as stronger than one backed by a single
  source. A reconcile step requires the agent to state any disagreement
  between its own reading and the engine's factors.
- **Derivation, not memorisation.** Suspicious IPs must come from the login
  evidence just read. The prompt contains no IP address at all — a test
  enforces that, because a literal IP would let the agent "investigate" the
  seeded scenario without reading anything.
- **Calibration.** Each threat level licenses a specific strength of claim.
  Only CRITICAL may centre on likely compromise, and even there the wording
  is "consistent with", never "the account was compromised". HIGH and MEDIUM
  explicitly may not assert compromise; LOW with no factors must not
  manufacture concern.

It deliberately contains **no scoring rules**. Two tests enforce that: one
bans point values and `score +=`-style text, another matches
threshold-shaped constructs (`score >= 80`, `critical: 80`) so the model can
never derive a score itself. The engine scores; the agent investigates.

### Execution trace

`--trace` prints the investigation journey, built from the events TrueForge
actually recorded (`mcp.initialize`, tool calls on `model.message.tool_calls`,
results on `tool.response`, paired by `tool_call_id`). Nothing is synthesised.
`--json` emits the full result including raw events, which is what a UI would
consume later.

### Model choice

The default is `google-gemini/gemini-3-6-flash`, verified end-to-end against
the seeded scenario. Override with `--model` or `$TRUEFORGE_MODEL`; the
runner validates the model against `GET /api/v1/models` before starting a
session and lists the alternatives if it is missing.

Two requirements: **tool/function calling**, and enough context for a full
login history (~1,900 tokens for the seeded `admin` account).

**Known-incompatible: `groq/gpt-oss-120b`.** A tool-using turn fails on the
second model call:

```
'messages.2' : for 'role:assistant' the following must be satisfied
[('messages.2' : property 'reasoning_content' is unsupported)]
```

TrueForge v0.1.4 persists the model's reasoning as `thinking_blocks` and
replays it to the provider as `reasoning_content`; Groq's OpenAI-compatible
API rejects that property on input. Nothing in Sentinel triggers it — MCP
registration, tool discovery and the first tool call all succeed first. It is
specific to reasoning models on providers that reject the field; Gemini,
OpenAI and Anthropic all accept it. `ModelParams` documents extra keys as
"forwarded as-is", but v0.1.4 drops unknown keys, so `reasoning_format`
cannot be used to work around it.

The deterministic investigation always runs without any LLM:

```bash
python -m investigator.run_investigation
```

### Tests

```bash
pytest -q                 # unit tests only; no server required
pytest -m integration -q  # needs TrueForge + the Sentinel MCP server running
```

The console's event-to-timeline transformation -- tool correlation, replay
idempotence, the approval record -- is a pure function in
`ui/web/src/correlate.ts`, tested without a browser and without adding a test
framework (Node's own runner and native TypeScript stripping):

```bash
cd ui/web && npm test
```

Integration tests skip **only** when a prerequisite is genuinely absent —
TrueForge not running, the MCP server not running, or the configured model
not registered. Once those are present nothing skips: a broken registration,
provisioning failure or tool-orchestration regression fails the suite. The
sole concession is a bounded retry for transient provider outages (503 /
rate limiting), which retries and then fails.

## Operator console

The console is where the approval gate becomes visible. A trace scrolling past
in a terminal does not show an operator what the agent wants to do to a
production account; a button next to the account name does.

```bash
python -m ui.server          # http://127.0.0.1:8792
```

That is the whole setup. `ui/web/dist` is committed, so the console runs with
Python alone -- npm is needed to *change* the frontend, not to run it.

What it shows:

- **What the agent is doing, while it does it** -- provisioning, then each
  MCP tool call TrueForge actually made, with its arguments and its result,
  streamed as TrueForge records it. The agent's turn is polled once a second
  and the events recorded so far are re-read, so a tool call reaches the
  console about a second after it happens rather than at the end of the run.
  Nothing is synthesised: every row comes from an event TrueForge recorded.
- **What it is waiting on** -- when TrueForge pauses the turn, the console
  renders the exact containment call, its arguments, and what it will do in
  plain words. Approve and Deny are the only ways forward.
- **What it decided, and who decided it** -- the deterministic risk engine's
  score and threat level are shown next to, and visibly apart from, the
  agent's narrative. See "The verdict is the engine's" below.

The console holds no security logic. It starts investigations, streams what
TrueForge reports, and carries a decision back to the paused turn. Scoring
stays in `investigator/risk.py`; the gate stays in the harness.

### An approval answers one specific request

A decision names the gate it answers.

Every pause mints a `gate_id`. It rides out on the `approval_required` event,
the browser sends it back with the decision, and the server refuses anything
that does not match the gate currently open:

```
POST /api/investigations/{id}/decision
{"gate_id": "a358cc9a...", "allowed": false, "reason": "Shared VPN."}

400  gate_id missing or not a string
409  gate_id names a gate that is not the open one   -> nothing executes
409  no gate is open at all                          -> nothing executes
```

This is not ceremony. Without it, a decision means "approve whatever gate
happens to be open right now" -- so a duplicated click, a second browser tab,
or a retried request could approve the *next* containment action, which the
operator never saw. An investigation can pause more than once, and the two
pauses can propose very different things. `test_a_gate1_decision_cannot_approve_gate2`
in `ui/test_console.py` holds that line.

### The verdict is the engine's

The console never reads a threat level out of the model's prose.

`assess_user_risk` is the deterministic engine's MCP tool. When its result
comes back on the event stream, `ui/runner.py` parses it and republishes the
score, threat level and risk factors as a structured `assessment` event --
verbatim, with no recomputation, and dropped entirely rather than guessed at
if the payload is not a completed assessment. The console renders that beside
the agent's narrative, labelled, so the split is legible at a glance:

```
DETERMINISTIC RISK ENGINE          AI INVESTIGATOR
100 / 100  CRITICAL                narrative, evidence, assessment
6 evidence-backed factors
Computed by investigator/risk.py
```

No scoring logic is duplicated in TypeScript. There is one scorer, and it is
`investigator/risk.py`.

### Architecture

```
Browser (React)
    |  POST /api/investigations        start
    |  GET  .../events                 SSE: the run as it happens
    |  POST .../decision               allow / deny
    v
ui/server.py  (Starlette)
    v
ui/runner.py     -- runs the investigation on a worker thread; the
    |               on_approval callback blocks it on a threading.Event
    v               until a human answers. Nothing is auto-approved.
trueforge/agent.py  -> TrueForge -> Sentinel MCP tools
```

If the operator never answers, the run stays paused until it times out
(`ui.runner.APPROVAL_TIMEOUT`, 10 minutes) and containment does **not**
execute. The failure mode is "nothing happened", never "it went ahead".
An investigation may pause more than once; each gate waits for its own
decision, so an earlier answer can never release a containment call the
operator has not seen.

Every event carries a monotonic `seq`, and a follower is replayed the whole
run from its first event. That makes reconnection trivial and safe: the
browser retries with backoff, replays, and the reducer drops anything at or
below the highest `seq` it has already rendered. No duplicates, no gaps,
order preserved -- and no second event-stream architecture to maintain.

### Binding beyond this machine

Every route can start an investigation, read its evidence trace, or approve
containment of a production account. On `127.0.0.1` that is the operator's
own machine. Anywhere else it is whoever can reach the port, so the console
refuses to bind there without a shared token:

```bash
python -m ui.server --host 0.0.0.0 --token "$(openssl rand -hex 24)"
```

The token is then required on every request, as an `Authorization: Bearer`
header or a `?token=` query parameter -- the query string is what the SSE
stream uses, since `EventSource` cannot set headers. Open the URL the server
prints on startup and the console carries the token for you.
`SENTINEL_CONSOLE_TOKEN` sets it from the environment instead of the
command line. This is a shared secret, not per-operator identity: put it
behind a real proxy if you need accountable, per-person access.

### Frontend development

```bash
cd ui/web
npm install
npm run dev      # Vite on :5173, proxies /api to the Python console
npm run build    # refresh the committed dist/
```

### Tests

`ui/test_console.py` drives the console with a fake agent, so it needs
neither TrueForge nor a model. The tests that matter assert the gate holds:
a run pauses and does not finish without a decision, a denial reason reaches
the agent, and a decision posted outside the pause is rejected.

## Qodo Code Review Evidence

Every substantive change in Sentinel landed through a pull request reviewed by
Qodo before merge. Nothing was pushed straight to `main`.

| PR | Change | Qodo raised | Outcome |
|---|---|---|---|
| [#2](https://github.com/mank25/Sentinel/pull/2) | Investigation tools, risk engine, reporting | Batch the suspicious-IP lookups; run per-IP lookups concurrently | **Dismissed, deliberately.** Both are throughput optimisations for a serial `get_network_activity` loop. The seeded scenario correlates a handful of IPs against a 20 KB local SQLite file, so the round-trip cost is nil and concurrency would buy nothing measurable. Kept the serial loop because the execution trace stays a readable, ordered narrative — which is the point of an investigator. Revisit if the evidence store ever moves off-box. |
| [#3](https://github.com/mank25/Sentinel/pull/3) | TrueForge integration, HTTP MCP transport | Unify the stdio runner and the MCP adapter on one async assessment pipeline | **Partly accepted, deferred in part.** Qodo's own recommendation was to keep the transport-isolated package and synchronous adapter, and it was right: making the deterministic analyzer/risk/report layers async would add complexity to code whose entire value is being simple and predictable. The duplicated pipeline wiring it identified is real, and `investigator/assessment.py` now exists as the single composition layer the MCP tool uses. Collapsing the stdio runner onto it too is the honest remaining follow-up. |
| [#4](https://github.com/mank25/Sentinel/pull/4) | Prompt as behaviour contract + tests | Consider enforcing tool ordering deterministically in the runtime rather than in prose | **Dismissed, with reasoning.** Enforcing the order in code would duplicate the orchestration TrueForge already owns and would make the agent a fixed script rather than an investigator. The concern behind the finding — that prose instructions are not guarantees — is instead answered by tests: `investigator/test_prompts.py` fails the build if the prompt ever contains a literal IP or a scoring rule, so the model cannot fake evidence or invent a score even if it ignores the prose. |
| [#5](https://github.com/mank25/Sentinel/pull/5) | Containment + human approval gate | *(in review)* | The PR asks Qodo two specific questions: whether the evidence/containment two-database split is the right boundary, and whether `resume_turn_with_approval` handles a turn completing between the poll and the resume. |

The pattern worth noting: Qodo's most useful findings on this repo were
architectural rather than defect-level, and the most valuable one (#3) was the
duplicated composition path — which is why `investigator/assessment.py` exists.
The performance suggestions were correct in general and wrong for this
workload, which is the kind of call the review is there to prompt rather than
to make.
