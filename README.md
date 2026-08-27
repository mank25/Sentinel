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

Integration tests skip **only** when a prerequisite is genuinely absent —
TrueForge not running, the MCP server not running, or the configured model
not registered. Once those are present nothing skips: a broken registration,
provisioning failure or tool-orchestration regression fails the suite. The
sole concession is a bounded retry for transient provider outages (503 /
rate limiting), which retries and then fails.
