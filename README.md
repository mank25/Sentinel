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

### Execution trace

`--trace` prints the investigation journey, built from the events TrueForge
actually recorded (`mcp.initialize`, tool calls on `model.message.tool_calls`,
results on `tool.response`, paired by `tool_call_id`). Nothing is synthesised.
`--json` emits the full result including raw events, which is what a UI would
consume later.

### Known limitation: reasoning models on an OpenAI-compatible provider

With `groq/gpt-oss-120b`, a tool-using turn fails on the second model call:

```
'messages.2' : for 'role:assistant' the following must be satisfied
[('messages.2' : property 'reasoning_content' is unsupported)]
```

TrueForge v0.1.4 persists the model's reasoning as `thinking_blocks` and
replays it to the provider as `reasoning_content` on the assistant message;
Groq's OpenAI-compatible API rejects that property on input. It is not
triggered by anything in Sentinel -- MCP registration, tool discovery and the
tool call itself all succeed first, and the deterministic pipeline is
unaffected. `ModelParams` documents extra keys as "forwarded as-is", but
v0.1.4 drops unknown keys, so `reasoning_format` cannot be used to work
around it.

Until a non-reasoning model or a more tolerant provider is configured, the
deterministic investigation runs without any LLM:

```bash
python -m investigator.run_investigation
```

### Tests

```bash
pytest -q                 # unit tests only; no server required
pytest -m integration -q  # needs TrueForge + the Sentinel MCP server running
```
