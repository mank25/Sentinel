# Sentinel

AI Security Investigator — an MCP server exposing read-only security
investigation tools over a local SQLite event store.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install "mcp==2.1.0"
```

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
python -m pytest investigator -q

# or, without pytest installed:
python -m investigator.test_analyzer
python -m investigator.test_risk
python -m investigator.test_report
python -m investigator.test_run_investigation
```
