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

The server speaks MCP over stdio and exposes one tool:

- `get_login_history(username)` — returns the user's profile and their most
  recent login events.

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
