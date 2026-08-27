"""Shared bearer-token contract for the Sentinel MCP HTTP transport.

The stdio MCP server needs no credentials: it is spawned as a subprocess by
its client and is reachable by nobody else. The streamable-HTTP transport is
different -- it is a listening socket serving login histories, network
intelligence and risk assessments -- so it authenticates every request.

Two parties must agree on one secret:

* ``mcp/sentinel_mcp/http_server.py`` verifies ``Authorization: Bearer ...``
* ``trueforge/client.py`` registers that header with TrueForge as the MCP
  server's ``header`` auth

so the token is resolved here, once. This module lives in ``trueforge``
because the HTTP transport exists to satisfy TrueForge's remote-only MCP
requirement; the stdio tool layer (``server.py``) does not import it.

Resolution order:

1. ``SENTINEL_MCP_TOKEN`` if set -- the right choice for real deployments.
2. Otherwise a token persisted in ``.sentinel-mcp-token`` (mode 0600,
   gitignored), created on first use so local development needs no setup.
"""

import os
import secrets
import stat
from pathlib import Path

TOKEN_ENV = "SENTINEL_MCP_TOKEN"
TOKEN_FILENAME = ".sentinel-mcp-token"

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def token_path() -> Path:
    return PROJECT_ROOT / TOKEN_FILENAME


def _read_token_file() -> str | None:
    path = token_path()

    if not path.is_file():
        return None

    token = path.read_text().strip()

    return token or None


def _write_token_file(token: str) -> None:
    """Persist a generated token readable only by the current user."""

    path = token_path()
    path.write_text(f"{token}\n")
    path.chmod(stat.S_IRUSR | stat.S_IWUSR)


def resolve_token(create: bool = False) -> str | None:
    """Return the shared MCP token.

    With ``create=False`` this never has side effects; it returns ``None``
    when no token has been established yet.
    """

    from_env = os.environ.get(TOKEN_ENV)

    if from_env:
        return from_env.strip()

    existing = _read_token_file()

    if existing:
        return existing

    if not create:
        return None

    token = secrets.token_urlsafe(32)
    _write_token_file(token)

    return token


def require_token() -> str:
    """Return the shared token, generating one on first use."""

    token = resolve_token(create=True)

    if not token:
        raise RuntimeError(
            "Could not establish a Sentinel MCP token. Set "
            f"{TOKEN_ENV} explicitly."
        )

    return token


def authorization_header(token: str | None = None) -> dict:
    """The header TrueForge must send to reach the Sentinel MCP server."""

    return {"Authorization": f"Bearer {token or require_token()}"}
