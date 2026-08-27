"""Unit tests for the Sentinel MCP bearer-token contract and enforcement.

No server and no network: the token helpers are exercised against a temporary
project root, and the ASGI middleware is driven directly.
"""

import asyncio
import os
import stat
import sys
from pathlib import Path

import pytest

from trueforge import mcp_auth
from trueforge.mcp_auth import (
    TOKEN_ENV,
    authorization_header,
    require_token,
    resolve_token,
)

# http_server lives outside the installed packages (see pyproject), so import
# it the way it is actually run.
sys.path.insert(
    0,
    str(Path(__file__).resolve().parent.parent / "mcp" / "sentinel_mcp"),
)

import http_server  # noqa: E402


@pytest.fixture
def isolated_root(tmp_path, monkeypatch):
    """Point the token file at a temp dir and clear the env override."""

    monkeypatch.setattr(mcp_auth, "PROJECT_ROOT", tmp_path)
    monkeypatch.delenv(TOKEN_ENV, raising=False)

    return tmp_path


# ------------------------------------------------------------------
# Token resolution
# ------------------------------------------------------------------

def test_resolve_token_has_no_side_effects_by_default(isolated_root):
    assert resolve_token() is None
    assert not (isolated_root / mcp_auth.TOKEN_FILENAME).exists()


def test_env_var_wins(isolated_root, monkeypatch):
    monkeypatch.setenv(TOKEN_ENV, "from-env")

    assert resolve_token() == "from-env"
    # Still no file written.
    assert not (isolated_root / mcp_auth.TOKEN_FILENAME).exists()


def test_require_token_generates_and_persists(isolated_root):
    token = require_token()

    assert len(token) >= 32
    assert resolve_token() == token


def test_generated_token_is_stable_across_calls(isolated_root):
    assert require_token() == require_token()


def test_token_file_is_private(isolated_root):
    require_token()

    mode = stat.S_IMODE(os.stat(mcp_auth.token_path()).st_mode)

    assert mode == 0o600


def test_authorization_header_shape(isolated_root):
    assert authorization_header("abc") == {"Authorization": "Bearer abc"}


# ------------------------------------------------------------------
# Bind-host guard
# ------------------------------------------------------------------

def test_loopback_bind_is_allowed(monkeypatch):
    monkeypatch.delenv("SENTINEL_MCP_ALLOW_REMOTE", raising=False)

    for host in ["127.0.0.1", "::1", "localhost"]:
        http_server.check_bind_host(host)


def test_non_loopback_bind_is_refused(monkeypatch):
    monkeypatch.delenv("SENTINEL_MCP_ALLOW_REMOTE", raising=False)

    with pytest.raises(SystemExit) as excinfo:
        http_server.check_bind_host("0.0.0.0")

    assert "SENTINEL_MCP_ALLOW_REMOTE" in str(excinfo.value)


def test_non_loopback_bind_allowed_with_explicit_opt_in(monkeypatch):
    monkeypatch.setenv("SENTINEL_MCP_ALLOW_REMOTE", "1")

    http_server.check_bind_host("0.0.0.0")


# ------------------------------------------------------------------
# Bearer-token middleware
# ------------------------------------------------------------------

def _call_middleware(token, presented_header=None, scope_type="http"):
    """Drive the ASGI middleware and capture what it sent."""

    called = {"inner": False}
    sent = []

    async def inner_app(scope, receive, send):
        called["inner"] = True

        await send({
            "type": "http.response.start",
            "status": 200,
            "headers": [],
        })
        await send({"type": "http.response.body", "body": b"ok"})

    headers = []

    if presented_header is not None:
        headers.append((b"authorization", presented_header.encode()))

    middleware = http_server.BearerTokenMiddleware(inner_app, token)

    async def send(message):
        sent.append(message)

    async def receive():
        return {"type": "http.request", "body": b""}

    asyncio.run(
        middleware({"type": scope_type, "headers": headers}, receive, send)
    )

    return called["inner"], sent


def test_middleware_allows_the_correct_token():
    reached, sent = _call_middleware("s3cret", "Bearer s3cret")

    assert reached is True
    assert sent[0]["status"] == 200


def test_middleware_rejects_a_missing_token():
    reached, sent = _call_middleware("s3cret", None)

    assert reached is False
    assert sent[0]["status"] == 401


def test_middleware_rejects_a_wrong_token():
    reached, sent = _call_middleware("s3cret", "Bearer wrong")

    assert reached is False
    assert sent[0]["status"] == 401


def test_middleware_rejects_a_bare_token_without_the_scheme():
    reached, sent = _call_middleware("s3cret", "s3cret")

    assert reached is False
    assert sent[0]["status"] == 401


def test_unauthorized_response_advertises_the_scheme():
    _, sent = _call_middleware("s3cret", "Bearer nope")

    headers = dict(sent[0]["headers"])

    assert b"www-authenticate" in headers


def test_middleware_passes_through_non_http_scopes():
    """Lifespan events must not be intercepted."""

    reached, _ = _call_middleware("s3cret", None, scope_type="lifespan")

    assert reached is True
