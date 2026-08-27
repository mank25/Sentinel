"""Serve the Sentinel MCP tools over authenticated streamable HTTP.

TrueForge v0.1.4 only accepts ``remote`` MCP servers (``MCPServerType`` is the
single-value enum ``["remote"]``, and the manifest requires a ``url``), so the
stdio entrypoint in :mod:`server` cannot be registered with it directly.

The tools and the read-only security model are unchanged: this exposes the
exact same ``server`` object over a second transport. What it adds is
confidentiality, which stdio got for free and a listening socket does not.
These tools return login histories, network intelligence and user risk
assessments, so every request must present the shared bearer token (see
:mod:`trueforge.mcp_auth`), and binding to a non-loopback interface requires
an explicit opt-in.

    python mcp/sentinel_mcp/http_server.py

Environment:
    SENTINEL_MCP_HOST          bind address (default 127.0.0.1)
    SENTINEL_MCP_PORT          bind port (default 8791)
    SENTINEL_MCP_TOKEN         shared bearer token (auto-generated if unset)
    SENTINEL_MCP_ALLOW_REMOTE  set to 1 to permit a non-loopback bind
"""

import os
import secrets
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]

if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent))

import uvicorn  # noqa: E402

from server import server  # noqa: E402
from trueforge.mcp_auth import TOKEN_ENV, require_token  # noqa: E402

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8791
MCP_PATH = "/mcp"

LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}


class BearerTokenMiddleware:
    """Reject any request that does not carry the shared bearer token.

    Implemented as raw ASGI rather than ``BaseHTTPMiddleware`` so that
    streamable-HTTP and SSE responses are not buffered.
    """

    def __init__(self, app, token: str):
        self.app = app
        self.expected = f"Bearer {token}"

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers") or [])
        presented = headers.get(b"authorization", b"").decode("latin-1")

        # Constant-time compare so the token cannot be recovered by timing.
        if not secrets.compare_digest(presented, self.expected):
            await self._unauthorized(send)
            return

        await self.app(scope, receive, send)

    @staticmethod
    async def _unauthorized(send) -> None:
        body = b'{"error":"unauthorized"}'

        await send({
            "type": "http.response.start",
            "status": 401,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
                (b"www-authenticate", b'Bearer realm="sentinel-mcp"'),
            ],
        })
        await send({"type": "http.response.body", "body": body})


def resolve_host() -> str:
    return os.environ.get("SENTINEL_MCP_HOST", DEFAULT_HOST)


def resolve_port() -> int:
    """Read the port from the environment, falling back to the default."""

    raw = os.environ.get("SENTINEL_MCP_PORT")

    if not raw:
        return DEFAULT_PORT

    try:
        return int(raw)

    except ValueError:
        raise SystemExit(
            f"SENTINEL_MCP_PORT must be an integer, got {raw!r}"
        ) from None


def allow_remote() -> bool:
    return os.environ.get("SENTINEL_MCP_ALLOW_REMOTE", "").strip() in {
        "1",
        "true",
        "yes",
    }


def check_bind_host(host: str) -> None:
    """Refuse to expose the tools off-host without an explicit decision.

    The bearer token is the real access control; this is defence in depth
    against an accidental ``SENTINEL_MCP_HOST=0.0.0.0``.
    """

    if host in LOOPBACK_HOSTS or allow_remote():
        return

    raise SystemExit(
        f"Refusing to bind the Sentinel MCP server to {host!r}.\n"
        "These tools expose login history and network intelligence. Bind to "
        "127.0.0.1, or set SENTINEL_MCP_ALLOW_REMOTE=1 if you really intend "
        "to serve other hosts (the bearer token still applies)."
    )


def resolve_url(host: str | None = None, port: int | None = None) -> str:
    """The URL TrueForge should be pointed at."""

    host = host or resolve_host()
    port = port if port is not None else resolve_port()

    # TrueForge connects from the host, so advertise a reachable address
    # rather than a wildcard bind.
    if host in ("0.0.0.0", "::", ""):
        host = "127.0.0.1"

    return f"http://{host}:{port}{MCP_PATH}"


def build_app(token: str):
    """The streamable-HTTP app, wrapped in bearer-token authentication."""

    app = server.streamable_http_app(streamable_http_path=MCP_PATH)
    app.add_middleware(BearerTokenMiddleware, token=token)

    return app


def main() -> None:
    host = resolve_host()
    port = resolve_port()

    check_bind_host(host)

    token = require_token()

    print(f"Sentinel MCP (streamable-http) listening on {resolve_url()}")
    print(
        "Authentication: bearer token required "
        f"(from ${TOKEN_ENV} or .sentinel-mcp-token)"
    )

    uvicorn.run(
        build_app(token),
        host=host,
        port=port,
        log_level="warning",
    )


if __name__ == "__main__":
    main()
