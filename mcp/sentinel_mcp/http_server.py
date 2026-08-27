"""Serve the Sentinel MCP tools over streamable HTTP.

TrueForge v0.1.4 only accepts ``remote`` MCP servers (``MCPServerType`` is the
single-value enum ``["remote"]``, and the manifest requires a ``url``), so the
stdio entrypoint in :mod:`server` cannot be registered with it directly.

This module changes nothing about the tools or the read-only security model:
it exposes the exact same ``server`` object over a second transport.

    python -m sentinel_mcp.http_server
    python mcp/sentinel_mcp/http_server.py

Bind host/port with SENTINEL_MCP_HOST / SENTINEL_MCP_PORT.
"""

import asyncio
import os
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]

if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from server import server  # noqa: E402

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8791
MCP_PATH = "/mcp"


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


def resolve_url(host: str | None = None, port: int | None = None) -> str:
    """The URL TrueForge should be pointed at."""

    host = host or resolve_host()
    port = port if port is not None else resolve_port()

    # TrueForge connects from the host, so advertise a reachable address
    # rather than a wildcard bind.
    if host in ("0.0.0.0", "::", ""):
        host = "127.0.0.1"

    return f"http://{host}:{port}{MCP_PATH}"


def main() -> None:
    host = resolve_host()
    port = resolve_port()

    print(f"Sentinel MCP (streamable-http) listening on {resolve_url()}")

    asyncio.run(
        server.run_streamable_http_async(
            host=host,
            port=port,
            streamable_http_path=MCP_PATH,
        )
    )


if __name__ == "__main__":
    main()
