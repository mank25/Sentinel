"""Readiness checks for a Sentinel demo.

Sentinel has four moving parts that live outside this process -- TrueForge,
a model provider, the Sentinel MCP server and the seeded evidence store --
and a failure in any of them used to surface as a traceback from deep inside
an investigation. A stack trace is a bad first experience and a worse
diagnosis: it names the line that raised, not the thing that is missing.

Every check here answers two questions instead:

    what is wrong?
    what do I type to fix it?

Nothing in this module mutates anything. It does not register the MCP server
with TrueForge, create an agent or seed a database -- so running it never
changes the state of the demo it is inspecting.

    python -m sentinel.preflight
"""

import asyncio
import sqlite3
import sys
from dataclasses import dataclass
from pathlib import Path

import httpx2

from trueforge.config import SENTINEL_TOOLS, TrueForgeConfig
from trueforge.mcp_auth import TOKEN_ENV, resolve_token

PROJECT_ROOT = Path(__file__).resolve().parent.parent
EVIDENCE_DB = PROJECT_ROOT / "data" / "security.db"
CONSOLE_BUILD = PROJECT_ROOT / "ui" / "web" / "dist" / "index.html"

# Long enough to distinguish "not listening" from "slow", short enough that a
# down service does not stall the whole check.
PROBE_TIMEOUT = 5.0

READY = "READY"
MISSING = "NOT READY"


@dataclass
class Check:
    """One readiness result: the answer, and the fix if it is negative."""

    name: str
    ok: bool
    detail: str
    fix: str = ""

    @property
    def status(self) -> str:
        return READY if self.ok else MISSING


def check_evidence_database(db_path: Path = EVIDENCE_DB) -> Check:
    """The read-only evidence store, and whether the incident is seeded."""

    if not db_path.is_file():
        return Check(
            "Evidence DB", False,
            "data/security.db does not exist",
            "python data/init_db.py",
        )

    try:
        # mode=ro, like every other read of this file in the project: a
        # readiness check must not be the one thing that creates or writes
        # the evidence store.
        uri = f"{db_path.resolve().as_uri()}?mode=ro"

        with sqlite3.connect(uri, uri=True) as connection:
            connection.execute("PRAGMA query_only = 1")

            users = connection.execute(
                "SELECT count(*) FROM users"
            ).fetchone()[0]
            logins = connection.execute(
                "SELECT count(*) FROM login_events"
            ).fetchone()[0]
            network = connection.execute(
                "SELECT count(*) FROM network_events"
            ).fetchone()[0]

    except sqlite3.Error as exc:
        return Check(
            "Evidence DB", False,
            f"cannot be read ({type(exc).__name__})",
            "python data/init_db.py --reset",
        )

    if not (users and logins and network):
        return Check(
            "Evidence DB", False,
            f"seeded incompletely ({users} users, {logins} logins, "
            f"{network} network records)",
            "python data/init_db.py --reset",
        )

    return Check(
        "Evidence DB", True,
        f"{users} user(s), {logins} login events, "
        f"{network} network records, read-only",
    )


def check_trueforge(config: TrueForgeConfig) -> Check:
    """Is the TrueForge server up and answering its capabilities route?"""

    try:
        response = httpx2.get(
            f"{config.api}/capabilities", timeout=PROBE_TIMEOUT
        )

    except httpx2.HTTPError:
        return Check(
            "TrueForge", False,
            f"unreachable at {config.base_url}",
            "Start TrueForge, or set $TRUEFORGE_BASE_URL to where it runs.",
        )

    if response.status_code >= 400:
        return Check(
            "TrueForge", False,
            f"answered HTTP {response.status_code} at {config.base_url}",
            "Check that $TRUEFORGE_BASE_URL points at a TrueForge server.",
        )

    return Check("TrueForge", True, f"v0.1.4 API at {config.base_url}")


def check_model(config: TrueForgeConfig) -> Check:
    """Is the configured model actually registered with a provider?

    Checked before a session exists because an unconfigured model otherwise
    fails deep inside a turn as an opaque provider error.
    """

    try:
        response = httpx2.get(f"{config.api}/models", timeout=PROBE_TIMEOUT)
        response.raise_for_status()
        available = [
            model.get("name") for model in response.json().get("data", [])
        ]

    except (httpx2.HTTPError, ValueError):
        return Check(
            "Model", False,
            "could not list models from TrueForge",
            "Fix TrueForge first; this check depends on it.",
        )

    if config.model in available:
        return Check("Model", True, config.model)

    return Check(
        "Model", False,
        f"'{config.model}' is not configured",
        "Add a provider under TrueForge Settings -> Model Providers, or "
        f"pick one of: {', '.join(available) or '(none configured)'}",
    )


async def _list_mcp_tools(url: str, token: str) -> list:
    """Complete a real MCP handshake and return the tool names it offers."""

    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    # The bearer token rides on the HTTP client, which is how the mcp 2.x
    # streamable-HTTP transport takes request headers.
    http = httpx2.AsyncClient(
        headers={"Authorization": f"Bearer {token}"},
        timeout=PROBE_TIMEOUT,
    )

    async with http:
        async with streamable_http_client(url, http_client=http) as streams:
            read, write = streams[0], streams[1]

            async with ClientSession(read, write) as session:
                await session.initialize()
                listing = await session.list_tools()

                return [tool.name for tool in listing.tools]


def check_mcp_server(config: TrueForgeConfig) -> Check:
    """Is the Sentinel MCP server listening, authenticated, and current?

    This does a real MCP handshake and lists the tools rather than pinging
    the port, because "something is listening" is the weakest of the three
    things worth knowing. A server left running from an earlier checkout
    answers a ping perfectly and then fails provisioning with a missing
    tool -- which is a confusing error at the wrong moment, and exactly the
    kind of thing a readiness check exists to catch first.
    """

    token = resolve_token()

    if not token:
        return Check(
            "MCP server", False,
            "no bearer token has been resolved",
            f"Export ${TOKEN_ENV}, or let the server generate "
            ".sentinel-mcp-token on first run.",
        )

    try:
        names = asyncio.run(
            asyncio.wait_for(
                _list_mcp_tools(config.mcp_url, token),
                timeout=PROBE_TIMEOUT * 2,
            )
        )

    except asyncio.TimeoutError:
        return Check(
            "MCP server", False,
            f"did not complete an MCP handshake at {config.mcp_url}",
            "python mcp/sentinel_mcp/http_server.py",
        )

    except Exception as exc:  # noqa: BLE001 - reported, never raised at a user
        # The MCP client wraps transport and protocol faults in several
        # exception types, and an unauthorised handshake is one of them.
        # Distinguish the case worth naming; report the rest plainly.
        if "401" in str(exc) or "unauthorized" in str(exc).lower():
            return Check(
                "MCP server", False,
                "listening, but it rejected our bearer token",
                f"Make both sides resolve the same token: export "
                f"${TOKEN_ENV} for each, or let both read "
                ".sentinel-mcp-token.",
            )

        return Check(
            "MCP server", False,
            f"unreachable at {config.mcp_url} ({type(exc).__name__})",
            "python mcp/sentinel_mcp/http_server.py",
        )

    missing = [tool for tool in SENTINEL_TOOLS if tool not in names]

    if missing:
        return Check(
            "MCP server", False,
            f"running, but missing {', '.join(missing)}",
            "It is serving an older build. Restart it: "
            "python mcp/sentinel_mcp/http_server.py",
        )

    return Check(
        "MCP server", True,
        f"{len(names)} tools, authenticated at {config.mcp_url}",
    )


def check_console_build(build: Path = CONSOLE_BUILD) -> Check:
    """The committed React build the console serves.

    Not fatal: the CLI demo needs no frontend. Reported so an operator who
    wanted the browser console is told why they got a 503 instead.
    """

    if build.is_file():
        return Check("Operator console", True, "built (ui/web/dist)")

    return Check(
        "Operator console", False,
        "ui/web/dist is missing",
        "cd ui/web && npm install && npm run build "
        "(only needed for the browser console)",
    )


def run_checks(config: TrueForgeConfig | None = None) -> list:
    """Every readiness check, in dependency order.

    TrueForge is checked before the model because the model check is a query
    against TrueForge: reporting "model not configured" when the server is
    simply down would send an operator to the wrong place.
    """

    config = config or TrueForgeConfig.from_env()

    return [
        check_evidence_database(),
        check_mcp_server(config),
        check_trueforge(config),
        check_model(config),
        check_console_build(),
    ]


# Everything below is presentation.

def format_checks(checks: list) -> str:
    width = max(len(check.name) for check in checks)
    lines = []

    for check in checks:
        mark = "OK  " if check.ok else "FAIL"
        lines.append(
            f"  [{mark}] {check.name.ljust(width)}  "
            f"{check.status:<9}  {check.detail}"
        )

        if not check.ok and check.fix:
            lines.append(f"         {' ' * width}  -> {check.fix}")

    return "\n".join(lines)


def blocking(checks: list) -> list:
    """Failures that make an investigation impossible.

    The console build is deliberately not one of them: the CLI demo runs
    without a browser, and refusing to start over a missing frontend would
    block a path that works.
    """

    return [
        check for check in checks
        if not check.ok and check.name != "Operator console"
    ]


def main(argv=None) -> int:
    config = TrueForgeConfig.from_env()
    checks = run_checks(config)

    print("Sentinel readiness")
    print(format_checks(checks))

    failed = blocking(checks)

    if failed:
        print(
            f"\n{len(failed)} blocking problem"
            f"{'' if len(failed) == 1 else 's'}. "
            "Fix the arrows above and re-run."
        )
        return 1

    print("\nAll systems ready.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
