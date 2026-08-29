"""The Sentinel operator console: HTTP surface.

Four endpoints, deliberately:

    GET  /                          the console
    POST /api/investigations        start one, returns a run id
    GET  /api/investigations/{id}/events   SSE: the run as it happens
    POST /api/investigations/{id}/decision allow or deny containment

The console holds no security logic. It starts investigations, streams what
TrueForge reports, and carries a human's decision back to the paused turn.
"""

import argparse
import asyncio
import json
import os
import secrets
from pathlib import Path

import uvicorn
from sse_starlette.sse import EventSourceResponse
from starlette.applications import Starlette
from starlette.datastructures import Headers, QueryParams
from starlette.responses import FileResponse, JSONResponse, PlainTextResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from trueforge.config import TrueForgeConfig
from ui.runner import RunRegistry

# The built React app. `dist` is committed, so running the console needs
# only Python -- npm is required to *change* the frontend, not to run it.
DIST = Path(__file__).resolve().parent / "web" / "dist"

BUILD_MISSING = """\
The Sentinel console frontend has not been built.

    cd ui/web && npm install && npm run build

Or run the deterministic investigation, which needs no UI:

    python -m investigator.run_investigation
"""

registry = RunRegistry()

# Hosts that only this machine can reach. Binding anywhere else puts the
# start, stream and containment-decision routes on the network, so main()
# requires a token before it will do that.
LOOPBACK = frozenset({"127.0.0.1", "::1", "localhost"})

# The shared secret every request must carry, or None for the loopback-only
# default. Set by main(); the guard below is a no-op while it is None.
CONSOLE_TOKEN: str | None = None


def set_console_token(token: str | None) -> None:
    """Require ``token`` on every route, or drop the requirement if None."""

    global CONSOLE_TOKEN

    CONSOLE_TOKEN = token or None


def _authorized(scope) -> bool:
    header = Headers(scope=scope).get("authorization", "")

    if header.startswith("Bearer "):
        if secrets.compare_digest(header[7:], CONSOLE_TOKEN):
            return True

    # EventSource cannot set a header, so the stream -- and the page the
    # operator opens -- carry the token in the query string instead.
    supplied = QueryParams(scope.get("query_string", b"")).get("token", "")

    return bool(supplied) and secrets.compare_digest(supplied, CONSOLE_TOKEN)


class TokenGuard:
    """Reject unauthenticated requests whenever a console token is set.

    Written as raw ASGI rather than a ``BaseHTTPMiddleware``: the events
    route is a long-lived SSE stream, and BaseHTTPMiddleware buffers
    streaming responses.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if (
            scope["type"] != "http"
            or CONSOLE_TOKEN is None
            or _authorized(scope)
        ):
            await self.app(scope, receive, send)
            return

        response = JSONResponse(
            {"error": "This console requires an operator token."},
            status_code=401,
        )

        await response(scope, receive, send)


async def index(request):
    page = DIST / "index.html"

    if not page.exists():
        return PlainTextResponse(BUILD_MISSING, status_code=503)

    return FileResponse(page)


async def start_investigation(request):
    try:
        body = await request.json()

    except (json.JSONDecodeError, ValueError):
        body = {}

    username = (body.get("username") or "").strip()

    if not username:
        return JSONResponse(
            {"error": "A username is required."}, status_code=400
        )

    run = registry.create(username)
    run.start()

    return JSONResponse({"id": run.id, "username": run.username})


async def stream_events(request):
    run = registry.get(request.path_params["run_id"])

    if run is None:
        return JSONResponse({"error": "No such run."}, status_code=404)

    async def publisher():
        loop = asyncio.get_running_loop()

        # follow() replays what already happened before it yields anything
        # live, so a reconnecting browser is never left with a half-drawn
        # investigation -- and never sees the replayed events twice.
        follower = run.follow()

        try:
            while True:
                if await request.is_disconnected():
                    break

                # follow() blocks on a queue; keep it off the event loop.
                event = await loop.run_in_executor(None, next, follower)

                if event is None:
                    yield {"event": "ping", "data": "{}"}
                    continue

                yield {"data": json.dumps(event)}

                if event["kind"] in ("complete", "error"):
                    break

        finally:
            # Deregister this follower so a closed tab stops accumulating
            # events for the life of the run.
            follower.close()

    return EventSourceResponse(publisher())


async def decide(request):
    run = registry.get(request.path_params["run_id"])

    if run is None:
        return JSONResponse({"error": "No such run."}, status_code=404)

    try:
        body = await request.json()

    except (json.JSONDecodeError, ValueError):
        body = {}

    allowed = body.get("allowed") if isinstance(body, dict) else None

    # Deliberately not bool(): a truthiness test reads the JSON string
    # "false" as an approval, and this value executes containment.
    if not isinstance(allowed, bool):
        return JSONResponse(
            {"error": "'allowed' must be a JSON boolean: true or false."},
            status_code=400,
        )

    reason = (body.get("reason") or "").strip()

    if not run.decide(allowed, reason):
        return JSONResponse(
            {"error": f"This run is not awaiting a decision ({run.status})."},
            status_code=409,
        )

    return JSONResponse({"status": run.status, "allowed": allowed})


def build_app():
    routes = [
        Route("/", index),
        Route("/api/investigations", start_investigation, methods=["POST"]),
        Route(
            "/api/investigations/{run_id}/events", stream_events
        ),
        Route(
            "/api/investigations/{run_id}/decision",
            decide,
            methods=["POST"],
        ),
    ]

    # Mounted last so it can never shadow an API route.
    if (DIST / "assets").is_dir():
        routes.append(
            Mount(
                "/assets",
                StaticFiles(directory=DIST / "assets"),
                name="assets",
            )
        )

    return TokenGuard(Starlette(routes=routes))


app = build_app()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the Sentinel operator console."
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8792)
    parser.add_argument(
        "--token",
        default=os.environ.get("SENTINEL_CONSOLE_TOKEN"),
        help=(
            "Require this token on every request. Mandatory when --host is "
            "not a loopback address. Also read from SENTINEL_CONSOLE_TOKEN."
        ),
    )

    args = parser.parse_args(argv)

    # Every route here can start an investigation, read its evidence trace,
    # or approve containment of a production account. On loopback that is
    # the operator's own machine; anywhere else it is whoever can reach the
    # port, so a token is not optional.
    if args.host not in LOOPBACK and not args.token:
        parser.error(
            f"--host {args.host} exposes the console beyond this machine, "
            "where any reachable client could approve containment. Pass "
            "--token (or set SENTINEL_CONSOLE_TOKEN) to require one, or "
            "bind 127.0.0.1."
        )

    set_console_token(args.token)

    config = TrueForgeConfig.from_env()

    query = f"?token={args.token}" if args.token else ""

    print(f"Sentinel console  http://{args.host}:{args.port}/{query}")
    print(f"TrueForge         {config.base_url}")
    print(f"MCP server        {config.mcp_url}")
    print(f"Model             {config.model}")

    if args.token:
        print("Auth              token required on every request")

    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
