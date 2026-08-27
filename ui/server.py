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
from pathlib import Path

import uvicorn
from sse_starlette.sse import EventSourceResponse
from starlette.applications import Starlette
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
        # Replay what already happened, so a reconnecting browser is never
        # left with a half-drawn investigation.
        for event in run.history():
            yield {"data": json.dumps(event)}

        loop = asyncio.get_running_loop()
        follower = run.follow()

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

    return EventSourceResponse(publisher())


async def decide(request):
    run = registry.get(request.path_params["run_id"])

    if run is None:
        return JSONResponse({"error": "No such run."}, status_code=404)

    try:
        body = await request.json()

    except (json.JSONDecodeError, ValueError):
        body = {}

    allowed = bool(body.get("allowed"))
    reason = (body.get("reason") or "").strip()

    if not run.decide(allowed, reason):
        return JSONResponse(
            {"error": f"This run is not awaiting a decision ({run.status})."},
            status_code=409,
        )

    return JSONResponse({"status": run.status, "allowed": allowed})


def build_app() -> Starlette:
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

    return Starlette(routes=routes)


app = build_app()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the Sentinel operator console."
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8792)

    args = parser.parse_args(argv)
    config = TrueForgeConfig.from_env()

    print(f"Sentinel console  http://{args.host}:{args.port}")
    print(f"TrueForge         {config.base_url}")
    print(f"MCP server        {config.mcp_url}")
    print(f"Model             {config.model}")

    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
