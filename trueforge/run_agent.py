"""CLI entrypoint for a TrueForge-orchestrated Sentinel investigation.

    python -m trueforge.run_agent --username admin
    python -m trueforge.run_agent --username admin --trace
    python -m trueforge.run_agent --username admin --json
"""

import argparse
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from trueforge.agent import SentinelAgent  # noqa: E402
from trueforge.client import TrueForgeError  # noqa: E402
from trueforge.config import TrueForgeConfig  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m trueforge.run_agent",
        description=(
            "Run a Sentinel security investigation as a TrueForge agent."
        ),
    )

    parser.add_argument(
        "--username",
        default="admin",
        help="Account to investigate (default: admin).",
    )
    parser.add_argument(
        "--trace",
        action="store_true",
        help="Print the tool-call execution trace.",
    )
    parser.add_argument(
        "--json",
        dest="as_json",
        action="store_true",
        help="Print the full result, including raw events, as JSON.",
    )
    parser.add_argument(
        "--model",
        help="Model FQN as reported by GET /api/v1/models "
             "(default: $TRUEFORGE_MODEL or groq/gpt-oss-120b).",
    )
    parser.add_argument(
        "--base-url",
        help="TrueForge base URL (default: $TRUEFORGE_BASE_URL or "
             "http://localhost:8790).",
    )
    parser.add_argument(
        "--mcp-url",
        help="Sentinel MCP streamable-HTTP URL (default: $SENTINEL_MCP_URL "
             "or http://127.0.0.1:8791/mcp).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        help="Seconds to wait for the investigation turn.",
    )

    return parser


def _format_trace(trace: list) -> str:
    lines = []

    for entry in trace:
        step = entry.get("step")

        if step == "mcp.initialize":
            lines.append(
                f"  [mcp] initialized {entry.get('server')} "
                f"({entry.get('transport')})"
            )

        elif step == "tool.call":
            arguments = json.dumps(entry.get("arguments", {}))
            lines.append(f"  -> tool call: {entry.get('tool')}{arguments}")

        elif step == "tool.response":
            content = (entry.get("content") or "").replace("\n", " ")
            preview = content[:160] + ("..." if len(content) > 160 else "")
            lines.append(f"  <- evidence returned: {preview}")

        elif step == "model.message":
            content = (entry.get("content") or "").replace("\n", " ")
            preview = content[:160] + ("..." if len(content) > 160 else "")
            lines.append(f"  [model] {preview}")

        elif step == "turn.done":
            lines.append(f"  [turn] {entry.get('status')}")

    return "\n".join(lines)


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    config = TrueForgeConfig.from_env()

    if args.model:
        config.model = args.model

    if args.base_url:
        config.base_url = args.base_url.rstrip("/")

    if args.mcp_url:
        config.mcp_url = args.mcp_url

    if args.timeout:
        config.timeout = args.timeout

    try:
        with SentinelAgent(config) as agent:
            print(
                f"Connecting to TrueForge at {config.base_url} "
                f"(model: {config.model}) ...",
                file=sys.stderr,
            )

            result = agent.investigate(args.username)

    except TrueForgeError as exc:
        print(f"\nInvestigation failed: {exc}", file=sys.stderr)
        return 1

    if args.as_json:
        print(json.dumps(result, indent=2))
        return 0 if not result.get("error") else 1

    print(f"\n=== TRUEFORGE SESSION {result['session_id']} ===")
    print(f"turn: {result['turn_id']}  status: {result['status']}")
    print(f"tool calls: {result['tool_calls']}")

    if args.trace:
        print("\n=== EXECUTION TRACE ===")
        print(_format_trace(result["trace"]))

    if result.get("error"):
        # Keep the trace above the error in terminal output.
        sys.stdout.flush()
        print(f"\nInvestigation error: {result['error']}", file=sys.stderr)
        return 1

    print("\n=== SENTINEL AGENT INVESTIGATION ===\n")
    print(result["response"])

    return 0


if __name__ == "__main__":
    sys.exit(main())
