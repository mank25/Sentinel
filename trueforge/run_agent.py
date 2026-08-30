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

from trueforge.agent import (  # noqa: E402
    SentinelAgent,
    allow_all,
    deny_all,
)
from trueforge.client import approval_item  # noqa: E402
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
             "(default: $TRUEFORGE_MODEL, else the configured default).",
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
    parser.add_argument(
        "--delegate",
        action="store_true",
        help="Investigate through specialist subagents (identity, timeline "
             "and network) coordinated by a lead analyst, instead of one "
             "linear thread. Each specialist runs on its own TrueForge "
             "thread. Slower and more model calls; off by default.",
    )

    approval = parser.add_mutually_exclusive_group()
    approval.add_argument(
        "--approve",
        action="store_true",
        help="Approve every containment request without prompting. For "
             "scripted demos only -- it removes the human from the loop.",
    )
    approval.add_argument(
        "--deny",
        action="store_true",
        help="Deny every containment request without prompting.",
    )
    parser.add_argument(
        "--deny-reason",
        default="Denied by operator.",
        help="Reason shown to the agent when a request is denied.",
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

        elif step == "tool.approval_required":
            lines.append("  [!] paused for human approval")

        elif step == "turn.done":
            lines.append(f"  [turn] {entry.get('status')}")

    return "\n".join(lines)


def describe_request(item: dict) -> str:
    """Render one pending containment request for a human to judge."""

    arguments = dict(item.get("arguments") or {})
    justification = arguments.pop("justification", None)

    target = ", ".join(f"{k}={v!r}" for k, v in arguments.items())

    lines = [
        "",
        "=" * 68,
        "  CONTAINMENT APPROVAL REQUIRED",
        "=" * 68,
        f"  action:  {item.get('tool')}",
        f"  target:  {target or '(none)'}",
    ]

    if justification:
        lines.append(f"  reason:  {justification}")

    lines.append("=" * 68)

    return "\n".join(lines)


def prompt_for_approval(pending: list, deny_reason: str) -> list:
    """Ask the operator to decide on each pending containment call."""

    decisions = []

    for item in pending:
        print(describe_request(item))

        answer = ""

        while answer not in {"y", "yes", "n", "no"}:
            try:
                answer = input("  Approve this action? [y/N] ").strip().lower()

            except EOFError:
                # Non-interactive stdin: refuse rather than assume consent.
                answer = "n"

            if answer == "":
                answer = "n"

        allow = answer in {"y", "yes"}

        print(f"  -> {'APPROVED' if allow else 'DENIED'}\n")

        decisions.append(
            approval_item(
                item["thread_id"],
                item["tool_call_id"],
                allow,
                None if allow else deny_reason,
            )
        )

    return decisions


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

    config.delegate = args.delegate

    try:
        with SentinelAgent(config) as agent:
            print(
                f"Connecting to TrueForge at {config.base_url} "
                f"(model: {config.model}) ...",
                file=sys.stderr,
            )

            if args.approve:
                on_approval = allow_all

            elif args.deny:
                def on_approval(pending):
                    return deny_all(pending, args.deny_reason)

            else:
                def on_approval(pending):
                    return prompt_for_approval(pending, args.deny_reason)

            result = agent.investigate(
                args.username,
                on_approval=on_approval,
            )

    except TrueForgeError as exc:
        print(f"\nInvestigation failed: {exc}", file=sys.stderr)
        return 1

    if args.as_json:
        print(json.dumps(result, indent=2))
        return 0 if not result.get("error") else 1

    print(f"\n=== TRUEFORGE SESSION {result['session_id']} ===")
    print(f"turn: {result['turn_id']}  status: {result['status']}")
    print(f"tool calls: {result['tool_calls']}")

    for decision in result.get("approvals", []):
        verdict = "APPROVED" if decision["allowed"] else "DENIED"
        print(f"containment: {decision['tool']} -> {verdict}")

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
