"""One command that runs the whole Sentinel story.

    python -m sentinel.demo

It resets the demo state, checks that every service is ready, runs a real
TrueForge investigation, narrates the agent's tool calls as TrueForge records
them, stops at the containment gate for a human decision, and prints the
incident report including whether containment was verified.

What this module is not: it is not a second implementation of anything. The
investigation runs through :class:`trueforge.agent.SentinelAgent`, the same
object the CLI and the browser console use. There is no demo-only code path,
no scripted trace, and no simulated approval. If TrueForge is down, the demo
does not run -- because the demo *is* TrueForge running.

Flags:

    --reset-only     reseed the evidence and clear the containment log
    --check          run the readiness checks and stop
    --approve/--deny answer the gate without prompting (scripted demo)
    --no-reset       keep the existing containment history
"""

import argparse
import json
import sys
from datetime import datetime

from investigator import containment
from sentinel import preflight
from trueforge.agent import SentinelAgent, allow_all, deny_all
from trueforge.client import TrueForgeError
from trueforge.config import TrueForgeConfig
from trueforge.run_agent import prompt_for_approval

RULE = "=" * 72
THIN = "-" * 72

DEFAULT_USERNAME = "admin"


# ---------------------------------------------------------------------
# Demo state
# ---------------------------------------------------------------------

def reset_demo_state(
    username: str = DEFAULT_USERNAME,
    evidence_db=None,
) -> list:
    """Put the demo back to its starting position.

    Repeatability is a feature, not a convenience: a judge who watches the
    approve path and then wants to watch the deny path must not have to
    hand-edit SQLite, and an account left contained by the previous run
    changes what the next investigation finds.

    Reseeding the *evidence* is a rebuild from ``data/init_db.py``, which is
    the source of truth for it. Clearing the *containment* log is a real
    delete -- it is Sentinel's only write path, and forgetting a demo action
    is exactly what "reset" should mean.
    """

    notes = []

    # Imported here rather than at module scope: data/ is a script directory,
    # not an installed package, so this import only works from a checkout and
    # must not break `import sentinel.demo` anywhere else.
    sys.path.insert(0, str(preflight.PROJECT_ROOT))

    from data.init_db import DB_PATH as EVIDENCE_DB, init_db

    evidence = evidence_db or EVIDENCE_DB

    init_db(evidence, reset=True)
    notes.append("evidence reseeded from data/init_db.py")

    # Read at call time, not bound at import: tests redirect it, and so
    # does anyone running the demo against a scratch store.
    store = containment.DB_PATH

    if store.is_file():
        store.unlink()
        notes.append("containment audit log cleared")
    else:
        notes.append("containment audit log was already empty")

    status = containment.account_status(username)
    assert status["contained"] is False, "reset left the account contained"

    return notes


# ---------------------------------------------------------------------
# Narration
# ---------------------------------------------------------------------

def _clock(created_at: str | None) -> str:
    """The event's own timestamp, or blank -- never a made-up one.

    A timeline that invents a time for an event that did not carry one is
    telling the operator something the trace does not support.
    """

    if not created_at:
        return " " * 8

    try:
        return datetime.fromisoformat(
            created_at.replace("Z", "+00:00")
        ).strftime("%H:%M:%S")

    except ValueError:
        return " " * 8


def _short(value, limit: int = 96) -> str:
    text = str(value).replace("\n", " ")
    return text if len(text) <= limit else f"{text[:limit]}…"


def narrate(entries: list) -> None:
    """Print newly-recorded trace entries as they arrive.

    Every line below comes from an event TrueForge recorded. Nothing is
    synthesised, and an entry whose step this function does not recognise is
    skipped rather than guessed at.
    """

    for entry in entries:
        step = entry.get("step")
        when = _clock(entry.get("created_at"))
        thread = entry.get("thread_id")

        # Only label a thread when it is not the root agent's, so a linear
        # investigation stays uncluttered and a delegated one is obvious.
        tag = "" if thread in (None, "main") else f"[{thread[:8]}] "

        if step == "mcp.initialize":
            print(f"  {when}  {tag}MCP connected · {entry.get('server')} "
                  f"({entry.get('transport')})")

        elif step == "thread.created":
            print(f"  {when}  {tag}subagent started · {entry.get('name')}")

        elif step == "thread.done":
            print(f"  {when}  {tag}subagent finished")

        elif step == "tool.call":
            args = ", ".join(
                f"{k}={_short(v, 60)}"
                for k, v in (entry.get("arguments") or {}).items()
            )
            print(f"  {when}  {tag}→ {entry.get('tool')}({args})")

        elif step == "tool.response":
            print(f"  {when}  {tag}← {_short(entry.get('content'))}")

        elif step == "tool.approval_required":
            print(f"  {when}  {tag}⚠ paused — human approval required")

        elif step == "model.message":
            print(f"  {when}  {tag}· {_short(entry.get('content'))}")


# ---------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------

def _verdict_from_trace(trace: list) -> dict | None:
    """The engine's own verdict, lifted out of its tool result.

    Read from the ``assess_user_risk`` response rather than from the model's
    prose, for the same reason the console does it: the score belongs to
    ``investigator/risk.py``, and reading it back out of a narrative would
    make the model its author.
    """

    for entry in reversed(trace):
        if entry.get("step") != "tool.response":
            continue

        if entry.get("tool") != "assess_user_risk":
            continue

        try:
            payload = json.loads(entry.get("content") or "")

        except (json.JSONDecodeError, TypeError, ValueError):
            continue

        if isinstance(payload, dict) and payload.get("found"):
            return payload

    return None


def print_report(result: dict, username: str) -> None:
    """The incident report: engine verdict, human decision, real outcome."""

    print()
    print(RULE)
    print("  SENTINEL INCIDENT REPORT")
    print(RULE)
    print(f"  Subject        {username}")

    verdict = _verdict_from_trace(result.get("trace", []))

    if verdict:
        print(f"  Threat         {verdict.get('threat_level')}")
        print(f"  Risk           {verdict.get('risk_score')} / 100  "
              "(investigator/risk.py — deterministic)")

        factors = [
            factor for factor in verdict.get("risk_factors", [])
            if factor.get("points", 0) > 0
        ]
        print(f"  Factors        {len(factors)} evidence-backed")
    else:
        print("  Threat         not assessed — the risk engine was not "
              "reached in this run")

    print(f"  Tool calls     {', '.join(result.get('tool_calls', [])) or '—'}")

    approvals = result.get("approvals", [])

    if not approvals:
        print("  Human decision no containment was proposed")
    else:
        for approval in approvals:
            outcome = "APPROVED" if approval["allowed"] else "DENIED"
            print(f"  Human decision {outcome} — {approval['tool']}")

            if approval.get("reason"):
                print(f"                 reason: {approval['reason']}")

    # The authoritative record of what actually happened to the environment.
    # Read from the containment store, not from the agent's narrative: the
    # agent reports, this verifies.
    actions = containment.list_actions()

    print(THIN)

    if actions:
        print("  Containment store (the record of what actually ran):")
        for action in actions:
            print(f"    {action['timestamp']}  {action['action']}"
                  f"({action['target']})  status={action['status']}")
    else:
        print("  Containment store: empty — nothing was executed.")

    print(THIN)
    print()
    print(result.get("response") or "(the agent produced no narrative)")
    print()
    print(RULE)


# ---------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m sentinel.demo",
        description="Run the Sentinel demo end to end.",
    )
    parser.add_argument("--username", default=DEFAULT_USERNAME)
    parser.add_argument(
        "--check", action="store_true",
        help="Run the readiness checks and exit.",
    )
    parser.add_argument(
        "--reset-only", action="store_true",
        help="Reset the demo state and exit.",
    )
    parser.add_argument(
        "--no-reset", action="store_true",
        help="Keep the existing containment history.",
    )
    parser.add_argument(
        "--delegate", action="store_true",
        help="Run the delegated investigation (lead agent + specialist "
             "subagents). Slower and more model calls; see --help in "
             "trueforge.run_agent.",
    )

    decision = parser.add_mutually_exclusive_group()
    decision.add_argument(
        "--approve", action="store_true",
        help="Approve containment without prompting (scripted demo).",
    )
    decision.add_argument(
        "--deny", action="store_true",
        help="Deny containment without prompting (scripted demo).",
    )
    parser.add_argument(
        "--deny-reason", default="Denied by operator.",
    )

    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    config = TrueForgeConfig.from_env()
    config.delegate = args.delegate

    print(RULE)
    print("  SENTINEL — autonomous security investigation on TrueForge")
    print(RULE)

    # ---------------------------------------------------------------
    # 1. Reset
    # ---------------------------------------------------------------
    if not args.no_reset and not args.check:
        print("\n[1/4] Resetting demo state")

        for note in reset_demo_state(args.username):
            print(f"  · {note}")

        if args.reset_only:
            print("\nDemo state reset.")
            return 0

    # ---------------------------------------------------------------
    # 2. Readiness
    # ---------------------------------------------------------------
    print("\n[2/4] Readiness")

    checks = preflight.run_checks(config)
    print(preflight.format_checks(checks))

    blocking = preflight.blocking(checks)

    if blocking:
        print(
            f"\nCannot run the demo: {len(blocking)} service is not ready. "
            "Follow the arrows above."
            if len(blocking) == 1 else
            f"\nCannot run the demo: {len(blocking)} services are not ready. "
            "Follow the arrows above."
        )
        return 1

    if args.check:
        print("\nAll systems ready.")
        return 0

    # ---------------------------------------------------------------
    # 3. Investigate
    # ---------------------------------------------------------------
    print(f"\n[3/4] Investigating '{args.username}' through TrueForge")
    print(f"      agent: {config.agent_name}"
          f"{' (delegated)' if args.delegate else ''}")
    print(THIN)

    if args.approve:
        on_approval = allow_all

    elif args.deny:
        def on_approval(pending):
            return deny_all(pending, args.deny_reason)

    else:
        def on_approval(pending):
            # Blocks until a human answers. An empty answer is a denial.
            return prompt_for_approval(pending, args.deny_reason)

    try:
        with SentinelAgent(config) as agent:
            result = agent.investigate(
                args.username,
                on_approval=on_approval,
                on_trace=narrate,
            )

    except TrueForgeError as exc:
        print(f"\nInvestigation failed: {exc}", file=sys.stderr)
        return 1

    # ---------------------------------------------------------------
    # 4. Report
    # ---------------------------------------------------------------
    print(THIN)
    print("\n[4/4] Report")

    print_report(result, args.username)

    if result.get("error"):
        print(f"Investigation error: {result['error']}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
