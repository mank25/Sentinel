"""End-to-end deterministic Sentinel investigation runner.

Supported invocations (both work):

    python -m investigator.run_investigation
    python investigator/run_investigation.py
"""

import asyncio
import json
import sys
from pathlib import Path

# Direct execution puts ``investigator/`` on sys.path instead of the project
# root, so the ``investigator`` package itself would not be importable. Put
# the project root back on the path before importing from it.
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from investigator.analyzer import (
    analyze_login_history,
    correlate_network_data,
)

from investigator.risk import calculate_risk
from investigator.report import generate_report

SERVER_PATH = (
    Path(__file__).resolve().parent.parent
    / "mcp"
    / "sentinel_mcp"
    / "server.py"
)


async def _lookup_network_activity(session, ip_address: str) -> dict:
    """Look up one IP, turning a transport failure into structured evidence.

    A failure for a single IP must not destroy the whole investigation, but
    it must never look like a clean result either.
    """

    try:
        result = await session.call_tool(
            "get_network_activity",
            {"ip_address": ip_address},
        )

        return json.loads(result.content[0].text)

    except Exception as exc:  # noqa: BLE001 - surfaced as evidence, not raised
        return {
            "found": False,
            "ip_address": ip_address,
            "error": f"Network intelligence lookup failed: {exc}",
        }


async def run_pipeline(session, username: str, verbose: bool = True) -> dict:
    """Drive the investigation over an already-connected MCP session."""

    # -----------------------------------------
    # 1. Retrieve login evidence
    # -----------------------------------------

    login_result = await session.call_tool(
        "get_login_history",
        {"username": username},
    )

    login_data = json.loads(
        login_result.content[0].text
    )

    # -----------------------------------------
    # 2. Analyze login evidence
    # -----------------------------------------

    login_evidence = analyze_login_history(
        login_data
    )

    if not login_evidence.get("found"):
        return login_evidence

    # -----------------------------------------
    # 3. Look up every suspicious IP
    # -----------------------------------------

    suspicious_ips = login_evidence.get(
        "suspicious_ips",
        [],
    )

    network_results = []

    # No suspicious IPs means there is nothing to look up.
    for ip_address in suspicious_ips:
        network_results.append(
            await _lookup_network_activity(session, ip_address)
        )

    # -----------------------------------------
    # 4. Correlate login + network evidence
    # -----------------------------------------

    investigation = correlate_network_data(
        login_evidence,
        network_results,
    )

    # -----------------------------------------
    # 5. Calculate deterministic risk
    # -----------------------------------------

    risk = calculate_risk(investigation)

    investigation["risk"] = risk

    report = generate_report(investigation)

    if verbose:
        print("\n=== SENTINEL REPORT ===\n")
        print(report)

    return investigation


async def investigate(username: str) -> dict:
    """Run a complete deterministic Sentinel investigation."""

    server_params = StdioServerParameters(
        command=sys.executable,
        args=[str(SERVER_PATH)],
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:

            # Initialize MCP connection
            await session.initialize()

            return await run_pipeline(session, username)


async def main():
    result = await investigate("admin")

    print("\n=== SENTINEL INVESTIGATION ===\n")

    print(
        json.dumps(
            result,
            indent=2,
        )
    )


if __name__ == "__main__":
    asyncio.run(main())
