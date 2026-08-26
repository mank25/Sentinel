import asyncio
import json
import sys
from pathlib import Path

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
            # 3. Find suspicious IPs
            # -----------------------------------------

            suspicious_ips = login_evidence.get(
                "suspicious_ips",
                [],
            )

            network_data = {
                "found": False,
            }

            # For the first version, investigate the
            # suspicious IPs one at a time.
            if suspicious_ips:

                network_result = await session.call_tool(
                    "get_network_activity",
                    {
                        "ip_address": suspicious_ips[0]
                    },
                )

                network_data = json.loads(
                    network_result.content[0].text
                )

            # -----------------------------------------
            # 4. Correlate login + network evidence
            # -----------------------------------------

            investigation = correlate_network_data(
                login_evidence,
                network_data,
            )
            # -----------------------------------------
            # 5. Calculate deterministic risk
            # -----------------------------------------

            risk = calculate_risk(investigation)

            investigation["risk"] = risk

            report = generate_report(investigation)

            print("\n=== SENTINEL REPORT ===\n")
            print(report)

            return investigation


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