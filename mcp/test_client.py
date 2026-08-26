import asyncio
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


SERVER_PATH = Path(__file__).resolve().parent / "sentinel_mcp" / "server.py"

server_params = StdioServerParameters(
    command=sys.executable,
    args=[str(SERVER_PATH)],
)


async def main():
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:

            # Connect to the MCP server
            await session.initialize()

            # Ask the server what tools it provides
            tools = await session.list_tools()

            print("Available tools:")

            for tool in tools.tools:
                print(f"- {tool.name}")

            # Call our login investigation tool
            login_result = await session.call_tool(
                "get_login_history",
                {"username": "admin"},
            )

            print("\nLogin history result:")
            print(login_result)

            # Call our network investigation tool
            network_result = await session.call_tool(
                "get_network_activity",
                {"ip_address": "185.123.45.67"},
            )

            print("\nNetwork activity result:")
            print(network_result)


if __name__ == "__main__":
    asyncio.run(main())