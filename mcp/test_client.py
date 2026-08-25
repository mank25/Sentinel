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

            # Call our security investigation tool
            result = await session.call_tool(
                "get_login_history",
                {"username": "admin"},
            )

            print("\nTool result:")
            print(result)


if __name__ == "__main__":
    asyncio.run(main())