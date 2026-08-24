import sqlite3
from pathlib import Path

from mcp.server import MCPServer



BASE_DIR = Path(__file__).resolve().parents[2]
DB_PATH = BASE_DIR / "data" / "security.db"

server = MCPServer(
    name="Sentinel Security Tools",
    description="Read-only security investigation tools for Sentinel.",
)


@server.tool()
async def get_login_history(username: str) -> dict:
    """
    Retrieve login history for a user.

    This is a read-only security investigation tool.
    """

    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row

    try:
        user = connection.execute(
            """
            SELECT
                id,
                username,
                role,
                normal_location,
                normal_device
            FROM users
            WHERE username = ?
            """,
            (username,),
        ).fetchone()

        if user is None:
            return {
                "found": False,
                "error": f"User '{username}' was not found.",
            }

        events = connection.execute(
            """
            SELECT
                timestamp,
                source_ip,
                device,
                location,
                success,
                mfa_status
            FROM login_events
            WHERE user_id = ?
            ORDER BY timestamp DESC
            LIMIT 100
            """,
            (user["id"],),
        ).fetchall()

        return {
            "found": True,
            "user": dict(user),
            "login_events": [dict(event) for event in events],
        }

    finally:
        connection.close()


async def main():
    await server.run_stdio_async()


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())