import asyncio
import sqlite3
from pathlib import Path

from mcp.server import MCPServer


BASE_DIR = Path(__file__).resolve().parents[2]
DB_PATH = BASE_DIR / "data" / "security.db"

# Structured error returned to the calling agent whenever the security database
# cannot be read. It deliberately omits filesystem details.
DB_UNAVAILABLE_ERROR = {
    "found": False,
    "error": "Security database is unavailable or invalid",
}

server = MCPServer(
    name="Sentinel Security Tools",
    description="Read-only security investigation tools for Sentinel.",
)


def _connect_read_only(db_path: Path) -> sqlite3.Connection:
    """
    Open the security database strictly read-only.

    Using the ``mode=ro`` URI prevents SQLite from creating a missing database
    file, and ``query_only`` blocks any write attempt on the connection.
    """

    # ``as_uri`` requires an absolute path and quotes any special characters.
    uri = f"{Path(db_path).resolve().as_uri()}?mode=ro"
    connection = sqlite3.connect(uri, uri=True)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only = 1")
    return connection


def _get_login_history_sync(username: str, db_path: Path = DB_PATH) -> dict:
    """Blocking SQLite work behind :func:`get_login_history`."""

    db_path = Path(db_path).resolve()

    if not db_path.is_file():
        return dict(DB_UNAVAILABLE_ERROR)

    connection = None

    try:
        connection = _connect_read_only(db_path)

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

    except sqlite3.Error:
        # Missing, empty, corrupted or unexpectedly-shaped database.
        return dict(DB_UNAVAILABLE_ERROR)

    finally:
        if connection is not None:
            connection.close()


@server.tool()
async def get_login_history(username: str) -> dict:
    """
    Retrieve login history for a user.

    This is a read-only security investigation tool.
    """

    return await asyncio.to_thread(_get_login_history_sync, username)


async def main():
    await server.run_stdio_async()


if __name__ == "__main__":
    asyncio.run(main())
