import asyncio
import sqlite3
import sys
from pathlib import Path

from mcp.server import MCPServer
from mcp.types import ToolAnnotations

BASE_DIR = Path(__file__).resolve().parents[2]
DB_PATH = BASE_DIR / "data" / "security.db"

# Running this file directly puts ``mcp/sentinel_mcp/`` on sys.path, so the
# deterministic ``investigator`` package would not be importable. Put the
# project root back before importing from it.
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from investigator.assessment import assess, summarize  # noqa: E402

# Every tool in this server only ever reads. The annotations make that
# explicit to any MCP client, so hosts can grant read-only tools without
# human approval.
READ_ONLY = ToolAnnotations(
    read_only_hint=True,
    destructive_hint=False,
    idempotent_hint=True,
    open_world_hint=False,
)

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

@server.tool(annotations=READ_ONLY)
async def get_login_history(username: str) -> dict:
    """
    Retrieve login history for a user.

    This is a read-only security investigation tool.
    """

    return await asyncio.to_thread(_get_login_history_sync, username)

@server.tool(annotations=READ_ONLY)
async def get_network_activity(ip_address: str) -> dict:
    """Return network intelligence for an IP address.

    This is a read-only security investigation tool.
    """

    return await asyncio.to_thread(
        _get_network_activity_sync,
        ip_address,
    )

def _get_network_activity_sync(ip_address: str) -> dict:
    """Perform the read-only SQLite lookup in a worker thread."""

    if not DB_PATH.exists():
        return {
            "found": False,
            "error": "Security database is unavailable.",
        }

    connection = None

    try:
        connection = sqlite3.connect(
            f"file:{DB_PATH}?mode=ro",
            uri=True,
        )
        connection.row_factory = sqlite3.Row

        connection.execute("PRAGMA query_only = 1")

        row = connection.execute(
            """
            SELECT
                ip_address,
                reputation,
                country,
                known,
                connection_count,
                timestamp
            FROM network_events
            WHERE ip_address = ?
            ORDER BY timestamp DESC
            LIMIT 1
            """,
            (ip_address,),
        ).fetchone()

        if row is None:
            return {
                "found": False,
                "ip_address": ip_address,
            }

        return {
            "found": True,
            "ip_address": row["ip_address"],
            "reputation": row["reputation"],
            "country": row["country"],
            "known": bool(row["known"]),
            "connection_count": row["connection_count"],
            "timestamp": row["timestamp"],
        }

    except sqlite3.Error:
        return {
            "found": False,
            "ip_address": ip_address,
            "error": "Unable to read network security data.",
        }

    finally:
        if connection is not None:
            connection.close()

def _assess_user_risk_sync(username: str) -> dict:
    """Run the deterministic pipeline end-to-end inside this process."""

    login_data = _get_login_history_sync(username)

    investigation = assess(login_data, _get_network_activity_sync)

    return summarize(investigation)


@server.tool(annotations=READ_ONLY)
async def assess_user_risk(username: str) -> dict:
    """Run Sentinel's deterministic risk assessment for a user.

    This is the authoritative scoring path. It re-reads the login history,
    looks up every suspicious IP, correlates the evidence and returns the
    computed threat level, risk score and the risk factors that justify it.

    The score is produced by Sentinel's deterministic risk engine, not by a
    language model. Always use the numbers this tool returns verbatim and
    never estimate a score independently.

    This is a read-only security investigation tool.
    """

    return await asyncio.to_thread(_assess_user_risk_sync, username)


async def main():
    await server.run_stdio_async()


if __name__ == "__main__":
    asyncio.run(main())
