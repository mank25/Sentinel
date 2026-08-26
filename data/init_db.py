"""Create and seed the Sentinel demo security database.

Importing this module has no side effects; run it as a script (or call
:func:`init_db`) to build the demo database.
"""

import sqlite3
from contextlib import closing
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "security.db"


def init_db(db_path: Path = DB_PATH) -> None:
    """Create the schema and seed the demo security events at ``db_path``."""

    db_path.parent.mkdir(parents=True, exist_ok=True)

    with closing(sqlite3.connect(db_path)) as connection:
        with connection:
            connection.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                role TEXT NOT NULL,
                normal_location TEXT,
                normal_device TEXT
            )
            """)

            connection.execute("""
            CREATE TABLE IF NOT EXISTS login_events (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                device TEXT NOT NULL,
                location TEXT NOT NULL,
                success INTEGER NOT NULL,
                mfa_status TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
            """)

            connection.execute("""
            CREATE TABLE IF NOT EXISTS network_events (
                id INTEGER PRIMARY KEY,
                ip_address TEXT NOT NULL,
                reputation TEXT NOT NULL,
                country TEXT NOT NULL,
                known INTEGER NOT NULL,
                connection_count INTEGER NOT NULL,
                timestamp TEXT NOT NULL
            )
            """)

            # Demo user
            connection.execute("""
            INSERT OR IGNORE INTO users
            (id, username, role, normal_location, normal_device)
            VALUES (?, ?, ?, ?, ?)
            """, (
                1,
                "admin",
                "administrator",
                "Delhi",
                "MacBook"
            ))

            already_seeded = connection.execute(
                "SELECT 1 FROM login_events WHERE user_id = ? LIMIT 1",
                (1,),
            ).fetchone()

            if already_seeded is None:
                _seed_login_events(connection)

            network_seeded = connection.execute(
                "SELECT 1 FROM network_events LIMIT 1").fetchone()

            if network_seeded is None:
                _seed_network_events(connection)

    print(f"Database created at: {db_path}")


def _seed_login_events(connection: sqlite3.Connection) -> None:
    """Insert the demo login events for the ``admin`` user."""

    # Normal historical login
    connection.execute("""
    INSERT INTO login_events
    (user_id, timestamp, source_ip, device, location, success, mfa_status)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        1,
        "2026-08-24T09:14:00",
        "10.10.1.20",
        "MacBook",
        "Delhi",
        1,
        "passed"
    ))

    # Suspicious failed attempts
    for i in range(47):
        connection.execute("""
        INSERT INTO login_events
        (user_id, timestamp, source_ip, device, location, success, mfa_status)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            1,
            f"2026-08-25T02:{10 + i // 60:02d}:{i % 60:02d}",
            "185.123.45.67",
            "Unknown",
            "Unknown",
            0,
            "failed"
        ))

    # Suspicious successful login
    connection.execute("""
    INSERT INTO login_events
    (user_id, timestamp, source_ip, device, location, success, mfa_status)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        1,
        "2026-08-25T02:14:00",
        "185.123.45.67",
        "Unknown",
        "Unknown",
        1,
        "failed"
    ))

def _seed_network_events(connection: sqlite3.Connection) -> None:
    """Insert demo network intelligence for the suspicious IP."""

    connection.execute("""
    INSERT INTO network_events
    (ip_address, reputation, country, known, connection_count, timestamp)
    VALUES (?, ?, ?, ?, ?, ?)
    """, (
        "185.123.45.67",
        "suspicious",
        "Unknown",
        0,
        58,
        "2026-08-25T02:14:01"
    ))

if __name__ == "__main__":
    init_db()
