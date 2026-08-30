"""Create and seed the Sentinel demo security database.

This file is the source of truth for `data/security.db`, which is not
committed. Importing the module has no side effects; run it as a script (or
call :func:`init_db`) to build the database.

    python data/init_db.py            # create if absent, leave existing data
    python data/init_db.py --reset    # drop and reseed the incident

The seeded data is one coherent incident, not a bag of suspicious rows. See
:data:`INCIDENT_NARRATIVE` for the story the evidence tells. Nothing in
Sentinel reads that narrative -- it exists so a human can check that the rows
below are internally consistent. The agent has to derive the story from the
evidence, and the deterministic risk engine scores the evidence, so neither
of them is ever handed the answer.
"""

import argparse
import sqlite3
from contextlib import closing
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "security.db"

# The account under investigation, and its established baseline. Every
# anomaly below is an anomaly *relative to these two values* -- that is what
# makes "unknown device" and "unknown location" meaningful rather than
# decorative.
BASELINE_LOCATION = "Delhi"
BASELINE_DEVICE = "MacBook"
CORPORATE_IP = "10.10.1.20"

# The attacker's infrastructure. It appears here, in the evidence, and
# nowhere else in the project: not in the system prompt, not in the risk
# engine, not in the UI. investigator/test_prompts.py fails the build if an
# IP literal ever reaches the prompt, because an agent handed the answer is
# not investigating.
ATTACKER_IP = "185.123.45.67"

INCIDENT_NARRATIVE = """\
2026-08-24 09:21  admin signs in from the Delhi office on their MacBook.
2026-08-24 14:02  A second routine sign-in the same afternoon.
2026-08-25 09:47  Another routine sign-in. This is the baseline.

2026-08-26 02:11  Overnight, password guessing begins from 185.123.45.67.
                  41 attempts fail on the password itself, so MFA is never
                  reached.
2026-08-26 02:21  The password starts succeeding: the next 6 attempts get
                  past the password and are stopped at MFA, which the real
                  owner denies. This is the credential-compromise moment --
                  the attacker now has the password.
2026-08-26 02:24  On the 7th push the prompt is approved. MFA fatigue. The
                  attempt succeeds, from an unknown device in an unknown
                  location.
2026-08-26 02:24  Network intelligence for 185.123.45.67: suspicious
                  reputation, not a known source, 58 connections.

The corporate egress 10.10.1.20 is also recorded, with a clean reputation.
It is there so corroboration is a real question rather than a foregone
conclusion: an investigator who checks both IPs learns that one is
suspicious and the other is not.
"""

SCHEMA = [
    """
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        role TEXT NOT NULL,
        normal_location TEXT,
        normal_device TEXT
    )
    """,
    """
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
    """,
    """
    CREATE TABLE IF NOT EXISTS network_events (
        id INTEGER PRIMARY KEY,
        ip_address TEXT NOT NULL,
        reputation TEXT NOT NULL,
        country TEXT NOT NULL,
        known INTEGER NOT NULL,
        connection_count INTEGER NOT NULL,
        timestamp TEXT NOT NULL
    )
    """,
]

TABLES = ["login_events", "network_events", "users"]


def init_db(db_path: Path = DB_PATH, reset: bool = False) -> None:
    """Create the schema and seed the demo incident at ``db_path``.

    With ``reset=True`` the existing rows are deleted first, so the demo is
    repeatable without deleting the file or editing it by hand.
    """

    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    with closing(sqlite3.connect(db_path)) as connection:
        with connection:
            for statement in SCHEMA:
                connection.execute(statement)

            if reset:
                for table in TABLES:
                    connection.execute(f"DELETE FROM {table}")

            connection.execute(
                """
                INSERT OR IGNORE INTO users
                (id, username, role, normal_location, normal_device)
                VALUES (?, ?, ?, ?, ?)
                """,
                (1, "admin", "administrator",
                 BASELINE_LOCATION, BASELINE_DEVICE),
            )

            seeded = connection.execute(
                "SELECT 1 FROM login_events WHERE user_id = ? LIMIT 1",
                (1,),
            ).fetchone()

            if seeded is None:
                _seed_login_events(connection)

            seeded = connection.execute(
                "SELECT 1 FROM network_events LIMIT 1"
            ).fetchone()

            if seeded is None:
                _seed_network_events(connection)

    print(f"Database {'reset' if reset else 'created'} at: {db_path}")


def _login(connection, timestamp, ip, device, location, success, mfa):
    connection.execute(
        """
        INSERT INTO login_events
        (user_id, timestamp, source_ip, device, location, success, mfa_status)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (1, timestamp, ip, device, location, success, mfa),
    )


def _seed_login_events(connection: sqlite3.Connection) -> None:
    """Seed the incident described in :data:`INCIDENT_NARRATIVE`."""

    # ------------------------------------------------------------------
    # Baseline: three routine sign-ins from the corporate egress, on the
    # user's own device, in their own city, with MFA satisfied. This is what
    # the anomalies are anomalous against.
    # ------------------------------------------------------------------
    for timestamp in (
        "2026-08-24T09:21:00",
        "2026-08-24T14:02:00",
        "2026-08-25T09:47:00",
    ):
        _login(
            connection, timestamp, CORPORATE_IP,
            BASELINE_DEVICE, BASELINE_LOCATION, 1, "passed",
        )

    # ------------------------------------------------------------------
    # Password guessing. 41 attempts fail on the password, so the second
    # factor is never challenged -- recording these as "failed" MFA would
    # overstate what happened, and the evidence has to be honest before the
    # engine scores it.
    # ------------------------------------------------------------------
    minute, second = 11, 0

    for _ in range(41):
        _login(
            connection,
            f"2026-08-26T02:{minute:02d}:{second:02d}",
            ATTACKER_IP, "Unknown", "Unknown", 0, "not_reached",
        )

        second += 14

        if second >= 60:
            minute += 1
            second -= 60

    # ------------------------------------------------------------------
    # The password starts working. Six attempts now clear the password and
    # are stopped at MFA, which the account owner denies. This is the
    # credential-compromise moment: from here the attacker has the password
    # and is only held back by the second factor.
    # ------------------------------------------------------------------
    for offset in range(6):
        _login(
            connection,
            f"2026-08-26T02:{21 + offset // 4:02d}:{(offset * 15) % 60:02d}",
            ATTACKER_IP, "Unknown", "Unknown", 0, "failed",
        )

    # ------------------------------------------------------------------
    # MFA fatigue: the seventh push is approved and the sign-in succeeds,
    # from an unknown device in an unknown location.
    # ------------------------------------------------------------------
    _login(
        connection, "2026-08-26T02:24:18",
        ATTACKER_IP, "Unknown", "Unknown", 1, "passed",
    )


def _seed_network_events(connection: sqlite3.Connection) -> None:
    """Seed network intelligence for both IPs that appear in the evidence.

    The corporate egress is recorded as clean on purpose. Corroboration only
    means something if a lookup could have come back the other way.
    """

    rows = [
        (ATTACKER_IP, "suspicious", "Unknown", 0, 58,
         "2026-08-26T02:24:19"),
        (CORPORATE_IP, "clean", "India", 1, 412,
         "2026-08-26T09:00:00"),
    ]

    connection.executemany(
        """
        INSERT INTO network_events
        (ip_address, reputation, country, known, connection_count, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        rows,
    )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Create and seed the Sentinel demo security database."
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Delete the existing rows and reseed the incident.",
    )
    parser.add_argument(
        "--narrative",
        action="store_true",
        help="Print the incident the seeded evidence describes, and exit.",
    )

    args = parser.parse_args(argv)

    if args.narrative:
        print(INCIDENT_NARRATIVE)
        return 0

    init_db(reset=args.reset)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
