"""Containment actions: Sentinel's only write path.

Everything else in Sentinel reads. This module is the sole exception, and it
is deliberately narrow.

Two stores, one direction each:

* ``data/security.db`` -- the evidence store. Opened ``mode=ro`` with
  ``PRAGMA query_only`` by the MCP evidence tools, and never written by
  anything in this project.
* ``data/containment.db`` -- the containment store, written only here. It is
  an append-only audit log of response actions.

An investigation can therefore never modify the evidence it reasons about,
and containment can never be mistaken for evidence.

Recording an action is not a simulation of some other system: this store *is*
the record of what containment has been authorised, and
:func:`account_status` / :func:`ip_status` read it back so the rest of
Sentinel observes the change.

Nothing here decides *whether* to contain. The model proposes, TrueForge
pauses for a human, and only an approved tool call reaches this module.
"""

import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "containment.db"

ACTION_CONTAIN_ACCOUNT = "contain_account"
ACTION_BLOCK_IP = "block_ip"

VALID_ACTIONS = {ACTION_CONTAIN_ACCOUNT, ACTION_BLOCK_IP}

SCHEMA = """
CREATE TABLE IF NOT EXISTS containment_actions (
    id INTEGER PRIMARY KEY,
    timestamp TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    justification TEXT NOT NULL,
    threat_level TEXT,
    risk_score INTEGER,
    status TEXT NOT NULL DEFAULT 'active'
)
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _connect(db_path: Path) -> sqlite3.Connection:
    """Open the containment store read-write, creating it if needed.

    This is the one connection in Sentinel that is not read-only, and it
    points at the containment database -- never at the evidence database.
    """

    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    connection.execute(SCHEMA)

    return connection


def record_action(
    action: str,
    target: str,
    justification: str,
    threat_level: str | None = None,
    risk_score: int | None = None,
    db_path: Path = DB_PATH,
) -> dict:
    """Append one containment action to the audit log.

    ``justification`` is required: an action nobody can explain later is not
    an auditable action.
    """

    if action not in VALID_ACTIONS:
        return {
            "ok": False,
            "error": (
                f"Unknown containment action {action!r}. "
                f"Valid actions: {sorted(VALID_ACTIONS)}"
            ),
        }

    if not (target or "").strip():
        return {"ok": False, "error": "A containment target is required."}

    if not (justification or "").strip():
        return {
            "ok": False,
            "error": (
                "A justification is required so the action can be audited "
                "later."
            ),
        }

    timestamp = _now()

    with closing(_connect(db_path)) as connection:
        with connection:
            cursor = connection.execute(
                """
                INSERT INTO containment_actions
                (timestamp, action, target, justification,
                 threat_level, risk_score, status)
                VALUES (?, ?, ?, ?, ?, ?, 'active')
                """,
                (
                    timestamp,
                    action,
                    target.strip(),
                    justification.strip(),
                    threat_level,
                    risk_score,
                ),
            )

            action_id = cursor.lastrowid

    return {
        "ok": True,
        "action_id": action_id,
        "action": action,
        "target": target.strip(),
        "timestamp": timestamp,
        "justification": justification.strip(),
        "threat_level": threat_level,
        "risk_score": risk_score,
        "status": "active",
    }


def _actions_for(action: str, target: str, db_path: Path) -> list:
    db_path = Path(db_path)

    if not db_path.is_file():
        return []

    with closing(_connect(db_path)) as connection:
        rows = connection.execute(
            """
            SELECT id, timestamp, action, target, justification,
                   threat_level, risk_score, status
            FROM containment_actions
            WHERE action = ? AND target = ?
            ORDER BY timestamp DESC, id DESC
            """,
            (action, target),
        ).fetchall()

    return [dict(row) for row in rows]


def account_status(username: str, db_path: Path = DB_PATH) -> dict:
    """Whether an account is currently contained, and why."""

    actions = _actions_for(ACTION_CONTAIN_ACCOUNT, username, db_path)
    active = [a for a in actions if a["status"] == "active"]

    return {
        "username": username,
        "contained": bool(active),
        "containment_actions": actions,
    }


def ip_status(ip_address: str, db_path: Path = DB_PATH) -> dict:
    """Whether an IP is currently blocked, and why."""

    actions = _actions_for(ACTION_BLOCK_IP, ip_address, db_path)
    active = [a for a in actions if a["status"] == "active"]

    return {
        "ip_address": ip_address,
        "blocked": bool(active),
        "containment_actions": actions,
    }


def list_actions(db_path: Path = DB_PATH) -> list:
    """The whole containment audit log, newest first."""

    db_path = Path(db_path)

    if not db_path.is_file():
        return []

    with closing(_connect(db_path)) as connection:
        rows = connection.execute(
            """
            SELECT id, timestamp, action, target, justification,
                   threat_level, risk_score, status
            FROM containment_actions
            ORDER BY timestamp DESC, id DESC
            """
        ).fetchall()

    return [dict(row) for row in rows]
