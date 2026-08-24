import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / "security.db"

connection = sqlite3.connect(DB_PATH)
cursor = connection.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL,
    normal_location TEXT,
    normal_device TEXT
)
""")

cursor.execute("""
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

# Demo user
cursor.execute("""
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

# Normal historical login
cursor.execute("""
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
    cursor.execute("""
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
cursor.execute("""
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

connection.commit()
connection.close()

print(f"Database created at: {DB_PATH}")