import json
import sqlite3
from pathlib import Path

DB_PATH = Path("data/threat_hunting.db")


def get_connection():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    with get_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                incident_id TEXT PRIMARY KEY,
                host TEXT NOT NULL,
                severity TEXT NOT NULL,
                users TEXT NOT NULL,
                source_ips TEXT NOT NULL,
                alerts TEXT NOT NULL,
                timeline TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                threat_score INTEGER NOT NULL DEFAULT 0,
                priority TEXT NOT NULL DEFAULT 'Low',
                risk_summary TEXT NOT NULL DEFAULT 'Not assessed',
                status TEXT NOT NULL DEFAULT 'New'
            )
        """)

        columns = {
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(incidents)"
            ).fetchall()
        }

        migrations = {
            "threat_score": (
                "ALTER TABLE incidents ADD COLUMN "
                "threat_score INTEGER NOT NULL DEFAULT 0"
            ),
            "priority": (
                "ALTER TABLE incidents ADD COLUMN "
                "priority TEXT NOT NULL DEFAULT 'Low'"
            ),
            "risk_summary": (
                "ALTER TABLE incidents ADD COLUMN "
                "risk_summary TEXT NOT NULL DEFAULT 'Not assessed'"
            ),
            "status": (
                "ALTER TABLE incidents ADD COLUMN "
                "status TEXT NOT NULL DEFAULT 'New'"
            ),
        }

        for column, statement in migrations.items():
            if column not in columns:
                connection.execute(statement)

        # Store investigation notes separately from incident records.
        connection.execute("""
            CREATE TABLE IF NOT EXISTS investigation_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT NOT NULL,
                note TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # Record important incident investigation actions.
        connection.execute("""
            CREATE TABLE IF NOT EXISTS incident_audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT NOT NULL,
                action TEXT NOT NULL,
                details TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)

def save_incident(incident):
    with get_connection() as connection:
        connection.execute("""
            INSERT INTO incidents (
                incident_id, host, severity, users,
                source_ips, alerts, timeline,
                threat_score, priority, risk_summary
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(incident_id) DO UPDATE SET
                host = excluded.host,
                severity = excluded.severity,
                users = excluded.users,
                source_ips = excluded.source_ips,
                alerts = excluded.alerts,
                timeline = excluded.timeline,
                threat_score = excluded.threat_score,
                priority = excluded.priority,
                risk_summary = excluded.risk_summary
        """, (
            incident["incident_id"],
            incident["host"],
            incident["severity"],
            json.dumps(incident["users"]),
            json.dumps(incident["source_ips"]),
            json.dumps(incident["alerts"]),
            json.dumps(incident["timeline"]),
            incident.get("threat_score", 0),
            incident.get("priority", "Low"),
            incident.get("risk_summary", "Not assessed"),
        ))


def get_all_incidents():
    with get_connection() as connection:
        rows = connection.execute("""
            SELECT * FROM incidents
            ORDER BY created_at DESC
        """).fetchall()

    return [dict(row) for row in rows]


def update_incident_status(incident_id, status):
    """Update incident status and record changes in the audit log."""

    allowed_statuses = {"New", "Investigating", "Resolved"}

    if status not in allowed_statuses:
        raise ValueError(
            f"Invalid status. Choose one of: "
            f"{', '.join(sorted(allowed_statuses))}"
        )

    with get_connection() as connection:
        incident = connection.execute("""
            SELECT status FROM incidents WHERE incident_id = ?
        """, (incident_id,)).fetchone()

        if incident is None:
            return False

        old_status = incident["status"]

        if old_status != status:
            connection.execute("""
                UPDATE incidents SET status = ?
                WHERE incident_id = ?
            """, (status, incident_id))

            connection.execute("""
                INSERT INTO incident_audit_log
                    (incident_id, action, details)
                VALUES (?, ?, ?)
            """, (
                incident_id,
                "Status changed",
                f"Status changed from {old_status} to {status}",
            ))

    return True

def add_investigation_note(incident_id, note):
    """Save a note and record the action in the audit log."""

    note = note.strip()

    if not note:
        raise ValueError("Investigation note cannot be empty.")

    initialize_database()

    with get_connection() as connection:
        incident = connection.execute(
            "SELECT 1 FROM incidents WHERE incident_id = ?",
            (incident_id,),
        ).fetchone()

        if incident is None:
            return False

        cursor = connection.execute("""
            INSERT INTO investigation_notes (incident_id, note)
            VALUES (?, ?)
        """, (incident_id, note))

        note_id = cursor.lastrowid

        connection.execute("""
            INSERT INTO incident_audit_log
                (incident_id, action, details)
            VALUES (?, ?, ?)
        """, (
            incident_id,
            "Investigation note added",
            f"Investigation note #{note_id} added",
        ))

    return True

def get_investigation_notes(incident_id):
    """Return an incident's notes from oldest to newest."""

    initialize_database()

    with get_connection() as connection:
        rows = connection.execute("""
            SELECT id, incident_id, note, created_at
            FROM investigation_notes
            WHERE incident_id = ?
            ORDER BY id ASC
        """, (incident_id,)).fetchall()

    return [dict(row) for row in rows]

def get_incident_audit_log(incident_id):
    """Return audit events from oldest to newest."""

    initialize_database()

    with get_connection() as connection:
        rows = connection.execute("""
            SELECT id, incident_id, action, details, created_at
            FROM incident_audit_log
            WHERE incident_id = ?
            ORDER BY id ASC
        """, (incident_id,)).fetchall()

    return [dict(row) for row in rows]

if __name__ == "__main__":
    initialize_database()
    print(f"Database initialized: {DB_PATH}")
    print("Incident scoring and status columns verified.")
    print("Investigation notes table verified.")
