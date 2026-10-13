import json
import sqlite3
from pathlib import Path
import pandas as pd

DATABASE_PATH=Path("security_events.db")

def get_connection():
    connection=sqlite3.connect(
        DATABASE_PATH,
        timeout=10,
        check_same_thread=False,
    )

    connection.execute("PRAGMA journal_mode=WAL;")

    return connection

def migrate_alert_table(connection):
    columns={
        row[1] 
        for row in connection.execute(
            """
            PRAGMA table_info(security_alerts)
            """
        ).fetchall()
    }

    if "first_seen" not in columns:
        connection.execute(
            """
            ALTER TABLE security_alerts
            ADD COLUMN first_seen TEXT
            """
        )
    if "last_seen" not in columns:
        connection.execute(
            """
            ALTER TABLE security_alerts
            ADD COLUMN last_seen TEXT
            """
        )
    if "occurrence_count" not in columns:
        connection.execute(
            """
            ALTER TABLE security_alerts
            ADD COLUMN occurrence_count
            INTEGER NOT NULL DEFAULT 1
            """
        )
    if "status" not in columns:
        connection.execute(
            """ 
            ALTER TABLE security_alerts
            ADD COLUMN status TEXT 
            DEFAULT 'Active'
            """
        )
    connection.execute(
        """
        UPDATE security_alerts
        SET
            first_seen=
                COALESCE(first_seen, timestamp),

            last_seen=
                COALESCE(last_seen, timestamp),

            occurrence_count=
                COALESCE(occurrence_count, 1),

            status=
                COALESCE(status, 'Active')


        """
    )
        

def initialize_database():
    with get_connection() as connection:
        connection.execute(
            """ 
            CREATE TABLE IF NOT EXISTS security_events(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                username TEXT,
                ip_address TEXT,
                status TEXT,
                event_type TEXT,
                source_ip TEXT,
                log_source TEXT,
                raw_message TEXT,
                event_data TEXT
            )
             """
        )

        connection.execute(
            """ 
            CREATE TABLE IF NOT EXISTS security_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                severity TEXT NOT NULL,
                category TEXT NOT NULL,
                title TEXT NOT NULL,
                ip_address TEXT,
                description TEXT,
                risk_score REAL,
                first_seen TEXT,
                last_seen TEXT,
                occurrence_count INTEGER
                    NOT NULL DEFAULT 1,
                status TEXT
                    NOT NULL DEFAULT 'Active'
            )
            """
        )
        migrate_alert_table(connection)

        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_security_lookup

            ON security_alerts(
                category,
                title,
                ip_address,
                status
            )
            """
        )

def save_security_event(event:dict):

    initialize_database()

    timestamp=event.get("timestamp", pd.Timestamp.now())

    known_fields={
        "timestamp",
        "username",
        "ip_address",
        "status",
        "event_type",
        "source_ip",
        "log_source",
        "raw_message",
    }

    extra_data={
        key:value for key, value in event.items()
        if key not in known_fields
    }

    with get_connection() as connection:

        connection.execute(
            """ 
            INSERT INTO security_events(
                timestamp,
                username,
                ip_address,
                status,
                event_type,
                source_ip,
                log_source,
                raw_message,
                event_data
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(timestamp),
                event.get("username"),
                event.get("ip_address"),
                event.get("status"),
                event.get("event_type"),
                event.get("source_ip"),
                event.get("log_source"),
                event.get("raw_message"),
                json.dumps(
                    extra_data,
                    default=str,

                ),
            ),
        )

def get_security_events():

    initialize_database()

    with get_connection() as connection:
        events=pd.read_sql_query(
            """
            SELECT *
            FROM security_events
            ORDER BY timestamp DESC
            """,
            connection,
        )
    return events

def save_or_update_alert(alert:dict):
    initialize_database()

    timestamp=alert.get("timestamp", pd.Timestamp.now())

    severity=alert.get("severity", "Low")

    category=alert.get("category", "Unknown")

    title=alert.get("title", "Unknown Alert")

    ip_address=alert.get("ip_address")

    description=alert.get("description")

    risk_score=alert.get("risk_score", 0)

    with get_connection() as connection:
        exisiting_alert=connection.execute(
            """
            SELECT id, occurrence_count
            FROM security_alerts
            WHERE category = ? AND title = ?
            AND COALESCE(ip_address, '') = COALESCE (?, '')
            AND status='Active'
            ORDER BY id DESC
            LIMIT 1
            """,
            (
                category, title, ip_address,
            ),
        ).fetchone()

        if exisiting_alert is not None:
            alert_id=exisiting_alert[0]
            connection.execute(
                """
                UPDATE security_alerts
                SET 
                    timestamp = ?,
                    last_seen=?,
                    severity=?,
                    description=?,
                    risk_score=?,
                    occurrence_count= occurrence_count + 1
                WHERE id = ?
                """,
                (
                    str(timestamp),
                    str(timestamp),
                    severity,
                    description,
                    risk_score,
                    alert_id,
                ),
            )

            return "updated"

        connection.execute(
            """
            INSERT INTO security_alerts(
                timestamp,
                first_seen,
                last_seen,
                severity,
                category,
                title,
                ip_address,
                description,
                risk_score,
                occurrence_count,
                status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(timestamp),
                str(timestamp),
                str(timestamp),
                severity,
                category,
                title,
                ip_address,
                description,
                risk_score,
                1,
                "Active",
            ),
        )
        return "inserted"

def save_security_alert(alert:dict):

    return save_or_update_alert(alert)

def get_security_alerts():

    initialize_database()

    with get_connection() as connection:
        alerts=pd.read_sql_query(
            """
            SELECT * 
            FROM security_alerts
            ORDER BY timestamp DESC """,

            connection,
        )

    return alerts


