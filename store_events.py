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