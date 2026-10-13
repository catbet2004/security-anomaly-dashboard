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
                risk_score REAL
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

def save_security_alert(alert:dict):

    initialize_database()

    timestamp=alert.get("timestamp", pd.Timestamp.now())

    with get_connection() as connection:

        connection.execute(
            """
            INSERT INTO security_alerts(
                timestamp,
                severity,
                category,
                title,
                ip_address,
                description,
                risk_score
            )
            VALUES(?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(timestamp),
                alert.get("severity"),
                alert.get("category"),
                alert.get("title"),
                alert.get("ip_address"),
                alert.get("description"),
                alert.get("risk_score"),

            ),
        )

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

def alert_exists(title:str, ip_address:str, minutes: int=10) -> bool:

    initialize_database()

    with get_connection() as connection:

        result=connection.execute(
            """
            SELECT COUNT(*)
            FROM security_alerts
            WHERE title=?
            AND ip_address=?
            AND datatime(timestamp) >= datetime('now', ?)
            """,
            (
                title,
                ip_address,
                f"-{minutes} minutes",
            ),
        ).fetchone()

    return result[0] > 0

if __name__ == "__main__":

    test_alert = {
        "timestamp": pd.Timestamp.now(),
        "severity": "High",
        "category": "Firewall",
        "title": "Test Security Alert",
        "ip_address": "10.0.0.99",
        "description": "Testing alert storage.",
        "risk_score": 3.0,
    }

    save_security_alert(
        test_alert
    )

    print(
        get_security_alerts()
    )
        
