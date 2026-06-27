"""
SQLite database layer for the Cybersecurity Vulnerability Analysis system.

Provides table creation, connection management, and a module-level DB_PATH.
This module is framework-agnostic — it uses only the Python standard library.
"""

import os
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Optional

DB_PATH: str = os.path.join(os.path.dirname(__file__), "cyber_vuln.db")

_local = threading.local()


def get_db() -> sqlite3.Connection:
    """Return a thread-local sqlite3 connection with Row factory enabled."""
    conn = getattr(_local, 'connection', None)
    if conn is None:
        conn = sqlite3.connect(DB_PATH, timeout=30.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        _local.connection = conn
    return conn


def close_db() -> None:
    """Close the thread-local database connection if it is open."""
    conn = getattr(_local, 'connection', None)
    if conn is not None:
        conn.close()
        _local.connection = None


def init_db() -> None:
    """Create all tables if they do not already exist."""
    db = get_db()

    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id          TEXT PRIMARY KEY,
            username    TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role        TEXT NOT NULL DEFAULT 'user',
            created_at  TIMESTAMP NOT NULL
        );

        CREATE TABLE IF NOT EXISTS scans (
            id                TEXT PRIMARY KEY,
            file_path         TEXT NOT NULL,
            language          TEXT,
            mode              TEXT,
            risk_score        INTEGER,
            risk_level        TEXT,
            lifecycle_status  TEXT NOT NULL DEFAULT 'Safe',
            created_at        TIMESTAMP NOT NULL,
            updated_at        TIMESTAMP NOT NULL,
            user_id           TEXT,
            report_path       TEXT,
            executive_summary TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        );

        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id              TEXT PRIMARY KEY,
            scan_id         TEXT NOT NULL,
            vuln_id         TEXT,
            category        TEXT,
            severity        TEXT,
            line_number     INTEGER,
            line_content    TEXT,
            status          TEXT NOT NULL DEFAULT 'open',
            cwe_id          TEXT,
            owasp_category  TEXT,
            recommendation  TEXT,
            ai_explanation  TEXT,
            created_at      TIMESTAMP NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scans (id)
        );

        CREATE TABLE IF NOT EXISTS score_history (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id          TEXT NOT NULL,
            score            INTEGER,
            lifecycle_status TEXT,
            changed_by       TEXT,
            reason           TEXT,
            timestamp        TIMESTAMP NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scans (id)
        );

        CREATE TABLE IF NOT EXISTS audit_logs (
            id                   INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id              TEXT,
            action               TEXT,
            performed_by         TEXT,
            role                 TEXT DEFAULT 'system',
            old_score            INTEGER,
            new_score            INTEGER,
            old_status           TEXT,
            new_status           TEXT,
            vulnerability_status TEXT,
            severity_level       TEXT,
            details              TEXT,
            timestamp            TIMESTAMP NOT NULL
        );
        """
    )

    db.commit()
