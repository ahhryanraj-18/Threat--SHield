"""SQLite storage: an `analyses` table (every check) and a `feedback` table.

Uses only Python's built-in sqlite3 module. Every query uses "?" placeholders,
never string formatting, so user input cannot change the SQL (no SQL injection).
"""

import json
import os
import sqlite3
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "threatshield.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  TEXT NOT NULL,
    kind        TEXT NOT NULL,          -- 'url' or 'email'
    input       TEXT NOT NULL,          -- what was pasted
    domain      TEXT,                   -- registered domain checked
    score       INTEGER NOT NULL,
    verdict     TEXT NOT NULL,
    rule_ids    TEXT NOT NULL,          -- JSON list, e.g. ["R04", "R08"]
    elapsed_ms  REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS feedback (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id  INTEGER NOT NULL REFERENCES analyses(id),
    created_at   TEXT NOT NULL,
    correct      INTEGER NOT NULL,      -- 1 = verdict was right, 0 = wrong
    rule_ids     TEXT NOT NULL          -- copy of the rules that fired
);
"""


def connect(path=DB_PATH):
    """Open the database; rows come back as dictionaries-like objects."""
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(path=DB_PATH):
    """Create the tables if they do not exist yet."""
    with connect(path) as conn:
        conn.executescript(SCHEMA)


def now():
    """Return the current local time as text, to the second."""
    return datetime.now().isoformat(sep=" ", timespec="seconds")


def save_analysis(kind, result, elapsed_ms, path=DB_PATH):
    """Store one check and return its new id."""
    with connect(path) as conn:
        cur = conn.execute(
            "INSERT INTO analyses (created_at, kind, input, domain, score, verdict, rule_ids, elapsed_ms) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (now(), kind, result["input"], result["domain"], result["score"],
             result["verdict"], json.dumps(result["rule_ids"]), elapsed_ms))
        return cur.lastrowid


def recent_analyses(limit=20, path=DB_PATH):
    """Return the most recent checks, newest first, each with its latest feedback (or None)."""
    with connect(path) as conn:
        rows = conn.execute(
            "SELECT a.*, "
            "  (SELECT f.correct FROM feedback f WHERE f.analysis_id = a.id "
            "   ORDER BY f.id DESC LIMIT 1) AS feedback "
            "FROM analyses a ORDER BY a.id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(row) for row in rows]


def save_feedback(analysis_id, correct, path=DB_PATH):
    """Store a right/wrong click with a copy of the rules that fired; return False if no such check."""
    with connect(path) as conn:
        row = conn.execute("SELECT rule_ids FROM analyses WHERE id = ?", (analysis_id,)).fetchone()
        if row is None:
            return False
        # Copying rule_ids here means tune.py only needs the feedback table.
        conn.execute(
            "INSERT INTO feedback (analysis_id, created_at, correct, rule_ids) VALUES (?, ?, ?, ?)",
            (analysis_id, now(), 1 if correct else 0, row["rule_ids"]))
        return True


def repeat_domains(min_count=3, path=DB_PATH):
    """Return domains flagged (suspicious or malicious) at least min_count times, most first."""
    # One domain showing up again and again suggests an active campaign.
    with connect(path) as conn:
        rows = conn.execute(
            "SELECT domain, COUNT(*) AS times FROM analyses "
            "WHERE verdict != 'benign' AND domain != '' "
            "GROUP BY domain HAVING COUNT(*) >= ? ORDER BY times DESC",
            (min_count,)).fetchall()
    return [dict(row) for row in rows]
