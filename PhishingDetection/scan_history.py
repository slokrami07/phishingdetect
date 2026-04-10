"""
scan_history.py — SQLite-backed scan history for PhishGuard.
Replaces the flat scan_log.txt with a queryable database.
"""
import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'scans.db')


class ScanHistory:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _get_conn(self):
        """Return a thread-safe connection."""
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Create the scans table if it doesn't exist."""
        with self._get_conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    url       TEXT NOT NULL,
                    verdict   TEXT NOT NULL,
                    confidence REAL DEFAULT 0,
                    source    TEXT DEFAULT 'ai_analysis',
                    reasoning TEXT,
                    timestamp TEXT NOT NULL
                )
            """)
            conn.commit()

    def log_scan(self, url: str, verdict: str, confidence: float = 0.0,
                 source: str = 'ai_analysis', reasoning: str = ''):
        """Insert a new scan record."""
        try:
            with self._get_conn() as conn:
                conn.execute(
                    """INSERT INTO scans (url, verdict, confidence, source, reasoning, timestamp)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (url, verdict, round(confidence, 1), source, reasoning,
                     datetime.now().isoformat())
                )
                conn.commit()
        except Exception as e:
            print(f"⚠️  ScanHistory.log_scan error: {e}")

    def get_recent(self, limit: int = 100) -> list:
        """Return the most recent scans as a list of dicts."""
        try:
            with self._get_conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
                ).fetchall()
                return [dict(row) for row in rows]
        except Exception as e:
            print(f"⚠️  ScanHistory.get_recent error: {e}")
            return []

    def get_stats(self) -> dict:
        """Return a summary of verdict counts."""
        try:
            with self._get_conn() as conn:
                rows = conn.execute(
                    "SELECT verdict, COUNT(*) as count FROM scans GROUP BY verdict"
                ).fetchall()
                stats = {row['verdict']: row['count'] for row in rows}
                total = sum(stats.values())
                stats['total'] = total
                return stats
        except Exception as e:
            print(f"⚠️  ScanHistory.get_stats error: {e}")
            return {}


# Singleton so all parts of the app share one connection
scan_history = ScanHistory()
