import json
import sqlite3
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "phishing_history.db"


def get_connection():
    """Create a connection to the SQLite database."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create the history table if it does not already exist."""
    conn = get_connection()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            prediction TEXT NOT NULL,
            confidence REAL NOT NULL,
            risk_level TEXT NOT NULL,
            feature_analysis TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


def _row_to_dict(row):
    """Convert a SQLite row into a dictionary with parsed feature analysis."""
    data = dict(row)
    if data.get("feature_analysis"):
        try:
            data["feature_analysis"] = json.loads(data["feature_analysis"])
        except (TypeError, json.JSONDecodeError):
            data["feature_analysis"] = {}
    return data


def add_scan(url, prediction, confidence, risk_level, feature_analysis):
    """Store a scan result in the database."""
    conn = get_connection()
    conn.execute(
        """
        INSERT INTO scans (url, prediction, confidence, risk_level, feature_analysis, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (url, prediction, confidence, risk_level, json.dumps(feature_analysis), datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
    )
    conn.commit()
    scan_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
    conn.close()
    return scan_id


def get_recent_scans(limit=8):
    """Fetch the most recent scan records."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM scans ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    conn.close()
    return [_row_to_dict(row) for row in rows]


def get_scans_filtered(search="", prediction="", risk_level="", start_date="", end_date="", limit=None):
    """Fetch scan history using optional search and filter arguments."""
    conn = get_connection()
    query = "SELECT * FROM scans WHERE 1=1"
    params = []

    if search:
        term = f"%{search}%"
        query += " AND (url LIKE ? OR prediction LIKE ? OR risk_level LIKE ?)"
        params.extend([term, term, term])

    if prediction:
        query += " AND prediction = ?"
        params.append(prediction)

    if risk_level:
        query += " AND risk_level = ?"
        params.append(risk_level)

    if start_date:
        query += " AND created_at >= ?"
        params.append(f"{start_date} 00:00:00")

    if end_date:
        query += " AND created_at <= ?"
        params.append(f"{end_date} 23:59:59")

    query += " ORDER BY id DESC"
    if limit is not None:
        query += " LIMIT ?"
        params.append(limit)

    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [_row_to_dict(row) for row in rows]


def get_daily_scan_stats():
    """Return daily scan counts for the dashboard chart."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT substr(created_at, 1, 10) AS day, COUNT(*) AS count FROM scans GROUP BY substr(created_at, 1, 10) ORDER BY day ASC"
    ).fetchall()
    conn.close()
    return [{"day": row["day"], "count": row["count"]} for row in rows]


def get_scan_by_id(scan_id):
    """Fetch a single scan by its identifier."""
    conn = get_connection()
    row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    conn.close()
    return _row_to_dict(row) if row else None


def get_dashboard_stats():
    """Return summary statistics for the dashboard."""
    conn = get_connection()
    total = conn.execute("SELECT COUNT(*) AS count FROM scans").fetchone()["count"]
    legitimate = conn.execute("SELECT COUNT(*) AS count FROM scans WHERE prediction = 'Legitimate'").fetchone()["count"]
    phishing = conn.execute("SELECT COUNT(*) AS count FROM scans WHERE prediction = 'Phishing'").fetchone()["count"]
    conn.close()

    return {
        "total": total,
        "legitimate": legitimate,
        "phishing": phishing,
        "accuracy": round((legitimate / total * 100) if total else 0, 2),
    }
