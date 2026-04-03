#!/usr/bin/env python3
"""
feature_store.py — SQLite-backed store for ML feature vectors.

Two tables:
  node_features — one row per (hour_bucket, node): aggregate auth stats
  ip_features   — one row per (hour_bucket, src_ip): per-attacker stats

Both tables accumulate over time; the ML detector reads them for training.
"""

import sqlite3
from pathlib import Path
from datetime import datetime
from typing import Optional

DB_PATH = Path("/home/rosse/siem/scripts/feature_store.db")


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _migrate(conn: sqlite3.Connection) -> None:
    """Add new columns to existing tables without breaking old data."""
    existing_node = {row[1] for row in conn.execute("PRAGMA table_info(node_features)").fetchall()}
    new_node_cols = [
        ("is_orchestrator",     "REAL    DEFAULT 0.0"),
        ("failure_velocity",    "REAL    DEFAULT 0.0"),
        ("hours_since_success", "REAL    DEFAULT 168.0"),
    ]
    for col, defn in new_node_cols:
        if col not in existing_node:
            conn.execute(f"ALTER TABLE node_features ADD COLUMN {col} {defn}")


def init_db() -> None:
    with _connect() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS node_features (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                bucket_time      TEXT    NOT NULL,
                node             TEXT    NOT NULL,
                ssh_failures     INTEGER DEFAULT 0,
                ssh_successes    INTEGER DEFAULT 0,
                unique_src_ips   INTEGER DEFAULT 0,
                unique_users_failed INTEGER DEFAULT 0,
                failure_rate     REAL    DEFAULT 0.0,
                cron_events      INTEGER DEFAULT 0,
                hour_of_day      INTEGER,
                day_of_week      INTEGER,
                anomaly_score    REAL,
                is_anomaly       INTEGER DEFAULT 0,
                UNIQUE(bucket_time, node)
            );

            CREATE TABLE IF NOT EXISTS ip_features (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                bucket_time      TEXT    NOT NULL,
                src_ip           TEXT    NOT NULL,
                fail_count       INTEGER DEFAULT 0,
                success_count    INTEGER DEFAULT 0,
                unique_users_tried INTEGER DEFAULT 0,
                node_count       INTEGER DEFAULT 0,
                has_threat_intel INTEGER DEFAULT 0,
                anomaly_score    REAL,
                is_anomaly       INTEGER DEFAULT 0,
                UNIQUE(bucket_time, src_ip)
            );

            CREATE INDEX IF NOT EXISTS idx_node_bucket ON node_features(bucket_time);
            CREATE INDEX IF NOT EXISTS idx_ip_bucket   ON ip_features(bucket_time);
        """)
        _migrate(conn)


def upsert_node_features(rows: list[dict]) -> int:
    """Insert or replace node feature rows. Returns count written."""
    if not rows:
        return 0
    # Ensure new fields have defaults so old callers don't break
    normalized = []
    for row in rows:
        r = dict(row)
        r.setdefault("is_orchestrator",     0.0)
        r.setdefault("failure_velocity",    0.0)
        r.setdefault("hours_since_success", 168.0)
        normalized.append(r)
    with _connect() as conn:
        conn.executemany("""
            INSERT INTO node_features
                (bucket_time, node, ssh_failures, ssh_successes, unique_src_ips,
                 unique_users_failed, failure_rate, cron_events, hour_of_day, day_of_week,
                 is_orchestrator, failure_velocity, hours_since_success)
            VALUES
                (:bucket_time, :node, :ssh_failures, :ssh_successes, :unique_src_ips,
                 :unique_users_failed, :failure_rate, :cron_events, :hour_of_day, :day_of_week,
                 :is_orchestrator, :failure_velocity, :hours_since_success)
            ON CONFLICT(bucket_time, node) DO UPDATE SET
                ssh_failures        = excluded.ssh_failures,
                ssh_successes       = excluded.ssh_successes,
                unique_src_ips      = excluded.unique_src_ips,
                unique_users_failed = excluded.unique_users_failed,
                failure_rate        = excluded.failure_rate,
                cron_events         = excluded.cron_events,
                hour_of_day         = excluded.hour_of_day,
                day_of_week         = excluded.day_of_week,
                is_orchestrator     = excluded.is_orchestrator,
                failure_velocity    = excluded.failure_velocity,
                hours_since_success = excluded.hours_since_success
        """, normalized)
    return len(rows)


def upsert_ip_features(rows: list[dict]) -> int:
    """Insert or replace IP feature rows. Returns count written."""
    if not rows:
        return 0
    with _connect() as conn:
        conn.executemany("""
            INSERT INTO ip_features
                (bucket_time, src_ip, fail_count, success_count, unique_users_tried,
                 node_count, has_threat_intel)
            VALUES
                (:bucket_time, :src_ip, :fail_count, :success_count, :unique_users_tried,
                 :node_count, :has_threat_intel)
            ON CONFLICT(bucket_time, src_ip) DO UPDATE SET
                fail_count          = excluded.fail_count,
                success_count       = excluded.success_count,
                unique_users_tried  = excluded.unique_users_tried,
                node_count          = excluded.node_count,
                has_threat_intel    = excluded.has_threat_intel
        """, rows)
    return len(rows)


def update_node_anomaly_scores(scores: list[dict]) -> None:
    """Write anomaly_score and is_anomaly back to node_features rows."""
    with _connect() as conn:
        conn.executemany("""
            UPDATE node_features
            SET anomaly_score = :anomaly_score, is_anomaly = :is_anomaly
            WHERE bucket_time = :bucket_time AND node = :node
        """, scores)


def update_ip_anomaly_scores(scores: list[dict]) -> None:
    """Write anomaly_score and is_anomaly back to ip_features rows."""
    with _connect() as conn:
        conn.executemany("""
            UPDATE ip_features
            SET anomaly_score = :anomaly_score, is_anomaly = :is_anomaly
            WHERE bucket_time = :bucket_time AND src_ip = :src_ip
        """, scores)


def get_node_training_data(days: int = 30) -> list[sqlite3.Row]:
    """Return node feature rows from the last N days for model training."""
    with _connect() as conn:
        return conn.execute("""
            SELECT * FROM node_features
            WHERE bucket_time >= datetime('now', ?)
            ORDER BY bucket_time ASC
        """, (f"-{days} days",)).fetchall()


def get_ip_training_data(days: int = 30) -> list[sqlite3.Row]:
    """Return IP feature rows from the last N days for model training."""
    with _connect() as conn:
        return conn.execute("""
            SELECT * FROM ip_features
            WHERE bucket_time >= datetime('now', ?)
            ORDER BY bucket_time ASC
        """, (f"-{days} days",)).fetchall()


def get_recent_node_features(hours: int = 1) -> list[sqlite3.Row]:
    """Return the most recent N hours of node features (for scoring)."""
    with _connect() as conn:
        return conn.execute("""
            SELECT * FROM node_features
            WHERE bucket_time >= datetime('now', ?)
            ORDER BY bucket_time DESC
        """, (f"-{hours} hours",)).fetchall()


def get_recent_ip_features(hours: int = 1) -> list[sqlite3.Row]:
    """Return the most recent N hours of IP features (for scoring)."""
    with _connect() as conn:
        return conn.execute("""
            SELECT * FROM ip_features
            WHERE bucket_time >= datetime('now', ?)
            ORDER BY bucket_time DESC
        """, (f"-{hours} hours",)).fetchall()


def get_node_history(node: str, hours: int = 3) -> list[sqlite3.Row]:
    """Return the last N hours of node_features for a specific node (excludes current bucket)."""
    with _connect() as conn:
        return conn.execute("""
            SELECT * FROM node_features
            WHERE node = ? AND bucket_time >= datetime('now', ?)
            ORDER BY bucket_time DESC
        """, (node, f"-{hours} hours")).fetchall()


def get_last_node_success(node: str) -> Optional[sqlite3.Row]:
    """Return the most recent node_features row where ssh_successes > 0 for this node."""
    with _connect() as conn:
        return conn.execute("""
            SELECT bucket_time FROM node_features
            WHERE node = ? AND ssh_successes > 0
            ORDER BY bucket_time DESC
            LIMIT 1
        """, (node,)).fetchone()


def get_recent_node_window(hours: int = 24) -> list[sqlite3.Row]:
    """Return all node features from the last N hours across all nodes (for z-score baseline)."""
    with _connect() as conn:
        return conn.execute("""
            SELECT * FROM node_features
            WHERE bucket_time >= datetime('now', ?)
            ORDER BY bucket_time ASC
        """, (f"-{hours} hours",)).fetchall()


def get_ip_series(hours: int = 6) -> list[sqlite3.Row]:
    """Return ip_features rows from the last N hours (for escalation sequence detection)."""
    with _connect() as conn:
        return conn.execute("""
            SELECT * FROM ip_features
            WHERE bucket_time >= datetime('now', ?)
            ORDER BY src_ip ASC, bucket_time ASC
        """, (f"-{hours} hours",)).fetchall()


def get_stats() -> dict:
    """Return summary stats about what's in the store."""
    with _connect() as conn:
        node_count = conn.execute("SELECT COUNT(*) FROM node_features").fetchone()[0]
        ip_count   = conn.execute("SELECT COUNT(*) FROM ip_features").fetchone()[0]
        oldest     = conn.execute("SELECT MIN(bucket_time) FROM node_features").fetchone()[0]
        newest     = conn.execute("SELECT MAX(bucket_time) FROM node_features").fetchone()[0]
        anomalies  = conn.execute("SELECT COUNT(*) FROM node_features WHERE is_anomaly = 1").fetchone()[0]
    return {
        "node_rows": node_count,
        "ip_rows":   ip_count,
        "oldest":    oldest,
        "newest":    newest,
        "anomalies": anomalies,
    }


if __name__ == "__main__":
    init_db()
    stats = get_stats()
    print(f"Feature store: {DB_PATH}")
    print(f"  Node rows : {stats['node_rows']}")
    print(f"  IP rows   : {stats['ip_rows']}")
    print(f"  Range     : {stats['oldest']} -> {stats['newest']}")
    print(f"  Anomalies : {stats['anomalies']}")
