from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class RunStore:
    """SQLite persistence for controlled attack runs and audit events."""

    def __init__(self, database_path: str | None = None):
        configured_path = database_path or os.getenv("RED_TEAM_DB_PATH", "data/redteam.db")
        self.database_path = Path(configured_path)
        if self.database_path != Path(":memory:"):
            self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=10)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS attack_runs (
                    run_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    overall_score INTEGER NOT NULL,
                    total_attacks INTEGER NOT NULL,
                    blocked_attacks INTEGER NOT NULL,
                    results_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    action TEXT NOT NULL,
                    run_id TEXT,
                    client_id TEXT NOT NULL,
                    detail TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_attack_runs_created_at
                    ON attack_runs(created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_audit_events_created_at
                    ON audit_events(created_at DESC);
                """
            )

    def save_run(self, run_id: str, results: list[dict[str, Any]]) -> dict[str, Any]:
        created_at = datetime.now(timezone.utc).isoformat()
        blocked = sum(item["status"] == "blocked" for item in results)
        score = round(sum(item["metrics"]["score"] for item in results) / len(results)) if results else 100
        record = {
            "run_id": run_id,
            "created_at": created_at,
            "overall_score": score,
            "total_attacks": len(results),
            "blocked_attacks": blocked,
            "results": results,
        }
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO attack_runs VALUES (?, ?, ?, ?, ?, ?)",
                (run_id, created_at, score, len(results), blocked, json.dumps(results)),
            )
        return record

    def list_runs(self, limit: int = 20) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT run_id, created_at, overall_score, total_attacks, blocked_attacks "
                "FROM attack_runs ORDER BY created_at DESC LIMIT ?",
                (max(1, min(limit, 100)),),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT run_id, created_at, overall_score, total_attacks, blocked_attacks, results_json "
                "FROM attack_runs WHERE run_id = ?",
                (run_id,),
            ).fetchone()
        if row is None:
            return None
        record = dict(row)
        record["results"] = json.loads(record.pop("results_json"))
        return record

    def add_audit_event(self, action: str, client_id: str, detail: str, run_id: str | None = None) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO audit_events (created_at, action, run_id, client_id, detail) VALUES (?, ?, ?, ?, ?)",
                (datetime.now(timezone.utc).isoformat(), action, run_id, client_id, detail),
            )

    def list_audit_events(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT created_at, action, run_id, client_id, detail FROM audit_events "
                "ORDER BY created_at DESC LIMIT ?",
                (max(1, min(limit, 100)),),
            ).fetchall()
        return [dict(row) for row in rows]
