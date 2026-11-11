"""Small, local SQLite store for completed URL analyses."""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

SCHEMA_VERSION = 3
DEFAULT_DATABASE_PATH = Path(__file__).resolve().parents[1] / "data" / "analysis_history.sqlite3"


class HistoryDatabaseError(RuntimeError):
    """A database operation failed; callers should not expose SQLite details."""


def configured_database_path(path: Path | str | None = None) -> Path:
    configured = path if path is not None else os.getenv("PHISHGUARD_DB_PATH")
    if configured is None or str(configured).strip() == "":
        return DEFAULT_DATABASE_PATH
    return Path(configured).expanduser().resolve()


class HistoryStore:
    def __init__(self, path: Path | str | None = None):
        self.path = configured_database_path(path)

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(self.path, timeout=5.0)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA busy_timeout = 5000")
            yield connection
        except sqlite3.Error as exc:
            raise HistoryDatabaseError("SQLite operation failed") from exc
        finally:
            if connection is not None:
                connection.close()

    def initialize(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                version = int(connection.execute("PRAGMA user_version").fetchone()[0])
                if version > SCHEMA_VERSION:
                    raise HistoryDatabaseError("Database schema is newer than this application")
                if version < 1:
                    connection.execute(
                        """CREATE TABLE IF NOT EXISTS analysis_history (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            created_at TEXT NOT NULL,
                            normalized_url TEXT NOT NULL CHECK(length(normalized_url) > 0),
                            prediction TEXT NOT NULL CHECK(prediction IN ('legitimate', 'phishing')),
                            phishing_score REAL NOT NULL CHECK(phishing_score >= 0 AND phishing_score <= 1),
                            legitimate_score REAL NOT NULL CHECK(legitimate_score >= 0 AND legitimate_score <= 1),
                            decision_threshold REAL NOT NULL CHECK(decision_threshold >= 0 AND decision_threshold <= 1),
                            model_version TEXT NOT NULL CHECK(length(model_version) > 0),
                            model_algorithm TEXT NOT NULL CHECK(length(model_algorithm) > 0),
                            measured_features TEXT NOT NULL CHECK(json_valid(measured_features))
                        )"""
                    )
                    connection.execute(
                        "CREATE INDEX IF NOT EXISTS idx_analysis_history_created_at "
                        "ON analysis_history(created_at DESC, id DESC)"
                    )
                    connection.execute("PRAGMA user_version = 1")
                    version = 1
                if version < 2:
                    columns = {
                        row[1]
                        for row in connection.execute("PRAGMA table_info(analysis_history)")
                    }
                    if "explanation_json" not in columns:
                        connection.execute(
                            "ALTER TABLE analysis_history ADD COLUMN explanation_json TEXT "
                            "CHECK(explanation_json IS NULL OR json_valid(explanation_json))"
                        )
                    connection.execute("PRAGMA user_version = 2")
                    version = 2
                if version < 3:
                    columns = {
                        row[1]
                        for row in connection.execute("PRAGMA table_info(analysis_history)")
                    }
                    if "novelty_json" not in columns:
                        connection.execute(
                            "ALTER TABLE analysis_history ADD COLUMN novelty_json TEXT "
                            "CHECK(novelty_json IS NULL OR json_valid(novelty_json))"
                        )
                    connection.execute("PRAGMA user_version = 3")
                connection.commit()
        except HistoryDatabaseError:
            raise
        except (OSError, sqlite3.Error) as exc:
            raise HistoryDatabaseError("Database initialization failed") from exc

    @staticmethod
    def _timestamp() -> str:
        return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")

    def insert_analysis(self, result: dict[str, Any]) -> dict[str, Any]:
        created_at = self._timestamp()
        features_json = json.dumps(result["measured_features"], separators=(",", ":"), sort_keys=True)
        explanation = result.get("explanation")
        if explanation is not None and (
            not isinstance(explanation, dict)
            or explanation.get("model_version") != result.get("model_version")
            or explanation.get("model_algorithm") != result.get("model_algorithm")
        ):
            raise ValueError("explanation model metadata must match its analysis record")
        explanation_json = (
            json.dumps(explanation, separators=(",", ":"), sort_keys=True)
            if explanation is not None else None
        )
        novelty = result.get("novelty_detection")
        novelty_json = json.dumps(novelty, separators=(",", ":"), sort_keys=True) if novelty is not None else None
        try:
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                cursor = connection.execute(
                    """INSERT INTO analysis_history (
                        created_at, normalized_url, prediction, phishing_score, legitimate_score,
                        decision_threshold, model_version, model_algorithm, measured_features,
                        explanation_json, novelty_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        created_at,
                        result["normalized_url"],
                        result["prediction"],
                        result["phishing_score"],
                        result["legitimate_score"],
                        result["decision_threshold"],
                        result["model_version"],
                        result["model_algorithm"],
                        features_json,
                        explanation_json,
                        novelty_json,
                    ),
                )
                analysis_id = int(cursor.lastrowid)
                record = {
                    "id": analysis_id,
                    "created_at": created_at,
                    "normalized_url": result["normalized_url"],
                    "prediction": result["prediction"],
                    "phishing_score": result["phishing_score"],
                    "legitimate_score": result["legitimate_score"],
                    "decision_threshold": result["decision_threshold"],
                    "model_version": result["model_version"],
                    "model_algorithm": result["model_algorithm"],
                    "measured_features": json.loads(features_json),
                    "explanation": json.loads(explanation_json) if explanation_json is not None else None,
                    "novelty_detection": json.loads(novelty_json) if novelty_json is not None else None,
                }
                connection.commit()
            return record
        except (sqlite3.Error, OSError, KeyError, TypeError, ValueError) as exc:
            raise HistoryDatabaseError("Analysis could not be persisted") from exc

    @staticmethod
    def _decode_row(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        explanation_json = item.pop("explanation_json", None)
        novelty_json = item.pop("novelty_json", None)
        try:
            item["measured_features"] = json.loads(item["measured_features"])
            item["explanation"] = (
                json.loads(explanation_json) if explanation_json is not None else None
            )
            item["novelty_detection"] = json.loads(novelty_json) if novelty_json is not None else None
        except (json.JSONDecodeError, TypeError) as exc:
            raise HistoryDatabaseError("Stored analysis data is invalid") from exc
        if item["explanation"] is not None and (
            not isinstance(item["explanation"], dict)
            or item["explanation"].get("model_version") != item["model_version"]
            or item["explanation"].get("model_algorithm") != item["model_algorithm"]
        ):
            raise HistoryDatabaseError("Stored explanation model metadata does not match its analysis")
        return item

    def list_analyses(self, limit: int, offset: int) -> tuple[list[dict[str, Any]], int]:
        try:
            with self._connection() as connection:
                connection.execute("BEGIN")
                total = int(connection.execute("SELECT COUNT(*) FROM analysis_history").fetchone()[0])
                rows = connection.execute(
                    "SELECT * FROM analysis_history ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
                    (limit, offset),
                ).fetchall()
                connection.commit()
            return [self._decode_row(row) for row in rows], total
        except (sqlite3.Error, OSError) as exc:
            raise HistoryDatabaseError("History could not be read") from exc

    def get_analysis(self, analysis_id: int) -> dict[str, Any] | None:
        try:
            with self._connection() as connection:
                row = connection.execute(
                    "SELECT * FROM analysis_history WHERE id = ?", (analysis_id,)
                ).fetchone()
            return self._decode_row(row) if row is not None else None
        except (sqlite3.Error, OSError) as exc:
            raise HistoryDatabaseError("Analysis could not be read") from exc

    def delete_analysis(self, analysis_id: int) -> bool:
        try:
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                cursor = connection.execute("DELETE FROM analysis_history WHERE id = ?", (analysis_id,))
                connection.commit()
            return cursor.rowcount > 0
        except (sqlite3.Error, OSError) as exc:
            raise HistoryDatabaseError("Analysis could not be deleted") from exc

    def clear_history(self) -> int:
        try:
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                cursor = connection.execute("DELETE FROM analysis_history")
                deleted = cursor.rowcount
                connection.commit()
            return deleted
        except (sqlite3.Error, OSError) as exc:
            raise HistoryDatabaseError("History could not be cleared") from exc
