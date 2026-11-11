import json
import sqlite3

from backend.src.history_store import HistoryStore, SCHEMA_VERSION


def analysis_result(url="https://example.com/login"):
    return {
        "normalized_url": url,
        "prediction": "phishing",
        "phishing_score": 0.875,
        "legitimate_score": 0.125,
        "decision_threshold": 0.5,
        "model_version": "url-classifier-2",
        "model_algorithm": "random_forest",
        "measured_features": {"url_length": len(url), "uses_https": 1},
    }


def test_initialization_creates_versioned_schema_and_is_repeatable(tmp_path):
    database_path = tmp_path / "nested" / "history.sqlite3"
    store = HistoryStore(database_path)
    store.initialize()
    created = store.insert_analysis(analysis_result())
    store.initialize()

    with sqlite3.connect(database_path) as connection:
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        columns = {row[1] for row in connection.execute("PRAGMA table_info(analysis_history)")}
        indexes = {row[1] for row in connection.execute("PRAGMA index_list(analysis_history)")}
    assert version == SCHEMA_VERSION
    assert {
        "id", "created_at", "normalized_url", "prediction", "phishing_score",
        "legitimate_score", "decision_threshold", "model_version", "model_algorithm",
        "measured_features", "explanation_json",
    }.issubset(columns)
    assert "idx_analysis_history_created_at" in indexes
    assert store.get_analysis(created["id"]) == created
    assert store.list_analyses(10, 0)[1] == 1


def test_insert_preserves_scores_features_and_utc_timestamp(tmp_path):
    store = HistoryStore(tmp_path / "history.sqlite3")
    store.initialize()
    result = analysis_result()
    record = store.insert_analysis(result)
    assert record["prediction"] == "phishing"
    assert record["phishing_score"] == 0.875
    assert record["legitimate_score"] == 0.125
    assert record["measured_features"] == result["measured_features"]
    assert record["created_at"].endswith("Z")
    assert "T" in record["created_at"]

    with sqlite3.connect(store.path) as connection:
        raw = connection.execute(
            "SELECT measured_features FROM analysis_history WHERE id = ?", (record["id"],)
        ).fetchone()[0]
    assert json.loads(raw) == result["measured_features"]


def test_schema_v1_migration_preserves_history_and_adds_nullable_explanation(tmp_path):
    database_path = tmp_path / "legacy-v1.sqlite3"
    old_result = analysis_result("https://legacy.example/login")
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """CREATE TABLE analysis_history (
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
            """INSERT INTO analysis_history (
                created_at, normalized_url, prediction, phishing_score, legitimate_score,
                decision_threshold, model_version, model_algorithm, measured_features
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                "2025-01-01T00:00:00Z", old_result["normalized_url"], old_result["prediction"],
                old_result["phishing_score"], old_result["legitimate_score"],
                old_result["decision_threshold"], old_result["model_version"],
                old_result["model_algorithm"], json.dumps(old_result["measured_features"]),
            ),
        )
        connection.execute("PRAGMA user_version = 1")

    store = HistoryStore(database_path)
    store.initialize()
    migrated = store.get_analysis(1)
    assert migrated is not None
    assert migrated["normalized_url"] == old_result["normalized_url"]
    assert migrated["model_version"] == old_result["model_version"]
    assert migrated["measured_features"] == old_result["measured_features"]
    assert migrated["explanation"] is None
    assert migrated["novelty_detection"] is None
    with sqlite3.connect(database_path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 3
        assert connection.execute("SELECT COUNT(*) FROM analysis_history").fetchone()[0] == 1


def test_explanation_is_saved_and_retrieved_with_its_model_version(tmp_path):
    store = HistoryStore(tmp_path / "explanations.sqlite3")
    store.initialize()
    explanation = {
        "model_version": "url-classifier-3",
        "model_algorithm": "logistic_regression",
        "positive_class": "phishing",
        "intercept": 0.25,
        "reconstructed_logit": 1.5,
        "decision_function_logit": 1.5,
        "reconstruction_error": 0.0,
        "feature_contributions": [],
        "interpretation": "Additive logit contributions, not causation.",
    }
    result = analysis_result()
    result["model_version"] = "url-classifier-3"
    result["model_algorithm"] = "logistic_regression"
    result["explanation"] = explanation

    inserted = store.insert_analysis(result)
    retrieved = store.get_analysis(inserted["id"])
    assert inserted["explanation"] == explanation
    assert retrieved is not None
    assert retrieved["explanation"] == explanation
    assert retrieved["explanation"]["model_version"] == retrieved["model_version"]
    assert store.list_analyses(10, 0)[0][0]["explanation"] == explanation


def test_delete_and_clear_only_remove_records(tmp_path):
    store = HistoryStore(tmp_path / "history.sqlite3")
    store.initialize()
    first = store.insert_analysis(analysis_result("https://one.example/"))
    second = store.insert_analysis(analysis_result("https://two.example/"))
    assert store.delete_analysis(first["id"]) is True
    assert store.delete_analysis(first["id"]) is False
    assert store.clear_history() == 1
    assert store.list_analyses(10, 0) == ([], 0)
    store.initialize()
    assert store.path.is_file()
    assert store.get_analysis(second["id"]) is None
