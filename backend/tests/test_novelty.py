import platform
import sqlite3

import joblib
import numpy as np
import pandas as pd
import pytest
import sklearn
from fastapi.testclient import TestClient
from sklearn.ensemble import IsolationForest

from backend.src.api import create_app
from backend.src.features import FEATURE_NAMES, extract_url_features
from backend.src.history_store import HistoryStore
from backend.src.novelty import (
    DEFAULT_MAX_FALSE_POSITIVE_RATE,
    NOVELTY_ARTIFACT_SCHEMA,
    NOVELTY_ARTIFACT_VERSION,
    NOVELTY_CONFIG,
    THRESHOLD_POLICY,
    NoveltyArtifactError,
    NoveltyTrainingError,
    anomaly_scores,
    load_novelty_artifact,
    score_novelty,
    select_threshold,
    train_novelty_detector,
    validate_novelty_artifact,
)
from backend.src.training import MODEL_VERSION
from backend.src import novelty as novelty_module
from backend.src.training import DataAudit


def feature_frame(rows=32):
    urls = [f"https://legit{index}.example/path/{index}?q={index % 3}" for index in range(rows)]
    return pd.DataFrame([extract_url_features(url) for url in urls], columns=FEATURE_NAMES)


def novelty_artifact():
    frame = feature_frame(40)
    detector = IsolationForest(**NOVELTY_CONFIG).fit(frame.iloc[:20])
    return {
        "artifact_schema_version": NOVELTY_ARTIFACT_SCHEMA,
        "detector_version": NOVELTY_ARTIFACT_VERSION,
        "detector": detector,
        "algorithm": "isolation_forest",
        "feature_names": list(FEATURE_NAMES),
        "feature_count": len(FEATURE_NAMES),
        "dataset_sha256": "a" * 64,
        "training_partition": {
            "fit_rows": 20, "fit_labels": ["legitimate only"], "domain_overlap_verified": True,
            "rows_by_split": {"train": {"legitimate": 20}}, "training_partition_hash": "b" * 64,
        },
        "detector_config": dict(NOVELTY_CONFIG),
        "threshold": 0.0,
        "maximum_validation_false_positive_rate": DEFAULT_MAX_FALSE_POSITIVE_RATE,
        "threshold_policy": THRESHOLD_POLICY,
        "scikit_learn_version": sklearn.__version__,
        "python_version": platform.python_version(),
        "score_definition": "anomaly_score = -IsolationForest.score_samples(features); larger values are more unusual",
    }


def test_fit_receives_only_legitimate_training_rows(monkeypatch):
    frame = feature_frame(16)
    labels = pd.Series([0] * 10 + [1] * 6)
    seen = {}
    original_fit = IsolationForest.fit

    def recording_fit(detector, x, y=None, sample_weight=None):
        seen["rows"] = len(x)
        seen["features"] = x.copy()
        return original_fit(detector, x, y=y, sample_weight=sample_weight)

    monkeypatch.setattr(IsolationForest, "fit", recording_fit)
    model, _elapsed = train_novelty_detector(frame, labels, list(range(10)))
    assert seen["rows"] == 10
    assert len(seen["features"]) == 10
    assert getattr(model, "n_features_in_") == 17
    train_novelty_detector(frame, labels, list(range(11)))
    assert seen["rows"] == 10
    with pytest.raises(NoveltyTrainingError, match="labels"):
        train_novelty_detector(frame, pd.Series([0] * 10 + [2] * 6), list(range(11)))


def test_threshold_maximizes_recall_under_declared_fpr_cap():
    threshold, metrics = select_threshold(
        np.array([0.1, 0.2, 0.3, 0.4, 0.5]), np.array([0, 0, 1, 1, 1]), 0.0
    )
    assert threshold == pytest.approx(0.3)
    assert metrics["recall_phishing"] == 1.0
    assert metrics["false_positive_rate_legitimate_as_unusual"] == 0.0


def test_threshold_rejects_invalid_inputs_and_fpr():
    with pytest.raises(NoveltyTrainingError):
        select_threshold([0.1], [0], DEFAULT_MAX_FALSE_POSITIVE_RATE)
    with pytest.raises(NoveltyTrainingError):
        select_threshold([float("nan"), 0.2], [0, 1], DEFAULT_MAX_FALSE_POSITIVE_RATE)
    with pytest.raises(NoveltyTrainingError):
        select_threshold([0.1, 0.2], [0, 1], 1.1)


def test_isolation_forest_scores_are_deterministic_and_ordered():
    frame = feature_frame(24)
    first = IsolationForest(**NOVELTY_CONFIG).fit(frame.iloc[:16])
    second = IsolationForest(**NOVELTY_CONFIG).fit(frame.iloc[:16])
    np.testing.assert_array_equal(anomaly_scores(first, frame.iloc[16:]), anomaly_scores(second, frame.iloc[16:]))
    wrong_order = frame.loc[:, list(reversed(FEATURE_NAMES))]
    with pytest.raises(NoveltyTrainingError, match="feature order"):
        anomaly_scores(first, wrong_order)


def test_artifact_schema_and_corrupt_artifacts_are_checked(tmp_path):
    artifact = novelty_artifact()
    assert validate_novelty_artifact(artifact) is artifact
    valid_path = tmp_path / "valid.joblib"
    joblib.dump(artifact, valid_path)
    assert load_novelty_artifact(valid_path)["detector_version"] == NOVELTY_ARTIFACT_VERSION
    wrong = dict(artifact, feature_names=list(reversed(FEATURE_NAMES)))
    with pytest.raises(NoveltyArtifactError, match="feature schema"):
        validate_novelty_artifact(wrong)
    corrupt = tmp_path / "corrupt.joblib"
    corrupt.write_bytes(b"not a joblib artifact")
    with pytest.raises(NoveltyArtifactError):
        load_novelty_artifact(corrupt)
    missing = tmp_path / "missing.joblib"
    with pytest.raises(NoveltyArtifactError, match="missing"):
        load_novelty_artifact(missing)


def test_unavailable_novelty_never_claims_normal():
    result = score_novelty(None, feature_frame(1))
    assert result["available"] is False
    assert result["is_unusual"] is None
    assert result["anomaly_score"] is None


def test_training_pipeline_uses_validation_for_threshold_then_scores_test_once(monkeypatch, tmp_path):
    frame = feature_frame(12)
    labels = pd.Series([0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1], dtype="int8")
    groups = [f"domain-{index}" for index in range(len(labels))]
    audit = DataAudit(12, 0, 0, (), 0, 0, 0, 0, 12, 6, 6, 12, 0)
    monkeypatch.setattr(novelty_module, "load_dataset", lambda _path: (frame, labels, groups, audit))
    monkeypatch.setattr(novelty_module, "grouped_splits", lambda *_args: (
        [0, 1, 2, 3, 4, 5], [6, 7, 8, 9], [10, 11]
    ))
    score_calls = []

    def controlled_scores(_detector, data):
        score_calls.append(list(data.index))
        values = {6: 0.1, 7: 0.2, 8: 0.3, 9: 0.4, 10: 0.1, 11: 0.4}
        return np.asarray([values[index] for index in data.index])

    monkeypatch.setattr(novelty_module, "anomaly_scores", controlled_scores)
    fitted_indices = []
    original_fit = IsolationForest.fit

    def recording_fit(detector, data, y=None, sample_weight=None):
        fitted_indices.extend(data.index.tolist())
        return original_fit(detector, data, y=y, sample_weight=sample_weight)

    monkeypatch.setattr(IsolationForest, "fit", recording_fit)
    dataset_path = tmp_path / "small.csv"
    dataset_path.write_text("synthetic fixture", encoding="utf-8")
    report = novelty_module.train_and_evaluate_novelty(dataset_path, tmp_path / "novelty-out", 0.0)
    assert fitted_indices == [0, 1, 2]
    assert score_calls == [[6, 7, 8, 9], [10, 11]]
    assert report["threshold"] == pytest.approx(0.3)
    assert report["final_test_used_for_selection_or_tuning"] is False


def test_version_two_history_migration_preserves_existing_record(tmp_path):
    path = tmp_path / "schema-v2.sqlite3"
    with sqlite3.connect(path) as connection:
        connection.execute("""CREATE TABLE analysis_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL,
            normalized_url TEXT NOT NULL, prediction TEXT NOT NULL,
            phishing_score REAL NOT NULL, legitimate_score REAL NOT NULL,
            decision_threshold REAL NOT NULL, model_version TEXT NOT NULL,
            model_algorithm TEXT NOT NULL, measured_features TEXT NOT NULL,
            explanation_json TEXT)""")
        connection.execute("""INSERT INTO analysis_history VALUES
            (1, '2025-01-01T00:00:00Z', 'https://old.example/', 'legitimate',
             0.1, 0.9, 0.5, 'url-classifier-3', 'logistic_regression', '{}', NULL)""")
        connection.execute("PRAGMA user_version = 2")
    store = HistoryStore(path)
    store.initialize()
    row = store.get_analysis(1)
    assert row["normalized_url"] == "https://old.example/"
    assert row["explanation"] is None
    assert row["novelty_detection"] is None
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 3
        assert "novelty_json" in {row[1] for row in connection.execute("PRAGMA table_info(analysis_history)")}


def test_analysis_persists_and_returns_separate_novelty_result(tmp_path):
    # Reuse the existing deterministic API test fixture model semantics.
    from backend.tests.test_api import make_artifact

    detector_artifact = novelty_artifact()
    test_model = make_artifact()
    client = TestClient(create_app(
        artifact=test_model, novelty_artifact=detector_artifact,
        database_path=tmp_path / "novelty.sqlite3",
    ))
    response = client.post("/analyze", json={"url": "https://example.test/path"})
    assert response.status_code == 200
    result = response.json()
    assert result["model_version"] == MODEL_VERSION
    novelty = result["novelty_detection"]
    assert novelty["available"] is True
    assert novelty["detector_version"] == NOVELTY_ARTIFACT_VERSION
    assert novelty["is_unusual"] == (novelty["anomaly_score"] >= novelty["threshold"])
    assert result["prediction"] in {"legitimate", "phishing"}
    saved = client.get("/history").json()["items"][0]
    assert saved["novelty_detection"] == novelty
    detail = client.get(f"/history/{saved['id']}").json()
    assert detail["novelty_detection"] == novelty


def test_classifier_remains_available_when_novelty_artifact_missing(tmp_path):
    from backend.tests.test_api import make_artifact

    client = TestClient(create_app(
        artifact=make_artifact(), novelty_path=tmp_path / "absent.joblib",
        database_path=tmp_path / "unavailable.sqlite3",
    ))
    response = client.post("/analyze", json={"url": "https://example.test/path"})
    assert response.status_code == 200
    assert response.json()["novelty_detection"]["available"] is False
    assert response.json()["novelty_detection"]["is_unusual"] is None
    assert client.get("/healthz").json()["model_ready"] is True


def test_corrupt_novelty_artifact_does_not_disable_classifier(tmp_path):
    from backend.tests.test_api import make_artifact

    corrupt = tmp_path / "bad.joblib"
    corrupt.write_bytes(b"not joblib")
    client = TestClient(create_app(
        artifact=make_artifact(), novelty_path=corrupt,
        database_path=tmp_path / "corrupt-novelty.sqlite3",
    ))
    result = client.post("/analyze", json={"url": "https://example.test/path"})
    assert result.status_code == 200
    assert result.json()["novelty_detection"]["available"] is False


def test_novelty_does_not_change_classifier_prediction_or_scores(tmp_path):
    from backend.tests.test_api import make_artifact

    classifier_artifact = make_artifact()
    ordinary = TestClient(create_app(
        artifact=classifier_artifact, novelty_path=tmp_path / "missing.joblib",
        database_path=tmp_path / "ordinary.sqlite3",
    )).post("/analyze", json={"url": "https://example.test/path"}).json()
    enhanced = TestClient(create_app(
        artifact=classifier_artifact, novelty_artifact=novelty_artifact(),
        database_path=tmp_path / "enhanced.sqlite3",
    )).post("/analyze", json={"url": "https://example.test/path"}).json()
    for field in ("prediction", "phishing_score", "legitimate_score", "decision_threshold", "explanation"):
        assert enhanced[field] == ordinary[field]
    assert enhanced["novelty_detection"]["available"] is True
