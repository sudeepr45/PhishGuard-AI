import platform
import tempfile
from pathlib import Path

import joblib
import pandas as pd
import pytest
import sklearn
import tldextract
from sklearn.linear_model import LogisticRegression as SkLogisticRegression
from sklearn.pipeline import Pipeline as SkPipeline
from sklearn.preprocessing import StandardScaler as SkStandardScaler
from fastapi.testclient import TestClient

from backend.src.api import MODEL_SCOPE, MAX_URL_CHARACTERS, create_app, load_model_artifact, ModelArtifactError
import backend.src.api as api_module
from backend.src.features import FEATURE_NAMES, extract_url_features
from backend.src.training import MODEL_VERSION


class BoundaryModel:
    """Deterministic model double used only by API tests."""

    classes_ = [0, 1]
    n_features_in_ = len(FEATURE_NAMES)
    named_steps = {"classifier": None}

    def __init__(self, probabilities=(0.1, 0.9), prediction=1, fail=False, classes=None):
        self.named_steps = {"classifier": RandomForestClassifier()}
        self.probabilities = probabilities
        self.prediction = prediction
        self.fail = fail
        if classes is not None:
            self.classes_ = classes

    def predict(self, matrix):
        assert list(matrix.columns) == list(FEATURE_NAMES)
        if self.fail:
            raise RuntimeError("do not expose this internal detail")
        return [self.prediction]

    def predict_proba(self, matrix):
        assert list(matrix.columns) == list(FEATURE_NAMES)
        if self.fail:
            raise RuntimeError("do not expose this internal detail")
        return [self.probabilities]


class RandomForestClassifier:
    """Marker with the estimator class name expected in the artifact."""


def make_artifact(model=None, **overrides):
    artifact = {
        "model": model or BoundaryModel(),
        "model_version": MODEL_VERSION,
        "algorithm": "random_forest",
        "feature_names": list(FEATURE_NAMES),
        "scikit_learn_version": sklearn.__version__,
        "tldextract_version": tldextract.__version__,
        "python_version": platform.python_version(),
        "model_scope": MODEL_SCOPE,
        "decision_threshold": 0.5,
    }
    artifact.update(overrides)
    return artifact


def client_with_test_model(model=None, database_path=None, **overrides):
    tempdir = None
    if database_path is None:
        tempdir = tempfile.TemporaryDirectory(prefix="phishguard-test-")
        database_path = Path(tempdir.name) / "history.sqlite3"
    client = TestClient(create_app(artifact=make_artifact(model, **overrides), database_path=database_path))
    # Keep the isolated temporary database alive for the duration of the client.
    client._phishguard_test_tempdir = tempdir
    return client


def fitted_logistic_pipeline():
    urls = [f"https://site{index}.example/path/{index}?item={index % 5}" for index in range(64)]
    frame = pd.DataFrame(
        [extract_url_features(url) for url in urls], columns=FEATURE_NAMES
    )
    labels = [int(index >= len(frame) // 2) for index in range(len(frame))]
    pipeline = SkPipeline([
        ("scale", SkStandardScaler()),
        ("classifier", SkLogisticRegression(max_iter=1000, solver="liblinear", random_state=412)),
    ])
    pipeline.fit(frame, labels)
    return pipeline


def test_health_reports_process_and_model_readiness_separately():
    ready = client_with_test_model().get("/healthz").json()
    assert ready == {"status": "ready", "api_running": True, "model_ready": True, "database_ready": True}


def test_public_demo_runs_inference_without_initializing_or_persisting_history(monkeypatch, tmp_path):
    db_path = tmp_path / "not-created" / "history.sqlite3"
    monkeypatch.setenv("PHISHGUARD_PUBLIC_DEMO", "false")
    local_client = TestClient(create_app(artifact=make_artifact(), database_path=tmp_path / "local.sqlite3"))
    local_body = local_client.post("/analyze", json={"url": "https://example.com/login"}).json()

    monkeypatch.setenv("PHISHGUARD_PUBLIC_DEMO", "true")
    client = TestClient(create_app(artifact=make_artifact(), database_path=db_path))

    response = client.post("/analyze", json={"url": "https://example.com/login"})

    assert response.status_code == 200
    public_body = response.json()
    assert public_body == local_body
    assert public_body["prediction"] == "phishing"
    assert list(public_body["measured_features"]) == list(FEATURE_NAMES)
    assert client.get("/healthz").json() == {
        "status": "ready", "api_running": True, "model_ready": True, "database_ready": None,
    }
    assert not db_path.parent.exists()


def test_public_demo_false_preserves_local_history_behavior(monkeypatch, tmp_path):
    monkeypatch.setenv("PHISHGUARD_PUBLIC_DEMO", "false")
    db_path = tmp_path / "local-history.sqlite3"
    client = TestClient(create_app(artifact=make_artifact(), database_path=db_path))
    assert client.post("/analyze", json={"url": "https://example.com"}).status_code == 200
    assert client.get("/history").json()["total"] == 1
    assert db_path.is_file()
    assert client.get("/openapi.json").status_code == 200


def test_public_demo_disables_history_routes_and_api_docs(monkeypatch, tmp_path):
    monkeypatch.setenv("PHISHGUARD_PUBLIC_DEMO", "true")
    client = TestClient(create_app(artifact=make_artifact(), database_path=tmp_path / "unused.sqlite3"))

    for response in (
        client.get("/history"),
        client.get("/history/1"),
        client.get("/history/not-an-id"),
        client.get("/history/0"),
        client.delete("/history/1"),
        client.delete("/history"),
        client.delete("/history", params={"confirm": "true"}),
    ):
        assert response.status_code == 404
        assert response.json() == {"detail": "History is disabled in public demo mode."}
    for path in ("/openapi.json", "/docs", "/redoc"):
        assert client.get(path).status_code == 404


def test_public_demo_email_screening_remains_available(monkeypatch):
    monkeypatch.setenv("PHISHGUARD_PUBLIC_DEMO", "true")
    client = TestClient(create_app(artifact=make_artifact()))
    response = client.post("/analyze-email", json={"raw_email": "From: sender@example.org\nSubject: demo\n\nVisit https://example.com"})
    assert response.status_code == 200
    assert response.json()["extracted_link_count"] == 1


def test_configurable_artifact_paths_and_server_binding(monkeypatch, tmp_path):
    model_path = tmp_path / "configured-model.joblib"
    novelty_path = tmp_path / "configured-novelty.joblib"
    monkeypatch.setenv("PHISHGUARD_MODEL_PATH", str(model_path))
    monkeypatch.setenv("PHISHGUARD_NOVELTY_PATH", str(novelty_path))
    seen = []
    monkeypatch.setattr(api_module, "load_model_artifact", lambda path: seen.append(path) or make_artifact())
    monkeypatch.setattr(api_module, "load_novelty_artifact", lambda path: seen.append(path) or None)

    configured = create_app()
    assert seen == [model_path, novelty_path]

    calls = []
    monkeypatch.setattr(api_module.uvicorn, "run", lambda *args, **kwargs: calls.append(kwargs))
    monkeypatch.setenv("HOST", "0.0.0.0")
    monkeypatch.setenv("PORT", "8765")
    api_module.main()
    assert calls == [{"host": "0.0.0.0", "port": 8765, "access_log": False}]
    assert configured.state.model_artifact["algorithm"] == "random_forest"


def test_configured_cors_allows_only_exact_origins_without_credentials(monkeypatch):
    monkeypatch.setenv("PHISHGUARD_CORS_ORIGINS", "https://demo.example, http://localhost:4173")
    client = TestClient(create_app(artifact=make_artifact()))
    allowed = client.options("/analyze", headers={
        "Origin": "https://demo.example",
        "Access-Control-Request-Method": "POST",
    })
    assert allowed.headers["access-control-allow-origin"] == "https://demo.example"
    assert allowed.headers.get("access-control-allow-credentials") != "true"
    denied = client.options("/analyze", headers={
        "Origin": "https://other.example",
        "Access-Control-Request-Method": "POST",
    })
    assert "access-control-allow-origin" not in denied.headers


def test_cors_is_not_added_when_origins_are_unconfigured(monkeypatch):
    monkeypatch.delenv("PHISHGUARD_CORS_ORIGINS", raising=False)
    client = TestClient(create_app(artifact=make_artifact()))
    response = client.options("/analyze", headers={
        "Origin": "https://example.org",
        "Access-Control-Request-Method": "POST",
    })
    assert "access-control-allow-origin" not in response.headers


def test_cors_rejects_wildcard_origins(monkeypatch):
    monkeypatch.setenv("PHISHGUARD_CORS_ORIGINS", "*")
    with pytest.raises(ValueError, match=r"exact HTTP\(S\) origins"):
        create_app(artifact=make_artifact())


def test_production_startup_initializes_configured_database_path(monkeypatch, tmp_path):
    database_path = tmp_path / "startup" / "custom-history.sqlite3"
    monkeypatch.setenv("PHISHGUARD_DB_PATH", str(database_path))
    client = TestClient(create_app(artifact=make_artifact()))
    with client:
        health = client.get("/healthz").json()
        assert health["database_ready"] is True
        assert database_path.is_file()


def test_valid_url_returns_legacy_and_typed_fields_and_all_features():
    response = client_with_test_model().post("/analyze", json={"url": "https://example.com/login"})
    assert response.status_code == 200
    body = response.json()
    assert body["prediction"] == "phishing"
    assert body["normalized_url"] == "https://example.com/login"
    assert body["model_algorithm"] == "random_forest"
    assert body["phishing_score"] == 0.9
    assert body["legitimate_score"] == 0.1
    assert body["decision_threshold"] == 0.5
    assert body["model_version"] == MODEL_VERSION
    assert set(body["measured_features"]) == set(FEATURE_NAMES)
    assert list(body["measured_features"]) == list(FEATURE_NAMES)
    assert body["evidence"] == body["measured_features"]
    assert body["measured_features"]["uses_https"] == 1
    assert "not proof" in body["interpretation"]
    assert "uncalibrated" in body["interpretation"]
    assert "url" not in body


def test_successful_model_analysis_is_persisted_without_changing_response():
    client = client_with_test_model()
    response = client.post("/analyze", json={"url": "https://example.com/login"})
    assert response.status_code == 200
    result = response.json()
    history = client.get("/history")
    assert history.status_code == 200
    body = history.json()
    assert body["total"] == 1
    assert body["has_more"] is False
    record = body["items"][0]
    for key in (
        "normalized_url", "prediction", "phishing_score", "legitimate_score",
        "decision_threshold", "model_version", "model_algorithm", "measured_features", "explanation",
    ):
        assert record[key] == (result["evidence"] if key == "measured_features" else result[key])
    assert record["created_at"].endswith("Z")
    assert record["created_at"].startswith("20")


def test_logistic_regression_explanation_is_serialized_and_persisted():
    pipeline = fitted_logistic_pipeline()
    client = client_with_test_model(model=pipeline, algorithm="logistic_regression")
    response = client.post("/analyze", json={"url": "https://example.com/login?next=home"})
    assert response.status_code == 200
    body = response.json()
    explanation = body["explanation"]
    assert explanation["model_version"] == MODEL_VERSION
    assert explanation["model_algorithm"] == "logistic_regression"
    assert explanation["positive_class"] == "phishing"
    assert len(explanation["feature_contributions"]) == 17
    assert [item["feature_name"] for item in explanation["feature_contributions"]] == list(FEATURE_NAMES)
    assert explanation["reconstructed_logit"] == pytest.approx(
        explanation["decision_function_logit"], abs=1e-10
    )
    assert "not causal" in explanation["interpretation"]

    record = client.get("/history").json()["items"][0]
    assert record["explanation"] == explanation
    detail = client.get(f"/history/{record['id']}").json()
    assert detail["explanation"] == explanation


def test_scheme_less_url_is_consistently_normalized_to_https():
    response = client_with_test_model().post("/analyze", json={"url": "Example.COM/path?q=1"})
    assert response.status_code == 200
    assert response.json()["normalized_url"] == "https://example.com/path?q=1"
    assert response.json()["measured_features"]["uses_https"] == 1

    port_response = client_with_test_model().post("/analyze", json={"url": "example.com:8080/path"})
    assert port_response.status_code == 200
    assert port_response.json()["normalized_url"] == "https://example.com:8080/path"


def test_score_mapping_respects_model_class_order():
    model = BoundaryModel(probabilities=(0.8, 0.2), prediction=1, classes=[1, 0])
    response = client_with_test_model(model).post("/analyze", json={"url": "https://example.com"})
    assert response.status_code == 200
    assert response.json()["prediction"] == "phishing"
    assert response.json()["phishing_score"] == 0.8
    assert response.json()["legitimate_score"] == 0.2


def test_legitimate_prediction_and_threshold_metadata():
    model = BoundaryModel(probabilities=(0.8, 0.2), prediction=0)
    response = client_with_test_model(model, decision_threshold=0.7).post(
        "/analyze", json={"url": "https://example.com"}
    )
    assert response.status_code == 200
    assert response.json()["prediction"] == "legitimate"
    assert response.json()["decision_threshold"] == 0.7


def test_missing_empty_unsupported_malformed_and_unexpected_requests_are_rejected():
    client = client_with_test_model()
    assert client.post("/analyze", json={}).status_code == 422
    assert client.post("/analyze", json={"url": ""}).status_code == 422
    assert client.post("/analyze", json={"url": "   "}).status_code == 422
    assert client.post("/analyze", json={"url": "javascript:alert(1)"}).status_code == 422
    assert client.post("/analyze", json={"url": "data:text/html,hi"}).status_code == 422
    assert client.post("/analyze", json={"url": "file:///etc/passwd"}).status_code == 422
    assert client.post("/analyze", json={"url": "https:///missing-host"}).status_code == 422
    assert client.post("/analyze", json={"url": "https://bad host.test"}).status_code == 422
    assert client.post("/analyze", json={"url": "https://example.com\n/path"}).status_code == 422
    assert client.post("/analyze", json={"url": "https://example.com", "email": "x"}).status_code == 422
    assert client.post("/analyze", content=b"not-json", headers={"content-type": "application/json"}).status_code == 422


def test_oversized_url_and_body_are_rejected():
    client = client_with_test_model()
    assert client.post("/analyze", json={"url": "https://example.com/" + "a" * MAX_URL_CHARACTERS}).status_code == 422
    assert client.post("/analyze", content=b" " * 16_385).status_code == 413


def test_missing_and_corrupt_model_artifacts_leave_api_up_but_not_ready(tmp_path):
    for path in (tmp_path / "missing.joblib", tmp_path / "corrupt.joblib"):
        if path.name == "corrupt.joblib":
            path.write_bytes(b"not a joblib file")
        client = TestClient(create_app(model_path=path, database_path=tmp_path / f"{path.stem}-history.sqlite3"))
        health = client.get("/healthz").json()
        assert health["api_running"] is True
        assert health["model_ready"] is False
        assert health["status"] == "model_unavailable"
        response = client.post("/analyze", json={"url": "https://example.com"})
        assert response.status_code == 503
        assert "missing or incompatible" in response.json()["detail"]


def test_history_empty_pagination_order_retrieval_and_delete():
    client = client_with_test_model()
    assert client.get("/history").json() == {
        "items": [], "total": 0, "limit": 20, "offset": 0, "has_more": False,
    }
    first = client.post("/analyze", json={"url": "https://first.example/path"}).json()
    second = client.post("/analyze", json={"url": "https://second.example/path"}).json()
    page = client.get("/history", params={"limit": 1, "offset": 0}).json()
    assert page["total"] == 2
    assert len(page["items"]) == 1
    assert page["items"][0]["normalized_url"] == second["normalized_url"]
    assert page["has_more"] is True
    later = client.get("/history", params={"limit": 1, "offset": 1}).json()
    assert later["items"][0]["normalized_url"] == first["normalized_url"]
    assert client.get("/history", params={"limit": 101}).status_code == 422

    analysis_id = page["items"][0]["id"]
    fetched = client.get(f"/history/{analysis_id}")
    assert fetched.status_code == 200
    assert fetched.json() == page["items"][0]
    assert client.get("/history/999999").status_code == 404
    assert client.get("/history/0").status_code == 422
    assert client.delete(f"/history/{analysis_id}").json() == {"deleted": True, "analysis_id": analysis_id, "deleted_count": None}
    assert client.delete(f"/history/{analysis_id}").status_code == 404
    assert client.get("/history").json()["total"] == 1


def test_clear_history_requires_confirmation_and_preserves_database_schema():
    client = client_with_test_model()
    client.post("/analyze", json={"url": "https://example.com"})
    assert client.delete("/history").status_code == 400
    assert client.get("/history").json()["total"] == 1
    cleared = client.delete("/history", params={"confirm": "true"})
    assert cleared.status_code == 200
    assert cleared.json()["deleted"] is True
    assert cleared.json()["deleted_count"] == 1
    assert client.get("/history").json()["total"] == 0


def test_database_unavailable_is_reported_and_failed_write_is_not_claimed_as_saved(tmp_path):
    blocked_parent = tmp_path / "regular-file"
    blocked_parent.write_text("not a directory", encoding="utf-8")
    unavailable = TestClient(create_app(
        artifact=make_artifact(), database_path=blocked_parent / "history.sqlite3"
    ))
    health = unavailable.get("/healthz").json()
    assert health["api_running"] is True
    assert health["model_ready"] is True
    assert health["database_ready"] is False
    assert health["status"] == "database_unavailable"
    assert unavailable.post("/analyze", json={"url": "https://example.com"}).status_code == 503

    client = client_with_test_model()
    store = client.app.state.history_store

    def failed_insert(_result):
        raise HistoryDatabaseError("simulated write failure")

    from backend.src.history_store import HistoryDatabaseError

    store.insert_analysis = failed_insert
    response = client.post("/analyze", json={"url": "https://example.com/private"})
    assert response.status_code == 503
    assert "private" not in response.text
    assert client.get("/healthz").json()["database_ready"] is False


def test_incompatible_artifacts_are_rejected(tmp_path):
    artifact_path = tmp_path / "bad.joblib"
    joblib.dump({"model": BoundaryModel()}, artifact_path)
    try:
        load_model_artifact(artifact_path)
    except ModelArtifactError:
        pass
    else:
        raise AssertionError("incomplete model artifact must be rejected")

    assert client_with_test_model(feature_names=list(FEATURE_NAMES[:-1])).get("/healthz").json()["model_ready"] is False

    wrong_order = BoundaryModel()
    wrong_order.feature_names_in_ = list(reversed(FEATURE_NAMES))
    assert client_with_test_model(wrong_order).get("/healthz").json()["model_ready"] is False


def test_inference_failure_is_generic_and_does_not_expose_exception_details():
    response = client_with_test_model(BoundaryModel(fail=True)).post(
        "/analyze", json={"url": "https://example.com/private-path"}
    )
    assert response.status_code == 500
    assert response.json() == {"detail": "URL analysis failed. Try again later."}
    assert "internal detail" not in response.text
    assert "private-path" not in response.text


def test_openapi_documents_url_only_research_scope_and_scores():
    schema = client_with_test_model().get("/openapi.json").json()
    assert "URL text alone" in schema["info"]["description"]
    analyze = schema["paths"]["/analyze"]["post"]
    assert "uncalibrated estimated model scores" in analyze["description"]
    assert "AnalysisResponse" in str(analyze["responses"]["200"])
    assert "503" in analyze["responses"]
