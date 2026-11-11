from __future__ import annotations

import json

import numpy as np
import pandas as pd

from backend.src import evaluate_external as external
from backend.src.features import FEATURE_NAMES


class FrozenClassifier:
    classes_ = np.array([0, 1])

    def predict_proba(self, frame):
        assert list(frame.columns) == list(FEATURE_NAMES)
        return np.tile([0.25, 0.75], (len(frame), 1))

    def predict(self, frame):
        return np.ones(len(frame), dtype=int)


class FrozenNovelty:
    def score_samples(self, frame):
        assert list(frame.columns) == list(FEATURE_NAMES)
        return np.linspace(-0.2, -0.8, len(frame))


def test_canonical_url_matches_api_normalization():
    assert external._canonical_url("  HTTP://EXAMPLE.COM:80/login ") == "http://example.com/login"
    assert external._canonical_url("example.com/login") == "https://example.com/login"


def test_external_data_uses_raw_url_label_and_recomputes_features(tmp_path):
    csv = tmp_path / "external.csv"
    pd.DataFrame([
        {"url": "https://bad.example/a", "type": "phishing", "precomputed": -999},
        {"url": "https://good.example/", "type": "legitimate", "precomputed": 999},
        {"url": "https://BAD.example:443/a", "type": "phishing", "precomputed": 999},
        {"url": "not a URL", "type": "legitimate", "precomputed": 123},
    ]).to_csv(csv, index=False)

    features, labels, prepared = external._prepare_external(csv)
    assert list(features.columns) == list(FEATURE_NAMES)
    assert len(features) == 2
    assert labels.tolist() == [1, 0]
    assert features.iloc[0]["url_length"] == len("https://bad.example/a")
    assert prepared["audit"]["malformed_url_rows"] == 1
    assert prepared["audit"]["same_label_normalized_duplicate_rows_excluded"] == 1


def test_conflicting_canonical_labels_are_excluded(tmp_path):
    csv = tmp_path / "external.csv"
    pd.DataFrame([
        {"url": "https://example.org/login", "type": "phishing"},
        {"url": "https://EXAMPLE.org:443/login", "type": "legitimate"},
        {"url": "https://safe.org/", "type": "legitimate"},
        {"url": "https://bad.org/", "type": "phishing"},
    ]).to_csv(csv, index=False)
    _features, labels, prepared = external._prepare_external(csv)
    assert len(labels) == 2
    assert prepared["audit"]["normalized_url_conflict_keys"] == 1
    assert prepared["audit"]["rows_in_conflicting_url_groups"] == 2


def test_evaluation_excludes_training_domains_and_never_fits(tmp_path, monkeypatch):
    external_csv = tmp_path / "external.csv"
    pd.DataFrame([
        {"url": "https://training.example/a", "type": "phishing"},
        {"url": "https://clean-one.test/", "type": "legitimate"},
        {"url": "https://clean-two.test/", "type": "phishing"},
        {"url": "https://clean-three.test/", "type": "legitimate"},
    ]).to_csv(external_csv, index=False)
    training_csv = tmp_path / "training.csv"
    training_csv.write_text("fixture", encoding="utf-8")
    classifier_path = tmp_path / "classifier.joblib"
    novelty_path = tmp_path / "novelty.joblib"
    classifier_path.write_bytes(b"classifier")
    novelty_path.write_bytes(b"novelty")

    classifier_artifact = {
        "model": FrozenClassifier(), "model_version": "url-classifier-3",
        "algorithm": "logistic_regression", "feature_names": list(FEATURE_NAMES),
        "decision_threshold": 0.5,
    }
    novelty_artifact = {
        "detector": FrozenNovelty(), "detector_version": "url-novelty-1",
        "feature_names": list(FEATURE_NAMES), "threshold": 0.5,
    }
    monkeypatch.setattr(external, "load_model_artifact", lambda _path: classifier_artifact)
    monkeypatch.setattr(external, "load_novelty_artifact", lambda _path: novelty_artifact)
    monkeypatch.setattr(external, "_training_url_sets", lambda _path: (
        {"https://training.example/a"}, {"training.example"},
        {"https://training.example/a"}, {"training.example"},
        {"retained_rows": 1, "train_rows": 1, "train_domains": 1, "conflicting_normalized_urls": 0},
    ))

    report = external.evaluate_external(
        external_csv, training_csv, classifier_path, novelty_path, tmp_path / "result.json"
    )
    assert report["data_audit"]["exact_normalized_url_overlaps_with_full_phiusiil_retained_set"] == 1
    assert report["data_audit"]["remaining_rows_after_domain_exclusion"] == 3
    assert report["evaluation_set"] == {"rows": 3, "legitimate": 2, "phishing": 1}
    assert report["frozen_classifier"]["metrics"]["confusion_matrix"] == [[0, 2], [0, 1]]
    assert report["frozen_novelty_detector"]["metrics"]["confusion_matrix"] == [[1, 1], [0, 1]]
    assert json.loads((tmp_path / "result.json").read_text()) == report
    assert not hasattr(classifier_artifact["model"], "fit")
    assert not hasattr(novelty_artifact["detector"], "fit")


def test_metrics_include_fpr_auc_and_fixed_label_order():
    result = external._metrics(np.array([0, 0, 1, 1]), np.array([0, 1, 1, 0]), np.array([0.1, 0.7, 0.8, 0.2]))
    assert result["confusion_matrix"] == [[1, 1], [1, 1]]
    assert result["false_positive_rate_legitimate_as_phishing"] == 0.5
    assert result["roc_auc"] == 0.75
