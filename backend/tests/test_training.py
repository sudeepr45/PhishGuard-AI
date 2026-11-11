import json

import pandas as pd
import pytest

from backend.src.api import URLRequest, load_model_artifact
from backend.src.evaluate import evaluate_saved_model
from backend.src.features import FEATURE_NAMES, extract_url_features
from backend.src.training import (
    DataValidationError,
    fit_model_candidates,
    grouped_splits,
    load_dataset,
    normalize_url,
    train_and_evaluate,
)


def write_dataset(path, rows):
    pd.DataFrame(rows, columns=["URL", "label"]).to_csv(path, index=False)


def test_source_label_mapping_and_normalized_duplicate_removal(tmp_path):
    source = tmp_path / "small.csv"
    write_dataset(source, [
        ("HTTPS://Example.com:443", "1"),
        ("https://example.com/", "1"),
        ("http://phish.test/login", "0"),
    ])
    features, labels, groups, audit = load_dataset(source)
    assert list(labels) == [0, 1]  # source 1=legitimate, source 0=phishing
    assert len(features) == 2
    assert len(groups) == 2
    assert audit.normalized_duplicate_rows_dropped == 1


def test_conflicting_normalized_duplicate_labels_are_excluded_and_audited(tmp_path):
    source = tmp_path / "conflict.csv"
    write_dataset(source, [
        ("http://example.com/", "0"),
        ("HTTP://EXAMPLE.COM:80", "1"),
        ("https://legit.test/", "1"),
        ("https://phish.test/login", "0"),
    ])
    _features, labels, _groups, audit = load_dataset(source)
    assert len(labels) == 2
    assert audit.normalized_duplicate_label_conflicts == 1
    assert audit.conflicting_label_rows_dropped == 2


def test_missing_columns_are_rejected_and_unknown_labels_are_audited(tmp_path):
    missing = tmp_path / "missing.csv"
    pd.DataFrame({"URL": ["https://example.com"]}).to_csv(missing, index=False)
    with pytest.raises(DataValidationError, match="missing required columns"):
        load_dataset(missing)

    unknown = tmp_path / "unknown.csv"
    write_dataset(unknown, [
        ("https://bad-label.test/", "2"),
        ("https://missing-label.test/", None),
        ("https://legit.test/", "1"),
        ("https://phish.test/", "0"),
    ])
    _features, _labels, _groups, audit = load_dataset(unknown)
    assert audit.invalid_label_rows_dropped == 2
    assert audit.invalid_label_values == ("2", "<missing>")


def test_normalization_and_group_split_keep_domains_disjoint():
    assert normalize_url("HTTPS://Example.com:443") == "https://example.com/"
    urls, labels, groups = [], [], []
    for index in range(100):
        host = f"site{index}.example{index}.com"
        urls.append(index)
        labels.append(index % 2)
        groups.append(host)
    train, validation, test = grouped_splits(pd.Series(labels), groups)
    assert (train, validation, test) == grouped_splits(pd.Series(labels), groups)
    group_sets = [{groups[index] for index in part} for part in (train, validation, test)]
    assert not group_sets[0] & group_sets[1]
    assert not group_sets[0] & group_sets[2]
    assert not group_sets[1] & group_sets[2]


@pytest.mark.parametrize("url", [
    "https://example.com",
    "HTTP://EXAMPLE.COM/login",
    "https://example.com:443/login",
    "https://example.com/path/?a=1&b=2#section",
    "https://example.com/a/../login",
    "https://example.com/%2Flogin",
    "  https://example.com/login  ",
    "example.com/login",
])
def test_training_and_runtime_features_use_the_same_canonical_url(tmp_path, url):
    runtime_url = URLRequest(url=url).url
    runtime_features = extract_url_features(runtime_url)
    training_canonical_features = extract_url_features(normalize_url(runtime_url))
    assert training_canonical_features == runtime_features

    source = tmp_path / "parity.csv"
    write_dataset(source, [
        (url, "1"),
        ("https://independent-phishing.test/login", "0"),
        ("https://independent-legitimate.test/home", "1"),
    ])
    features, _labels, _groups, audit = load_dataset(source)
    if "://" not in url.strip():
        # The dataset policy requires an explicit HTTP(S) scheme. Runtime can
        # accept scheme-less input, but the dataset loader does not invent one.
        assert audit.invalid_url_rows_dropped == 1
        assert len(features) == 2
    else:
        assert audit.invalid_url_rows_dropped == 0
        assert features.iloc[0].to_dict() == runtime_features


def test_training_feature_extraction_receives_normalized_duplicate_key(tmp_path, monkeypatch):
    import backend.src.training as training

    source = tmp_path / "canonical-training.csv"
    write_dataset(source, [
        ("https://legitimate.test", "1"),
        ("https://phishing.test:443/login", "0"),
    ])
    extracted_inputs = []
    original_extractor = training.extract_url_features

    def capture(url):
        extracted_inputs.append(url)
        return original_extractor(url)

    monkeypatch.setattr(training, "extract_url_features", capture)
    load_dataset(source)

    assert extracted_inputs == [
        "https://legitimate.test/",
        "https://phishing.test/login",
    ]


def test_preprocessing_uses_only_runtime_features_and_counts_invalid_urls(tmp_path):
    source = tmp_path / "extra-columns.csv"
    pd.DataFrame([
        {"URL": "https://legit.test/", "label": "1", "FILENAME": "a.txt", "URLSimilarityIndex": 100},
        {"URL": "https://phish.test/", "label": "0", "FILENAME": "b.txt", "URLSimilarityIndex": 1},
        {"URL": "javascript:alert(1)", "label": "0", "FILENAME": "c.txt", "URLSimilarityIndex": 2},
    ]).to_csv(source, index=False)
    features, _labels, _groups, audit = load_dataset(source)
    features_again, _labels_again, _groups_again, audit_again = load_dataset(source)
    assert list(features.columns) == list(FEATURE_NAMES)
    pd.testing.assert_frame_equal(features, features_again)
    assert audit == audit_again
    assert audit.invalid_url_rows_dropped == 1
    assert audit.invalid_label_rows_dropped == 0


def test_scalers_fit_on_training_rows_only():
    features = pd.DataFrame(0.0, index=range(6), columns=FEATURE_NAMES)
    features.iloc[4:, 0] = 100_000
    labels = pd.Series([0, 1, 0, 1, 0, 1])
    models, _durations = fit_model_candidates(features, labels, [0, 1, 2, 3])
    for model in models.values():
        scaler = model.named_steps["scale"]
        assert scaler.n_samples_seen_ == 4
        assert scaler.mean_[0] == 0


def test_training_writes_comparison_report_and_loadable_selected_artifact(tmp_path):
    source = tmp_path / "project-data.csv"
    rows = []
    for index in range(120):
        source_label = "1" if index % 2 == 0 else "0"
        rows.append((f"https://site{index}.example{index}.com/path/{index}?n={index}", source_label))
    write_dataset(source, rows)

    output_dir = tmp_path / "artifacts"
    report = train_and_evaluate(source, output_dir)
    artifact = load_model_artifact(output_dir / "url_model.joblib")
    saved_report = json.loads((output_dir / "evaluation.json").read_text(encoding="utf-8"))
    test_report = evaluate_saved_model(source, output_dir)

    assert report["feature_names"] == list(FEATURE_NAMES)
    assert {"logistic_regression", "random_forest"}.issubset(report["validation"])
    assert report["selected_algorithm"] in {"logistic_regression", "random_forest"}
    assert report["selected_model"]["final_test"]["confusion_matrix"]
    assert report["selected_model"]["final_test"]["accuracy"] >= 0
    assert report["selected_model"]["final_test"]["single_url_inference_time_ms"] >= 0
    assert report["domain_overlap_verified"] is True
    assert artifact["algorithm"] == report["selected_algorithm"]
    assert artifact["decision_threshold"] == 0.5
    assert list(artifact["feature_names"]) == list(FEATURE_NAMES)
    assert set(artifact["model"].predict(pd.DataFrame(0, index=range(2), columns=FEATURE_NAMES))) <= {0, 1}
    assert (output_dir / "final_test_evaluation.json").is_file()
    assert saved_report["selected_algorithm"] == report["selected_algorithm"]
    assert test_report["selected_algorithm"] == report["selected_algorithm"]
    assert 0 <= test_report["metrics"]["roc_auc"] <= 1

