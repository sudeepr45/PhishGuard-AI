"""Train and evaluate an independent Isolation Forest for URL novelty triage."""

from __future__ import annotations

import hashlib
import json
import math
import os
import platform
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from typing import Any

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import IsolationForest
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score

from .features import FEATURE_NAMES
from .training import SEED, grouped_splits, load_dataset

NOVELTY_ARTIFACT_VERSION = "url-novelty-1"
NOVELTY_ARTIFACT_SCHEMA = 1
DEFAULT_MAX_FALSE_POSITIVE_RATE = 0.05
NOVELTY_CONFIG: dict[str, Any] = {
    "n_estimators": 300,
    "max_samples": 256,
    "contamination": "auto",
    "max_features": 1.0,
    "bootstrap": False,
    "random_state": SEED,
    "n_jobs": -1,
}
THRESHOLD_POLICY = (
    "On validation only, choose the anomaly-score threshold (score = -score_samples; "
    "unusual when score >= threshold) that maximizes phishing recall subject to the "
    "configured maximum false-positive rate among legitimate URLs. Ties choose lower "
    "validation false-positive rate, then the higher threshold."
)


class NoveltyTrainingError(ValueError):
    """Invalid split or threshold inputs for novelty training."""


class NoveltyArtifactError(RuntimeError):
    """Novelty artifact is absent or incompatible."""


def validate_novelty_artifact(artifact: Any) -> dict[str, Any]:
    required = {
        "artifact_schema_version", "detector_version", "detector", "algorithm",
        "feature_names", "feature_count", "dataset_sha256", "training_partition",
        "detector_config", "threshold", "maximum_validation_false_positive_rate",
        "threshold_policy", "scikit_learn_version", "python_version", "score_definition",
    }
    if not isinstance(artifact, dict) or not required.issubset(artifact):
        raise NoveltyArtifactError("novelty artifact metadata is incomplete")
    if (artifact["artifact_schema_version"] != NOVELTY_ARTIFACT_SCHEMA or
            artifact["detector_version"] != NOVELTY_ARTIFACT_VERSION or
            artifact["algorithm"] != "isolation_forest"):
        raise NoveltyArtifactError("novelty artifact schema or version is incompatible")
    if artifact["feature_names"] != list(FEATURE_NAMES) or artifact["feature_count"] != len(FEATURE_NAMES):
        raise NoveltyArtifactError("novelty feature schema is incompatible")
    detector = artifact["detector"]
    if not isinstance(detector, IsolationForest) or not callable(getattr(detector, "score_samples", None)):
        raise NoveltyArtifactError("novelty detector is missing or has the wrong estimator type")
    if getattr(detector, "n_features_in_", None) != len(FEATURE_NAMES):
        raise NoveltyArtifactError("novelty detector feature count is incompatible")
    estimator_names = getattr(detector, "feature_names_in_", None)
    if estimator_names is not None and list(estimator_names) != list(FEATURE_NAMES):
        raise NoveltyArtifactError("novelty detector feature ordering is incompatible")
    config = artifact["detector_config"]
    if not isinstance(config, dict) or set(config) != set(NOVELTY_CONFIG):
        raise NoveltyArtifactError("novelty detector configuration is invalid")
    estimator_params = detector.get_params(deep=False)
    if any(key not in estimator_params or estimator_params[key] != value for key, value in config.items()):
        raise NoveltyArtifactError("novelty detector configuration does not match its estimator")
    if len(getattr(detector, "estimators_", ())) != config["n_estimators"]:
        raise NoveltyArtifactError("novelty detector fitted tree count is incompatible")
    try:
        threshold = float(artifact["threshold"])
        max_fpr = float(artifact["maximum_validation_false_positive_rate"])
    except (TypeError, ValueError):
        raise NoveltyArtifactError("novelty threshold metadata is invalid") from None
    if not math.isfinite(threshold) or not math.isfinite(max_fpr) or not 0 <= max_fpr <= 1:
        raise NoveltyArtifactError("novelty threshold metadata is invalid")
    if artifact["threshold_policy"] != THRESHOLD_POLICY:
        raise NoveltyArtifactError("novelty threshold policy is incompatible")
    if artifact["score_definition"] != "anomaly_score = -IsolationForest.score_samples(features); larger values are more unusual":
        raise NoveltyArtifactError("novelty score definition is incompatible")
    if artifact["scikit_learn_version"] != sklearn.__version__ or artifact["python_version"] != platform.python_version():
        raise NoveltyArtifactError("novelty artifact dependency versions are incompatible")
    if (not isinstance(artifact["dataset_sha256"], str) or len(artifact["dataset_sha256"]) != 64 or
            any(character not in "0123456789abcdef" for character in artifact["dataset_sha256"].lower())):
        raise NoveltyArtifactError("novelty dataset hash metadata is invalid")
    partition = artifact["training_partition"]
    if (not isinstance(partition, dict) or partition.get("fit_labels") != ["legitimate only"] or
            not isinstance(partition.get("fit_rows"), int) or partition["fit_rows"] <= 0 or
            partition.get("domain_overlap_verified") is not True or
            not isinstance(partition.get("rows_by_split"), dict) or
            partition["rows_by_split"].get("train", {}).get("legitimate") != partition["fit_rows"]):
        raise NoveltyArtifactError("novelty training partition metadata is invalid")
    partition_hash = partition.get("training_partition_hash")
    if (not isinstance(partition_hash, str) or len(partition_hash) != 64 or
            any(character not in "0123456789abcdef" for character in partition_hash.lower())):
        raise NoveltyArtifactError("novelty training partition hash is invalid")
    try:
        if not np.isfinite(float(detector.offset_)):
            raise ValueError
    except (AttributeError, TypeError, ValueError):
        raise NoveltyArtifactError("novelty estimator is not fitted") from None
    return artifact


def load_novelty_artifact(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise NoveltyArtifactError("novelty artifact is missing")
    try:
        return validate_novelty_artifact(joblib.load(path))
    except NoveltyArtifactError:
        raise
    except Exception as exc:
        raise NoveltyArtifactError("novelty artifact could not be loaded or validated") from exc


def score_novelty(artifact: dict[str, Any] | None, features: pd.DataFrame) -> dict[str, Any]:
    if artifact is None:
        return {
            "available": False, "is_unusual": None, "anomaly_score": None,
            "threshold": None, "detector_version": None, "detector": None,
            "interpretation": "Novelty detection is unavailable because no compatible detector artifact is loaded.",
        }
    try:
        values = anomaly_scores(artifact["detector"], features)
        if len(values) != 1:
            raise NoveltyTrainingError("inference expects exactly one feature row")
        score = float(values[0])
        threshold = float(artifact["threshold"])
        unusual = bool(score >= threshold)
        return {
            "available": True, "is_unusual": unusual, "anomaly_score": score,
            "threshold": threshold, "detector_version": artifact["detector_version"],
            "detector": "Isolation Forest",
            "interpretation": (
                "This URL is structurally unusual relative to legitimate training URLs; that does not establish phishing intent."
                if unusual else
                "This URL falls within patterns familiar to the legitimate training distribution; that does not establish legitimacy."
            ),
        }
    except Exception as exc:
        raise NoveltyTrainingError("novelty inference failed") from exc


def anomaly_scores(detector: IsolationForest, features: pd.DataFrame) -> np.ndarray:
    if list(features.columns) != list(FEATURE_NAMES):
        raise NoveltyTrainingError("feature order does not match the novelty schema")
    values = -np.asarray(detector.score_samples(features), dtype=float)
    if values.shape != (len(features),) or not np.isfinite(values).all():
        raise NoveltyTrainingError("detector returned non-finite or mismatched scores")
    return values


def select_threshold(
    scores: np.ndarray | list[float], labels: np.ndarray | list[int], max_fpr: float,
) -> tuple[float, dict[str, float]]:
    scores_array = np.asarray(scores, dtype=float)
    labels_array = np.asarray(labels, dtype=int)
    if (scores_array.ndim != 1 or scores_array.shape != labels_array.shape or
            not len(scores_array) or not np.isfinite(scores_array).all() or
            set(np.unique(labels_array)) != {0, 1}):
        raise NoveltyTrainingError("validation data must contain finite scores and both target classes")
    if not math.isfinite(max_fpr) or not 0 <= max_fpr <= 1:
        raise NoveltyTrainingError("maximum false-positive rate must be between 0 and 1")

    candidates = np.unique(scores_array)
    candidates = np.append(candidates, np.nextafter(candidates[-1], math.inf))
    legitimate = labels_array == 0
    phishing = labels_array == 1
    eligible: list[tuple[float, float, float, float]] = []
    for threshold in candidates:
        alerts = scores_array >= threshold
        fpr = float(alerts[legitimate].mean())
        recall = float(alerts[phishing].mean())
        if fpr <= max_fpr + 1e-15:
            eligible.append((recall, fpr, float(threshold), float(alerts.mean())))
    if not eligible:
        raise NoveltyTrainingError("no threshold satisfies the configured false-positive limit")
    best_recall = max(row[0] for row in eligible)
    best_fpr = min(row[1] for row in eligible if row[0] == best_recall)
    threshold = max(row[2] for row in eligible if row[0] == best_recall and row[1] == best_fpr)
    alerts = scores_array >= threshold
    return threshold, {
        "accuracy": float(accuracy_score(labels_array, alerts.astype(int))),
        "precision_phishing": float(precision_score(labels_array, alerts.astype(int), zero_division=0)),
        "recall_phishing": float(recall_score(labels_array, alerts.astype(int), zero_division=0)),
        "f1_phishing": float(f1_score(labels_array, alerts.astype(int), zero_division=0)),
        "false_positive_rate_legitimate_as_unusual": float(alerts[legitimate].mean()),
        "legitimate_url_alert_rate": float(alerts[legitimate].mean()),
        "phishing_url_detection_rate": float(alerts[phishing].mean()),
    }


def evaluate_detector(
    scores: np.ndarray, labels: pd.Series | np.ndarray, threshold: float,
) -> dict[str, Any]:
    scores_array = np.asarray(scores, dtype=float)
    labels_array = np.asarray(labels, dtype=int)
    if scores_array.shape != labels_array.shape or not np.isfinite(scores_array).all():
        raise NoveltyTrainingError("evaluation scores must be finite and match labels")
    predictions = (scores_array >= threshold).astype(int)
    matrix = confusion_matrix(labels_array, predictions, labels=[0, 1])
    tn, fp, fn, tp = (int(value) for value in matrix.ravel())
    return {
        "accuracy": float(accuracy_score(labels_array, predictions)),
        "precision_phishing": float(precision_score(labels_array, predictions, zero_division=0)),
        "recall_phishing": float(recall_score(labels_array, predictions, zero_division=0)),
        "f1_phishing": float(f1_score(labels_array, predictions, zero_division=0)),
        "false_positive_rate_legitimate_as_unusual": fp / (fp + tn) if fp + tn else 0.0,
        "legitimate_url_alert_rate": fp / (fp + tn) if fp + tn else 0.0,
        "phishing_url_detection_rate": tp / (tp + fn) if tp + fn else 0.0,
        "confusion_matrix_labels": ["legitimate", "phishing"],
        "confusion_matrix": matrix.tolist(),
        "counts": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
        "roc_auc": float(roc_auc_score(labels_array, scores_array)) if len(np.unique(labels_array)) == 2 else None,
    }


def train_novelty_detector(
    features: pd.DataFrame, labels: pd.Series, train_indices: list[int],
) -> tuple[IsolationForest, float]:
    if list(features.columns) != list(FEATURE_NAMES):
        raise NoveltyTrainingError("training features do not match the expected feature order")
    if not train_indices or not set(labels.iloc[train_indices].unique()).issubset({0, 1}):
        raise NoveltyTrainingError("training partition labels are invalid")
    legitimate_train_indices = [index for index in train_indices if labels.iloc[index] == 0]
    if not legitimate_train_indices:
        raise NoveltyTrainingError("training partition has no legitimate rows for novelty fitting")
    detector = IsolationForest(**NOVELTY_CONFIG)
    started = perf_counter()
    detector.fit(features.iloc[legitimate_train_indices])
    return detector, perf_counter() - started


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def train_and_evaluate_novelty(
    dataset_path: Path,
    output_dir: Path,
    max_false_positive_rate: float = DEFAULT_MAX_FALSE_POSITIVE_RATE,
) -> dict[str, Any]:
    if not math.isfinite(max_false_positive_rate) or not 0 <= max_false_positive_rate <= 1:
        raise NoveltyTrainingError("maximum false-positive rate must be between 0 and 1")
    features, labels, groups, audit = load_dataset(dataset_path)
    train_idx, validation_idx, test_idx = grouped_splits(labels, groups)
    detector, training_seconds = train_novelty_detector(features, labels, train_idx)

    validation_scores = anomaly_scores(detector, features.iloc[validation_idx])
    validation_labels = labels.iloc[validation_idx]
    threshold, _threshold_selection_metrics = select_threshold(
        validation_scores, validation_labels.to_numpy(), max_false_positive_rate
    )
    validation_metrics = evaluate_detector(validation_scores, validation_labels, threshold)
    # Threshold, detector configuration and feature schema are frozen above.
    # The final-test partition is scored once and never affects any choice.
    final_test_scores = anomaly_scores(detector, features.iloc[test_idx])
    final_test_metrics = evaluate_detector(final_test_scores, labels.iloc[test_idx], threshold)

    stamp = datetime.now(timezone.utc).isoformat()
    dataset_hash = _sha256(dataset_path)
    counts = {
        split: {
            "rows": len(indexes),
            "legitimate": int((labels.iloc[indexes] == 0).sum()),
            "phishing": int((labels.iloc[indexes] == 1).sum()),
            "domain_groups": len({groups[index] for index in indexes}),
        }
        for split, indexes in (("train", train_idx), ("validation", validation_idx), ("test", test_idx))
    }
    report: dict[str, Any] = {
        "artifact_schema_version": NOVELTY_ARTIFACT_SCHEMA,
        "detector_version": NOVELTY_ARTIFACT_VERSION,
        "detector": "IsolationForest",
        "dataset": "PhiUSIIL Phishing URL Dataset, UCI ID 967",
        "dataset_sha256": dataset_hash,
        "training_date_utc": stamp,
        "feature_names": list(FEATURE_NAMES),
        "feature_count": len(FEATURE_NAMES),
        "label_mapping": {"0": "legitimate", "1": "phishing"},
        "training_partition": {
            "method": "existing registrable-domain grouped 60/20/20 split",
            "seed": SEED,
            "rows_by_split": counts,
            "fit_rows": counts["train"]["legitimate"],
            "fit_labels": ["legitimate only"],
            "domain_overlap_verified": True,
            "training_partition_hash": hashlib.sha256(
                json.dumps(sorted((groups[index], int(labels.iloc[index])) for index in train_idx if labels.iloc[index] == 0),
                           separators=(",", ":")).encode("utf-8")
            ).hexdigest(),
        },
        "detector_config": dict(NOVELTY_CONFIG),
        "score_definition": "anomaly_score = -IsolationForest.score_samples(features); larger values are more unusual",
        "threshold_policy": THRESHOLD_POLICY,
        "maximum_validation_false_positive_rate": max_false_positive_rate,
        "threshold": float(threshold),
        "validation": {"threshold": float(threshold), **validation_metrics},
        "final_test": final_test_metrics,
        "training_time_seconds": training_seconds,
        "final_test_used_for_selection_or_tuning": False,
        "scope_note": (
            "Novelty identifies structural deviation from legitimate training URLs. "
            "An unusual URL is not necessarily phishing, and a familiar URL is not necessarily legitimate."
        ),
        "versions": {"python": platform.python_version(), "scikit_learn": sklearn.__version__, "pandas": pd.__version__},
        "dataset_audit": {
            "retained_rows": audit.retained_rows,
            "retained_legitimate": audit.retained_legitimate,
            "retained_phishing": audit.retained_phishing,
        },
    }
    artifact = {
        "artifact_schema_version": NOVELTY_ARTIFACT_SCHEMA,
        "detector_version": NOVELTY_ARTIFACT_VERSION,
        "detector": detector,
        "algorithm": "isolation_forest",
        "feature_names": list(FEATURE_NAMES),
        "feature_count": len(FEATURE_NAMES),
        "dataset_sha256": dataset_hash,
        "training_date_utc": stamp,
        "training_partition": report["training_partition"],
        "detector_config": dict(NOVELTY_CONFIG),
        "threshold": float(threshold),
        "maximum_validation_false_positive_rate": max_false_positive_rate,
        "threshold_policy": THRESHOLD_POLICY,
        "validation_metrics": validation_metrics,
        "scikit_learn_version": sklearn.__version__,
        "python_version": platform.python_version(),
        "score_definition": report["score_definition"],
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    artifact_path = output_dir / "novelty_detector.joblib"
    temporary_artifact = artifact_path.with_suffix(".joblib.tmp")
    joblib.dump(artifact, temporary_artifact)
    os.replace(temporary_artifact, artifact_path)
    for filename, data in (("evaluation.json", report), ("final_test_evaluation.json", {
        "detector_version": NOVELTY_ARTIFACT_VERSION,
        "dataset_sha256": dataset_hash,
        "threshold_frozen_before_final_test": True,
        "threshold": float(threshold),
        "metrics": final_test_metrics,
        "scope_note": report["scope_note"],
    })):
        path = output_dir / filename
        temporary = path.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(data, indent=2, allow_nan=False) + "\n", encoding="utf-8")
        os.replace(temporary, path)
    return report


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Train/evaluate standalone URL novelty detector")
    parser.add_argument("--dataset", type=Path, default=Path("data/raw/PhiUSIIL_Phishing_URL_Dataset.csv"))
    parser.add_argument("--output", type=Path, default=Path("outputs/phase-a-novelty"))
    parser.add_argument("--max-fpr", type=float, default=DEFAULT_MAX_FALSE_POSITIVE_RATE)
    args = parser.parse_args()
    print(json.dumps(train_and_evaluate_novelty(args.dataset, args.output, args.max_fpr), indent=2))


if __name__ == "__main__":
    main()
