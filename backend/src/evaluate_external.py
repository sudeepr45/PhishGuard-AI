"""Read-only evaluation of frozen PhishGuard artifacts on an external URL CSV.

The evaluator uses only raw URL and label columns. It never fits, recalibrates,
or writes either model artifact.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support, roc_auc_score

from .api import URLRequest, load_model_artifact
from .features import FEATURE_NAMES, extract_url_features
from .novelty import anomaly_scores, load_novelty_artifact
from .training import (
    PHIUSIIL_LABELS,
    domain_group,
    grouped_splits,
    normalize_url,
    validate_url,
)

DEFAULT_EXTERNAL_CSV = Path("outputs/external-evaluation/input/URL-dataset.csv")
DEFAULT_TRAINING_CSV = Path("data/raw/PhiUSIIL_Phishing_URL_Dataset.csv")
DEFAULT_CLASSIFIER = Path("outputs/phase-a/url_model.joblib")
DEFAULT_NOVELTY = Path("outputs/phase-a-novelty/novelty_detector.joblib")
DEFAULT_OUTPUT = Path("outputs/external-evaluation/evaluation.json")
EXTERNAL_LABELS = {"phishing": 1, "legitimate": 0}


class ExternalEvaluationError(ValueError):
    """External data or frozen artifacts do not satisfy evaluation requirements."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_url(value: Any) -> str:
    """Use the same pydantic validator as runtime URL requests."""
    return URLRequest(url=value).url


def _training_url_sets(path: Path) -> tuple[set[str], set[str], set[str], set[str], dict[str, int]]:
    """Recreate load_dataset's retained URL order and obtain only train groups.

    The filtering and normalization rules intentionally mirror training.load_dataset;
    grouped_splits remains the source of the existing frozen train partition.
    """
    header = pd.read_csv(path, nrows=0).columns
    if not {"URL", "label"}.issubset(header):
        raise ExternalEvaluationError("training dataset is missing URL/label columns")
    frame = pd.read_csv(path, usecols=["URL", "label"], dtype={"URL": "string", "label": "string"})
    seen_exact: set[tuple[str, str]] = set()
    normalized_labels: dict[str, int] = {}
    label_sets: dict[str, set[int]] = {}
    row_counts: Counter[str] = Counter()
    ordered: list[str] = []
    for raw_url, raw_label in frame[["URL", "label"]].itertuples(index=False, name=None):
        if pd.isna(raw_label) or str(raw_label) not in PHIUSIIL_LABELS:
            continue
        url = str(raw_url).strip()
        if not validate_url(url):
            continue
        exact = (url, str(raw_label))
        if exact in seen_exact:
            continue
        seen_exact.add(exact)
        key = normalize_url(url)
        label = PHIUSIIL_LABELS[str(raw_label)]
        row_counts[key] += 1
        label_sets.setdefault(key, set()).add(label)
        if key not in normalized_labels:
            normalized_labels[key] = label
            ordered.append(key)
    conflicts = {key for key, values in label_sets.items() if len(values) > 1}
    retained = [key for key in ordered if key not in conflicts]
    labels = pd.Series([normalized_labels[key] for key in retained], dtype="int64")
    groups = [domain_group(key) for key in retained]
    train_indices, _, _ = grouped_splits(labels, groups)
    train_urls = {retained[index] for index in train_indices}
    train_domains = {groups[index] for index in train_indices}
    all_urls = set(retained)
    all_domains = set(groups)
    summary = {
        "retained_rows": len(retained),
        "train_rows": len(train_indices),
        "train_domains": len(train_domains),
        "conflicting_normalized_urls": len(conflicts),
    }
    return all_urls, all_domains, train_urls, train_domains, summary


def _prepare_external(path: Path) -> tuple[pd.DataFrame, pd.Series, dict[str, Any]]:
    header = pd.read_csv(path, nrows=0).columns
    if not {"url", "type"}.issubset(header):
        raise ExternalEvaluationError("external CSV must contain raw 'url' and 'type' columns")
    frame = pd.read_csv(path, usecols=["url", "type"], dtype={"url": "string", "type": "string"})
    audit: dict[str, Any] = {
        "source_rows": int(len(frame)),
        "missing_url_rows": int(frame["url"].isna().sum()),
        "missing_label_rows": int(frame["type"].isna().sum()),
        "invalid_label_values": sorted({str(v) for v in frame.loc[frame["type"].notna(), "type"] if str(v) not in EXTERNAL_LABELS}),
        "exact_duplicate_rows": int(frame.duplicated(subset=["url", "type"]).sum()),
    }
    invalid_labels = frame["type"].isna() | ~frame["type"].isin(EXTERNAL_LABELS)
    frame = frame.loc[~invalid_labels & frame["url"].notna()].copy()
    normalized: list[str | None] = []
    malformed = 0
    for raw_url in frame["url"]:
        try:
            normalized.append(_canonical_url(str(raw_url)))
        except (ValueError, UnicodeError):
            normalized.append(None)
            malformed += 1
    frame["normalized_url"] = normalized
    audit["malformed_url_rows"] = malformed
    frame = frame.loc[frame["normalized_url"].notna()].copy()
    frame["label"] = frame["type"].map(EXTERNAL_LABELS).astype("int64")
    label_sets = frame.groupby("normalized_url", sort=False)["label"].agg(lambda values: set(values))
    conflicts = {key for key, values in label_sets.items() if len(values) > 1}
    audit["normalized_url_conflict_keys"] = len(conflicts)
    audit["rows_in_conflicting_url_groups"] = int(frame["normalized_url"].isin(conflicts).sum())
    conflict_mask = frame["normalized_url"].isin(conflicts)
    non_conflicting_rows = int((~conflict_mask).sum())
    frame = frame.loc[~conflict_mask].drop_duplicates(subset=["normalized_url"], keep="first").copy()
    audit["same_label_normalized_duplicate_rows_excluded"] = non_conflicting_rows - frame["normalized_url"].nunique()
    audit["valid_unique_rows_before_overlap"] = int(len(frame))
    audit["class_counts_before_overlap"] = {
        "legitimate": int((frame["label"] == 0).sum()),
        "phishing": int((frame["label"] == 1).sum()),
    }
    values = [extract_url_features(value) for value in frame["normalized_url"]]
    features = pd.DataFrame(values, columns=FEATURE_NAMES, dtype="int64")
    labels = frame["label"].reset_index(drop=True)
    frame = frame.reset_index(drop=True)
    frame["domain"] = [domain_group(url) for url in frame["normalized_url"]]
    return features, labels, {"frame": frame, "audit": audit}


def _metrics(labels: np.ndarray, predicted: np.ndarray, scores: np.ndarray) -> dict[str, Any]:
    precision, recall, f1, _ = precision_recall_fscore_support(
        labels, predicted, labels=[1], average="binary", zero_division=0
    )
    matrix = confusion_matrix(labels, predicted, labels=[0, 1])
    tn, fp, fn, tp = (int(value) for value in matrix.ravel())
    return {
        "accuracy": float(accuracy_score(labels, predicted)),
        "precision_phishing": float(precision),
        "recall_phishing": float(recall),
        "f1_phishing": float(f1),
        "false_positive_rate_legitimate_as_phishing": float(fp / (fp + tn)) if fp + tn else None,
        "roc_auc": float(roc_auc_score(labels, scores)) if len(np.unique(labels)) == 2 else None,
        "confusion_matrix_labels": ["legitimate", "phishing"],
        "confusion_matrix": matrix.tolist(),
        "counts": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
    }


def evaluate_external(
    external_csv: Path = DEFAULT_EXTERNAL_CSV,
    training_csv: Path = DEFAULT_TRAINING_CSV,
    classifier_path: Path = DEFAULT_CLASSIFIER,
    novelty_path: Path = DEFAULT_NOVELTY,
    output_path: Path | None = DEFAULT_OUTPUT,
) -> dict[str, Any]:
    """Evaluate both frozen artifacts after excluding exact and domain overlaps."""
    model_hash_before = sha256_file(classifier_path)
    novelty_hash_before = sha256_file(novelty_path)
    classifier = load_model_artifact(classifier_path)
    novelty = load_novelty_artifact(novelty_path)
    if classifier["model_version"] != "url-classifier-3" or classifier["algorithm"] != "logistic_regression":
        raise ExternalEvaluationError("active classifier is not url-classifier-3 Logistic Regression")
    if classifier["feature_names"] != list(FEATURE_NAMES) or novelty["feature_names"] != list(FEATURE_NAMES):
        raise ExternalEvaluationError("artifact feature order does not match the canonical schema")
    all_train_urls, all_train_domains, fit_urls, fit_domains, train_summary = _training_url_sets(training_csv)
    features, labels, prepared = _prepare_external(external_csv)
    frame = prepared["frame"]
    normalized = set(frame["normalized_url"])
    domains = set(frame["domain"])
    exact_overlap = normalized & all_train_urls
    fit_exact_overlap = normalized & fit_urls
    overlapping_domains = domains & all_train_domains
    fit_overlapping_domains = domains & fit_domains
    domain_mask = frame["domain"].isin(overlapping_domains).to_numpy()
    exact_mask = frame["normalized_url"].isin(exact_overlap).to_numpy()
    keep = ~domain_mask
    prepared["audit"].update({
        "exact_normalized_url_overlaps_with_full_phiusiil_retained_set": len(exact_overlap),
        "exact_normalized_url_overlaps_with_classifier_fit_partition": len(fit_exact_overlap),
        "registrable_domains_overlapping_full_phiusiil_retained_set": len(overlapping_domains),
        "registrable_domains_overlapping_classifier_fit_partition": len(fit_overlapping_domains),
        "external_rows_on_overlapping_full_phiusiil_domains_excluded": int(domain_mask.sum()),
        "exact_overlap_rows_excluded": int(exact_mask.sum()),
        "remaining_rows_after_domain_exclusion": int(keep.sum()),
    })
    if len(np.unique(labels.to_numpy()[keep])) != 2:
        raise ExternalEvaluationError("both target classes must remain after overlap exclusion")
    X = features.loc[keep].reset_index(drop=True)
    y = labels.to_numpy()[keep]
    probability_matrix = np.asarray(classifier["model"].predict_proba(X), dtype=float)
    classes = list(classifier["model"].classes_)
    if classes != [0, 1] or probability_matrix.shape != (len(X), 2) or not np.isfinite(probability_matrix).all():
        raise ExternalEvaluationError("classifier outputs or class order are incompatible")
    phishing_probability = probability_matrix[:, classes.index(1)]
    threshold = float(classifier["decision_threshold"])
    predicted = (phishing_probability >= threshold).astype("int64")
    model_predict = np.asarray(classifier["model"].predict(X), dtype="int64")
    if not np.array_equal(predicted, model_predict):
        raise ExternalEvaluationError("artifact threshold does not reproduce the classifier prediction rule")
    anomaly = anomaly_scores(novelty["detector"], X)
    novelty_predicted = (anomaly >= float(novelty["threshold"])).astype("int64")
    report = {
        "evaluation_created_utc": datetime.now(timezone.utc).isoformat(),
        "independence_assessment": "evaluation rows and registrable domains are disjoint from the complete retained PhiUSIIL corpus; source feed lineage remains a limitation",
        "source_dataset": {
            "title": "Phishing URL dataset",
            "doi": "10.17632/vfszbj9b36.1",
            "version": 1,
            "source_page": "https://data.mendeley.com/datasets/vfszbj9b36/1",
            "download_url": "https://data.mendeley.com/public-files/datasets/vfszbj9b36/files/f0de314f-ea72-4385-9faa-f06593bb0a2d/file_downloaded",
            "retrieved_date": "2026-11-11",
            "file": external_csv.name,
            "sha256": sha256_file(external_csv),
            "license": "CC BY 4.0",
            "provenance": "Mendeley Data record by Jishnu K. S. Kaitholikkal and Arthi B (2024); record describes URLs sourced from PhishTank, Majestic Million, and other sources. Individual row-level source attribution is not supplied.",
            "columns_used": {"url": "url", "label": "type"},
            "label_mapping": {"phishing": 1, "legitimate": 0},
            "precomputed_features_used": False,
        },
        "training_reference": {
            "dataset": "local PhiUSIIL source; existing grouped split reproduced without fitting",
            "training_partition": train_summary,
            "overlap_policy": "exclude every external record whose canonical registrable domain occurs anywhere in the retained PhiUSIIL corpus; separately count URL/domain overlap with the classifier fit partition",
        },
        "data_audit": prepared["audit"],
        "evaluation_set": {
            "rows": int(len(y)),
            "legitimate": int((y == 0).sum()),
            "phishing": int((y == 1).sum()),
        },
        "frozen_classifier": {
            "model_version": classifier["model_version"],
            "algorithm": "Logistic Regression",
            "artifact_sha256": model_hash_before,
            "threshold": threshold,
            "metrics": _metrics(y, predicted, phishing_probability),
        },
        "frozen_novelty_detector": {
            "detector_version": novelty["detector_version"],
            "algorithm": "Isolation Forest",
            "artifact_sha256": novelty_hash_before,
            "threshold": float(novelty["threshold"]),
            "score_definition": "-IsolationForest.score_samples; higher values are more unusual; frozen artifact threshold, unusual => positive phishing-alert proxy",
            "metrics": _metrics(y, novelty_predicted, anomaly),
        },
        "limitations": [
            "This corpus is a separate Mendeley record and records PhishTank/Majestic Million among its sources, but row-level lineage is unavailable; source overlap beyond exact URLs and registrable domains cannot be ruled out.",
            "Domain overlap exclusion is conservative and changes the target population; resulting metrics apply only to retained domains.",
            "Dataset labels are not independently re-verified at evaluation time; labels may be stale, disputed, or represent historical status.",
            "This is URL-string-only evaluation. The external corpus and PhiUSIIL original held-out test metrics are distinct experiments and are not pooled.",
            "Novelty detection identifies deviation from the legitimate training distribution; its phishing-class metrics are an external proxy assessment, not a phishing classifier claim.",
        ],
    }
    model_hash_after = sha256_file(classifier_path)
    novelty_hash_after = sha256_file(novelty_path)
    if model_hash_after != model_hash_before or novelty_hash_after != novelty_hash_before:
        raise ExternalEvaluationError("a frozen model artifact changed during evaluation")
    report["artifact_integrity"] = {
        "classifier_sha256_before": model_hash_before,
        "classifier_sha256_after": model_hash_after,
        "novelty_sha256_before": novelty_hash_before,
        "novelty_sha256_after": novelty_hash_after,
        "unchanged": True,
    }
    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--external", type=Path, default=DEFAULT_EXTERNAL_CSV)
    parser.add_argument("--training", type=Path, default=DEFAULT_TRAINING_CSV)
    parser.add_argument("--classifier", type=Path, default=DEFAULT_CLASSIFIER)
    parser.add_argument("--novelty", type=Path, default=DEFAULT_NOVELTY)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    print(json.dumps(evaluate_external(args.external, args.training, args.classifier, args.novelty, args.output), indent=2))


if __name__ == "__main__":
    main()
