"""Dataset validation, leakage-resistant splitting, model training, evaluation."""

from __future__ import annotations

import hashlib
import json
import os
import platform
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from urllib.parse import urlsplit, urlunsplit

import joblib
import pandas as pd
import sklearn
import tldextract
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    precision_recall_fscore_support,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from .features import FEATURE_NAMES, extract_url_features

SEED = 412
MODEL_VERSION = "url-classifier-3"
PHIUSIIL_LABELS = {"0": 1, "1": 0}  # source: 0=phishing, 1=legitimate
EXPECTED_COLUMNS = {"URL", "label"}
RANDOM_FOREST_CONFIG = {
    "n_estimators": 100,
    "max_depth": 24,
    "min_samples_leaf": 2,
    "class_weight": "balanced",
    "random_state": SEED,
    "n_jobs": -1,
}
DECISION_THRESHOLD = 0.5
SELECTION_RULE = (
    "Select Random Forest only if validation precision, recall, F1, and false-positive "
    "rate are all no worse than Logistic Regression, and recall or F1 improves by "
    "at least 0.005; otherwise retain Logistic Regression. Accuracy is reported but "
    "is not used for selection."
)
_SUFFIX_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())


class DataValidationError(ValueError):
    """Raised when source records cannot safely support the planned run."""


@dataclass(frozen=True)
class DataAudit:
    source_rows: int
    invalid_url_rows_dropped: int
    invalid_label_rows_dropped: int
    invalid_label_values: tuple[str, ...]
    exact_duplicate_rows_dropped: int
    normalized_duplicate_rows_dropped: int
    normalized_duplicate_label_conflicts: int
    conflicting_label_rows_dropped: int
    retained_rows: int
    retained_phishing: int
    retained_legitimate: int
    unique_domain_groups: int
    mixed_label_domain_groups: int


def validate_url(url: str) -> bool:
    if not isinstance(url, str) or not url or len(url) > 100_000:
        return False
    if any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in url):
        return False
    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        if parsed.scheme.lower() not in {"http", "https"} or not hostname:
            return False
        _ = parsed.port
        try:
            import ipaddress

            ipaddress.ip_address(hostname)
        except ValueError:
            hostname.encode("idna")
        return True
    except (ValueError, UnicodeError):
        return False


def normalize_url(url: str) -> str:
    """Normalize only scheme/host casing, IDNA, default ports, and empty path."""
    parsed = urlsplit(url)
    if not validate_url(url):
        raise ValueError("cannot normalize an invalid HTTP(S) URL")
    host = parsed.hostname or ""
    try:
        host = host.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError:
        host = host.lower()
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    try:
        port = parsed.port
    except ValueError:
        raise ValueError("invalid port") from None
    if port is not None and not (
        (parsed.scheme.lower() == "http" and port == 80)
        or (parsed.scheme.lower() == "https" and port == 443)
    ):
        host = f"{host}:{port}"
    userinfo = ""
    if parsed.username is not None:
        userinfo = parsed.netloc.rsplit("@", 1)[0] + "@"
    return urlunsplit((parsed.scheme.lower(), userinfo + host, parsed.path or "/", parsed.query, parsed.fragment))


def domain_group(url: str) -> str:
    host = urlsplit(url).hostname or ""
    try:
        host = host.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError:
        host = host.lower()
    try:
        import ipaddress

        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    extracted = _SUFFIX_EXTRACTOR(host)
    return extracted.top_domain_under_public_suffix or host


def load_dataset(path: Path) -> tuple[pd.DataFrame, pd.Series, list[str], DataAudit]:
    """Load only raw URL and source label; never consume precomputed features."""
    header = pd.read_csv(path, nrows=0).columns
    missing = EXPECTED_COLUMNS.difference(header)
    if missing:
        raise DataValidationError(f"dataset missing required columns: {sorted(missing)}")
    frame = pd.read_csv(path, usecols=["URL", "label"], dtype={"URL": "string", "label": "string"})
    source_rows = len(frame)
    invalid_label_mask = frame["label"].isna() | ~frame["label"].isin(PHIUSIIL_LABELS)
    invalid_label_values = tuple(sorted({
        "<missing>" if pd.isna(value) else str(value)
        for value in frame.loc[invalid_label_mask, "label"]
    }))
    invalid_label_rows = int(invalid_label_mask.sum())
    frame = frame.loc[~invalid_label_mask]

    exact_seen: set[tuple[str, str]] = set()
    normalized_labels: dict[str, int] = {}
    normalized_row_counts: Counter[str] = Counter()
    normalized_row_labels: dict[str, set[int]] = {}
    kept_urls: list[str] = []
    kept_labels: list[int] = []
    kept_keys: list[str] = []
    exact_dupes = normalized_dupes = invalid_urls = 0
    for raw_url, source_label in frame[["URL", "label"]].itertuples(index=False, name=None):
        url = str(raw_url).strip()
        if not validate_url(url):
            invalid_urls += 1
            continue
        phishing_label = PHIUSIIL_LABELS[str(source_label)]
        exact_key = (url, str(source_label))
        if exact_key in exact_seen:
            exact_dupes += 1
            continue
        exact_seen.add(exact_key)
        key = normalize_url(url)
        normalized_row_counts[key] += 1
        normalized_row_labels.setdefault(key, set()).add(phishing_label)
        if key in normalized_labels:
            if normalized_labels[key] == phishing_label:
                normalized_dupes += 1
            continue
        normalized_labels[key] = phishing_label
        kept_urls.append(url)
        kept_labels.append(phishing_label)
        kept_keys.append(key)
    conflicting_keys = {key for key, values in normalized_row_labels.items() if len(values) > 1}
    label_conflicts = len(conflicting_keys)
    conflicting_rows = sum(normalized_row_counts[key] for key in conflicting_keys)
    retained = [(url, label, key) for url, label, key in zip(kept_urls, kept_labels, kept_keys) if key not in conflicting_keys]
    kept_urls = [url for url, _label, _key in retained]
    kept_labels = [label for _url, label, _key in retained]
    kept_keys = [key for _url, _label, key in retained]
    # No first-seen label is allowed to decide a conflicting target.
    if not kept_urls or set(kept_labels) != {0, 1}:
        raise DataValidationError("both phishing and legitimate examples are required after validation")

    # `kept_keys` are produced by the same normalize_url function used by the
    # API after request validation. Keep `kept_urls` as the trimmed source
    # values for traceability and existing domain grouping, but train from the
    # canonical representation served to inference.
    features = pd.DataFrame(
        [extract_url_features(url) for url in kept_keys], columns=FEATURE_NAMES
    )
    labels = pd.Series(kept_labels, name="is_phishing", dtype="int8")
    groups = [domain_group(url) for url in kept_urls]
    counts = Counter(kept_labels)
    labels_per_domain: dict[str, set[int]] = {}
    for group, label in zip(groups, kept_labels):
        labels_per_domain.setdefault(group, set()).add(label)
    audit = DataAudit(
        source_rows=source_rows,
        invalid_url_rows_dropped=invalid_urls,
        invalid_label_rows_dropped=invalid_label_rows,
        invalid_label_values=invalid_label_values,
        exact_duplicate_rows_dropped=exact_dupes,
        normalized_duplicate_rows_dropped=normalized_dupes,
        normalized_duplicate_label_conflicts=label_conflicts,
        conflicting_label_rows_dropped=conflicting_rows,
        retained_rows=len(kept_urls),
        retained_phishing=counts[1],
        retained_legitimate=counts[0],
        unique_domain_groups=len(set(groups)),
        mixed_label_domain_groups=sum(len(domain_labels) > 1 for domain_labels in labels_per_domain.values()),
    )
    return features, labels, groups, audit


def _best_group_split(indices: list[int], labels: pd.Series, groups: list[str], target_fraction: float) -> tuple[list[int], list[int]]:
    """Choose among eight fixed grouped shuffles by size and class rate only."""
    global_phishing_rate = float(labels.mean())
    best: tuple[float, list[int], list[int]] | None = None
    splitter = GroupShuffleSplit(n_splits=8, test_size=target_fraction, random_state=SEED)
    for rest_local, held_local in splitter.split(indices, labels, groups):
        rest = [indices[i] for i in rest_local]
        held = [indices[i] for i in held_local]
        size_fraction = len(held) / len(indices)
        phishing_rate = float(labels.iloc[held].mean())
        score = abs(size_fraction - target_fraction) + abs(phishing_rate - global_phishing_rate)
        if best is None or score < best[0]:
            best = (score, rest, held)
    assert best is not None
    return best[1], best[2]


def grouped_splits(labels: pd.Series, groups: list[str]) -> tuple[list[int], list[int], list[int]]:
    """Create approx. 60/20/20 splits with disjoint registrable domains."""
    indices = list(range(len(labels)))
    development_idx, test_idx = _best_group_split(indices, labels, groups, target_fraction=0.20)
    validation_local = list(range(len(development_idx)))
    dev_labels = labels.iloc[development_idx].reset_index(drop=True)
    dev_groups = [groups[i] for i in development_idx]
    train_local, validation_local = _best_group_split(validation_local, dev_labels, dev_groups, target_fraction=0.25)
    train_idx = [development_idx[i] for i in train_local]
    validation_idx = [development_idx[i] for i in validation_local]
    sets = [set(groups[i] for i in part) for part in (train_idx, validation_idx, test_idx)]
    if sets[0] & sets[1] or sets[0] & sets[2] or sets[1] & sets[2]:
        raise DataValidationError("domain leakage detected across grouped splits")
    for name, part in zip(("train", "validation", "test"), (train_idx, validation_idx, test_idx)):
        if set(labels.iloc[part]) != {0, 1}:
            raise DataValidationError(f"grouped {name} split does not contain both classes")
    return train_idx, validation_idx, test_idx


def _metrics(y_true: pd.Series, predictions, probabilities) -> dict:
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true, predictions, labels=[1], average="binary", zero_division=0
    )
    matrix = confusion_matrix(y_true, predictions, labels=[0, 1])
    tn, fp, fn, tp = (int(value) for value in matrix.ravel())
    result = {
        "accuracy": float(accuracy_score(y_true, predictions)),
        "precision_phishing": float(precision),
        "recall_phishing": float(recall),
        "f1_phishing": float(f1),
        "confusion_matrix_labels": ["legitimate", "phishing"],
        "confusion_matrix": matrix.tolist(),
        "false_positive_rate_legitimate_as_phishing": fp / (fp + tn) if fp + tn else 0.0,
        "counts": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
    }
    result["roc_auc"] = float(roc_auc_score(y_true, probabilities)) if probabilities is not None else None
    return result


def build_model_candidates() -> dict[str, Pipeline]:
    """Create fixed baseline/challenger pipelines with train-only scaling."""
    return {
        "logistic_regression": Pipeline([
            ("scale", StandardScaler()),
            ("classifier", LogisticRegression(
                max_iter=2000, class_weight="balanced", random_state=SEED, solver="liblinear"
            )),
        ]),
        "random_forest": Pipeline([
            ("scale", StandardScaler()),
            ("classifier", RandomForestClassifier(**RANDOM_FOREST_CONFIG)),
        ]),
    }


def fit_model_candidates(
    features: pd.DataFrame, labels: pd.Series, train_indices: list[int]
) -> tuple[dict[str, Pipeline], dict[str, float]]:
    """Fit both candidates on training indices only and report fit duration."""
    models = build_model_candidates()
    durations: dict[str, float] = {}
    train_features = features.iloc[train_indices]
    train_labels = labels.iloc[train_indices]
    for name, model in models.items():
        started = perf_counter()
        model.fit(train_features, train_labels)
        durations[name] = perf_counter() - started
    return models, durations


def _measure_model(model: Pipeline, features: pd.DataFrame, labels: pd.Series) -> dict:
    """Measure predictions and metrics on one partition, after a small warm-up."""
    warmup = features.iloc[:min(32, len(features))]
    model.predict(warmup)
    started = perf_counter()
    predictions = model.predict(features)
    inference_seconds = perf_counter() - started
    one_url = features.iloc[:1]
    single_started = perf_counter()
    for _ in range(100):
        model.predict(one_url)
    single_url_ms = (perf_counter() - single_started) * 10
    probabilities = model.predict_proba(features)[:, 1] if hasattr(model, "predict_proba") else None
    result = _metrics(labels, predictions, probabilities)
    result["inference_time_seconds"] = inference_seconds
    result["inference_time_ms_per_url"] = inference_seconds * 1000 / len(features)
    result["single_url_inference_time_ms"] = single_url_ms
    result["inference_time_method"] = (
        "predict only, after warm-up; batch metrics use the full partition, "
        "single_url_inference_time_ms is the mean of 100 single-row predictions"
    )
    return result


def _random_forest_improves(baseline: dict, challenger: dict) -> bool:
    """Apply the predeclared validation-only non-inferiority selection rule."""
    noninferior = (
        challenger["precision_phishing"] >= baseline["precision_phishing"]
        and challenger["recall_phishing"] >= baseline["recall_phishing"]
        and challenger["f1_phishing"] >= baseline["f1_phishing"]
        and challenger["false_positive_rate_legitimate_as_phishing"]
        <= baseline["false_positive_rate_legitimate_as_phishing"]
    )
    meaningful_gain = (
        challenger["recall_phishing"] >= baseline["recall_phishing"] + 0.005
        or challenger["f1_phishing"] >= baseline["f1_phishing"] + 0.005
    )
    return noninferior and meaningful_gain


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def train_and_evaluate(dataset_path: Path, output_dir: Path) -> dict:
    features, labels, groups, audit = load_dataset(dataset_path)
    train_idx, validation_idx, test_idx = grouped_splits(labels, groups)
    models, training_times = fit_model_candidates(features, labels, train_idx)
    majority = DummyClassifier(strategy="most_frequent")
    started = perf_counter()
    majority.fit(features.iloc[train_idx], labels.iloc[train_idx])
    training_times["majority_baseline"] = perf_counter() - started
    validation = {
        name: _measure_model(model, features.iloc[validation_idx], labels.iloc[validation_idx])
        for name, model in models.items()
    }
    validation["majority_baseline"] = _measure_model(
        majority, features.iloc[validation_idx], labels.iloc[validation_idx]
    )
    selected = "random_forest" if _random_forest_improves(
        validation["logistic_regression"], validation["random_forest"]
    ) else "logistic_regression"
    selected_model = models[selected]

    # The held-out test set is scored only after validation-based selection.
    final_test = _measure_model(
        selected_model, features.iloc[test_idx], labels.iloc[test_idx]
    )
    label_mapping = {
        "model_0": "legitimate", "model_1": "phishing",
        "source_label_0": "phishing", "source_label_1": "legitimate",
    }
    training_config = {
        "logistic_regression": {
            "classifier": "LogisticRegression", "solver": "liblinear",
            "class_weight": "balanced", "max_iter": 2000,
            "random_state": SEED, "scaler": "StandardScaler",
        },
        "random_forest": {
            "classifier": "RandomForestClassifier", **RANDOM_FOREST_CONFIG,
            "scaler": "StandardScaler (fit on training partition only)",
        },
        "majority_baseline": {"classifier": "DummyClassifier", "strategy": "most_frequent"},
        "grouping": "registrable domain using bundled Public Suffix List",
        "split": "best size and phishing-prevalence balance of 8 fixed GroupShuffleSplit partitions; approximate 60/20/20",
        "split_seed": SEED,
        "test_split_labels_used_only_for_prevalence_balance": True,
        "final_test_used_for_model_selection": False,
    }
    timestamp = datetime.now(timezone.utc).isoformat()
    sha256 = _sha256(dataset_path)
    split_class_counts = {
        name: {
            "legitimate": int((labels.iloc[indexes] == 0).sum()),
            "phishing": int((labels.iloc[indexes] == 1).sum()),
        }
        for name, indexes in (("train", train_idx), ("validation", validation_idx), ("test", test_idx))
    }
    evaluation = {
        "model_version": MODEL_VERSION,
        "selected_algorithm": selected,
        "selection_rule": SELECTION_RULE,
        "training_date_utc": timestamp,
        "dataset": "PhiUSIIL Phishing URL Dataset, UCI ID 967",
        "dataset_sha256": sha256,
        "seed": SEED,
        "label_mapping": label_mapping,
        "feature_names": list(FEATURE_NAMES),
        "decision_threshold": DECISION_THRESHOLD,
        "audit": asdict(audit),
        "split_rows": {"train": len(train_idx), "validation": len(validation_idx), "test": len(test_idx)},
        "split_class_counts": split_class_counts,
        "domain_overlap_verified": True,
        "validation": {
            name: {"training_time_seconds": training_times[name], **validation[name]}
            for name in (*models, "majority_baseline")
        },
        "selected_model": {
            "algorithm": selected,
            "validation": validation[selected],
            "final_test": final_test,
        },
        "scope_note": "Random registrable-domain grouped snapshot performance does not establish future real-world performance.",
        "training_config": training_config,
        "versions": {
            "python": platform.python_version(), "scikit_learn": sklearn.__version__,
            "pandas": pd.__version__, "tldextract": tldextract.__version__,
        },
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    artifact_path = output_dir / "url_model.joblib"
    artifact = {
        "model": selected_model,
        "model_version": MODEL_VERSION,
        "algorithm": selected,
        "feature_names": list(FEATURE_NAMES),
        "training_config": training_config[selected],
        "training_date_utc": timestamp,
        "dataset_sha256": sha256,
        "decision_threshold": DECISION_THRESHOLD,
        "validation_metrics": validation[selected],
        "final_test_metrics": final_test,
        "scikit_learn_version": sklearn.__version__,
        "tldextract_version": tldextract.__version__,
        "python_version": platform.python_version(),
        "label_mapping": label_mapping,
        "model_scope": "URL-string lexical features trained on the UCI PhiUSIIL snapshot; no page fetch or reputation lookup.",
    }
    temp_path = artifact_path.with_suffix(".joblib.tmp")
    joblib.dump(artifact, temp_path)
    os.replace(temp_path, artifact_path)
    result_path = output_dir / "evaluation.json"
    temp_result = result_path.with_suffix(".json.tmp")
    temp_result.write_text(json.dumps(evaluation, indent=2) + "\n", encoding="utf-8")
    os.replace(temp_result, result_path)
    test_result = {
        "model_version": MODEL_VERSION,
        "selected_algorithm": selected,
        "dataset_sha256": sha256,
        "training_date_utc": timestamp,
        "final_test_rows": len(test_idx),
        "audit": asdict(audit),
        "metrics": final_test,
        "confusion_matrix_labels": final_test["confusion_matrix_labels"],
        "test_split_labels_used_only_for_prevalence_balance": True,
        "final_test_used_for_model_selection": False,
        "scope_note": evaluation["scope_note"],
    }
    test_path = output_dir / "final_test_evaluation.json"
    temp_test = test_path.with_suffix(".json.tmp")
    temp_test.write_text(json.dumps(test_result, indent=2) + "\n", encoding="utf-8")
    os.replace(temp_test, test_path)
    return evaluation


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Train and evaluate the Phase A URL baseline")
    parser.add_argument("--dataset", type=Path, default=Path("data/raw/PhiUSIIL_Phishing_URL_Dataset.csv"))
    parser.add_argument("--output", type=Path, default=Path("outputs/phase-a"))
    args = parser.parse_args()
    result = train_and_evaluate(args.dataset, args.output)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
