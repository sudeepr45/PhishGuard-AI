"""Re-evaluate the saved model on the deterministic held-out URL test split."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from datetime import datetime, timezone

from .api import load_model_artifact
from .training import _measure_model, _sha256, grouped_splits, load_dataset


def evaluate_saved_model(dataset_path: Path, output_dir: Path) -> dict:
    artifact = load_model_artifact(output_dir / "url_model.joblib")
    dataset_hash = _sha256(dataset_path)
    if artifact["dataset_sha256"] != dataset_hash:
        raise ValueError("dataset checksum does not match the training artifact")
    features, labels, groups, audit = load_dataset(dataset_path)
    _train_idx, _validation_idx, test_idx = grouped_splits(labels, groups)
    test_metrics = _measure_model(
        artifact["model"], features.iloc[test_idx], labels.iloc[test_idx]
    )
    result = {
        "model_version": artifact["model_version"],
        "selected_algorithm": artifact.get("algorithm", "logistic_regression"),
        "dataset_sha256": dataset_hash,
        "training_date_utc": artifact.get("training_date_utc"),
        "evaluation_date_utc": datetime.now(timezone.utc).isoformat(),
        "final_test_rows": len(test_idx),
        "audit": audit.__dict__,
        "metrics": test_metrics,
        "confusion_matrix_labels": test_metrics["confusion_matrix_labels"],
        "decision_threshold": artifact.get("decision_threshold", 0.5),
        "scope_note": "Random grouped split performance does not establish future real-world performance.",
        "final_test_used_for_selection": False,
    }
    result_path = output_dir / "final_test_evaluation.json"
    temp_path = result_path.with_suffix(".json.tmp")
    temp_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    os.replace(temp_path, result_path)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=Path("data/raw/PhiUSIIL_Phishing_URL_Dataset.csv"))
    parser.add_argument("--output", type=Path, default=Path("outputs/phase-a"))
    args = parser.parse_args()
    print(json.dumps(evaluate_saved_model(args.dataset, args.output), indent=2))


if __name__ == "__main__":
    main()
