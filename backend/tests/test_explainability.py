import numpy as np
import pandas as pd
import pytest
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from backend.src.explainability import ExplainabilityError, explain_logistic_regression
from backend.src.features import FEATURE_NAMES, extract_url_features


def fitted_pipeline():
    urls = [
        f"https://site{index}.example/path/{index}?item={index % 7}"
        for index in range(64)
    ]
    rows = [extract_url_features(url) for url in urls]
    frame = pd.DataFrame(rows, columns=FEATURE_NAMES)
    labels = pd.Series([int(index >= len(frame) // 2) for index in range(len(frame))])
    pipeline = Pipeline([
        ("scale", StandardScaler()),
        ("classifier", LogisticRegression(max_iter=1000, solver="liblinear", random_state=412)),
    ])
    pipeline.fit(frame, labels)
    return pipeline


@pytest.mark.parametrize("url", [
    "https://example.com",
    "http://shop.example.co.uk/sign-in?next=12",
    "https://203.0.113.10/a/../verify?x=%2F#step",
])
def test_all_feature_contributions_map_to_coefficients_and_reconstruct_logit(url):
    pipeline = fitted_pipeline()
    measured = extract_url_features(url)
    frame = pd.DataFrame([[measured[name] for name in FEATURE_NAMES]], columns=FEATURE_NAMES)

    explanation = explain_logistic_regression(pipeline, frame, "test-model-v1")
    scaler = pipeline.named_steps["scale"]
    classifier = pipeline.named_steps["classifier"]
    standardized = (frame.to_numpy(dtype=float)[0] - scaler.mean_) / scaler.scale_
    expected_contributions = standardized * classifier.coef_[0]

    assert [item.feature_name for item in explanation.feature_contributions] == list(FEATURE_NAMES)
    assert [item.measured_value for item in explanation.feature_contributions] == [
        measured[name] for name in FEATURE_NAMES
    ]
    np.testing.assert_allclose(
        [item.coefficient for item in explanation.feature_contributions], classifier.coef_[0]
    )
    np.testing.assert_allclose(
        [item.standardized_value for item in explanation.feature_contributions], standardized
    )
    np.testing.assert_allclose(
        [item.logit_contribution for item in explanation.feature_contributions], expected_contributions
    )
    assert explanation.intercept == classifier.intercept_[0]
    assert explanation.model_version == "test-model-v1"
    assert explanation.model_algorithm == "logistic_regression"
    assert explanation.positive_class == "phishing"
    assert explanation.reconstructed_logit == pytest.approx(
        explanation.intercept + sum(expected_contributions)
    )
    assert explanation.decision_function_logit == pytest.approx(
        pipeline.decision_function(frame)[0]
    )
    assert explanation.reconstruction_error < 1e-10
    for item, contribution in zip(explanation.feature_contributions, expected_contributions, strict=True):
        expected_direction = (
            "toward_phishing" if contribution > 0
            else "toward_legitimate" if contribution < 0
            else "neutral"
        )
        assert item.direction == expected_direction


def test_non_finite_and_malformed_feature_inputs_are_rejected():
    pipeline = fitted_pipeline()
    frame = pd.DataFrame(
        [[0.0] * len(FEATURE_NAMES)], columns=FEATURE_NAMES
    )
    frame.loc[0, "url_length"] = np.inf
    with pytest.raises(ExplainabilityError, match="finite"):
        explain_logistic_regression(pipeline, frame, "test-model-v1")

    short_frame = pd.DataFrame([[0.0] * (len(FEATURE_NAMES) - 1)], columns=FEATURE_NAMES[:-1])
    with pytest.raises(ExplainabilityError, match="exactly one row of 17"):
        explain_logistic_regression(pipeline, short_frame, "test-model-v1")

    reversed_frame = pd.DataFrame([[0.0] * len(FEATURE_NAMES)], columns=list(reversed(FEATURE_NAMES)))
    with pytest.raises(ExplainabilityError, match="names or order"):
        explain_logistic_regression(pipeline, reversed_frame, "test-model-v1")

    with pytest.raises(ExplainabilityError, match="model version"):
        explain_logistic_regression(pipeline, frame.assign(url_length=0), " ")


def test_non_logistic_or_unfitted_pipeline_is_rejected():
    with pytest.raises(ExplainabilityError, match="fitted scikit-learn Pipeline"):
        explain_logistic_regression(object(), pd.DataFrame([[0] * 17], columns=FEATURE_NAMES), "test-v1")

    pipeline = Pipeline([
        ("scale", StandardScaler()),
        ("classifier", LogisticRegression()),
    ])
    frame = pd.DataFrame([[0.0] * 17], columns=FEATURE_NAMES)
    with pytest.raises(ExplainabilityError, match="feature order is missing"):
        explain_logistic_regression(pipeline, frame, "test-v1")
