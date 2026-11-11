"""Exact additive logit contributions for the active Logistic Regression model."""

from __future__ import annotations

import math
from typing import Literal

import numpy as np
import pandas as pd
from pydantic import BaseModel, ConfigDict, Field
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

from .features import FEATURE_NAMES


class ExplainabilityError(ValueError):
    """The fitted model or feature input cannot be explained safely."""


class FeatureContribution(BaseModel):
    model_config = ConfigDict(extra="forbid")

    feature_name: str
    measured_value: float
    standardized_value: float
    coefficient: float
    logit_contribution: float
    direction: Literal["toward_phishing", "toward_legitimate", "neutral"]


class LogisticRegressionExplanation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    model_version: str
    model_algorithm: Literal["logistic_regression"]
    positive_class: Literal["phishing"]
    intercept: float
    reconstructed_logit: float
    decision_function_logit: float
    reconstruction_error: float
    feature_contributions: list[FeatureContribution]
    interpretation: str


def explain_logistic_regression(
    pipeline: Pipeline,
    feature_input: pd.DataFrame,
    model_version: str,
) -> LogisticRegressionExplanation:
    """Explain one row and verify additive terms reproduce the fitted pipeline logit.

    `feature_input` must be the exact, ordered DataFrame passed to inference. The
    returned contributions are in logit space and are not causal attributions.
    """
    if not isinstance(pipeline, Pipeline):
        raise ExplainabilityError("model must be a fitted scikit-learn Pipeline")
    if not isinstance(feature_input, pd.DataFrame):
        raise ExplainabilityError("features must be supplied as a pandas DataFrame")
    if feature_input.shape != (1, len(FEATURE_NAMES)):
        raise ExplainabilityError("explanation requires exactly one row of 17 features")
    if list(feature_input.columns) != list(FEATURE_NAMES):
        raise ExplainabilityError("feature names or order do not match the active model schema")
    if not isinstance(model_version, str) or not model_version.strip():
        raise ExplainabilityError("model version is required for a persisted explanation")

    if not {"scale", "classifier"}.issubset(pipeline.named_steps):
        raise ExplainabilityError("pipeline must contain scale and classifier steps")
    scaler = pipeline.named_steps["scale"]
    classifier = pipeline.named_steps["classifier"]
    if not isinstance(classifier, LogisticRegression):
        raise ExplainabilityError("classifier must be Logistic Regression")

    pipeline_names = getattr(pipeline, "feature_names_in_", None)
    scaler_names = getattr(scaler, "feature_names_in_", None)
    if pipeline_names is None or list(pipeline_names) != list(FEATURE_NAMES):
        raise ExplainabilityError("fitted pipeline feature order is missing or incompatible")
    if scaler_names is None or list(scaler_names) != list(FEATURE_NAMES):
        raise ExplainabilityError("fitted scaler feature order is missing or incompatible")

    means = getattr(scaler, "mean_", None)
    scales = getattr(scaler, "scale_", None)
    coefficients = getattr(classifier, "coef_", None)
    intercepts = getattr(classifier, "intercept_", None)
    classes = getattr(classifier, "classes_", None)
    expected_width = len(FEATURE_NAMES)
    if means is None or np.shape(means) != (expected_width,):
        raise ExplainabilityError("scaler means do not match the 17-feature schema")
    if scales is None or np.shape(scales) != (expected_width,):
        raise ExplainabilityError("scaler scales do not match the 17-feature schema")
    if coefficients is None or np.shape(coefficients) != (1, expected_width):
        raise ExplainabilityError("classifier coefficients do not match the binary 17-feature schema")
    if intercepts is None or np.shape(intercepts) != (1,):
        raise ExplainabilityError("classifier intercept does not match the binary model")
    if classes is None or list(classes) != [0, 1]:
        raise ExplainabilityError("classifier class order must be [0, 1] with phishing as class 1")

    values = feature_input.to_numpy(dtype=float, copy=True)[0]
    means = np.asarray(means, dtype=float)
    scales = np.asarray(scales, dtype=float)
    coefficients = np.asarray(coefficients, dtype=float)[0]
    intercept = float(np.asarray(intercepts, dtype=float)[0])
    if not all(np.isfinite(array).all() for array in (values, means, scales, coefficients)):
        raise ExplainabilityError("features, scaler values, and coefficients must be finite")
    if not math.isfinite(intercept) or (scales <= 0).any():
        raise ExplainabilityError("model intercept and scaler scales must be finite and valid")

    standardized = (values - means) / scales
    contributions = standardized * coefficients
    reconstructed_logit = float(intercept + contributions.sum())
    decision_function_logit = float(np.asarray(pipeline.decision_function(feature_input)).reshape(-1)[0])
    if not math.isfinite(reconstructed_logit) or not math.isfinite(decision_function_logit):
        raise ExplainabilityError("calculated model logits must be finite")
    reconstruction_error = abs(reconstructed_logit - decision_function_logit)
    if not math.isclose(reconstructed_logit, decision_function_logit, rel_tol=1e-12, abs_tol=1e-10):
        raise ExplainabilityError("feature contributions do not reconstruct the pipeline decision_function")

    explanations = []
    for name, measured, standardized_value, coefficient, contribution in zip(
        FEATURE_NAMES, values, standardized, coefficients, contributions, strict=True
    ):
        direction: Literal["toward_phishing", "toward_legitimate", "neutral"]
        if contribution > 0:
            direction = "toward_phishing"
        elif contribution < 0:
            direction = "toward_legitimate"
        else:
            direction = "neutral"
        explanations.append(FeatureContribution(
            feature_name=name,
            measured_value=float(measured),
            standardized_value=float(standardized_value),
            coefficient=float(coefficient),
            logit_contribution=float(contribution),
            direction=direction,
        ))

    return LogisticRegressionExplanation(
        model_version=model_version,
        model_algorithm="logistic_regression",
        positive_class="phishing",
        intercept=intercept,
        reconstructed_logit=reconstructed_logit,
        decision_function_logit=decision_function_logit,
        reconstruction_error=reconstruction_error,
        feature_contributions=explanations,
        interpretation=(
            "These are additive mathematical contributions to this Logistic Regression logit. "
            "Positive values move the logit toward phishing; negative values move it toward legitimate. "
            "They describe model behavior, not causal effects or proof that a URL is malicious."
        ),
    )
