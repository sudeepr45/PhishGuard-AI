"""Local-only HTTP API for URL classification and offline email link triage."""

from __future__ import annotations

import logging
import math
import os
import platform
import re
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Any, AsyncIterator
from urllib.parse import urlsplit

import joblib
import pandas as pd
import sklearn
import tldextract
import uvicorn
from fastapi import FastAPI, Path as APIPath, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, StrictStr, field_validator

from .features import FEATURE_NAMES, extract_url_features
from .explainability import LogisticRegressionExplanation, explain_logistic_regression
from .email_analysis import EmailInputError, MAX_EMAIL_BYTES, parse_email
from .history_store import HistoryDatabaseError, HistoryStore
from .novelty import NoveltyArtifactError, load_novelty_artifact, score_novelty, validate_novelty_artifact
from .training import MODEL_VERSION, normalize_url, validate_url

logger = logging.getLogger(__name__)
MAX_REQUEST_BYTES = 16_384
MAX_EMAIL_REQUEST_BYTES = MAX_EMAIL_BYTES + 8_192
MAX_URL_CHARACTERS = 8_192
DEFAULT_MODEL_PATH = Path("outputs/phase-a/url_model.joblib")
DEFAULT_NOVELTY_PATH = Path("outputs/phase-a-novelty/novelty_detector.joblib")
MODEL_SCOPE = (
    "URL-string lexical features trained on the UCI PhiUSIIL snapshot; no page fetch, "
    "reputation lookup, or claim about current website behavior."
)
API_DESCRIPTION = """Classify HTTP(S) URL text alone using the selected Phase 1 model and retain completed URL analyses in a local SQLite history. Pasted email triage parses headers and screens supported links offline; email content and links are transient and are not saved.

This is research classification. The service does not inspect webpage content, verify current website reputation,
fetch the submitted destination, or guarantee a website is safe. It does not replace browser security or professional
security tools. Scores are uncalibrated estimated model scores, not real-world probabilities or certainty.
No analysis history is transmitted to an external service.
Email Authentication-Results values are unverified header text; no SPF, DKIM, or DMARC verification is performed.
"""


def _public_demo_enabled() -> bool:
    return os.getenv("PHISHGUARD_PUBLIC_DEMO", "").strip().lower() == "true"


def _configured_cors_origins() -> list[str]:
    raw_origins = os.getenv("PHISHGUARD_CORS_ORIGINS", "")
    origins = [origin.strip() for origin in raw_origins.split(",") if origin.strip()]
    for origin in origins:
        parsed = urlsplit(origin)
        if (
            "*" in origin
            or parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.path
            or parsed.query
            or parsed.fragment
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise ValueError("PHISHGUARD_CORS_ORIGINS must contain exact HTTP(S) origins without paths or wildcards")
        try:
            _ = parsed.port
        except ValueError:
            raise ValueError("PHISHGUARD_CORS_ORIGINS contains an invalid port") from None
    return origins


class ModelArtifactError(RuntimeError):
    """The selected model artifact cannot safely serve inference."""


class ErrorResponse(BaseModel):
    detail: str


class URLRequest(BaseModel):
    """Only a URL is accepted. Scheme-less host input is treated as HTTPS."""

    model_config = ConfigDict(extra="forbid")
    url: Annotated[
        StrictStr,
        Field(
            min_length=1,
            max_length=MAX_URL_CHARACTERS,
            description="HTTP(S) URL. A URL submitted without a scheme is normalized to HTTPS.",
            examples=["https://example.com/login"],
        ),
    ]

    @field_validator("url")
    @classmethod
    def normalize_and_validate_url(cls, value: str) -> str:
        candidate = value.strip()
        if not candidate:
            raise ValueError("URL cannot be empty")
        if any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in candidate):
            raise ValueError("URL contains whitespace or control characters")
        parsed = urlsplit(candidate)
        if parsed.scheme.lower() in {"http", "https"}:
            if "://" not in candidate:
                raise ValueError("URL scheme must include //")
        elif parsed.scheme:
            # urlsplit interprets host:port as a scheme when no scheme is present.
            host_port = re.match(r"^[^:/?#]+:\d+(?:[/?#]|$)", candidate)
            if "://" in candidate or host_port is None:
                raise ValueError("Only HTTP and HTTPS URLs are supported")
            candidate = f"https://{candidate}"
        else:
            candidate = f"https://{candidate}"
        if len(candidate) > MAX_URL_CHARACTERS or not validate_url(candidate):
            raise ValueError("URL must be a valid HTTP or HTTPS URL with a hostname")
        try:
            return normalize_url(candidate)
        except ValueError as exc:
            raise ValueError("URL must be a valid HTTP or HTTPS URL with a hostname") from exc


class EmailRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    raw_email: Annotated[StrictStr, Field(min_length=1, max_length=MAX_EMAIL_BYTES)]


class NoveltyDetection(BaseModel):
    available: bool
    is_unusual: bool | None
    anomaly_score: float | None
    threshold: float | None
    detector_version: str | None
    detector: str | None
    interpretation: str


class EmailLinkResult(BaseModel):
    normalized_url: str
    sources: list[str]
    prediction: str
    model_version: str
    model_algorithm: str
    phishing_score: float
    legitimate_score: float
    decision_threshold: float
    measured_features: MeasuredFeatures
    explanation: LogisticRegressionExplanation | None
    novelty_detection: NoveltyDetection


class EmailAnalysisResponse(BaseModel):
    headers: dict[str, str | None]
    authentication_results: list[str]
    authentication_results_warning: str
    received_header_count: int
    extracted_link_count: int
    phishing_link_count: int
    legitimate_link_count: int
    unsupported_links: list[dict[str, str]]
    links: list[EmailLinkResult]
    truncated: bool
    mime_parts_examined: int
    triage_summary: str
    limitations: str


class MeasuredFeatures(BaseModel):
    """The 17 observed URL-string measurements; these are not feature attributions."""

    model_config = ConfigDict(extra="forbid")
    url_length: int
    hostname_length: int
    hostname_dot_count: int
    subdomain_count: int
    hyphen_count: int
    digit_count: int
    is_ip_hostname: int
    uses_https: int
    authority_has_at_sign: int
    percent_encoding_count: int
    malformed_percent_count: int
    path_length: int
    path_segment_count: int
    path_has_dot_segment: int
    query_length: int
    query_parameter_count: int
    has_fragment: int


class AnalysisResponse(BaseModel):
    """Model prediction, uncalibrated class scores, and measured URL characteristics."""

    normalized_url: str = Field(description="Canonicalized URL passed to the feature extractor and model.")
    prediction: str = Field(description="Model class: legitimate or phishing.")
    model_version: str
    model_algorithm: str
    model_scope: str
    phishing_score: float = Field(description="Uncalibrated estimated model score for class 1 (phishing), from predict_proba.")
    legitimate_score: float = Field(description="Uncalibrated estimated model score for class 0 (legitimate), from predict_proba.")
    decision_threshold: float = Field(description="Artifact-recorded threshold applied to phishing_score.")
    measured_features: MeasuredFeatures = Field(description="Observed URL measurements, not an explanation or feature attribution.")
    explanation: LogisticRegressionExplanation | None = Field(
        default=None,
        description="Additive Logistic Regression logit contributions, when supported by the active model.",
    )
    novelty_detection: NoveltyDetection
    interpretation: str
    # Backward-compatible fields consumed by the existing frontend.
    evidence: MeasuredFeatures = Field(description="Deprecated-compatible alias for measured_features.")


class HistoryRecord(BaseModel):
    id: int
    created_at: str
    normalized_url: str
    prediction: str
    phishing_score: float
    legitimate_score: float
    decision_threshold: float
    model_version: str
    model_algorithm: str
    measured_features: MeasuredFeatures
    explanation: LogisticRegressionExplanation | None = None
    novelty_detection: NoveltyDetection | None = None


class HistoryPage(BaseModel):
    items: list[HistoryRecord]
    total: int
    limit: int
    offset: int
    has_more: bool


class DeleteHistoryResponse(BaseModel):
    deleted: bool
    analysis_id: int | None = None
    deleted_count: int | None = None


def _validate_artifact(artifact: Any) -> dict[str, Any]:
    required = {
        "model", "model_version", "algorithm", "feature_names", "scikit_learn_version",
        "tldextract_version", "python_version", "model_scope", "decision_threshold",
    }
    if not isinstance(artifact, dict) or not required.issubset(artifact):
        raise ModelArtifactError("model artifact metadata is incomplete")
    if artifact["model_version"] != MODEL_VERSION or artifact["feature_names"] != list(FEATURE_NAMES):
        raise ModelArtifactError("model artifact version or feature schema is incompatible")
    if artifact["algorithm"] not in {"random_forest", "logistic_regression"}:
        raise ModelArtifactError("model artifact algorithm is incompatible")
    if artifact["scikit_learn_version"] != sklearn.__version__:
        raise ModelArtifactError("model artifact scikit-learn version is incompatible")
    if artifact["tldextract_version"] != tldextract.__version__:
        raise ModelArtifactError("model artifact URL suffix-list version is incompatible")
    if artifact["python_version"] != platform.python_version():
        raise ModelArtifactError("model artifact Python version is incompatible")
    model = artifact["model"]
    if not all(hasattr(model, method) for method in ("predict", "predict_proba")):
        raise ModelArtifactError("model artifact lacks required prediction methods")
    expected_classifier = {
        "random_forest": "RandomForestClassifier",
        "logistic_regression": "LogisticRegression",
    }[artifact["algorithm"]]
    classifier = getattr(model, "named_steps", {}).get("classifier")
    if classifier is None or type(classifier).__name__ != expected_classifier:
        raise ModelArtifactError("model artifact algorithm metadata does not match its estimator")
    classes = getattr(model, "classes_", None)
    feature_count = getattr(model, "n_features_in_", None)
    if classes is None or set(classes) != {0, 1} or feature_count != len(FEATURE_NAMES):
        raise ModelArtifactError("model artifact class labels or feature count are incompatible")
    model_feature_names = getattr(model, "feature_names_in_", None)
    if model_feature_names is not None and list(model_feature_names) != list(FEATURE_NAMES):
        raise ModelArtifactError("model artifact feature ordering is incompatible")
    try:
        threshold = float(artifact["decision_threshold"])
    except (TypeError, ValueError):
        raise ModelArtifactError("model artifact decision threshold is invalid") from None
    if not math.isfinite(threshold) or not 0 <= threshold <= 1:
        raise ModelArtifactError("model artifact decision threshold is invalid")
    if not isinstance(artifact["model_scope"], str) or not artifact["model_scope"].strip():
        raise ModelArtifactError("model artifact scope metadata is missing")
    return artifact


def load_model_artifact(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ModelArtifactError("model artifact is missing")
    try:
        artifact = joblib.load(path)
    except Exception as exc:
        raise ModelArtifactError("model artifact could not be loaded") from exc
    return _safe_validate_artifact(artifact)


def _safe_validate_artifact(artifact: Any) -> dict[str, Any]:
    try:
        return _validate_artifact(artifact)
    except ModelArtifactError:
        raise
    except Exception as exc:
        raise ModelArtifactError("model artifact metadata is invalid") from exc


class RequestSizeLimitMiddleware:
    """ASGI body cap that buffers at most the configured maximum."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        route_limit = MAX_EMAIL_REQUEST_BYTES if scope.get("path") in {"/analyze-email", "/api/analyze-email"} else MAX_REQUEST_BYTES
        raw_content_length = headers.get(b"content-length", b"")
        try:
            content_length = raw_content_length.decode("ascii", errors="strict")
        except UnicodeDecodeError:
            await self._error(send, 400, "Invalid Content-Length")
            return
        if content_length:
            try:
                if not content_length.isdecimal():
                    raise ValueError
                if int(content_length) > route_limit:
                    await self._error(send, 413, "Request body is too large")
                    return
            except ValueError:
                await self._error(send, 400, "Invalid Content-Length")
                return
        body = bytearray()
        more_body = True
        while more_body:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            if len(body) + len(chunk) > route_limit:
                await self._error(send, 413, "Request body is too large")
                return
            body.extend(chunk)
            more_body = message.get("more_body", False)

        replayed = False

        async def bounded_receive():
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return {"type": "http.disconnect"}

        await self.app(scope, bounded_receive, send)

    @staticmethod
    async def _error(send, status_code: int, message: str):
        body = (f'{{"detail":"{message}"}}').encode("utf-8")
        await send({"type": "http.response.start", "status": status_code, "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode("ascii"))]})
        await send({"type": "http.response.body", "body": body})


def create_app(
    model_path: Path | None = None,
    artifact: dict[str, Any] | None = None,
    database_path: Path | None = None,
    novelty_path: Path | None = None,
    novelty_artifact: dict[str, Any] | None = None,
) -> FastAPI:
    public_demo_mode = _public_demo_enabled()
    selected_model_path = (
        Path(os.getenv("PHISHGUARD_MODEL_PATH") or DEFAULT_MODEL_PATH)
        if model_path is None else Path(model_path)
    )
    selected_novelty_path = (
        Path(os.getenv("PHISHGUARD_NOVELTY_PATH") or DEFAULT_NOVELTY_PATH)
        if novelty_path is None else Path(novelty_path)
    )
    history_store = None if public_demo_mode else HistoryStore(database_path)

    def initialize_database(application: FastAPI) -> None:
        if public_demo_mode:
            application.state.database_ready = None
            application.state.database_error = None
            application.state.history_store = None
            return
        try:
            assert history_store is not None
            history_store.initialize()
            application.state.database_ready = True
            application.state.database_error = None
            application.state.history_store = history_store
        except HistoryDatabaseError as exc:
            logger.error("History database unavailable (%s)", str(exc))
            application.state.database_ready = False
            application.state.database_error = "Local analysis history is unavailable."
            application.state.history_store = history_store

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        if not public_demo_mode and not application.state.database_ready:
            initialize_database(application)
        yield

    app = FastAPI(
        title="PhishGuard AI URL API",
        version=MODEL_VERSION,
        description=API_DESCRIPTION,
        contact={"name": "PhishGuard AI research project"},
        openapi_url=None if public_demo_mode else "/openapi.json",
        docs_url=None if public_demo_mode else "/docs",
        redoc_url=None if public_demo_mode else "/redoc",
        lifespan=lifespan,
    )
    app.add_middleware(RequestSizeLimitMiddleware)
    cors_origins = _configured_cors_origins()
    if cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=cors_origins,
            allow_credentials=False,
            allow_methods=["GET", "HEAD", "POST", "DELETE"],
            allow_headers=["Content-Type"],
        )
    app.state.public_demo_mode = public_demo_mode
    app.state.database_ready = None if public_demo_mode else False
    app.state.database_error = "Local analysis history is unavailable."
    app.state.history_store = history_store
    try:
        loaded = _safe_validate_artifact(artifact) if artifact is not None else load_model_artifact(selected_model_path)
        app.state.model_artifact = loaded
        app.state.model_error = None
    except ModelArtifactError as exc:
        logger.warning("Selected model unavailable: %s", str(exc))
        app.state.model_artifact = None
        app.state.model_error = "Selected model is missing or incompatible. Restore the Phase 1 artifact."
    try:
        app.state.novelty_artifact = (
            validate_novelty_artifact(novelty_artifact)
            if novelty_artifact is not None else load_novelty_artifact(selected_novelty_path)
        )
        app.state.novelty_error = None
    except NoveltyArtifactError as exc:
        logger.warning("Novelty detector unavailable (%s)", str(exc))
        app.state.novelty_artifact = None
        app.state.novelty_error = "Novelty detection is unavailable because its artifact is missing or incompatible."

    # Explicit paths are used by tests and embedded callers; initializing them here
    # keeps those apps usable without a server lifespan. The production default is
    # initialized during application startup so importing this module writes nothing.
    if database_path is not None and not public_demo_mode:
        initialize_database(app)

    def available_history_store(request: Request) -> HistoryStore | None:
        if request.app.state.public_demo_mode:
            return None
        if not request.app.state.database_ready:
            initialize_database(request.app)
        if not request.app.state.database_ready:
            return None
        return request.app.state.history_store

    def disabled_history_response() -> JSONResponse:
        return JSONResponse(
            status_code=404,
            content={"detail": "History is disabled in public demo mode."},
        )

    @app.middleware("http")
    async def block_public_history_paths(request: Request, call_next):
        if public_demo_mode and (
            request.url.path == "/history" or request.url.path.startswith("/history/")
        ):
            return disabled_history_response()
        return await call_next(request)

    def database_failure(request: Request, operation: str, exc: HistoryDatabaseError):
        logger.error("History database %s failed (%s)", operation, str(exc))
        request.app.state.database_ready = False
        request.app.state.database_error = "Local analysis history is unavailable."
        return JSONResponse(status_code=503, content={"detail": request.app.state.database_error})

    def classify_url(url: str, loaded: dict[str, Any], novelty_loaded: dict[str, Any] | None) -> AnalysisResponse:
        features = extract_url_features(url)
        matrix = pd.DataFrame([[features[name] for name in FEATURE_NAMES]], columns=FEATURE_NAMES)
        classes = list(loaded["model"].classes_)
        probabilities = loaded["model"].predict_proba(matrix)[0]
        if len(probabilities) != len(classes):
            raise ValueError("model score dimensions do not match class labels")
        scores = {int(label): float(score) for label, score in zip(classes, probabilities)}
        if set(scores) != {0, 1} or any(not math.isfinite(score) or not 0 <= score <= 1 for score in scores.values()):
            raise ValueError("model returned invalid class scores")
        threshold = float(loaded["decision_threshold"])
        predicted = int(loaded["model"].predict(matrix)[0])
        if predicted not in (0, 1) or predicted != int(scores[1] >= threshold):
            raise ValueError("model prediction does not match its recorded threshold")
        measured = MeasuredFeatures(**features)
        explanation = None
        if loaded["algorithm"] == "logistic_regression":
            explanation = explain_logistic_regression(loaded["model"], matrix, loaded["model_version"])
        try:
            novelty_result = score_novelty(novelty_loaded, matrix)
        except Exception:
            novelty_result = {
                "available": False, "is_unusual": None, "anomaly_score": None,
                "threshold": None, "detector_version": None, "detector": None,
                "interpretation": "Novelty detection is unavailable because the detector could not score this URL.",
            }
        return AnalysisResponse(
            normalized_url=url,
            prediction="phishing" if predicted == 1 else "legitimate",
            model_version=loaded["model_version"], model_algorithm=loaded["algorithm"],
            model_scope=loaded["model_scope"], phishing_score=scores[1], legitimate_score=scores[0],
            decision_threshold=threshold, measured_features=measured, explanation=explanation,
            novelty_detection=NoveltyDetection(**novelty_result),
            evidence=measured,
            interpretation=(
                "Scores are uncalibrated estimates from the model, not real-world probabilities. "
                "Measured URL characteristics are not explanations of the model decision. "
                "A legitimate classification is not proof that the destination is safe."
            ),
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(_request: Request, _exc: RequestValidationError):
        return JSONResponse(
            status_code=422,
            content={"detail": "Invalid request. Provide valid URL or email analysis input in a JSON object."},
        )

    @app.exception_handler(Exception)
    async def unexpected_error_handler(_request: Request, exc: Exception):
        logger.error("Unhandled API failure (%s)", type(exc).__name__)
        return JSONResponse(status_code=500, content={"detail": "Internal analysis error."})

    @app.get(
        "/healthz",
        summary="Check API, model, and database readiness",
        description="Reports process availability separately from selected-model and local SQLite readiness.",
    )
    def health(request: Request):
        model_ready = request.app.state.model_artifact is not None
        database_ready = request.app.state.database_ready
        if request.app.state.public_demo_mode:
            status = "ready" if model_ready else "model_unavailable"
        else:
            status = (
                "ready" if model_ready and database_ready
                else "model_unavailable" if not model_ready
                else "database_unavailable"
            )
        return {
            "status": status,
            "api_running": True,
            "model_ready": model_ready,
            "database_ready": database_ready,
        }

    @app.post(
        "/analyze",
        response_model=AnalysisResponse,
        summary="Classify a URL from its text",
        description=(
            "Runs the selected URL-only research classifier. No destination is fetched. "
            "Scores are uncalibrated estimated model scores, not guarantees or real-world probabilities. "
            "Measured features describe the submitted URL and are not feature attributions."
        ),
        responses={
            400: {"model": ErrorResponse, "description": "Malformed request framing."},
            413: {"model": ErrorResponse, "description": "Request body exceeds the configured size limit."},
            422: {"model": ErrorResponse, "description": "Invalid JSON, URL, or request fields."},
            500: {"model": ErrorResponse, "description": "Inference or internal analysis failure."},
            503: {"model": ErrorResponse, "description": "Selected model is unavailable."},
        },
    )
    def analyze(payload: URLRequest, request: Request):
        loaded = request.app.state.model_artifact
        if loaded is None:
            return JSONResponse(status_code=503, content={"detail": request.app.state.model_error})
        store = None if request.app.state.public_demo_mode else available_history_store(request)
        if not request.app.state.public_demo_mode and store is None:
            return JSONResponse(status_code=503, content={"detail": request.app.state.database_error})
        try:
            response = classify_url(payload.url, loaded, request.app.state.novelty_artifact)
            if store is not None:
                store.insert_analysis({
                    "normalized_url": response.normalized_url,
                    "prediction": response.prediction,
                    "phishing_score": response.phishing_score,
                    "legitimate_score": response.legitimate_score,
                    "decision_threshold": response.decision_threshold,
                    "model_version": response.model_version,
                    "model_algorithm": response.model_algorithm,
                    "measured_features": response.measured_features.model_dump(),
                    "explanation": (
                        response.explanation.model_dump()
                        if response.explanation is not None else None
                    ),
                    "novelty_detection": response.novelty_detection.model_dump(),
                })
            return response
        except HistoryDatabaseError as exc:
            return database_failure(request, "write", exc)
        except Exception as exc:
            logger.error("URL inference failed (%s)", type(exc).__name__)
            return JSONResponse(status_code=500, content={"detail": "URL analysis failed. Try again later."})

    @app.post("/analyze-email", response_model=EmailAnalysisResponse,
              summary="Screen links and inspect headers in a pasted email (offline)")
    def analyze_email(payload: EmailRequest, request: Request):
        loaded = request.app.state.model_artifact
        if loaded is None:
            return JSONResponse(status_code=503, content={"detail": request.app.state.model_error})
        try:
            parsed = parse_email(payload.raw_email)
            results: list[EmailLinkResult] = []
            normalized_links: dict[str, EmailLinkResult] = {}
            invalid_links = list(parsed.unsupported_links)
            for link in parsed.links:
                try:
                    normalized = URLRequest(url=link.url).url
                    if normalized in normalized_links:
                        normalized_links[normalized].sources = sorted(
                            set(normalized_links[normalized].sources) | link.sources
                        )
                        continue
                    result = classify_url(normalized, loaded, request.app.state.novelty_artifact)
                except Exception:
                    invalid_links.append({"value": link.url[:256], "reason": "not a valid supported HTTP(S) URL"})
                    continue
                link_result = EmailLinkResult(
                    normalized_url=result.normalized_url, sources=sorted(link.sources),
                    prediction=result.prediction, model_version=result.model_version,
                    model_algorithm=result.model_algorithm, phishing_score=result.phishing_score,
                    legitimate_score=result.legitimate_score, decision_threshold=result.decision_threshold,
                    measured_features=result.measured_features, explanation=result.explanation,
                    novelty_detection=result.novelty_detection,
                )
                normalized_links[normalized] = link_result
                results.append(link_result)
            phishing_count = sum(item.prediction == "phishing" for item in results)
            legitimate_count = sum(item.prediction == "legitimate" for item in results)
            if not results:
                summary = "URL-based screening could not assess this email because no supported active HTTP(S) links were found."
            elif phishing_count:
                summary = f"The URL model classified {phishing_count} extracted link(s) as phishing. This is link triage, not an email-level verdict."
            else:
                summary = f"The URL model classified {legitimate_count} supported link(s) as legitimate. This does not establish that the email is safe."
            return EmailAnalysisResponse(
                headers=parsed.headers, authentication_results=parsed.authentication_results,
                authentication_results_warning="Authentication-Results is user-supplied header text and has not been independently verified. No SPF, DKIM, or DMARC checks were performed.",
                received_header_count=parsed.received_count, extracted_link_count=len(results),
                phishing_link_count=phishing_count, legitimate_link_count=legitimate_count,
                unsupported_links=invalid_links, links=results, truncated=parsed.truncated,
                mime_parts_examined=parsed.mime_parts_examined, triage_summary=summary,
                limitations="Offline URL-only screening: the message is not classified by an email model; no links are opened, and headers remain unverified. This analysis is transient and is not saved to local history.",
            )
        except EmailInputError as exc:
            return JSONResponse(status_code=422, content={"detail": str(exc)})
        except Exception as exc:
            logger.error("Email triage failed (%s)", type(exc).__name__)
            return JSONResponse(status_code=500, content={"detail": "Email triage failed. Try again later."})

    @app.get(
        "/history",
        response_model=HistoryPage,
        summary="List saved URL analyses",
        description="Returns completed analyses newest first. Pagination uses a 20 item default and a maximum of 100.",
        responses={503: {"model": ErrorResponse, "description": "Local history database is unavailable."}},
    )
    def list_history(
        request: Request,
        limit: Annotated[int, Query(ge=1, le=100)] = 20,
        offset: Annotated[int, Query(ge=0)] = 0,
    ):
        if request.app.state.public_demo_mode:
            return disabled_history_response()
        store = available_history_store(request)
        if store is None:
            return JSONResponse(status_code=503, content={"detail": request.app.state.database_error})
        try:
            records, total = store.list_analyses(limit, offset)
            return HistoryPage(
                items=records,
                total=total,
                limit=limit,
                offset=offset,
                has_more=offset + len(records) < total,
            )
        except HistoryDatabaseError as exc:
            return database_failure(request, "read", exc)

    @app.get(
        "/history/{analysis_id}",
        response_model=HistoryRecord,
        summary="Retrieve one saved analysis",
        responses={
            404: {"model": ErrorResponse, "description": "Analysis does not exist."},
            422: {"model": ErrorResponse, "description": "Analysis ID must be a positive integer."},
            503: {"model": ErrorResponse, "description": "Local history database is unavailable."},
        },
    )
    def get_history_item(request: Request, analysis_id: Annotated[int, APIPath(ge=1)]):
        if request.app.state.public_demo_mode:
            return disabled_history_response()
        store = available_history_store(request)
        if store is None:
            return JSONResponse(status_code=503, content={"detail": request.app.state.database_error})
        try:
            record = store.get_analysis(analysis_id)
            if record is None:
                return JSONResponse(status_code=404, content={"detail": "Analysis not found."})
            return record
        except HistoryDatabaseError as exc:
            return database_failure(request, "read", exc)

    @app.delete(
        "/history/{analysis_id}",
        response_model=DeleteHistoryResponse,
        summary="Delete one saved analysis",
        responses={
            404: {"model": ErrorResponse, "description": "Analysis does not exist."},
            422: {"model": ErrorResponse, "description": "Analysis ID must be a positive integer."},
            503: {"model": ErrorResponse, "description": "Local history database is unavailable."},
        },
    )
    def delete_history_item(request: Request, analysis_id: Annotated[int, APIPath(ge=1)]):
        if request.app.state.public_demo_mode:
            return disabled_history_response()
        store = available_history_store(request)
        if store is None:
            return JSONResponse(status_code=503, content={"detail": request.app.state.database_error})
        try:
            if not store.delete_analysis(analysis_id):
                return JSONResponse(status_code=404, content={"detail": "Analysis not found."})
            return DeleteHistoryResponse(deleted=True, analysis_id=analysis_id)
        except HistoryDatabaseError as exc:
            return database_failure(request, "delete", exc)

    @app.delete(
        "/history",
        response_model=DeleteHistoryResponse,
        summary="Clear all saved analyses",
        description="Deletes analysis rows but retains the SQLite database and schema. Requires confirm=true.",
        responses={
            400: {"model": ErrorResponse, "description": "Explicit confirmation was not supplied."},
            503: {"model": ErrorResponse, "description": "Local history database is unavailable."},
        },
    )
    def clear_history(request: Request, confirm: bool = Query(False)):
        if request.app.state.public_demo_mode:
            return disabled_history_response()
        if not confirm:
            return JSONResponse(status_code=400, content={"detail": "Set confirm=true to clear analysis history."})
        store = available_history_store(request)
        if store is None:
            return JSONResponse(status_code=503, content={"detail": request.app.state.database_error})
        try:
            deleted = store.clear_history()
            return DeleteHistoryResponse(deleted=True, deleted_count=deleted)
        except HistoryDatabaseError as exc:
            return database_failure(request, "clear", exc)

    return app


app = create_app()


def main() -> None:
    # Access logs are disabled so submitted URL paths are not written to logs.
    uvicorn.run(
        app,
        host=os.getenv("HOST", "127.0.0.1"),
        port=int(os.getenv("PORT", "8000")),
        access_log=False,
    )


if __name__ == "__main__":
    main()
