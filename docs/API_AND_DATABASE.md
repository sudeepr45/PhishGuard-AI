# API and local history

The FastAPI service binds to `127.0.0.1:8000`. When using the Vite app, the frontend sends same-origin `/api/...` requests; Vite strips `/api` and proxies them to the API. The backend routes below are shown without that frontend-only prefix.

API interactive schema: `http://127.0.0.1:8000/docs`.

## `GET /healthz`

Reports process, model and SQLite readiness separately.

```json
{
  "status": "ready",
  "api_running": true,
  "model_ready": true,
  "database_ready": true
}
```

`status` is `ready`, `model_unavailable` or `database_unavailable`. A running API can return a health response when the model or database is not ready.

## `POST /analyze`

The request body has exactly one field; extra fields are rejected. Scheme-less host input is normalized to HTTPS.

```http
POST /analyze
Content-Type: application/json
```

```json
{"url":"https://example.com/login?campaign=promo#section"}
```

The following response was captured from the promoted `url-classifier-3` Logistic Regression through the API implementation. The sample omits the additive `explanation` object for brevity; it does **not** establish the real-world status of the example domain. Scores are uncalibrated model outputs.

```json
{
  "normalized_url": "https://example.com/login?campaign=promo#section",
  "prediction": "phishing",
  "model_version": "url-classifier-3",
  "model_algorithm": "logistic_regression",
  "model_scope": "URL-string lexical features trained on the UCI PhiUSIIL snapshot; no page fetch or reputation lookup.",
  "phishing_score": 0.9999999995232531,
  "legitimate_score": 4.767468642086214e-10,
  "decision_threshold": 0.5,
  "measured_features": {
    "url_length": 48,
    "hostname_length": 11,
    "hostname_dot_count": 1,
    "subdomain_count": 0,
    "hyphen_count": 0,
    "digit_count": 0,
    "is_ip_hostname": 0,
    "uses_https": 1,
    "authority_has_at_sign": 0,
    "percent_encoding_count": 0,
    "malformed_percent_count": 0,
    "path_length": 6,
    "path_segment_count": 1,
    "path_has_dot_segment": 0,
    "query_length": 14,
    "query_parameter_count": 1,
    "has_fragment": 1
  },
  "interpretation": "Scores are uncalibrated estimates from the model, not real-world probabilities. Measured URL characteristics are not explanations of the model decision. A legitimate classification is not proof that the destination is safe.",
  "evidence": {
    "url_length": 48,
    "hostname_length": 11,
    "hostname_dot_count": 1,
    "subdomain_count": 0,
    "hyphen_count": 0,
    "digit_count": 0,
    "is_ip_hostname": 0,
    "uses_https": 1,
    "authority_has_at_sign": 0,
    "percent_encoding_count": 0,
    "malformed_percent_count": 0,
    "path_length": 6,
    "path_segment_count": 1,
    "path_has_dot_segment": 0,
    "query_length": 14,
    "query_parameter_count": 1,
    "has_fragment": 1
  }
}
```

`evidence` is a compatibility alias for `measured_features`. This response was captured from the promoted local artifact; it does not claim ground truth for the example URL.

The current response also includes `explanation` for Logistic Regression. It contains `model_version`, `model_algorithm`, `positive_class`, `intercept`, `reconstructed_logit`, `decision_function_logit`, `reconstruction_error`, and 17 ordered `feature_contributions`. Each contribution gives the feature name, measured value, standardized value, coefficient, logit contribution, and direction (`toward_phishing`, `toward_legitimate`, or `neutral`). The API verifies the intercept plus contributions reconstructs the model pipeline's `decision_function`. These values describe additive model arithmetic; they are not causal explanations or proof that a URL is malicious. `measured_features` remains a separate set of observed inputs.

Responses include a separate `novelty_detection` object. When the independent detector is available it contains `available`, `is_unusual`, `anomaly_score`, `threshold`, `detector_version`, `detector`, and an interpretation. Larger anomaly scores mean greater structural deviation; the URL is marked unusual at or above the validation-selected threshold. If the novelty artifact is unavailable or incompatible, the response uses `available: false` and null detector values while URL classification remains operational. Novelty never changes the phishing prediction or explains the Logistic Regression score.

## `POST /analyze-email`

This transient offline triage parses headers and extracts HTTP(S) URLs from plain text and HTML `href` values. Each supported URL receives the same phishing prediction, explanation, and separate novelty result as `/analyze`. The email itself is not classified or persisted; extracted email links are not added to URL history.

```json
{"raw_email":"From: sender@example.test\nSubject: Review\n\nVisit https://example.test/login"}
```

The response contains parsed headers, unverified `Authentication-Results`, a warning that no SPF/DKIM/DMARC checks were performed, a `received_header_count`, supported and unsupported link counts, and a per-link `links` array. The overall `triage_summary` describes URL screening only. No destination is fetched, no remote content is rendered, and no email content or extracted URL is saved.

## `GET /history`

Query parameters: `limit` is 1–100 (default 20); `offset` is zero or greater (default 0). Results are ordered newest first and tie-broken by descending ID. This abbreviated example shows a legacy record from before explanation and novelty persistence were added. Its null values are expected for old records; current successful analyses retain the model explanation and novelty result. Its prediction is model output, not ground truth for the domain.

```json
{
  "items": [
    {
      "id": 1,
      "created_at": "2026-11-11T12:54:02.089499Z",
      "normalized_url": "https://example.com/login?campaign=promo#section",
      "prediction": "phishing",
      "phishing_score": 0.9999999995232531,
      "legitimate_score": 4.767468642086214e-10,
      "decision_threshold": 0.5,
      "model_version": "url-classifier-3",
      "model_algorithm": "logistic_regression",
      "measured_features": {
        "url_length": 48,
        "hostname_length": 11,
        "hostname_dot_count": 1,
        "subdomain_count": 0,
        "hyphen_count": 0,
        "digit_count": 0,
        "is_ip_hostname": 0,
        "uses_https": 1,
        "authority_has_at_sign": 0,
        "percent_encoding_count": 0,
        "malformed_percent_count": 0,
        "path_length": 6,
        "path_segment_count": 1,
        "path_has_dot_segment": 0,
        "query_length": 14,
        "query_parameter_count": 1,
        "has_fragment": 1
      },
      "explanation": null,
      "novelty_detection": null
    }
  ],
  "total": 1,
  "limit": 20,
  "offset": 0,
  "has_more": false
}
```

Empty history returns `items: []` and `total: 0`.

## `GET /history/{analysis_id}`

Returns the saved record fields used in the history `items` object. `analysis_id` must be a positive integer. A saved detail is the original stored result and does not rerun the model. The history schema does not store `model_scope` or `interpretation`.

## `DELETE /history/{analysis_id}`

Deletes one row. A successful response follows `{"deleted":true,"analysis_id":1,"deleted_count":null}`. Deleting an absent ID returns 404.

## `DELETE /history?confirm=true`

The exact `confirm=true` query parameter is required. Without it, the endpoint returns 400 and makes no deletion. A successful response is `{"deleted":true,"analysis_id":null,"deleted_count":N}`. It deletes rows only; it retains the SQLite file and schema.

## Validation and errors

- `POST /analyze` accepts HTTP(S) URLs; a scheme-less host is treated as HTTPS. Leading/trailing whitespace is trimmed; embedded whitespace/control characters, unsupported protocols, malformed or hostless URLs, extra request fields, and URLs over 8,192 characters are rejected with 422.
- Request bodies are capped at 16,384 bytes except `/analyze-email`, which has a bounded larger allowance for its 256 KiB raw-message limit plus JSON overhead. Email parsing also limits MIME parts, decoded part sizes, and URLs. Oversized bodies return 413. Malformed request framing can return 400.
- Invalid JSON and invalid request fields return 422 with a JSON `detail` message.
- An absent or incompatible model and an unavailable database return 503. `/healthz` identifies readiness status.
- Inference/internal errors return a generic 500 response. Backend exceptions are not returned to clients.
- History records not found return 404; invalid IDs return 422; history database failures return 503.

Error response shape:

```json
{"detail":"Invalid request. Provide valid URL or email analysis input in a JSON object."}
```

Exact text varies by error case.

## SQLite storage, privacy and retention

Default path: `backend/data/analysis_history.sqlite3`. Set optional `PHISHGUARD_DB_PATH` to choose a different file. The parent directory is created on initialization. The version-3 `analysis_history` table stores:

| Column | Storage |
|---|---|
| `id` | Integer primary key, autoincrement. |
| `created_at` | UTC ISO 8601 timestamp. |
| `normalized_url` | URL string, including path, query and fragment. |
| `prediction` | `legitimate` or `phishing`. |
| `phishing_score`, `legitimate_score` | Model output scores, constrained to [0, 1]. |
| `decision_threshold` | Recorded threshold, constrained to [0, 1]. |
| `model_version`, `model_algorithm` | Model metadata. |
| `measured_features` | JSON text containing 17 feature values. |
| `explanation_json` | Nullable JSON text containing the additive explanation and its generating model version. |
| `novelty_json` | Nullable JSON text containing the time-of-analysis novelty verdict, score, threshold, and detector version. |

Initialization upgrades schema versions 1 and 2 additively with `ALTER TABLE`; it preserves existing rows, which receive null explanation and novelty fields as appropriate. Saved explanations and novelty results are returned with history and remain tied to their generating model/detector versions. Older records without novelty results remain readable.

The API binds to loopback, disables access logs, and does not transmit history to an external service. The local database is not encrypted by this application and has no automatic expiry. Anyone with access to the machine and database file may be able to read its contents. Users can delete individual rows or clear all rows from the History page. Clearing history leaves the database and schema in place.
