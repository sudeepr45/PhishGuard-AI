# Phase A URL baseline

Requires Python **3.12.10**. Create an isolated environment from the repository root in PowerShell:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r backend\requirements-dev.txt
```

The package versions are pinned in `requirements.txt` and `requirements-dev.txt`. The UCI data is retrieved separately and kept under ignored `data/raw/`; see [data/README.md](../data/README.md). The API and model training never visit URLs. URL feature definitions are documented in [FEATURES.md](FEATURES.md).

If you need to retrieve the data again, use the official UCI archive:

```powershell
New-Item -ItemType Directory -Force data\raw | Out-Null
Invoke-WebRequest -Uri 'https://archive.ics.uci.edu/static/public/967/phiusiil%2Bphishing%2Burl%2Bdataset.zip' -OutFile data\raw\phiusiil-uci-967.zip
Expand-Archive -LiteralPath data\raw\phiusiil-uci-967.zip -DestinationPath data\raw
Get-FileHash data\raw\PhiUSIIL_Phishing_URL_Dataset.csv -Algorithm SHA256
```

Run feature, data-validation, model-loading, and API tests:

```powershell
python -m pytest backend\tests
```

Train the fixed Logistic Regression baseline and Random Forest challenger. Candidate selection uses validation metrics only; after selection the chosen model is evaluated once on the final test partition. The command writes the selected model and machine-readable results:

```powershell
python -m backend.src.training --dataset data\raw\PhiUSIIL_Phishing_URL_Dataset.csv --output outputs\phase-a
```

The command writes `outputs/phase-a/url_model.joblib`, `outputs/phase-a/evaluation.json`, and `outputs/phase-a/final_test_evaluation.json`. They are ignored by Git. Re-running with the same dataset file, dependency versions, and seed repeats the training/evaluation procedure. Training feature extraction uses the canonical URL representation shared with runtime inference. The promoted active artifact is version `url-classifier-3`, selected Logistic Regression; the API response structure is unchanged.

The baseline uses `StandardScaler` and class-balanced Logistic Regression (`liblinear`, `max_iter=2000`, seed 412). The initial Random Forest challenger uses 100 trees, maximum depth 24, minimum leaf size 2, balanced class weights, seed 412, and all available CPU workers. Both pipelines fit scaling on training rows only. Selection chooses Random Forest only when validation precision, recall, F1 and false-positive rate are all no worse than Logistic Regression and recall or F1 improves by at least 0.005; otherwise Logistic Regression remains selected. Accuracy alone is not a selection criterion. Timing reports include full-validation-batch throughput and mean single-row `predict` latency after warm-up; these local measurements are workload and machine dependent.

Recheck only the held-out final test split without refitting:

```powershell
python -m backend.src.evaluate --dataset data\raw\PhiUSIIL_Phishing_URL_Dataset.csv --output outputs\phase-a
```

This writes `outputs/phase-a/final_test_evaluation.json` and refuses a dataset whose checksum differs from the one in the model metadata.

The corrected run on the retrieved UCI snapshot retained 234,894 rows: 134,849 legitimate and 100,045 phishing. It excluded 425 exact duplicates, 474 same-label canonical URL duplicates, and both rows in one conflicting normalized URL group. Invalid URL and label counts were zero. There are 175,508 registrable domains; 119 domains contain both labels and remain grouped in one partition. The fixed split is train 141,463 (81,153 legitimate; 60,310 phishing), validation 47,135 (26,896; 20,239), and test 46,296 (26,800; 19,496), with no domain overlap. Dataset-level parity with runtime normalization was verified on all retained rows with zero feature-vector differences.

Corrected Logistic Regression achieved validation accuracy **0.93415**, precision **0.98043**, recall **0.86388**, F1 **0.91847**, false-positive rate **0.012976**, and ROC-AUC **0.97007**. Its confusion matrix was `[[26547, 349], [2755, 17484]]`. Corrected final-test accuracy was **0.93427**, precision **0.98055**, recall **0.86100**, F1 **0.91689**, false-positive rate **0.012425**, and ROC-AUC **0.96306**; confusion matrix `[[26467, 333], [2710, 16786]]`.

Corrected Random Forest validation accuracy was **0.93357**, precision **0.98170**, recall **0.86136**, F1 **0.91760**, false-positive rate **0.012084**, and ROC-AUC **0.97185**; confusion matrix `[[26571, 325], [2806, 17433]]`. It failed the unchanged rule because its recall and F1 were below Logistic Regression, so Logistic Regression remains selected. The corrected Random Forest was not evaluated on the final test partition; the pipeline tests only the validation-selected model.

The previous `url-classifier-2` Random Forest achieved validation accuracy **0.99684** and final-test accuracy **0.99231**, but it used raw trimmed URL representations during training/evaluation while runtime inference canonicalized URLs. Those figures are historical results from the inconsistent pipeline, not current runtime performance. The corrected selected `url-classifier-3` uses canonical URL representations in both training and inference. The test partition was not used for model selection. The grouped random snapshot evaluation is not temporal validation and does not establish future or live-web generalization. Test-set phishing prevalence was considered during grouped partition construction.

Start the API from the repository root after training:

```powershell
python -m backend.src.api
```

It binds to `127.0.0.1:8000` and disables access logs. Send a request:

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/analyze -ContentType 'application/json' -Body '{"url":"https://example.com/login"}'
```

`GET /healthz` reports `api_running` separately from `model_ready`; the process remains available when the model is unavailable. `POST /analyze` accepts exactly one `url` field. An explicit HTTP(S) URL is accepted; a scheme-less URL is consistently normalized to HTTPS. Unsupported schemes, malformed hosts, whitespace/control characters, extra fields, and URLs over 8,192 characters return HTTP 422. The body limit is 16 KiB (HTTP 413).

The typed response includes `normalized_url`, `prediction`, model version and algorithm, scope, `phishing_score`, `legitimate_score`, recorded decision threshold, 17 ordered `measured_features`, and an `explanation` for the active Logistic Regression model. The explanation contains the intercept, standardized feature contributions, reconstructed logit, and the pipeline `decision_function` value. It is stored with its generating model version. Contributions are mathematical logit terms, not causal explanations or proof of intent; the measured features remain observations. Both class scores are uncalibrated outputs from `predict_proba`, not real-world probabilities. The response retains `evidence` as an alias for `measured_features` for frontend compatibility.

The service never fetches the submitted destination. It does not inspect webpage content, verify current website reputation, guarantee a site is safe, or replace browser security or professional security tools. Missing or incompatible model metadata returns HTTP 503; invalid request input returns HTTP 422; inference failures return a generic HTTP 500. Access logs remain disabled, submitted URLs are not logged, and API errors do not expose internal exception details. The server binds only to `127.0.0.1`.

## Offline email link triage

`POST /analyze-email` accepts `{"raw_email":"..."}` for transient local parsing. It extracts common sender and routing headers, notes the count of `Received` headers, and screens supported HTTP(S) URLs found in plain text or HTML `href` attributes using the same active `url-classifier-3` pipeline, 17 features, threshold, and Logistic Regression explanation as `/analyze`. Results contain per-link predictions and evidence, but the service does not train or invoke an email classifier.

Email requests allow up to 256 KiB of raw UTF-8 message data, at most 30 non-multipart MIME parts and 25 unique URLs; individual decoded text parts are capped at 64 KiB. The request middleware retains the 16 KiB limit for other routes and applies a bounded larger cap only to `/analyze-email`. Defanged links are reported as not screened. Unsupported schemes are not opened. No destination is fetched, redirects followed, HTML rendered, scripts executed, or remote images loaded. Email bodies and extracted links are not written to SQLite and are not logged. Existing URL analysis history is unchanged.

Parsed `Authentication-Results` content is unverified user-supplied header text. No SPF, DKIM, or DMARC check is performed. Link predictions are not a verdict on the email: legitimate link outputs do not establish safety, and a phishing link output alone does not prove the entire message is malicious. No independent sender authentication or email classification is provided.

## Separate URL novelty detector

The independently versioned Isolation Forest is trained separately and stored at `outputs/phase-a-novelty/novelty_detector.joblib`; it never writes to or replaces the Logistic Regression artifact in `outputs/phase-a`. To reproduce it:

```powershell
python -m backend.src.novelty --dataset data\raw\PhiUSIIL_Phishing_URL_Dataset.csv --output outputs\phase-a-novelty --max-fpr 0.05
```

It uses the existing cleaned, canonical URL records and grouped split. Only the 81,153 legitimate training rows are passed to `IsolationForest.fit`. Its 300-tree configuration is seeded at 412. The threshold is chosen using validation only to maximize phishing recall subject to the configurable maximum legitimate false-positive rate; 5% is the documented default. Final-test data is scored once after freezing this policy and is not used for fitting or tuning. See [the methodology report](../docs/MODEL_METHODOLOGY.md) for actual validation and final-test metrics.

The API loads this artifact independently. A missing or incompatible detector leaves URL classification available and returns `novelty_detection.available=false`; startup never trains a detector. Anomaly score is `-score_samples`, with larger values more unusual. Novelty describes structural deviation from the legitimate training distribution, not phishing intent.

## Local analysis history

The API stores each successfully completed analysis in a local SQLite database using Python's built-in `sqlite3` module. The default file is `backend/data/analysis_history.sqlite3`; set `PHISHGUARD_DB_PATH` to choose another path. The parent directory is created automatically. Database files and SQLite WAL sidecars in `backend/data/` are ignored by Git. No history is transmitted to an external service. Submitted URLs, including their path and query, are stored locally so history can reproduce the model result; the API does not store unrelated personal information.

The `analysis_history` table has: integer primary key `id`; UTC ISO 8601 `created_at`; `normalized_url`; constrained `prediction`; phishing and legitimate `REAL` scores; `REAL` decision threshold; model version and algorithm text; `measured_features` as JSON text; nullable `explanation_json`; and nullable `novelty_json` containing the time-of-analysis detector result. Schema version 2 added explanations; schema version 3 adds novelty results with additive `ALTER TABLE` migrations. Existing records and explanations remain intact, and older rows have null novelty. SQL constraints validate prediction labels, score and threshold ranges, nonempty URL/model fields, and valid JSON. An index supports newest-first ordering by timestamp and ID. Initialization runs at application startup, is safe to repeat, creates no replacement database when one exists, and does not delete history. Each connection is closed after use; writes use explicit SQLite transactions. If initialization or a write fails, health reports the database as unavailable and analysis does not claim to have been saved.

History endpoints:

- `GET /history?limit=20&offset=0` returns `items`, `total`, `limit`, `offset`, and `has_more`; records are newest first. `limit` is 1–100 (default 20), and `offset` is zero or greater. An empty database returns an empty `items` list and total 0.
- `GET /history/{analysis_id}` returns one record, or HTTP 404 if absent. IDs must be positive integers.
- `DELETE /history/{analysis_id}` deletes only that record, or returns HTTP 404 if absent.
- `DELETE /history?confirm=true` clears all rows while retaining the database file and schema. Without explicit confirmation it returns HTTP 400. The response reports the number of deleted records.

To inspect the file, open the configured database with a local SQLite browser or Python's `sqlite3` module. To clear history from PowerShell while the API is running, use `Invoke-RestMethod -Method Delete -Uri 'http://127.0.0.1:8000/history?confirm=true'`. The health response includes `api_running`, `model_ready`, and `database_ready`; overall `status` is `ready` only when both the model and database are ready.

Only load the model artifact generated by this repository's training command. `joblib` artifacts are Python pickle-based and loading an untrusted artifact can execute code.
