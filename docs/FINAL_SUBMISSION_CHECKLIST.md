# PHISHGUARD AI final submission checklist

This checklist records the current implementation and provides a clean launch and demonstration path. The application is a local research prototype; its model outputs are not security verdicts.

## Label and external-metric audit

The selected source file is Mendeley Data, *Phishing URL dataset*, version 1, DOI [10.17632/vfszbj9b36.1](https://data.mendeley.com/datasets/vfszbj9b36/1). Its documentation says records are categorized as `phishing` or `legitimate`; the record reports 104,438 phishing and 345,738 legitimate rows. The downloaded CSV has columns `url` and `type`, and those exact two string values. Representative rows agree with the documentation: the phishing class includes URLs such as `http://atualizacaodedados.online`; the legitimate class includes `https://www.google.com` and `https://www.youtube.com`.

The source-to-project mapping is **`phishing` → 1** and **`legitimate` → 0**. The project convention is class 1 = phishing. The evaluator uses this mapping in `backend/src/evaluate_external.py`. The source file's label counts reproduce the Mendeley counts exactly. After URL validation and canonical-duplicate removal, the class counts are 345,584 legitimate and 103,657 phishing. After excluding every registrable domain found in the complete retained PhiUSIIL source corpus, the evaluated set contains 276,674 legitimate and 94,923 phishing URLs.

The confusion matrix label order is `[legitimate, phishing]`, rows are actual labels, and columns are predicted labels: `[[TN, FP], [FN, TP]]`. Metrics were recalculated from fresh frozen-model predictions and source labels, independently of the stored metric helper and saved predictions. Those values match `outputs/external-evaluation/evaluation.json` exactly:

| Frozen component | Accuracy | Precision | Recall | F1 | Legitimate FPR | ROC-AUC | Confusion matrix |
|---|---:|---:|---:|---:|---:|---:|---|
| Logistic Regression `url-classifier-3` | 0.35747 | 0.28408 | 0.99684 | 0.44215 | 0.86189 | 0.77114 | `[[38211, 238463], [300, 94623]]` |
| Isolation Forest `url-novelty-1` alert proxy | 0.40733 | 0.22635 | 0.54597 | 0.32002 | 0.64023 | 0.44129 | `[[99538, 177136], [43098, 51825]]` |

The mapping and confusion orientation are correct; the poor results are preserved. The classifier's 99.68% phishing recall is paired with an 86.19% legitimate false-positive rate and 35.75% accuracy. The novelty detector's ROC-AUC is below chance on this sample. Its unusualness flag is only treated as a phishing-alert proxy for evaluation; Isolation Forest is not a phishing classifier. The external corpus is record- and registrable-domain-disjoint from PhiUSIIL, but its provenance lists PhishTank among sources and has no row-level lineage. Do not claim feed-independent evaluation or strong generalization. See [the complete external report](EXTERNAL_EVALUATION.md).

## Implemented behavior

- URL submission invokes the active Logistic Regression pipeline with the shared canonicalizer and the ordered 17 URL-string features.
- The API returns model prediction, threshold, uncalibrated class scores, measured features, and per-feature standardized coefficient contributions that reconstruct the phishing logit.
- The separate Isolation Forest returns an anomaly score, frozen threshold and availability status. A missing detector does not disable classification.
- Successful URL analyses are stored locally in SQLite schema version 3 with their model-versioned explanation and novelty result. History supports pagination, details, individual deletion and confirmed clear-all. Version 1 records remain readable with null explanation/novelty fields; version 2 records retain their explanation and may have null novelty.
- Email triage accepts pasted MIME or message text, parses selected headers, extracts supported links from plain text and HTML `href` values, and runs the URL models on those links. It is transient: no email content or extracted email link is saved. `Authentication-Results` is unverified text; SPF, DKIM and DMARC are not checked.
- Invalid URLs receive a validation error. A missing/incompatible classifier makes health report `model_unavailable` and `/analyze` returns 503 without a prediction. A missing/incompatible novelty artifact leaves URL classification available and returns `novelty_detection.available: false`.

## Experimental capabilities, limitations and future work

The standalone novelty result is experimental and is not combined with or used to alter the classifier output. Coefficient contributions are additive model arithmetic, not causal explanations. Class scores are uncalibrated and are not probabilities of real-world safety or phishing.

Email support is URL screening, not an email classifier. No live website fetching, webpage/DOM inspection, sender-authentication verification, external reputation query, live threat feed, zero-day detection, or cloud history is implemented. The original model evaluation is a grouped snapshot split, not temporal validation. External dataset evidence is limited by shared public-feed provenance and shows a very high false-positive rate. Future work may investigate improved data provenance, temporal and feed-separated evaluation, email classification, and secure page analysis only with separately validated designs.

## Clean setup and launch (Windows PowerShell)

Prerequisites: Python 3.12.10, Node.js 20.19+ or 22.12+, and npm. From the repository root:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r backend\requirements-dev.txt
npm.cmd ci
```

For the full application demonstration, place trusted, compatible runtime artifacts at these exact paths:

| File | Required for | Expected identity | SHA-256 |
|---|---|---|---|
| `outputs/phase-a/url_model.joblib` | URL and email-link classification, explanation, history | `url-classifier-3`, Logistic Regression, 17 features | `638dcbadf27792784483fc1daa48fa1e857fb465ccdad02db16c3c49a927ef71` |
| `outputs/phase-a-novelty/novelty_detector.joblib` | Separate novelty result | `url-novelty-1`, Isolation Forest, 17 features | `bca2b732893dc9a04958560bd2cbf109b878a26381e2cb459055394267527994` |

The classifier is required for the application to analyze anything. The novelty artifact is optional for classification but required to demonstrate the novelty result. The project does not configure a hosted model download. Do not substitute the historical Random Forest backup or an unverified joblib file.

Use a dedicated temporary history file for a presentation rather than a personal history database. In the first PowerShell terminal:

```powershell
$env:PHISHGUARD_DB_PATH = Join-Path $env:TEMP 'PhishGuard-final-demo.sqlite3'
.\.venv\Scripts\Activate.ps1
python -m backend.src.api
```

In a second terminal, from the repository root:

```powershell
npm.cmd run dev
```

Open `http://localhost:5173`. Confirm the API at `http://127.0.0.1:8000/healthz` returns `status: ready`, `model_ready: true`, and `database_ready: true`.

## Demonstration sequence

1. **URL path:** open Analyze, choose URL, and submit `https://example.com/login?source=demo`. Show the returned prediction without describing it as ground truth. Point out the version/threshold/scores, the separate measured-feature list, the contribution list, intercept/logit reconciliation, and the independent novelty result.
2. **Email path:** choose Email and paste this synthetic message:

   ```text
   From: demo@example.test
   Subject: Synthetic link screening demonstration
   MIME-Version: 1.0
   Content-Type: multipart/alternative; boundary=demo

   --demo
   Content-Type: text/plain; charset=utf-8

   Review https://example.org/plain-demo
   --demo
   Content-Type: text/html; charset=utf-8

   <a href="https://example.net/html-demo">Review</a>
   --demo--
   ```

   Show that both links receive URL predictions and the response says the email itself is not classified or saved. The example domains are not ground-truth samples.
3. **History:** show that the URL analysis appears with its stored explanation and novelty result. Confirm the email links did not add history. Open the detail view, then use individual deletion if desired. Do not clear a personal database.
4. **Failure behavior (optional API demonstration):** a missing novelty artifact yields `available: false` while classifier analysis works. A missing classifier yields `model_unavailable` and HTTP 503, with no fabricated prediction. Malformed URL input returns HTTP 422.

## Final verification commands

From the repository root, with `.venv` active:

```powershell
python -m pytest backend\tests -q
npm.cmd run lint
npm.cmd run build
git diff --check
```

The completed run for this review: backend **73 passed**; frontend lint passed; production build passed; `git diff --check` passed. API integration used temporary SQLite databases and the active artifacts; no real user history was used.

## Files that must accompany the project

### To run the full application

- All backend source under `backend/src/`, frontend source under `src/`, `public/`, `index.html`, Vite/TypeScript configuration, `package.json`, `package-lock.json`, `.python-version`, and both requirements files.
- The trusted active classifier artifact at `outputs/phase-a/url_model.joblib` and, for complete novelty functionality, `outputs/phase-a-novelty/novelty_detector.joblib`.
- No dataset or saved SQLite file is required for runtime startup. The API creates/migrates the local database. Do not include a user's `analysis_history.sqlite3` file.

### To reproduce training or the external evaluation

- For training or the evaluator's overlap analysis: `data/raw/PhiUSIIL_Phishing_URL_Dataset.csv` (56,854,345 bytes; SHA-256 `a236549cd369cd80bd478ff8e1779cbf44c58d5c3f79f7a51a1adbed7d06d1c6`). The verified source archive is also in `data/raw/`; its provenance and checksum are in [data/README.md](../data/README.md).
- To rerun external scoring: `outputs/external-evaluation/input/URL-dataset.csv` (32,312,600 bytes; SHA-256 `accb2dfbfd3329a8b5cb1b85dcad90314a660c272be755cb45d0f6865014b466`), plus both model artifacts and the PhiUSIIL CSV. Command: `python -m backend.src.evaluate_external --external outputs/external-evaluation/input/URL-dataset.csv`.
- To distribute the recorded result without rerunning it, include `docs/EXTERNAL_EVALUATION.md`, `outputs/external-evaluation/evaluation.json`, and `outputs/external-evaluation/manifest.json`. Keep the report's dataset attribution, class mapping and limitations with the metrics.

## Git and packaging inventory

`data/raw/` and `outputs/` are excluded by `.gitignore`; this excludes the source CSV/archive, classifier and novelty artifacts, model backups/candidates, training metrics, and external evaluation inputs/outputs. `.venv/`, `node_modules/`, `.pytest_cache/`, and `dist/` are also excluded. SQLite databases and WAL/SHM files under `backend/data/` are excluded. `artifacts/screenshots/` is **not** ignored and appears as untracked content in this working tree. The current images are stale prototype mockups that claim analysis/history are disconnected; do not submit them as current application screenshots. Keep them in the workspace and capture the running app afresh only if screenshots are required. Do not clean or delete the existing files as part of packaging.

Before submission, inspect `git status --short` and `git status --short --ignored`. Review every pre-existing modified and untracked item; do not assume this working tree is a clean checkout or stage files without reviewing them.
