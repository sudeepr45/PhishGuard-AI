# 5–7 minute demonstration guide

## Before presenting

Follow the acquisition and setup steps in the root [README](../README.md). The ignored model artifact must exist at `outputs/phase-a/url_model.joblib` before starting the API; obtain it from the project team as a trusted file or reproduce it manually from the documented UCI dataset and training command. Do not run model training as part of the live demo. Use a fresh or explicitly configured local history database if you want a clean history page.

## Suggested sequence

### 0:00–0:45 — Problem and scope

Introduce phishing URLs as the classification problem. State that PhishGuard AI is an academic URL-string research prototype. It does not visit a destination or verify its present safety.

### 0:45–1:30 — Explain the approach

Show the About page. Explain that the backend extracts 17 deterministic measurements from canonical URL text and passes them to Logistic Regression (`url-classifier-3`). The explanation shows standardized coefficient contributions that sum with the intercept to the model logit; these are mathematical terms, not causal proof. The separate Isolation Forest (`url-novelty-1`) reports unusualness and does not alter the classification. Email support parses pasted messages offline and screens links; it is not an email classifier. The system does not fetch pages or consult reputation data.

### 1:30–2:00 — Start the application

In one PowerShell terminal, start the backend from the repository root:

```powershell
.\.venv\Scripts\Activate.ps1
python -m backend.src.api
```

In a second terminal:

```powershell
npm.cmd run dev
```

Open `http://localhost:5173` and, if useful, show `http://127.0.0.1:8000/healthz` reporting model and database readiness.

### 2:00–3:00 — Submit a URL

Use one of these inert example-domain URLs as demonstration input:

- `https://example.com/`
- `https://example.org/account`
- `http://example.net/checkout?step=1`

These strings are for demonstrating the interface. They are not labeled here as phishing or legitimate ground truth. The model may classify an example-domain URL either way; show the returned output without presenting it as a verified fact about that domain.

### 3:00–4:15 — Explain the result

Point out the returned prediction, model version, decision threshold and uncalibrated scores. Review the 17 measured URL values separately from the ranked positive and negative model contributions. Show the intercept and reconstructed logit if time permits. Then explain the separate novelty flag and frozen threshold; unusual does not mean phishing.

### 4:15–5:30 — Show persistent history

Open History. Show the saved URL, timestamp, original prediction, model version and score. Open the record and explain that it displays the saved result without rerunning inference. Delete the demonstration record only after confirming the browser prompt.

### 5:30–6:30 — Limitations and future scope

If time permits, switch to email triage and submit a synthetic MIME message containing a plain-text URL and an HTML link. Point out parsed headers, URL-level predictions, and the transient/no-save notice. Authentication-Results text is unverified; SPF, DKIM and DMARC are not checked. Disclose the external classifier's 0.8619 legitimate false-positive rate and novelty ROC-AUC of 0.4413. These results, shared-feed provenance limits, and the random non-temporal PhiUSIIL evaluation do not establish strong generalization. Page fetching, DOM inspection and an email classifier are future work, not implemented features.

## Presenter reminders

- Say “the model predicts” or “the model returned”; do not say a URL is confirmed malicious or safe based on this application.
- Do not call model scores calibrated probabilities.
- Distinguish measured URL fields from the model's mathematical contribution values.
- Do not use real user URLs or expose local history during the demonstration.
- If deleting history, use the application's confirmation and explain that this clears rows, not the SQLite schema.
