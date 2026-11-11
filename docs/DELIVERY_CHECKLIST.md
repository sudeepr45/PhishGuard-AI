# Delivery readiness checklist

This checklist describes what a clean checkout needs and what requires a separate distribution decision. It does not commit, package or publish files.

## A. Source and project files to include in source control

- [ ] Root `README.md`, `.gitignore`, `.python-version`, `package.json` and `package-lock.json`.
- [ ] Frontend source under `src/`, `public/favicon.svg`, Vite and TypeScript configuration.
- [ ] Backend source under `backend/src/`, backend tests under `backend/tests/`, and pinned `backend/requirements.txt` / `backend/requirements-dev.txt`.
- [ ] Project documentation: `backend/README.md`, `backend/FEATURES.md`, `data/README.md`, and the documents under `docs/`.
- [ ] No generated Python caches, build output or local database files in source control.
- [ ] Review all existing modified and untracked project files before staging. Do not assume that files in the working tree have already been added to Git.

## B. Large or generated artifacts requiring a distribution decision

- [ ] **Dataset:** `data/raw/PhiUSIIL_Phishing_URL_Dataset.csv` (56,854,345 bytes in the inspected working tree) and its source archive (15,376,007 bytes) are ignored by Git. A clean clone must obtain the UCI archive using the URL and SHA-256 in `data/README.md`, then extract the CSV. Confirm attribution and the UCI CC BY 4.0 license before redistributing it.
- [ ] **Trained model:** `outputs/phase-a/url_model.joblib` (SHA-256 `638dcbadf27792784483fc1daa48fa1e857fb465ccdad02db16c3c49a927ef71`) is the promoted `url-classifier-3` Logistic Regression artifact. It is ignored and not tracked. The prior Random Forest artifact is preserved at `outputs/model-backups/url-classifier-2-random-forest-pre-promotion/url_model.joblib` (SHA-256 `c0271c904001348e1ad1aa9b2851afe3b4fbfe79c35310375244a87fd338d0d3`). No hosted model download is configured. A clean checkout must either receive a trusted compatible artifact and place it at the active path, or obtain the dataset and manually run the documented training command. Startup never trains automatically. Joblib artifacts can execute code when loaded; accept only a trusted artifact.
- [ ] **Evaluation outputs:** original model reports are under `outputs/phase-a/` and `outputs/phase-a-novelty/`. The independent external evaluation report and manifest are under ignored `outputs/external-evaluation/`; rerunning it also requires the external URL CSV and local PhiUSIIL CSV. Decide whether to include these ignored files in the submission package.
- [ ] **Screenshots:** the current `artifacts/screenshots/` directory is untracked and includes `analysis-email-desktop.png`. These screenshots are stale prototype mockups: they show disconnected analysis and history, planned novelty/email flows, and an old About page. Do not submit them as screenshots of the implemented application. Keep the untracked images; generate new captures from the running current UI only if the submission requires screenshots.
- [ ] Decide whether the final academic submission needs a copy of the model, dataset, screenshots or evaluation artifacts, and document their provenance/checksums if included. Do not silently add large files to Git.

## C. Local-only files that must remain excluded

- [ ] Python virtual environment `.venv/`, Python caches and `.pytest_cache/`.
- [ ] Node `node_modules/`, Vite `dist/` and other generated build output.
- [ ] `data/raw/`, `outputs/`, generated models, checkpoints and local experiment outputs unless an explicit distribution decision changes this policy.
- [ ] `backend/data/*.sqlite3` and SQLite `-wal` / `-shm` files. These may contain submitted URLs and analysis history; do not distribute user history.
- [ ] `.env`, `.env.*`, local credentials and machine-specific configuration. `.env.example` is the sole allowlisted pattern and must contain placeholders only if one is added later.
- [ ] Logs, temporary databases, personal test URLs and browser downloads.

## Fresh-checkout startup

1. Install Python 3.12.10 and Node.js 20.19+ or 22.12+.
2. Create `.venv`, install `backend\requirements-dev.txt`, and run `npm.cmd ci` from the repository root.
3. Obtain the dataset archive from the documented UCI source and verify its hash if reproducing the model.
4. Run `python -m backend.src.training --dataset 'data\raw\PhiUSIIL_Phishing_URL_Dataset.csv' --output 'outputs\phase-a'` manually, or place a trusted compatible `url_model.joblib` at the expected output path.
5. In one terminal, activate `.venv` and run `python -m backend.src.api`.
6. In a second terminal, run `npm.cmd run dev`; open `http://localhost:5173`. The API is at `http://127.0.0.1:8000`.

Full commands and acquisition hashes are in the root [README](../README.md).

## Verification before submission

- [ ] Run `python -m pytest backend\tests -q` from an active `.venv`.
- [ ] Run `npm.cmd run lint` and `npm.cmd run build` from the repository root.
- [ ] Run `git diff --check` and review `git status --short`, including untracked files.
- [ ] Confirm the expected model artifact exists and reports model version `url-classifier-3`, algorithm `logistic_regression`, and the 17-feature schema. Confirm `/healthz` reports model and database readiness.
- [ ] Check ignored files with `git status --short --ignored`; confirm no local SQLite history, raw dataset, model or secret file is staged.
- [ ] Search the frontend and repository for credentials or personal URL/history data before packaging.
- [ ] Confirm no model or dataset file was accidentally copied into `public/` or frontend build assets.
- [ ] Perform manual browser checks of Home, Analyze, loading/error/result states, History, detail, pagination/deletion, About, navigation and responsive desktop/mobile layouts. Browser visual testing was not performed during the previous integration phase and remains outstanding.
- [ ] Review screenshots, report wording, both dataset attributions/licenses, external-evaluation limitations and institutional submission requirements. See [the final submission checklist](FINAL_SUBMISSION_CHECKLIST.md).

## Current working-tree notes

The UCI CSV, UCI zip, active model, previous-model backup, and candidate artifacts exist locally but are Git-ignored. The active artifact is the corrected canonical-URL Logistic Regression model; the previous Random Forest is retained as a verified backup. API integration checks use a temporary SQLite database. Promotion did not retrain the model or change the database schema. Existing working-tree modifications and untracked files remain for the project owner to review; nothing has been staged or committed.
