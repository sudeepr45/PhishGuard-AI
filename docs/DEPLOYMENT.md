# Deployment configuration

PhishGuard AI has a local development mode and an explicit anonymous public demo mode. The public mode keeps URL inference and transient email link screening available, but it does not initialize SQLite, save URL analyses, or expose history and interactive API documentation routes. It does not add authentication or per-visitor storage.

## Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `PHISHGUARD_PUBLIC_DEMO` | `false` | Set to `true` to disable URL-analysis persistence, all history endpoints, and OpenAPI/Swagger/ReDoc routes. Other values leave local behavior enabled. |
| `VITE_PUBLIC_DEMO` | `false` | Set to `true` when building the frontend for public demo mode. Hides History navigation, redirects direct history-page visits to Analyze, and removes saved-history claims. |
| `VITE_API_BASE_URL` | `/api` | Frontend API base. The default preserves the Vite `/api` development/preview proxy. For a separately hosted backend, use its origin, for example `https://api.example.org`; trailing slashes are removed. This is a build-time Vite variable. |
| `HOST` | `127.0.0.1` | Host address passed to Uvicorn. Set to `0.0.0.0` when the hosting platform requires binding to all interfaces. |
| `PORT` | `8000` | Integer port passed to Uvicorn; set this from the hosting provider's assigned port. |
| `PHISHGUARD_MODEL_PATH` | `outputs/phase-a/url_model.joblib` | Optional path to the existing compatible URL classifier artifact. |
| `PHISHGUARD_NOVELTY_PATH` | `outputs/phase-a-novelty/novelty_detector.joblib` | Optional path to the existing novelty artifact. Missing/incompatible novelty remains unavailable without disabling URL inference. |
| `PHISHGUARD_CORS_ORIGINS` | unset | Optional comma-separated exact HTTP(S) origins, with no paths or wildcards. If unset/empty, no CORS middleware is added. Credentials are never enabled. |
| `PHISHGUARD_DB_PATH` | `backend/data/analysis_history.sqlite3` | Local-mode SQLite database file. Public demo mode does not initialize or write this database. |

The two public-mode switches are intentionally set independently: `PHISHGUARD_PUBLIC_DEMO=true` protects the backend regardless of client behavior, while `VITE_PUBLIC_DEMO=true` changes the frontend presentation and prevents history navigation/API calls. Set both for a public deployment. Vite variables are embedded when the frontend is built; backend variables must be set in the API process environment before startup.

## Public demo deployment

Configure the API process with `PHISHGUARD_PUBLIC_DEMO=true`, the host's `HOST` and `PORT`, compatible model artifact paths if they differ from defaults, and the exact frontend origin in `PHISHGUARD_CORS_ORIGINS` when frontend and API are hosted separately. Build the frontend with `VITE_PUBLIC_DEMO=true` and `VITE_API_BASE_URL` set to the API origin. A same-origin reverse proxy can instead keep the default `/api` base and route that prefix to FastAPI.

In this mode, `POST /analyze` still executes the selected model and returns its real prediction, explanations, and novelty result, but does not persist the URL or result. Email parsing and extracted-link screening remain transient. `GET /history`, `GET /history/{id}`, both history DELETE endpoints, and `/openapi.json`, `/docs`, and `/redoc` are unavailable. The API reports a clear 404 for disabled history routes. Local mode retains saved history and API documentation when `PHISHGUARD_PUBLIC_DEMO` is absent or false.

This is an anonymous demo, not an authenticated service. It does not provide per-user identity or rate limiting; configure appropriate platform or edge controls if public traffic requires them. Do not describe model scores as calibrated probabilities. The project has no trained email classifier, SPF/DKIM/DMARC verification, or live webpage/DOM inspection.

## Start locally

With the environment variables absent, run the existing local workflow:

```powershell
python -m backend.src.api
npm.cmd run dev
```

The API listens on `127.0.0.1:8000`, Vite uses the `/api` proxy, and successful URL analyses are saved to the configured local SQLite file.
