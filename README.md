# HORUS — AI-powered Log Intelligence & Incident Investigation Platform

Milestones 1-6.1 implemented: foundation + ingestion/parsing + detection + incident correlation + investigation + AI investigation (deterministic evidence, provider-agnostic, no autonomous remediation).
M7.1 adds React frontend shell (no business logic duplication).

No RAG/embeddings/vector DB, no Docker, no auth, no heavy UI kit yet.

## Target stack

**Backend (M1-M6.1):**
- **Python 3.12** (3.12+ compatible)
- FastAPI + Uvicorn
- SQLAlchemy 2.0 + SQLite (PostgreSQL-compatible, Alembic migrations from M3)
- Pydantic v2 + pydantic-settings
- Pytest + httpx TestClient (httpx used for LLM provider HTTP)
- Alembic (from M3)
- Dependency management: `backend/requirements.txt` only

**Frontend (M7.1):**
- React 18 + TypeScript 5 (strict) + Vite 6
- React Router 6 + TanStack Query 5
- Tailwind CSS 3 + lucide-react + date-fns (installed, used when needed)
- Vitest + Testing Library + MSW (for tests)

## Project layout (M7.1)

```text
Horus/
├── backend/
│   ├── alembic/                 # migrations (M3-M4, M5-M6 add no migration)
│   │   ├── versions/ee6daff0d589_baseline_m1_m2.py
│   │   ├── versions/2766f85eb50d_add_detection_tables.py
│   │   └── versions/88d0e2ecf30b_add_incident_correlation.py
│   ├── app/
│   │   ├── main.py              # create_app() + lifespan (parsers + detection)
│   │   ├── core/config.py       # + AI_PROVIDER/MODEL/API_KEY/TIMEOUT etc.
│   │   ├── core/logging_config.py
│   │   ├── api/v1/              # health, events, ingestion, alerts, rules, detection, incidents, correlation, investigation, investigate
│   │   ├── db/session.py        # engine + get_db + init_db + FK pragma
│   │   ├── models/              # event, detection_rule, alert, alert_event, incident, incident_alert
│   │   ├── detection/           # threshold/frequency rules
│   │   ├── correlation/         # source_ip/host strategies + engine
│   │   ├── investigation/       # service, timeline, summary (dynamic)
│   │   ├── ai/                  # schemas, evidence_selector, prompt, provider, validators, investigator (M6)
│   │   ├── services/            # detection + incident_correlation
│   │   └── schemas/             # detection, incident, investigation
│   ├── tests/                   # isolated in-memory DB per test (217 total)
│   └── requirements.txt
├── frontend/                    # M7.1 React shell
│   ├── index.html
│   ├── vite.config.ts           # proxy /api → localhost:8000, alias @ → src, vitest config
│   ├── tsconfig.json            # strict, no any
│   ├── tailwind.config.js
│   ├── postcss.config.js
│   ├── package.json
│   ├── .env.example             # VITE_API_BASE_URL
│   ├── public/favicon.svg
│   └── src/
│       ├── app/                 # App.tsx, router.tsx, queryClient.ts
│       ├── layouts/             # AppShell, Header (health), Sidebar (collapsible, drawer)
│       ├── pages/               # Dashboard, Events, Alerts, Incidents, Investigation, NotFound (placeholders)
│       ├── components/ui/       # Card, Badge, Button, Skeleton
│       ├── api/                 # client.ts, health.ts
│       ├── hooks/               # useHealth.ts
│       ├── types/               # api.ts (HealthResponse)
│       ├── styles/              # index.css (Tailwind)
│       └── test/setup.ts
├── .env.example
└── README.md
```

## Development (One-Command Startup)

From the project root:

```powershell
# 1. Install root deps (concurrently) + frontend deps
npm install

# 2. Start both backend + frontend with one command
npm run dev
```

This starts:
- Backend (FastAPI + Uvicorn): `http://127.0.0.1:8000`
- Frontend (Vite + React): `http://localhost:5173`
- API docs: `http://127.0.0.1:8000/docs`

Process output is prefixed with `[BACKEND]` and `[FRONTEND]` for clarity. Press `Ctrl+C` to stop both.

### Alternative: Separate terminals (if needed)

```powershell
# Terminal 1 - Backend
cd backend
uvicorn app.main:app --reload

# Terminal 2 - Frontend
cd frontend
npm run dev
```

## Setup (Windows PowerShell)

Requires Python 3.12+. Verify with `python --version`.

```powershell
# 1. Clone / open repo
cd C:\Users\avina\Desktop\Projects\Horus

# 2. Create and activate venv
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 3. Install deps
pip install -r backend\requirements.txt

# 4. Configure env (optional for M1 defaults)
copy .env.example .env
# Edit .env if needed: DATABASE_URL=sqlite:///./horus.db
```

Linux/macOS equivalent:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
cp .env.example .env
```

## Database migrations (M3-M6.1)

M3-M4 use Alembic. History: `ee6daff0d589` (baseline events) → `2766f85eb50d` (detection) → `88d0e2ecf30b` (incidents). **M5-M6 add no migrations** (dynamic investigation/AI).

| Scenario | Commands (from `backend/`) |
|----------|----------------------------|
| Fresh DB | `python -m alembic upgrade head` |
| Existing M1/M2 DB | `python -m alembic stamp ee6daff0d589` then `python -m alembic upgrade head` |
| Existing M3 DB | `python -m alembic upgrade head` (applies 88d0e2ecf30b) |

`alembic current` should show `88d0e2ecf30b (head)` on fresh or upgraded DB.
Existing event/alert data is preserved; only new tables are added.

Default detection rules (`BruteForceLogin`, `ErrorSpike`) are seeded on app startup (idempotent, not in migration).

## Run locally

From `backend/` (so `app` imports resolve):

```powershell
cd backend
# Ensure DB is migrated (fresh or existing)
python -m alembic upgrade head
# Or for existing M1/M2 DB: python -m alembic stamp ee6daff0d589; python -m alembic upgrade head

uvicorn app.main:app --reload
```

Then open:

- API root: <http://127.0.0.1:8000/>
- Health: <http://127.0.0.1:8000/api/v1/health>
- Ingest: <http://127.0.0.1:8000/api/v1/ingest>
- Detect: <http://127.0.0.1:8000/api/v1/detect>
- Correlate: <http://127.0.0.1:8000/api/v1/correlate> (strategy source_ip/host)
- Alerts: <http://127.0.0.1:8000/api/v1/alerts>
- Rules: <http://127.0.0.1:8000/api/v1/rules>
- Incidents: <http://127.0.0.1:8000/api/v1/incidents>
- Investigation: <http://127.0.0.1:8000/api/v1/incidents/{id}/investigation?include_events=true&include_timeline=true>
- AI Investigation: <http://127.0.0.1:8000/api/v1/incidents/{id}/investigate> (POST, requires AI_PROVIDER config)
- Interactive docs: <http://127.0.0.1:8000/docs>

Expected health response:

```json
{"status": "ok", "app": "Horus", "env": "dev", "database": "connected"}
```

## Frontend (M7.1) — React Shell

**Prerequisites:** Node 20+ (`node --version`), backend running on `http://localhost:8000`.

```powershell
# 1. Install
cd frontend
npm install

# 2. Configure env (VITE_ prefix is exposed to browser — never put secrets)
copy .env.example .env
# Edit frontend/.env if needed:
# VITE_API_BASE_URL=http://localhost:8000

# 3. Run dev server (proxy /api → localhost:8000)
npm run dev
# → http://localhost:5173

# 4. Build
npm run build

# 5. Tests
npm run test:run
# or watch: npm run test
```

**Env:** `frontend/.env.example` contains `VITE_API_BASE_URL=http://localhost:8000`. Do not commit `frontend/.env`. `VITE_` vars are public.

**Backend URL:** `src/api/client.ts` reads `import.meta.env.VITE_API_BASE_URL` (fallback `http://localhost:8000`), `vite.config.ts` proxies `/api` in dev.

**Health:** Header shows `System operational` / `Backend unavailable` / `Checking…` via `useHealth()` → `healthApi.getHealth()` → `GET /api/v1/health` polled 30s. Outage does not destroy shell.

### Example: ingest → detect → correlate → investigate → AI investigate

```powershell
# Ingest 5 failed logins from same IP (all within 60s window)
Invoke-RestMethod -Uri http://127.0.0.1:8000/api/v1/ingest -Method Post -ContentType "application/json" -Body (@{
  logs = @(
    '{"timestamp":"2026-09-14T10:00:00Z","level":"ERROR","message":"fail","ip":"10.0.0.5"}',
    '{"timestamp":"2026-09-14T10:00:05Z","level":"ERROR","message":"fail","ip":"10.0.0.5"}',
    '{"timestamp":"2026-09-14T10:00:10Z","level":"ERROR","message":"fail","ip":"10.0.0.5"}',
    '{"timestamp":"2026-09-14T10:00:15Z","level":"ERROR","message":"fail","ip":"10.0.0.5"}',
    '{"timestamp":"2026-09-14T10:00:20Z","level":"ERROR","message":"fail","ip":"10.0.0.5"}'
  )
  source = "auth-service"
} | ConvertTo-Json -Depth 4)

# Run detection (inclusive window)
Invoke-RestMethod -Uri http://127.0.0.1:8000/api/v1/detect -Method Post -ContentType "application/json" -Body (@{
  window_seconds = 60
  evaluation_time = "2026-09-14T10:00:30Z"
} | ConvertTo-Json)

# Correlate alerts into incidents (one strategy per run, default source_ip)
Invoke-RestMethod -Uri http://127.0.0.1:8000/api/v1/correlate -Method Post -ContentType "application/json" -Body (@{
  window_seconds = 3600
  evaluation_time = "2026-09-14T10:01:00Z"
  strategy = "source_ip"
} | ConvertTo-Json)

# List incidents
Invoke-RestMethod -Uri http://127.0.0.1:8000/api/v1/incidents
# Investigation context (dynamic, deterministic, bounded)
Invoke-RestMethod -Uri http://127.0.0.1:8000/api/v1/incidents/1/investigation
# AI investigation (requires AI_PROVIDER config, e.g. mock/gemini/groq/ollama)
# With mock (for testing): set AI_PROVIDER=mock in .env, then:
Invoke-RestMethod -Uri http://127.0.0.1:8000/api/v1/incidents/1/investigate -Method Post

# Update lifecycle (open → investigating → resolved only)
Invoke-RestMethod -Uri http://127.0.0.1:8000/api/v1/incidents/1 -Method Patch -ContentType "application/json" -Body (@{status="investigating"} | ConvertTo-Json)
```

## Environment variables

| Name | Default | Purpose |
|---|---|---|
| `APP_NAME` | `Horus` | FastAPI title + health payload |
| `APP_ENV` | `dev` | Environment label |
| `LOG_LEVEL` | `INFO` | stdlib logging level |
| `DATABASE_URL` | `sqlite:///./horus.db` | SQLAlchemy URL. Switch to `postgresql+psycopg2://...` later with no code change |
| `AI_PROVIDER` | `disabled` | AI provider: `disabled`/`mock`/`gemini`/`groq`/`ollama` (server-side only) |
| `AI_MODEL` | `gemini-2.5-flash` | Model name for provider (`openai/gpt-oss-120b` for groq) |
| `AI_API_KEY` | `` | API key (env only) |
| `AI_GROQ_API_KEY` | `` | Groq API key, from console.groq.com (env only) |
| `AI_TIMEOUT` | `30` | Provider timeout seconds |
| `AI_PROMPT_VERSION` | `m6.1-v1` | Prompt version for provenance |
| `AI_SCHEMA_VERSION` | `m6.1-v1` | Schema version for provenance |

Never commit `.env`. See `.env.example`.

## Tests

**Backend** — from `backend/`:

```powershell
cd backend
pytest -v
```

Tests use an isolated in-memory SQLite DB (`StaticPool`) via `tests/conftest.py`
and never touch `horus.db`. M3-M4 seed default rules per test via `ensure_default_rules`.

Covered (352 tests: M1-M6 suite plus detection-expansion and admin-reset tests):
- Health, events CRUD, ingestion (json/kv/text), normalizer, parsers, registry
- Detection rules: BruteForce (threshold, window inclusive, multi-IP, filter), ErrorSpike (rate AND min_events, group_by)
- New rules (each: positive/below-threshold/outside-window/missing-fields/unrelated/severity/identity/evidence/context/cooldown): PortScan, WebScan, AuthenticationAnomaly, SQLInjection, XSSAttempt, MalwareDetection, PrivilegeEscalation, SuspiciousProcess, DNSAnomaly, APIAbuse, DataTransferAnomaly, AccountTakeover, SecurityBlockBurst, plus all-rules synthetic fixture smoke coverage
- DetectionEngine (evaluation_time deterministic, rule filter), DetectionService (cooldown, evidence links)
- Correlation strategies: source_ip/host (same/different, boundary, missing, conflicting, priority/fallback), engine (one strategy per run, deterministic sort), service (reuse open/investigating, resolved not reused, max severity, first/last_seen, future excluded, rule_names filter, atomic)
- APIs: alerts, rules, detection, incidents (lifecycle open→investigating→resolved, filters), correlate (strategy default, validation)
- Investigation (M5): empty/one/multiple/shared events, deduplication, unified timeline (event before alert, equal ts), deterministic ordering, UTC, missing fields, correlation metadata, summary counts, entity extraction/dedup, detection metadata, raw_log, 404, truncation (alerts 100/events 500/timeline 600), include flags, dynamic freshness, orphan handling, determinism
- AI Investigation (M6): evidence selector (empty/normal, limits earliest+latest, raw_log 500, total 25k, truncation meta, stable IDs), prompt (system instructions, delimiters, untrusted data, truncation warning), provider (success/timeout/unavailable/auth/rate_limit), validators (valid/malformed/missing/invalid enum/fact without evidence/inference without confidence/unknown ID/hallucinated), security (prompt injection in message/raw_log/host/service/extra_data), API (success/missing/empty/timeout/unavailable/malformed/invalid citation, regression M1-M5 unaffected)

**Frontend (M7.1)** — from `frontend/`:

```powershell
cd frontend
npm run test:run   # Vitest run
# or watch: npm run test
```

Covered (30 tests):
- API client (success, non-2xx, malformed JSON, network error, 204)
- Health hook (loading, success, error)
- Router (dashboard/events/alerts/incidents/investigation, 404, redirect /→/dashboard)
- Sidebar (links, active state, collapse/expand, accessible labels)
- Header (branding, health loading/healthy/error, menu toggle)
- AppShell (header+sidebar+content, collapse, mobile drawer, Escape)

## Detection rules

HORUS currently provides deterministic detection coverage for a defined set of security-event patterns.
Additional detection rules can be added through the rule interface (`BaseRule` subclass + registry
`rule_type` + `DetectionRule` seed row). The LLM is never involved in detection.

| Rule | Detection pattern | Main evidence fields | Default severity |
|---|---|---|---|
| BruteForceLogin | 5+ failed logins, same IP, 60s | `extra_data.ip` | HIGH |
| ErrorSpike | 10+ ERRORs/service AND ≥20/min, 300s | `service`, `level` | MEDIUM |
| PortScan | 10+ distinct destination ports, one IP, 60s | `extra_data.ip`, `extra_data.destination_port` | HIGH |
| WebScan | 8+ distinct suspicious paths, one IP, 60s | `extra_data.ip`, `extra_data.path` | MEDIUM |
| AuthenticationAnomaly | 5+ distinct accounts, one IP, 60s (spray) | `extra_data.ip`, `extra_data.user` | HIGH |
| SQLInjection | explicit `attack_type`/WAF rule or strong payload signatures | `extra_data.attack_type`, `rule`, `payload`, `path` | HIGH |
| XSSAttempt | explicit `attack_type`/rule or strong payload signatures | `extra_data.attack_type`, `rule`, `payload` | HIGH |
| MalwareDetection | explicit endpoint verdict / threat family only | `extra_data.detection_type`, `threat_name`, `verdict` | CRITICAL |
| PrivilegeEscalation | allowlisted action or privileged role transition | `extra_data.action`, `old_role`, `new_role`, `target_user` | HIGH |
| SuspiciousProcess | explicit verdict, office-spawned shell, encoded combo, LOLBin download | `extra_data.process`, `parent_process`, `command`, `verdict` | HIGH |
| DNSAnomaly | malicious verdict OR 50+ distinct domains/host, 300s | `extra_data.domain`, `verdict`, host | MEDIUM |
| APIAbuse | 100+ API requests, one IP, 60s | `extra_data.ip`, `endpoint`, `method`, `status_code` | MEDIUM |
| DataTransferAnomaly | single outbound transfer ≥100 MiB | `extra_data.bytes_sent`, `direction`, `destination_ip` | HIGH |
| AccountTakeover | 5+ failures then success, same account, 300s | `extra_data.user`, `action` | HIGH |
| SecurityBlockBurst | 20+ explicit blocks, one source, 60s | `extra_data.action`, `source_ip` | MEDIUM |

Defaults (all rules enabled; tune via `DetectionRule` config/severity/cooldown or `PATCH /api/v1/rules/{name}`):

```text
BruteForceLogin      threshold=5, window=60s, cooldown=300s
ErrorSpike           min_events=10, window=300s, rate≥20/min, cooldown=600s
PortScan             threshold_ports=10, window=60s, cooldown=300s
WebScan              threshold_paths=8, window=60s, cooldown=300s
AuthenticationAnomaly threshold_accounts=5, window=60s, cooldown=300s
SQLInjection / XSSAttempt / MalwareDetection / PrivilegeEscalation / SuspiciousProcess
                     window=300s, cooldown=300–600s (signature/verdict driven)
DNSAnomaly           threshold_unique_domains=50, window=300s, cooldown=600s
APIAbuse             threshold_requests=100, window=60s, cooldown=600s
DataTransferAnomaly  threshold_bytes=104857600 (100 MiB), window=3600s, cooldown=600s
AccountTakeover      fail_threshold=5, window=300s, cooldown=900s
SecurityBlockBurst   threshold_blocks=20, window=60s, cooldown=300s
```

Example synthetic event (TEST-NET documentation range — never real data):

```json
{"timestamp": "2026-09-14T10:00:00Z", "level": "ERROR", "message": "Failed password",
 "source": "auth-service", "ip": "192.0.2.5"}
```

Test fixtures for every rule live in `backend/tests/fixtures/synthetic_security_events.py`.

Known limitations:

* Rules only see what telemetry provides — missing fields mean no detection, never a guess.
* Signature rules (SQLi/XSS) catch known-strong patterns; novel obfuscation can pass through.
* No geo/impossible-travel math (no reliable location data); account takeover uses fail-then-success only.
* DataTransferAnomaly needs explicit size + outbound direction; it reports "large outbound
  transfer detected", never "data was stolen".
* Cooldowns suppress repeat alerts per group key; tune `cooldown_seconds` per environment.

## Architectural decisions (ADR summary)

1. **Alembic from M3.** M1/M2 used `create_all()`. M3 introduces Alembic with baseline `ee6daff0d589` (events) + `2766f85eb50d` (detection) + `88d0e2ecf30b` (incidents). M5-M6 add no migration (dynamic investigation/AI). Fresh DB: `upgrade head`. Existing M1/M2 DB: `stamp ee6daff0d589` → `upgrade head` (preserves events).
2. **`requirements.txt` only.** Lowest friction for M1. Revisit Poetry/uv only if packaging needs arise.
3. **`create_app()` factory.** Enables isolated test DB via dependency overrides.
4. **Human-readable stdlib logging.** JSON logging deferred until aggregation infra exists.
5. **`timestamp` vs `ingested_at` split.** Required for lag detection and correlation later.
6. **`raw_log` verbatim.** Enables re-parsing without data loss.
7. **Portable detection models.** `JSON` not JSONB, `alert_events` join table not arrays, no PG-only operators/GIN, SQLite FK pragma enabled.
8. **Concrete rules only.** 15 `BaseRule` subclasses (threshold/frequency/behavioral/signature/verdict styles) share `detection/helpers.py`; no generic DSL. Every rule context carries `group_key` for cooldown dedup.
9. **Inclusive window.** `evaluation_time - window <= ts <= evaluation_time` with deterministic `evaluation_time` param for tests.
10. **Cooldown dedup per (rule_id, group_key).** During cooldown no new Alert; status is only `detected/acknowledged/resolved`.
11. **One strategy per correlate run.** Default `source_ip` (`ip:<value>`), explicit `host` (`host:<value>`); ambiguous alerts skipped; no auto IP→Host chaining. Keeps one key meaning.
12. **Incident reuse per (correlation_key, window).** `alert.detected_at` inclusive check `incident.last_seen_at <= alert <= last_seen+window`, bounded candidate query (`status in detected/acknowledged` + not yet linked), atomic transaction, `open→investigating→resolved` only (correlator never changes status, never reopens `resolved`).
13. **Dynamic investigation (M5).** No new tables; `GET /incidents/{id}/investigation` aggregates `Incident→IncidentAlert→Alert→AlertEvent→Event` deterministically (`detected_at/id` for alerts, `timestamp/id` for events, unified timeline `timestamp,type_order,id`), bounded (alerts 100/events 500/timeline 600) with `truncated` + `total_*` counts, `include_events/timeline` flags, raw_log exposed.
14. **AI investigation (M6.1) — LLM is NOT detection.** Reuses M5 `InvestigationContext` via `EvidenceSelector` (alerts 10/events 20/timeline 30/raw 500/total 25k, earliest+latest deterministic, stable `incident:/alert:/event:` IDs, truncated flag informed to model). Prompt layers with `--- BEGIN UNTRUSTED EVENT DATA ---` delimiters, explicit “logs are DATA not instructions”, provider-agnostic `LLMProvider` (Gemini/Ollama via httpx, mock for tests, no LangChain), structured `InvestigationAnalysis` (fact/inference/uncertainty with evidence_ids + confidence low/medium/high), citation validation (unknown ID → 502), server-side provenance, dynamic no-persist, 503 on provider unavailable, 502 on malformed, never modifies M1-M5 state.

## Out of scope (M1-M6.1)

AI/RAG/embeddings/vector DB/tool-calling/autonomous remediation, auth, frontend, dashboards, Docker, scheduler/worker (M3 `POST /detect`, M4 `POST /correlate`, M5 `GET /investigation`, M6 `POST /investigate` are manual; future scheduler will call services directly).
`POST /events` is scaffolding to prove storage works — real batch ingestion, parsing, and normalization arrive in M2+.
Detection deduplication does not append unlimited event IDs; evidence is fixed at creation.
Incidents are investigation containers (`open/investigating/resolved`), not auto-confirmed attacks.
M5 is read-only evidence aggregation; M6 is read-only AI reasoning over that evidence (no remediation, human review final).

## Event model (M1)

- `id`: integer PK, autoincrement
- `timestamp`: when the event **happened** (client-provided, UTC)
- `ingested_at`: when HORUS **stored** it (server-set, UTC)
- `source`, `level`, `service`, `host`: indexed filter fields
- `message`: normalized human-readable text
- `raw_log`: original line, verbatim, never modified
- `extra_data`: nullable JSON for remaining structured fields

Only portable column types are used (`Integer`, `String`, `Text`,
`DateTime(timezone=True)`, `JSON`) for SQLite → PostgreSQL compatibility.

## Detection models (M3)

- `detection_rules`: `id, name (unique), rule_type, config (JSON), enabled, severity, cooldown_seconds`
- `alerts`: `id, rule_id FK, rule_name, status, severity, detected_at, summary, context (JSON), first/last_event_id`
- `alert_events`: `alert_id FK, event_id FK, PK=(alert_id, event_id)`

## Incident models (M4)

- `incidents`: `id, title, status(open/investigating/resolved), severity(max of alerts), correlation_key(ip:/host:), context{strategy,window,key}, first/last_seen_at`
- `incident_alerts`: `incident_id FK, alert_id FK, PK(incident_id,alert_id), UNIQUE(alert_id)` — one alert → at most one incident, no reassignment in M4
- Evidence: `Incident → IncidentAlert → Alert → AlertEvent → Event` (no data copying)

