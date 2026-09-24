# M7 — HORUS Web Dashboard Architecture

**Status:** DESIGN ONLY — Approved for review, no frontend code yet.
**Head:** `88d0e2ecf30b` (M5) + M6.1 AI investigation (dynamic, no migration). 217 tests, 1 warning.
**Stack target:** React + TypeScript + Vite + React Router + TanStack Query + Tailwind CSS.

---

## 1. M7 Goals

Provide a security-operations-grade web UI that makes the deterministic pipeline visible and investigable:

1. System health at a glance.
2. Browse/filter normalized Events (the ground truth).
3. Review deterministic Alerts (why they fired, which rule, which events).
4. Triage correlated Incidents (open/investigating/resolved).
5. Open a rich Investigation page per incident (incident + alerts + events + unified timeline + entities + correlation + detection).
6. Request and inspect AI Investigation (M6.1) with explicit evidence citations and fact/inference/uncertainty separation.
7. Never duplicate detection/correlation/investigation logic in the browser; backend is source of truth.
8. Treat log content and AI output as untrusted data in the UI (escaped rendering, no HTML injection).

Out of scope for M7: auth/RBAC, WebSockets, real-time streaming, notifications, SIEM integrations, autonomous remediation, RAG.

## 2. Current Backend Integration Analysis

**Inspected:** `backend/app/main.py`, `backend/app/api/v1/*.py`, `backend/app/schemas/*.py`, `backend/app/models/*.py`, `backend/app/investigation/*`, `backend/app/ai/*`, `backend/alembic/versions/*`, `backend/tests/*`, `README.md`.

**Existing FastAPI app (`create_app` factory):** `lifespan` does `init_db()` + parser registry + detection rule seeding; routers mounted at `/api/v1`.

**Actual endpoints (verified via grep, no assumptions):**

| Method | Path | Schema | Notes |
|---|---|---|---|
| `GET` | `/api/v1/health` | `{status, app, env, database}` | |
| `POST` | `/api/v1/events` | `EventCreate → EventRead` | single, scaffolding |
| `GET` | `/api/v1/events?limit=1..200` | `list[EventRead]` newest-first | capped, no offset pagination yet |
| `POST` | `/api/v1/ingest` | `RawLogBatch{logs[], source?} → IngestResponse{accepted, failed, results[]}` | batch, deterministic parsing |
| `GET` | `/api/v1/rules` | `list[DetectionRuleRead]` | `?enabled` filter |
| `GET` | `/api/v1/rules/{name}` | `DetectionRuleRead` |  |
| `PATCH` | `/api/v1/rules/{name}` | `{enabled:bool} → DetectionRuleRead` |  |
| `POST` | `/api/v1/detect` | `DetectRequest{window_seconds, evaluation_time?, rule_names?} → DetectResponse{window, evaluation_time, alerts_created, alerts[]}` | manual |
| `GET` | `/api/v1/alerts?status&severity&rule_name&limit` | `list[AlertRead]` `detected_at desc` | `evidence_event_ids` in each |
| `GET` | `/api/v1/alerts/{id}` | `AlertRead` | |
| `PATCH` | `/api/v1/alerts/{id}` | `{status: acknowledged|resolved} → AlertRead` | |
| `POST` | `/api/v1/correlate` | `{window_seconds, evaluation_time?, strategy:source_ip|host, rule_names?} → {window, evaluation_time, strategy, incidents_created/updated, alerts_correlated, incidents[]}` | one strategy per run, default source_ip |
| `GET` | `/api/v1/incidents?status&severity&correlation_key&limit` | `list[IncidentRead]` `last_seen_at desc` | `alert_ids` in each |
| `GET` | `/api/v1/incidents/{id}` | `IncidentRead` + `alert_ids` | |
| `PATCH` | `/api/v1/incidents/{id}` | `{status: investigating|resolved} → IncidentRead` | only `open→investigating→resolved` |
| `GET` | `/api/v1/incidents/{id}/investigation?include_events&include_timeline` | `InvestigationContextResponse{incident, alerts[], events[], timeline[], correlation, summary, entities, detection[]}` | dynamic, bounded (alerts 100/events 500/timeline 600) |
| `POST` | `/api/v1/incidents/{id}/investigate` | `{} → {incident_id, analysis: InvestigationAnalysis, evidence_meta, provenance}` | M6.1, provider server-side, 404/502/503/500 |

**Schemas (strict Pydantic, UTC `DateTime`):** `EventRead`, `DetectionRuleRead`, `AlertRead`, `IncidentRead`, `InvestigationContextResponse` (with `TimelineEntry{type,id,timestamp,summary}`), `InvestigationAnalysis{summary, observations[{statement,type,evidence_ids,confidence}], supporting_evidence, alternative_explanations, recommended_steps, limitations, provenance{provider,model,prompt_version,schema_version,evidence_ids_used,truncated,created_at}}`. Evidence IDs are `incident:<id>`, `alert:<id>`, `event:<id>` (timeline not independently citeable).

**Error handling:** `404` not found, `400` invalid transition, `422` validation, `500` DB failure, `502` malformed AI, `503` provider unavailable — all JSON `detail`.

**Config:** `DATABASE_URL`, `AI_PROVIDER=disabled|mock|gemini|ollama`, `AI_MODEL`, `AI_API_KEY`, `AI_TIMEOUT`, `AI_PROMPT_VERSION` — server-side only, never from browser.

**Tests/migrations:** 217 tests via `StaticPool` in-memory DB; migrations `ee6daff0d589` → `2766f85eb50d` → `88d0e2ecf30b`; M5/M6 add no migration (dynamic).

## 3. Frontend Architecture

**Chosen stack:** `React 18 + TypeScript 5 + Vite 6 + React Router 6 + TanStack Query 5 + Tailwind CSS 3 + lucide-react + date-fns`.

Justification: React/TS/Vite is standard, fast, type-safe; Router for SPA pages; TanStack Query for server state (caching, retries, dedup) — avoids manual `useEffect/fetch`; Tailwind for maintainable utility styling without component library bloat; `lucide-react` is MIT, tree-shakable, consistent; `date-fns` for UTC formatting.

**Rejected:** Heavy UI kit (MUI/Ant) — overkill, forces theming; Redux/Zustand global store — not needed, server state dominates; Chart library initially — no dashboard metrics yet (see §27), add `recharts` only if backend adds stats; LangChain in frontend — never.

**Separation:**
```
React Component (presentational, props only)
  ↓
Feature Hook (useIncidents, useInvestigation) — composes TanStack Query
  ↓
API Service (typed fetch, base URL from env)
  ↓
FastAPI (source of truth)
```

## 4. Final Proposed Folder Structure

```
frontend/
  index.html
  vite.config.ts          # proxy /api → localhost:8000, path alias @ → src
  tsconfig.json           # strict, bundler
  tsconfig.node.json
  package.json
  tailwind.config.js
  postcss.config.js
  public/
    favicon.svg
  src/
    app/
      App.tsx             # RouterProvider, QueryClientProvider, ErrorBoundary
      router.tsx          # createBrowserRouter, route objects, lazy pages
      queryClient.ts      # QueryClient with retry 1, staleTime 30s, cache
    layouts/
      AppShell.tsx        # Header + Sidebar + <Outlet>, responsive
      Header.tsx          # HORUS wordmark, env badge, health indicator
      Sidebar.tsx         # NavLink with active state, collapsible
    pages/
      DashboardPage.tsx
      EventsPage.tsx
      EventDetailPage.tsx
      AlertsPage.tsx
      AlertDetailPage.tsx
      IncidentsPage.tsx
      IncidentDetailPage.tsx  # hosts InvestigationSection + AI section
      NotFoundPage.tsx
    features/
      dashboard/          # DashboardStats, RecentAlerts, RecentIncidents (feature-scoped)
      events/             # EventTable, EventFilters, EventDetailDrawer
      alerts/             # AlertTable, AlertDetail, RuleBadge
      incidents/          # IncidentTable, IncidentHeader, StatusBadge
      investigation/      # Timeline, EvidencePanel, EntitiesCard, CorrelationCard, SummaryCard
      ai/                 # AIInvestigationCard, ObservationList, CitationChips, ProvenanceFooter
    components/
      ui/                 # Button, Card, Badge, Skeleton, EmptyState, ErrorAlert, Dialog, Tabs
      evidence/           # EvidenceChip (alert:12/event:101), EvidenceList
      timeline/           # Timeline, TimelineItem
    api/
      client.ts           # fetch wrapper, baseURL from VITE_API_BASE_URL, error parsing to ApiError
      health.ts
      events.ts
      alerts.ts
      incidents.ts
      investigation.ts
      ai.ts               # postInvestigate
    hooks/
      useHealth.ts
      useEvents.ts
      useAlerts.ts
      useIncidents.ts
      useInvestigation.ts # useQuery for GET investigation
      useAIInvestigation.ts # useMutation for POST investigate
      usePagination.ts
      useFilters.ts
    types/
      api.ts              # Event, Alert, DetectionRule, Incident, InvestigationContext, InvestigationAnalysis, TimelineEntry, etc. — mirrors backend schemas, no any
      ui.ts               # ViewModel helpers if needed
    utils/
      formatDate.ts       # UTC formatting, relative time
      severity.ts         # getSeverityColor, getSeverityOrder, icon
      status.ts           # getStatusColor, getStatusLabel
      evidence.ts         # parseEvidenceId, groupCitation
      sanitize.ts         # escapeHtml, truncate
    styles/
      index.css           # Tailwind base + CSS vars for HORUS palette
```

**Why each:** `app/` = app shell (router/query); `layouts/` = shell chrome; `pages/` = route entry points (thin, compose features); `features/` = feature-oriented, colocated UI + hooks for cohesion (preferred over flat `components/` for M7); `components/ui` = reusable primitives; `components/evidence,timeline` = cross-feature shared; `api/` = typed services (no `fetch` in components); `hooks/` = TanStack Query wrappers (caching); `types/` = single source of truth from backend `schemas/`; `utils/` = pure helpers; `styles/` = Tailwind.

## 5. Application Layout

**Desktop (≥1024px):** Fixed header (56px) + collapsible sidebar (240px, icons-only at 64px when collapsed) + main content with max-width `1280px` centered, 24px padding.

**Header:** Left: HORUS logo/wordmark + `env` badge (`dev` amber). Center: optional global search (deferred, placeholder). Right: health dot (green/amber/red from `GET /health` polled 30s) + link to `/docs` (API docs) + version.

**Sidebar:** `NavLink` items with `lucide` icons:
- Dashboard (`LayoutDashboard`)
- Events (`ScrollText`)
- Alerts (`Siren`)
- Incidents (`Layers`)
- Rules (`ShieldCheck`) — secondary, maybe under Settings
Active state: left border accent + bg `slate-800`. Hover: `slate-700`. Keyboard focus ring.

**Page hierarchy:** `Dashboard` (overview) → `Events` (list → detail drawer) → `Alerts` (list → detail) → `Incidents` (list → detail tab with Investigation + AI) . Breadcrumbs only on detail pages: `Incidents / #12`.

**Responsive:** Sidebar becomes drawer overlay on `<768px` (hamburger), tables become cards, timeline stays vertical. No global search in M7.

## 6. Navigation

| Item | Path | Purpose |
|---|---|---|
| Dashboard | `/` | overview |
| Events | `/events` | paginated table, `→ /events/:id` drawer |
| Alerts | `/alerts` | list, `→ /alerts/:id` |
| Incidents | `/incidents` | list, `→ /incidents/:id` (tabs: Overview / Investigation / AI) |
| Rules | `/rules` | read-only list (optional for M7) |
| Health | via header dot | `GET /health` |

Top nav only for health. No notification bell in M7 (no WebSocket).

## 7. Page Architecture

### 7.1 Dashboard

**Purpose:** 10-second comprehension: “Is HORUS working? Anything open?”

**Widgets (all from existing APIs, no invented metrics):**
- Health card (`GET /health`): app/env/database status.
- Counts (client-side derived, no new endpoint): `total events` = `GET /events?limit=1` is insufficient; instead show `recent events count` or note “Run ingest to see data”. Clearly mark missing `GET /stats` as Future. M7 dashboard will show **recent lists** not aggregates.
- Recent Alerts (`GET /alerts?limit=5`): table with severity/status/rule.
- Recent Incidents (`GET /incidents?limit=5`): severity/status/correlation_key.
- Severity distribution: client-side count from fetched recent alerts (not global).
- Recent Activity: last 5 events (`GET /events?limit=5`).

If no data: empty state “No events yet — ingest logs to begin”.

**Missing API noted:** `GET /stats` (counts by severity/status, last 24h rate) — deferred, M7 will not fake it.

### 7.2 Events

**List:** `GET /events?limit` (currently limit 1..200, no offset). M7 will use `limit=50` default, “Load more” (increase limit) until backend adds `offset`/`cursor` pagination (see §27).

**Table columns:** `timestamp (UTC, sortable) | level (Badge) | source | service | host | message (truncated 120ch)`. Row click → detail drawer.

**Filters (client-side for now, server-side when backend supports):** `level` (multi-select), `source` (text), `service`, `host`, `time range` (date pickers). Since backend `GET /events` has no filter params, M7 will filter in memory on fetched page and clearly label “Client-side filter (fetch 200) — future `GET /events?source=&level=&from=&to=` will be server-side”.

**Detail drawer:** `EventRead` fields: `id, timestamp, ingested_at, source, level, service, host, message, raw_log (pre, escaped, copy button), extra_data (JSON tree, collapsed), parser info` (not yet exposed, note as future).

**Security:** `raw_log` and `message` rendered in `<pre>` with `white-space: pre-wrap`, escaped via React (no `dangerouslySetInnerHTML`).

### 7.3 Alerts

**List:** `GET /alerts?status&severity&rule_name&limit` — M7 will expose these exact filters (they exist). Columns: `severity (color+icon) | rule_name | status | detected_at | summary (truncated)`.

**Detail:** `GET /alerts/{id}` → show `Alert` + `DetectionRule` (via `GET /rules/{name}`) + `Alert Context` (JSON) + `Evidence Events` (fetch `evidence_event_ids` via `GET /events?ids=`? Currently no bulk `ids` endpoint — M7 will fetch each event via `GET /events` list and client filter, or via investigation context as workaround; mark `GET /events?ids=` as small addition).

**Distinction:** Alert header has blue left border “Deterministic” badge; AI section (if linked via incident) is separate amber card (see §10).

### 7.4 Incidents

**List:** `GET /incidents?status&severity&correlation_key&limit` — columns: `severity | status | title | correlation_key (mono) | first_seen | last_seen | alert_count (from alert_ids.length)`.

**Detail:** `GET /incidents/{id}` → header with `title, correlation_key, severity, status (Badge), first/last seen, created_at`. Tabs:
- **Overview:** incident metadata + `alert_ids` chips.
- **Investigation:** embeds `GET /incidents/{id}/investigation` (see §8).
- **AI Investigation:** `POST /incidents/{id}/investigate` trigger + result (see §10).

Path to investigation is single click from header CTA “Investigate →”.

## 8. Incident Investigation Page

**Route:** `/incidents/:id` with tabs, default `investigation` tab loads `GET /incidents/{id}/investigation`.

**Structure (top→bottom, consistent with M5 response):**

1. **Incident Header** — `IncidentRead` + `StatusBadge` + `SeverityBadge` + `CorrelationCard` (strategy/key/window).
2. **Summary Card** — `alert_count, event_count, unique_sources/hosts/services, severity_breakdown, time_span_seconds, truncated` (+ `total_*` if truncated).
3. **Timeline** — unified, vertical, `event` vs `alert` icons, clickable → scrolls to evidence.
4. **Alerts** — `AlertCard` per alert: `rule_name, severity, status, detected_at, summary, context JSON, evidence_event_ids chips`.
5. **Evidence Events** — `EventCard` per event: `timestamp, source, level, service, host, message, raw_log (collapsed), extra_data`.
6. **Entities** — `ips, hosts, services, sources` chips.
7. **Detection** — per alert `rule_name, rule_type, severity, summary, context`.
8. **AI Investigation** — separate section (see §10), not interleaved.

Analyst can answer: what, when, which alerts/events, which entities, why grouped, what AI thinks, what to do next.

## 9. Timeline Design

**Backend source of truth:** M5 `build_timeline` sorts by `(timestamp, type_order, id)` where `type_order 0=event,1=alert`.

**UI:** Vertical line, left-aligned, `TimelineItem` with:
- Left dot: `blue` for event, `amber` for alert, `red` for HIGH severity alert.
- Header: `HH:MM:SS UTC — Event #101 / Alert #12 — source / rule_name`
- Summary: `message` / `summary` (truncated, expandable)
- Expand: shows `raw_log` or `context` JSON.
- Click: emits `onSelectEvidence("event:101")` → highlights corresponding `EventCard` / `AlertCard` via `scrollIntoView` + ring.

No frontend re-sorting; render order as returned. If `timeline` length 600, virtualize with `min-height` and `overflow-y`.

## 10. AI Investigation UI

**Card with amber border to distinguish from deterministic blue.**

```
┌─ AI Investigation ─────────────────────────────────┐
│ Provider: mock • Model: mock-model • Prompt m6.1-v1 • 2026-09-16 09:30 UTC │
│ Truncated: evidence was bounded (10 alerts / 20 events shown)              │
│ Summary: “Summary 2-4 sentences…”                                          │
│ Observations:                                                               │
│  [Fact] Five failures from 10.0.0.5 …  [confidence —]  Evidence [event:1]… │
│  [Inference] May be automated…  confidence: medium  Evidence [alert:1]     │
│  [Uncertainty] Cannot determine if authorized test…                         │
│ Alternative Explanations (1-3)                                              │
│ Recommended Steps (2-5, no remediation)                                     │
│ Limitations                                                                 │
│ Provenance footer: model, truncated, evidence_ids_used count                │
│ [Re-investigate] button                                                     │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Types:** `Fact` = emerald badge, no confidence; `Inference` = amber badge + `confidence pill`; `Uncertainty` = slate badge. Evidence chips are `Button` variant `outline` with `alert:12` mono.

**States:** Loading skeleton (shimmer), Error `503` → “AI unavailable — deterministic evidence still available” (does not hide investigation), `502` → “AI returned invalid analysis”, Empty incident → “Insufficient evidence — AI skipped” (the deterministic insufficient-evidence analysis from M6).

**Never:** Render AI as verified truth; always show `Provenance` and `Limitations`.

## 11. Evidence Citation UX

- Chips: `<EvidenceChip id="alert:12" />` → `onClick` → `document.getElementById("alert-12")?.scrollIntoView({behavior:"smooth"})` + `ring-2`.
- IDs are `incident:<id>`, `alert:<id>`, `event:<id>` only; `timeline:` not citeable (spec).
- Backend IDs are authoritative; frontend does not generate IDs.
- In AI observations, each chip shows `Alert 12` / `Event 101` with icon (`Siren`/`ScrollText`).

## 12. AI Trust & Security UX

- **Log content:** Always `<pre>` + `overflow-auto`, `word-break: break-all`, no `dangerouslySetInnerHTML`. React escapes by default.
- **AI output:** Rendered as plain text in `Card`, no markdown HTML; if future markdown needed, use `dompurify` + strict allowlist, but M7 uses text.
- **Prompt injection:** UI cannot fix backend injection, but displays evidence in fenced JSON-like blocks; AI section is clearly “AI-generated (untrusted until validated)” badge.

## 13. API Architecture

```
Component
  ↓ useIncidents()  (TanStack Query)
    ↓ incidentsApi.list({status, limit})
      ↓ api/client.ts fetch(`${base}/api/v1/incidents?...`)
        ↓ FastAPI
```

**`api/client.ts`:** `baseURL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000"`, `fetch` wrapper that parses JSON, throws `ApiError{status, message, details}`.

**`api/*.ts` typed services:**
- `health.ts: getHealth(): Promise<Health>`
- `events.ts: listEvents({limit, source?, level?})`, `getEvent(id)`, `ingest(logs)`
- `alerts.ts: listAlerts(filters), getAlert(id), patchAlert(id, status)`
- `incidents.ts: listIncidents, getIncident, patchIncident`
- `investigation.ts: getInvestigation(id, {include_events, include_timeline})`
- `ai.ts: postInvestigate(id): Promise<{incident_id, analysis, evidence_meta, provenance}>`

**Hooks:** `useHealth` (poll 30s, `refetchInterval`), `useEvents`, `useAlerts`, `useIncidents`, `useInvestigation` (`useQuery`), `useAIInvestigation` (`useMutation`).

Components never directly `fetch`.

**Actual endpoints consumed:** all listed in §2. **Missing for M7 (see §27):** `GET /stats`, `GET /events` filter/pagination, `GET /events?ids=`, `GET /incidents/{id}/alerts` is via investigation already.

## 14. Server State vs UI State

**Server state (TanStack Query, cached, refetchable):** `health, events, alerts, incidents, investigation, aiAnalysis`. Keys like `["incidents", {status, limit}]`.

**Local UI state (useState/useReducer, not global store):** `filters (level/source), pagination limit, modal open, expanded evidence, selected timeline item, sidebar collapsed`. No Redux/Zustand needed; if needed later, `Jotai`.

## 15. Loading / Error / Empty States

| Page | Loading | Error | Empty | Partial AI Failure |
|---|---|---|---|---|
| Dashboard | Card skeletons | `ErrorAlert` + Retry button | “No events yet” | AI section shows “Unavailable” but dashboard still renders |
| Events | Table skeleton (5 rows) | Retry | “No events match filter” | — |
| Alerts | List skeleton | Retry | “No alerts” | — |
| Incidents | Table skeleton | Retry | “No incidents” | — |
| Investigation | Incident header skeleton + timeline skeleton | Incident error → full `ErrorAlert`; timeline error → inline retry | Empty incident → `EmptyState` with “No alerts linked” | M5 success + M6 `503` → show deterministic evidence + amber `AI unavailable` card |

All `useQuery` with `isLoading`, `isError`, `error`, `refetch`.

## 16. Pagination & Data Limits

**Backend limits (verified):** `events limit 1..200` (no offset), `alerts/incidents limit 1..200`, investigation `alerts 100/events 500/timeline 600` (bounded, `truncated` flag + `total_*`).

**M7 strategy:**
- Events: default `limit=50`, “Load more” increases to 100/200; document future `?offset`/`?cursor` needed for true pagination (not fake frontend pagination over full data).
- Alerts/Incidents: same, with filter-driven refetch.
- Investigation: render `truncated` banner with `total_*` counts if `summary.truncated`.

**Future backend:** `GET /events?from=&to=&level=&source=&cursor=` + `GET /incidents?cursor=` (cursor pagination). M7 will adapt hooks without UI change.

## 17. Filtering & Search

**Events:** `level` (multi), `source` (text), `service`, `host`, `time range` (from/to). Currently client-side on fetched 200; mark as “Client-side (fetch 200) — future server-side”.

**Alerts:** `severity, status, rule_name, time range` — all supported server-side (`GET /alerts?...`). M7 will wire directly.

**Incidents:** `severity, status, correlation_key, time range` — supported (`GET /incidents?...`).

No complex query DSL in M7.

## 18. Responsive Design

- Desktop (≥1024): sidebar 240 + main 1280 centered, tables with all columns.
- Laptop (768-1024): sidebar collapsible, tables horizontal scroll.
- Tablet (<768): sidebar drawer overlay, tables → cards (key-value), timeline full width, filters collapse to sheet.
- Mobile is readable but not priority; dense tables not forced.

## 19. Visual Design Direction

**Palette:** Dark SOC: `slate-900` bg, `slate-800` cards, `slate-700` borders, `slate-200` text. Accent `sky-500` for deterministic, `amber-500` for AI, `emerald-500` fact, `red-500` critical.

**Typography:** `Inter` (or system sans), `14px` base, `12px` mono for IDs, `600` for titles. Line-height `1.5`.

**Hierarchy:** Card `border` + `shadow-sm`, severity dot + label (not color alone), status pill.

**Avoid:** Neon glows, gamer gradients, excessive animations. Only subtle `transition-colors` on hover.

## 20. Accessibility

- Semantic HTML: `header`, `nav`, `main`, `table` with `thead/tbody`, `button` not `div`.
- Keyboard: Tab order, `Esc` closes drawer/dialog, `Enter` activates chips.
- Contrast: `slate-900` on `slate-200` passes WCAG AA; severity colors have text labels + icons.
- Focus: `focus-visible:ring-2 ring-sky-500` on all interactive.
- Screen reader: `aria-label` on icon buttons, `role="status"` on toasts, `aria-live` on loading.

## 21. TypeScript Strategy

**Strict `tsconfig.json`: `strict:true, noImplicitAny:true`.**

Types mirror backend Pydantic (single source):

```ts
// types/api.ts — generated from backend schemas, no any
export type Event = { id:number; timestamp:string; ingested_at:string; source:string; level:string; service?:string; host?:string; message:string; raw_log:string; extra_data?:Record<string,unknown> }
export type Alert = { id:number; rule_id:number; rule_name:string; status:string; severity:string; detected_at:string; summary:string; context:Record<string,any>; first_event_id:number; last_event_id:number; evidence_event_ids:number[] }
export type Incident = { id:number; title:string; status:string; severity:string; correlation_key:string; context:any; first_seen_at:string; last_seen_at:string; alert_ids:number[] }
export type TimelineEntry = { type:"event"|"alert"; id:number; timestamp:string; summary:string }
export type InvestigationContext = { incident:Incident; alerts:Alert[]; events:Event[]; timeline:TimelineEntry[]; correlation:any; summary:any; entities:any; detection:any[] }
export type Observation = { statement:string; type:"fact"|"inference"|"uncertainty"; evidence_ids:string[]; confidence?: "low"|"medium"|"high"|null }
export type InvestigationAnalysis = { summary:string; observations:Observation[]; supporting_evidence:string[]; alternative_explanations:{explanation:string;evidence_ids:string[]}[]; recommended_steps:string[]; limitations:string[]; provenance:{provider:string;model:string;prompt_version:string;schema_version:string;evidence_ids_used:string[];truncated:boolean;created_at:string} }
export type ApiError = { status:number; message:string; details?:any }
```

Mapping: `api/*` returns `Api` types directly; view models only if UI needs derived (e.g., `severityOrder`). No duplication.

## 22. Configuration

**Frontend env:** `VITE_API_BASE_URL` (e.g., `http://localhost:8000`), `VITE_APP_ENV` (dev/prod). Loaded via `import.meta.env`.

**No hardcoding:** All `fetch` uses `client.ts` baseURL.

**Dev vs prod:** `vite.config.ts` proxies `/api` to `localhost:8000` in dev; in prod, `VITE_API_BASE_URL` points to deployed FastAPI (e.g., `https://api.horus.local`). No `AI_API_KEY` in frontend (server-side only).

**.env.example:**
```
VITE_API_BASE_URL=http://localhost:8000
```

## 23. Testing Architecture

**Unit (Vitest):** `utils/formatDate`, `severity`, `evidence` helpers.

**Component (Vitest + Testing Library):** `AlertCard` (severity badge), `IncidentHeader` (status), `Timeline` (event before alert at equal ts), `AIObservationCard` (fact/inference/uncertainty rendering, confidence only for inference), `EvidenceChip` navigation, `ErrorAlert`, `EmptyState`.

**Integration (Vitest + MSW):** `useInvestigation` → mock `GET /incidents/1/investigation` → renders timeline + evidence; `useAIInvestigation` mock `POST /incidents/1/investigate` success → shows analysis, mock 503 → shows “AI unavailable” but investigation still renders.

**E2E (Playwright, 3 workflows):** `Dashboard → Events → Event detail`, `Alerts → Alert detail → Investigation`, `Incidents → Investigation → AI Investigate → citation click`. No exhaustive E2E.

## 24. Do NOT Implement These Yet

- Auth/RBAC, WebSockets, real-time, notifications, SIEM/Kafka/Redis/Celery, Kubernetes, multi-tenancy, autonomous remediation, RAG/vector DB, advanced analytics.

## 25. Backend Changes Required for M7

**Already available (use immediately):** All endpoints in §2, including `GET /incidents/{id}/investigation` (M5) and `POST /incidents/{id}/investigate` (M6.1, server-side provider). M5 bounded limits and deterministic ordering are exactly what UI needs.

**Small additions (recommended before M7.4, not blocking M7 bootstrap):**
- `GET /events?ids=1,2,3` bulk fetch (currently M7 must client-filter or use investigation context as workaround).
- `GET /events?level=&source=&service=&host=&from=&to=&limit=&offset=` server-side filter/pagination (currently client-side on 200).
- `GET /stats` (counts by severity/status, last 24h) for dashboard (currently dashboard shows recent lists, not aggregates).

**Future improvements (do not block M7):**
- Cursor pagination for `alerts/incidents`.
- `GET /incidents/{id}/alerts` and `GET /alerts/{id}/events` explicit sub-resources (currently via investigation).
- WebSocket for live `health` / new alerts.

**No business logic change, no migration, no AI change.**

## 26. Final Deliverable

This document is `M7_ARCHITECTURE.md` at repo root, covering §1-§30. No frontend code yet.

## 27. Implementation Phases

| Phase | Objective | Files/Components | APIs Required | Tests | Risks | Done When |
|---|---|---|---|---|---|---|
| **M7.0 Architecture** | This doc, review | `M7_ARCHITECTURE.md` | none | none | Over-design | Approved |
| **M7.1 Bootstrap** | Vite+TS+Tailwind+Router+Query scaffold, env, lint | `frontend/package.json`, `vite.config.ts`, `tsconfig.json`, `src/app/*` | none | `health` smoke | Misconfigured proxy | `npm run dev` shows blank shell + health |
| **M7.2 App Shell** | Header/Sidebar/Layout, routing, error boundary | `layouts/AppShell`, `pages/NotFound`, `router.tsx` | `GET /health` | Shell render tests | Sidebar a11y | Navigation works, responsive drawer |
| **M7.3 Dashboard** | Health, recent alerts/incidents/events (no fake stats) | `features/dashboard/*`, `pages/DashboardPage` | `health, alerts, incidents, events` | Dashboard skeletons/empty | Missing stats API (handled) | Dashboard shows recent lists, poll health |
| **M7.4 Events** | Table, filters (client-side), detail drawer, pagination load-more | `features/events/*`, `pages/EventsPage` | `GET /events` | Event table + filter tests | No server filter | Events browsable, detail shows raw_log |
| **M7.5 Alerts** | List with severity/rule/status filters, detail with evidence | `features/alerts/*`, `pages/AlertsPage, AlertDetailPage` | `GET /alerts`, `GET /alerts/{id}`, `GET /rules` | Alert card tests | Bulk events fetch workaround | Alerts triaged |
| **M7.6 Incidents** | List, detail header, status patch | `features/incidents/*`, `pages/IncidentsPage, IncidentDetailPage` | `GET /incidents`, `PATCH /incidents/{id}` | Status transition tests | No auto-refresh | Incidents manageable |
| **M7.7 Investigation** | Timeline, alerts, events, entities, correlation, summary (M5) | `features/investigation/*`, `pages/IncidentDetailPage` tabs | `GET /incidents/{id}/investigation` | Timeline ordering, evidence nav tests | Large payload (500 events) → virtualize | Investigation page complete |
| **M7.8 AI Investigation UI** | AI card, observations with citations, provenance, 503 handling | `features/ai/*`, `hooks/useAIInvestigation` | `POST /incidents/{id}/investigate` | AI card, citation chip, failure isolation tests | Prompt injection display, no HTML | AI section works, failure does not break investigation |
| **M7.9 Polish + Testing** | Responsive, a11y, visual polish, unit/component/integration/E2E | `components/ui/*`, `utils/*`, `styles/*` | all | Full 217+ frontend tests, Playwright 3 workflows | Scope creep | M7 done, documented |

Recommended order: **Shell first** (unblocks all pages), then **Events → Alerts → Incidents → Investigation → AI** (follows pipeline dependency).

## 28. Architectural Rules (Restated)

1. No business logic in React.
2. No duplicate detection/correlation/investigation logic in frontend.
3. Backend is source of truth (ordering, limits, IDs).
4. AI output untrusted until backend validated.
5. Log content untrusted, escaped.
6. AI failure must not break deterministic pages.
7. Dependencies justified, minimal.
8. No over-engineering.
9. No M1-M6.1 regression.
10. Design before code.

## 29. Final Review (Explicit Answers)

1. **Maintainable for beginner?** Yes — feature folders, thin hooks, typed `api/` services, no global store, Tailwind utilities are learnable; `README` documents each layer.
2. **Integrates cleanly?** Yes — consumes verified `/api/v1/*` with TanStack Query, respects existing `limit`, `include_*`, `strategy` params, uses `VITE_API_BASE_URL`.
3. **Separation clear?** Yes — `api/` → `hooks` → `features` → `pages`; no `fetch` in components, no timeline logic duplication.
4. **APIs immediately usable?** All in §2: health, events, ingestion, alerts, rules, detection, incidents, correlation, investigation, AI investigate.
5. **Missing APIs?** Small: `GET /events?ids=`, server-side `GET /events` filters + offset/cursor, `GET /stats` for dashboard aggregates.
6. **Add later?** `GET /stats`, cursor pagination, WebSocket, auth/RBAC, RAG, vector DB — all deferred (see §25/28).
7. **Dependencies necessary?** `react, typescript, vite, react-router, @tanstack/react-query, tailwind, lucide-react, date-fns` — each justified in §3; no chart lib until stats exist.
8. **AI failure isolated?** `useAIInvestigation` is `useMutation` with `onError` → amber “AI unavailable” card; `GET /investigation` (M5) remains 200 and rendered; no global error boundary triggered.
9. **Evidence citations?** `EvidenceChip` for `incident:/alert:/event:` IDs, `onClick` scrolls to `id="event-101"`; timeline not citeable per backend contract.
10. **Untrusted content safe?** `<pre>` escaped, no `dangerouslySetInnerHTML`, AI text plain, `dompurify` only if markdown later.
11. **Smallest sensible M7?** Shell (`M7.1-2`) + Events + Alerts + Incidents (list) + Investigation timeline — AI can be stubbed with mock provider; dashboard can be minimal.
12. **Build first after approval?** `M7.1 Bootstrap` (Vite+TS+Router+Query+Tailwind, `VITE_API_BASE_URL`, health check) then `M7.2 App Shell` — unblocks all feature pages.

**Next:** Await approval. On approval, start at `M7.1` as defined, no backend changes, no AI changes, incremental PRs per phase with tests.

