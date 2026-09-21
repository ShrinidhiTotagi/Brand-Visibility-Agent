# AI Search Visibility Agent v2 — Autonomous

A self-running agent that continuously tracks how visible a brand is across AI search engines (ChatGPT, Perplexity, Google AI Overviews). It scrapes brand websites for real content, observes AI search results (when API keys are provided), scores brands deterministically with explainable reasons, detects changes over time, learns from past recommendations, and lets users give DONE/NOT NEEDED feedback that feeds future suggestions.

## What the agent does

- **Autonomous loop** — starts automatically (or via the dashboard's Agent Control panel) and processes queued jobs: STARTUP, DAILY observations, WEEKLY re-analysis, discovery, learning updates, change detection.
- **Content evidence** — scrapes each brand's website using Python's standard library (no external crawlers) and stores real evidence (titles, headings, meta, contact info, text snippets).
- **AI search observation** — queries stored brand keyword lists against Gemini (`gemini-live`) or Google SERP (`google-serp`). Without API keys the integrations show **NOT CONNECTED** and no observations are fabricated.
- **Deterministic, explainable scoring** — AI Readiness Score = Profile 20% + Keywords 25% + Competitor 20% + Content 20% + AI-readiness 15%, each with human-readable reasons. Observed visibility (AI Search Visibility) is reported separately and only from real observations.
- **Change detection** — weekly snapshots of evidence compared to prior runs; changes stored in the change log.
- **Learning memory** — stores patterns (e.g. "missing author bio causes low trust"), and recommendations are filtered/highlighted against known patterns.
- **Feedback learning** — clicking DONE / NOT NEEDED on a recommendation marks it implemented and records a learning pattern.
- **Job queue with failure isolation** — every job retries (up to max_retries) and is marked FAILED_PERMANENTLY after; a run only fails if it has permanent failures. Retry failed jobs from the Job Queue panel.

## Setup

### 1. Install dependencies

```bash
pip install google-generativeai requests
```

`pymysql` and `mysql-connector-python` are only needed if you explicitly switch storage to MySQL.

### 2. Set environment variables

Copy `.env.example` to `.env` (or set these as real environment variables — the script reads the OS environment, it does not auto-load `.env`):

| Variable | Description | Default |
|---|---|---|
| `GEMINI_API_KEY` | Google Gemini API key (https://aistudio.google.com/app/apikey). Optional; enables `gemini-live` observations + Gemini-powered company discovery. | empty (NOT CONNECTED) |
| `GEMINI_MODEL` | Primary Gemini model. | `gemini-2.5-flash` |
| `GEMINI_FALLBACK_MODEL` | Backup Gemini model, used automatically on quota/rate errors (each model has its own free-tier quota bucket). | `gemini-2.5-flash-lite` |
| `SERPAPI_KEY` | SerpAPI key (https://serpapi.com/dashboard). Optional; enables `google-serp` observations. | empty (NOT CONNECTED) |
| `AGENT_DB` | Storage backend: `sqlite` (default) or `mysql`. | `sqlite` |
| `DB_HOST` / `DB_PORT` / `DB_USER` / `DB_PASSWORD` / `DB_NAME` | MySQL connection (only used when `AGENT_DB=mysql`). | — |
| `PORT` | HTTP port for the dashboard. | `8000` |
| `AUTO_START_LOOP` | `1` = start the autonomous loop on launch, `0` = wait for a manual start. | `1` |
| `AUTO_START_SCHEDULER` | `1` = start the Automation Scheduler on launch, `0` = start paused. | `1` |

> All API keys are optional and read from the environment only. No hardcoded secrets. Never commit `.env`.

### 3. Run

```bash
python agent.py
```

Open http://localhost:8000 in your browser (or double-click `start.bat`).

## Dashboard

- **Agent Control** — RUN AGENT NOW, pause/resume, live status/progress/current job, recent errors + activity, scheduler config.
- **Job Monitor** — filter jobs by status, retry or cancel individual jobs, view runs.
- **Automation & Scheduler** — per-company automations (full analysis, monitoring, change detection, query/data refresh) with schedule type, live status, run history, RUN NOW / enable / disable, per-company automation settings, and the scheduler controls (start / pause / resume / run once) plus its event activity log.
- **New Analysis** — add a company manually, import via CSV, or use the discovery panel.
- **Dashboard** — AI Readiness vs Observed AI Search Visibility gauges.
- **Companies / Evidence** — browse brands and the raw scraped evidence used for scoring.
- **History** — full audit trail of every run with per-criterion reasons.
- **Search Intelligence** — stored queries, observation history.
- **Change Log** — what changed between runs.
- **Learning & Feedback** — learned patterns and feedback history.
- **Learning Intelligence** (Phase 4) — live KPIs (active memories, events, patterns discovered/confirmed/invalidated, useful vs low-value queries, resolved/rejected recommendations, feedback), learning activity stream, pattern table with per-memory detail ("why was this learned"), query performance with intent aggregates, recommendation performance with feedback counts, and Human Control (disable/enable learning per company, rebuild from history, clear active influence, invalidate a memory).
- **Autonomous Agent** (Phase 5) — state-aware orchestration center: live agent status (IDLE/OBSERVING/DECIDING/EXECUTING/LEARNING/PAUSED/ERROR/COMPLETED), per-cycle KPIs, run controls (LIVE/dry-run, company scope), Company Intelligence per company (operational state, data/analysis/learning/integration freshness, profile diff, pending work, recent decisions, learning summary, next action + why), "What would you do?" simulation, and the Decision Timeline (every decision with reason, linked job and live status; PROPOSED decisions can be approved/skipped by humans).

## API (JSON)

Legacy: `/agent-state`, `/agent/start-run`, `/agent/stop`, `/agent/start-loop`, `/agent/config`, `/agent/run-company`, `/agent/run-discover`, `/companies`, `/companies/import`, `/history`, `/history-detail?id=N`, `/evidence?brand_id=N`, `/queries`, `/observations`, `/changes`, `/learning`, `/feedback` (GET/POST), `/jobs`, `/jobs/retry`, `/delete-audit`.

Autonomous runner + job queue:

| Method | Endpoint | Purpose |
| --- | --- | --- |
| POST | `/api/agent/run` | Create + run now (payload `{company_id?}`), processes immediately in background |
| POST | `/api/agent/pause` | Pause: no new jobs start; pending jobs kept |
| POST | `/api/agent/resume` | Resume pending job execution |
| GET | `/api/agent/status` | Live runner state, queue counts, current job, last/next run, recent errors + activity (all from real DB rows) |
| GET | `/api/agent/runs` | Run list with per-run stats |
| GET | `/api/agent/runs/:run_id` | Run detail: jobs + activity for that run |
| GET | `/api/agent/jobs` | All jobs, optional `?status=` filter (PENDING/RUNNING/COMPLETED/FAILED/RETRYING/CANCELLED/FAILED_PERMANENTLY) |
| GET | `/api/agent/jobs/:id` | Single job detail |
| POST | `/api/agent/jobs/:id/retry` | Re-queue a job (retry count reset) |
| POST | `/api/agent/jobs/:id/cancel` | Cancel a pending/queued job (timestamped; cascades to blocked dependents) |
| GET | `/api/agent/activity` | Real activity stream, optional `?limit=` |
| GET | `/api/agent/errors` | Failed/retrying/permanently-failed jobs |

Automation & scheduler:

| Method | Endpoint | Purpose |
| --- | --- | --- |
| GET | `/api/automations` | List all automations, optional `?company_id=` |
| GET | `/api/automations/:id` | Single automation detail + live status |
| POST | `/api/automations` | Create an automation `{company_id, automation_type, schedule_type}` |
| POST | `/api/automations/:id/enable` | Enable an automation |
| POST | `/api/automations/:id/disable` | Disable an automation |
| POST | `/api/automations/:id/run` | Run Now: creates run + jobs immediately |
| POST | `/api/automations/:id/update` | Update schedule_type / configuration |
| GET | `/api/automations/:id/history` | Automation run history |
| GET | `/api/automations/:id/next-run` | Real or projected next_run_at |
| GET | `/api/automation/status` | Dashboard KPIs: totals, status counts, jobs created/completed today, next scheduled |
| GET | `/api/scheduler/status` | Scheduler state: running/paused, interval, cycle count, last stats |
| GET | `/api/scheduler/activity` | Scheduler + automation event log, optional `?limit=` |
| POST | `/api/scheduler/start` | Start the scheduler loop |
| POST | `/api/scheduler/pause` | Pause the scheduler (no cycles until resumed) |
| POST | `/api/scheduler/resume` | Resume the scheduler |
| POST | `/api/scheduler/run-once` | Run one scheduler cycle immediately |
| GET | `/api/company/settings` | Per-company automation settings, `?company_id=` |
| POST | `/api/company/settings` | Update settings `{company_id, monitoring_enabled, analysis_frequency, ...}` |

`/agent-state` (dashboard bootstrap) includes an `automation` block with scheduler status, next scheduled run, and automation status counts.

Phase 4 self-learning + feedback engine:

| Method | Endpoint | Purpose |
| --- | --- | --- |
| GET | `/api/learning/memory` | Memories (`?company_id=&status=&memory_type=&limit=`) |
| GET | `/api/learning/memory/:companyId` | ACTIVE memories for one company |
| GET | `/api/learning/events` | Learning events (`?company_id=&memory_id=&event_type=&limit=`) |
| GET | `/api/learning/events/:companyId` | Events for one company |
| GET | `/api/learning/patterns` | ACTIVE patterns + observed cross-company patterns |
| GET | `/api/learning/query-performance` | Per-query history + per-intent aggregates (`?company_id=`) |
| GET | `/api/learning/recommendation-performance` | Recommendations with status + feedback counts (`?company_id=`) |
| GET | `/api/learning/dashboard` | §23 KPI summary, all values counted from real rows |
| POST | `/api/learning/rebuild/:companyId` | Re-derive patterns from stored history (never deletes events/feedback) |
| POST | `/api/learning/invalidate/:memoryId` | Set memory INVALIDATED `{reason}` (history preserved) |
| POST | `/api/learning/clear-influence/:companyId` | Set ACTIVE memories INACTIVE (history preserved) |
| POST | `/api/learning/company/:companyId` | Enable/disable learning `{learning_enabled: 0/1}` |
| POST | `/api/recommendations/:id/feedback` | Recommendation feedback `{feedback: USEFUL/NOT_USEFUL/INCORRECT/ALREADY_IMPLEMENTED, comment?}` |

Learning rules (deterministic, documented in code — no LLM-invented numbers):
- Recommendation statuses: `OPEN` (= NEW/ACTIVE), `DONE` (= RESOLVED), `REJECTED`, `INVALIDATED`. `USEFUL` keeps OPEN (+usefulness signal); `NOT_USEFUL` keeps OPEN but drops priority to Low; `INCORRECT` → INVALIDATED (never auto-regenerated); `ALREADY_IMPLEMENTED` → DONE (future duplicates suppressed unless the gap reappears in fresh evidence).
- Query fingerprint = lowercase alphanumeric normalization; duplicates reuse/update one record. Historical value = `clamp(0.5 + 0.1·min(useful,4) − 0.15·not_useful, 0.05, 0.95) × recency`. `ACTIVE → LOW_VALUE` at `QUERY_FAILURE_THRESHOLD` (default 3) consecutive non-useful results with zero successes; auto-`DISABLED` only at 3× threshold.
- Confidence = `0.35 + 0.10·min(obs,3) + verified?0.10 + positive_feedback?0.10 + recent?0.05` (0.05–0.95). Recency weight halves every `LEARNING_DECAY_DAYS` (default 90). Patterns activate after `MIN_PATTERN_OBSERVATIONS` (default 3); cross-company promotion after `MIN_GLOBAL_OBSERVATIONS` (default 3) companies. Learning changes DATA + PRIORITIZATION only; `UPDATE_LEARNING` failures stay on the job (retryable) and never fail the completed analysis.

Phase 5 autonomous intelligence + orchestration (the Scheduler and Agent Runner are unchanged; autonomy is a separate bounded service that only creates jobs from the registered pipeline types):

| Method | Endpoint | Purpose |
| --- | --- | --- |
| GET | `/api/agent/decisions` | Decision log (`?company_id=&status=&trigger_type=&limit=`) with live display statuses |
| GET | `/api/agent/decisions/:id` | Decision detail incl. linked job |
| GET | `/api/companies/:id/decisions` | Decisions for one company |
| POST | `/api/agent/decisions/:id/skip` | Human skip |
| POST | `/api/agent/decisions/:id/approve` | Human approve (creates the decided jobs) |
| GET | `/api/agent/autonomous/status` | Live status (IDLE/OBSERVING/DECIDING/EXECUTING/LEARNING/PAUSED/ERROR/COMPLETED), current company/action, queue counts, last cycle, limits |
| POST | `/api/agent/autonomous/run` | Bounded observe→decide→execute→reassess loop `{company_id?, max_cycles?, max_companies?, max_jobs_per_cycle?, dry_run?, background?}` |
| POST | `/api/companies/:id/decide` | Simulation: "what would the agent do right now" (assesses + records SIMULATION decisions, never executes) |
| GET | `/api/companies/:id/intelligence` | Company intelligence: state, freshness, pending work, recent decisions, learning summary, next action |

Decision rules (deterministic, no LLM in the loop):
- Operational states: `NEW → INITIALIZING → HEALTHY / STALE / CHANGED / ANALYSIS_REQUIRED / REANALYSIS_REQUIRED / DEGRADED / BLOCKED / ERROR / PAUSED`, derived from data/analysis/learning/integration freshness plus unprocessed changes (strictly newer than the last analysis) and inflight jobs. Healthy companies get no blind full analysis (`NO_ACTION`: "No meaningful change or stale data detected.").
- Priority ladder: 1 critical failed jobs (one bounded autonomous retry, never on persistent connectivity failures, never twice for the same job) · 2 missing data (DISCOVER/COLLECT) · 3 major changes → `REANALYZE_COMPANY` · 4 expired data → targeted collect chain (collect→validate→detect-changes, then reassess) · 5 outdated analysis / profile diff → minimal entry point (new keywords → queries, new competitors → competitor analysis, else brand analysis with bounded downstream closure) · 6 new evidence → gaps only · 7 stale query history → query enrichment · 8 optional competitor refresh.
- Major vs minor is classified deterministically (removed evidence, website/keyword/competitor profile changes, non-keyword/competitor user corrections, or ≥`MAJOR_CHANGE_COUNT` changes = major). Keyword/competitor corrections are served by the targeted rules, not double-counted.
- Every decision stores decision_id, company, action, priority, concrete reason, evidence, deterministic confidence and trigger; dedup checks inflight jobs first (`DECISION_SKIPPED`: "Equivalent job already active."); the same entry is never attempted twice in one run; each run is capped by `MAX_AUTONOMOUS_CYCLES` (10), `MAX_JOBS_PER_CYCLE` (25), `MAX_COMPANIES_PER_CYCLE` (5) with round-robin fairness; pause switches (agent/scheduler/automation/`AUTONOMOUS_ENABLED`) and dry-run mode (`AUTONOMOUS_MODE`) are honored; degraded integrations degrade gracefully (search-dependent steps skipped, fallback analysis on available evidence); the allowlist restricts actions to registered safe job types (collect/validate/analyze/decide/learn — never publish, spend, delete, or touch external systems).

Orchestrator (single-next-action loop over the same engines; Scheduler/Runner/Learning untouched):

| Method | Endpoint | Purpose |
| --- | --- | --- |
| GET | `/api/orchestrator/state` | Global state: agent/scheduler status, active company, current job, pending/blocked/failed counts, companies needing attention, next decision, last decision time |
| GET | `/api/orchestrator/company/:id/state` | Computed company state (`NEW/NEEDS_DATA/DATA_STALE/READY_FOR_ANALYSIS/ANALYZING/ANALYSIS_COMPLETE/CHANGES_DETECTED/LEARNING_UPDATE_REQUIRED/WAITING/ERROR/PAUSED`) + next action |
| GET | `/api/orchestrator/next-action/:id` | Pure next-best-action: `{action, priority, reason, confidence, signals[], dependencies[], blocked, source}` |
| GET | `/api/orchestrator/decisions` | Decision log (`?company_id=&status=&source=&limit=`) with live outcomes |
| GET | `/api/orchestrator/decisions/:id` | Decision detail incl. linked job |
| GET | `/api/orchestrator/activity` | Real orchestrator events, newest first |
| GET | `/api/orchestrator/metrics` | decisions_total/successful/failed, jobs created/skipped/blocked/retried, human reviews, companies completed/partial/failed |
| POST | `/api/orchestrator/run-once` | One bounded cycle: inspect → select → create next job → return decision (`{company_id?}`) |
| POST | `/api/orchestrator/run-company/:id` | Bounded stepwise run to `COMPLETED/PARTIAL/FAILED/WAITING_FOR_HUMAN` (`{max_steps?}`, default 15) |
| POST | `/api/orchestrator/pause` · `/resume` | Pause/resume the agent (existing control) |
| POST | `/api/orchestrator/decision/:id/approve` · `/reject` | Human approve (creates the job) / reject (cancels, kills inflight job) |

Orchestrator rules: ladder order is expired data → finest missing pipeline step in dependency order (validate → queries → search → brand → competitors → gaps → recommendations → store → detect → learning → WAIT), with new-company/discover/collect starters, keyword/competitor-change targeting, failure-aware RETRY (bounded, once per job) vs REQUEST_HUMAN_REVIEW, BLOCKED reporting with the missing prerequisite (prerequisite auto-runs first in run-company), and degraded alternatives that never fabricate (unavailable integrations are named in the PARTIAL result, e.g. "AI search observation (provider unavailable)"). Priority is deterministic (HIGH = expired/major/failed-retryable/new-company core steps; MEDIUM = refresh/analysis chain; LOW = WAIT). Confidence is rule-based; learning enriches explanations (useful-query citations, invalidated-pattern exclusion) but never overrides safety. Repetition guards: idempotent decision recording (SUPERSEDED on replace), per-run attempt tracking, and an honest stall break (PARTIAL/FAILED, never a silent loop). LLM use is limited to optional reason-text polishing (`ORCHESTRATOR_LLM_ASSIST=0` by default); actions are validated against `ALLOWED_AUTOMATIC_ACTIONS`, destructive names against `REQUIRES_HUMAN_APPROVAL`, and the source column distinguishes `RULE_ENGINE/LEARNING_ENGINE/SYSTEM_STATE/HUMAN/LLM_ASSISTED` so an LLM can never disguise itself as a rule.

Manager Agent, Phase 6 part 1 (registry + intake + selection + decomposition; execution arrives in part 2):

| Method | Endpoint | Purpose |
| --- | --- | --- |
| GET | `/api/manager/agents` | Registry with capabilities, health, live workload |
| GET | `/api/manager/agents/:id` | Single agent record |
| GET | `/api/manager/agents/:id/health` | Run this agent's health probe now |
| POST | `/api/manager/agents/:id/enable` · `/disable` | Operator status gate (a disabled/paused agent is never selected) |
| POST | `/api/manager/health-check` | Probe all agents, persist results |
| POST | `/api/manager/tasks` | Intake: `{"task": "..."}` → intent/capability detection, selection or decomposition |
| GET | `/api/manager/tasks` | Task list (`?status=&agent_id=&limit=`), subtasks included |
| GET | `/api/manager/tasks/:id` | Task detail with subtask graph |

Manager rules: selection is registry-driven (declared capabilities + ACTIVE status + health + input availability + version + prior success + workload, first deciding factor recorded as the reason — no hardcoded request→agent branches, no user-facing scores). Multi-agent requests decompose into subtasks plus a `SYNTHESIS` task that waits on all subtask ids (`parent_task_id`, `dependency_task_ids_json`). Tasks with no matching capability return `RECEIVED` + clarification; tasks whose agent is unavailable return `WAITING_FOR_HUMAN` — never fabricated execution. Registered agents: `ai-search-visibility` (ACTIVE, real health probe) and `finance-cash-flow` (PAUSED stub pending its backend; adding future agents = one registry row).

Manager execution (Part 2 — subtasks run as `MANAGER_SUBTASK`/`MANAGER_SYNTHESIS` jobs on the existing queue/Runner; `JOB_TYPES`/`PIPELINE_TYPES` untouched):
| Method | Endpoint | Purpose |
| --- | --- | --- |
| POST | `/api/manager/tasks/:id/execute` | Validate → queue subtask jobs respecting dependencies (`{background?}`) |
| POST | `/api/manager/tasks/:id/synthesize` | Gate on dependencies (`BLOCKED` + reason if unready) → queue synthesis |
| POST | `/api/manager/tasks/:id/cancel` | Cancel tree (pending/queued cancelled, running follows existing rules, history kept) |
| GET | `/api/manager/tasks/:id/subtasks` · `/results` · `/handoffs` · `/graph` · `/final-result` | Task tree, normalized results, field handoffs, dependency states, attributed final |
| GET | `/api/manager/results` · `/handoffs` · `/dashboard` · `/learning` | Recent results, handoffs, real-count dashboard, manager learning events |

Execution rules: every agent output validated against the contract (`task_id/agent_id/status/result/evidence/warnings/metadata`, status in COMPLETED/PARTIAL/FAILED/WAITING_FOR_INPUT/WAITING_FOR_HUMAN) before acceptance; validation refusals conclude the job while the task records the honest state (only infra errors retry). Results stored in `manager_task_results` (normalized envelope + preserved raw); handoffs in `agent_handoffs` (destination input-schema allowlist, secrets never pass). Synthesis is deterministic (facts/observations/warnings/missing-data sections, source attribution, conflict surfacing → human review, partial policy with `require_all` override); optional LLM summary polish (`MANAGER_LLM_SYNTHESIS=0` default) is numbers-validated with deterministic fallback. Outcomes (SUCCESS/FAILED/SKIPPED/CANCELLED/SUPERSEDED) sync from job states; learning flows into the existing system (`AGENT_EXECUTION_*`, `HANDOFF_*`, `SYNTHESIS_*`, `MANAGER_TASK_*`, `HUMAN_CORRECTION`); failed subtasks retry via the existing `retry_job`; unknown/paused agents are never executed ("registered but unavailable because no execution backend is implemented" — Finance stays PAUSED).

Agent Framework (contract layer over the same engines; no engine rewritten):

| Method | Endpoint | Purpose |
| --- | --- | --- |
| GET | `/api/framework/agents` | Registry with scrubbed config, health, workload |
| GET | `/api/framework/agents/:id` | Standard agent record (`:id` or `agent_id`) |
| POST | `/api/framework/agents/register` | Validated registration (semver, slugs, schemas; duplicates rejected; starts PAUSED; executors register in-process) |
| POST | `/api/framework/agents/:id/validate` | Contract check (metadata, capabilities) |
| GET | `/api/framework/agents/:id/health` | Live probe for one agent |
| GET | `/api/framework/agents/:id/capabilities` | Machine-readable capabilities + MCP tools/resources metadata |
| GET | `/api/framework/agents/:id/version` | Agent + framework versions |
| GET | `/api/framework/dashboard` | Counts + agent table (version/status/health/capabilities/last execution/last error, secrets scrubbed) |

Framework rules: standard input envelope (`request_id/agent_id/operation/input`, operation must be a declared capability) and output envelope (`request_id/agent_id/status/summary/data/evidence/warnings/errors/metadata`, documented statuses only) validated on both ends; error contract (`code/message/retryable/details`, secret-scrubbed) with retry classification (retryable/transient, non-retryable/contract, human-review) — the Runner still performs retries; per-operation timeouts (default 300s, daemon-guarded) return retryable `EXECUTION_TIMEOUT`, never stuck RUNNING; lifecycle transitions validated over the existing task vocabulary; versions compatibility-checked by major line (mismatch errors clearly, never silently executes); `request_id` idempotency at intake and execution (previous terminal result replayed without side effects); learning hooks (`before/after/failure/feedback`) call the existing learning system only; manager subtask dispatch routes through `framework_execute` (visibility behavior preserved: input-gate `WAITING_FOR_INPUT` survives via metadata); capability metadata carries MCP-ready `tools`/`resources` (metadata only, no MCP endpoints).

Reasoning engine (read-only assessment between evidence and orchestration; never executes, never writes learning memory):

| Method | Endpoint | Purpose |
| --- | --- | --- |
| POST | `/api/reasoning/company/:id` | Assess now (stores event; pure assessment, no jobs) |
| POST | `/api/reasoning/run-once/:id` | Assess + validate + persist; never creates jobs (QA/debugging) |
| GET | `/api/reasoning/company/:id/latest` · `/history` | Latest reasoning / event history |
| GET | `/api/reasoning/:id` | Single reasoning event in output shape |
| POST | `/api/reasoning/:id/validate` | Re-run the 8-check validator on a stored event |
| GET | `/api/reasoning/dashboard` | Runs, decisions, human reviews, conflicts, LLM vs deterministic counts + recent events |

Reasoning rules: 12-step pipeline (state → evidence+freshness → history → changes → missing info → learning (read-only) → candidates → constraints → selection → explanation → structured result). Facts, observations, interpretations and actions are stored separately. Evidence is priority-ordered (user corrections → verified → API → website → AI-inferred, never auto-factual). Conflicts on the same field go to human review unless a single user-verified correction deterministically wins. History uses association language ("coincides with"), never causal claims. Confidence is deterministic (HIGH ≥ 0.7, LOW < 0.45 or any conflict) with named signals. Candidate actions are restricted to the registered list; resolved recommendations are suppressed from candidacy. The 8-check validator (action known/allowed, dependencies satisfied, data present, company unpaused, automation on, no duplicate job, approval respected) returns REJECTED, never execution. Duplicate contexts reuse the existing event via deterministic fingerprint (profile + evidence version + changes + analyses + learning counts); `ORCHESTRATOR_USE_REASONING=0` by default with an explicit integration (`orchestrator_decide_with_reasoning`: validated reasoning enriches, orchestrator still decides); LLM assistance (`REASONING_LLM_ASSIST=0` default) is explanation-text-only, numbers-validated, with a recorded fallback constraint.

Tool calling + real MCP (no engine rewritten; tools are thin wrappers over existing functions):

| Surface | Details |
| --- | --- |
| Registry | `mcp_tools` table (id, schemas, capability, agent allowlist, risk, approval flag, enabled, timeout); 15 seeded read/analysis tools; runtime registration validated, duplicates rejected |
| Validation | 10 checks (exists, enabled, capability declared + allowlisted, agent ACTIVE, version compatible, schema, required params, permission/scope, risk policy, timeout); any failure rejects without executing |
| Execution | Timeout-guarded run, output envelope validated (malformed rejected, never reaches Reasoning/Learning), idempotent replay for safe ops via `request_id`, approval gate (`WAITING_FOR_HUMAN`, never auto-executes), secret-redacted audit row + activity line per call |
| Tool loop | Bounded reason → select (reasoning candidates mapped to tools) → validate → call → observe → re-reason (`MCP_MAX_TOOL_CALLS=10`); reads/assesses only, collection stays with the orchestrator |
| MCP server | `mcp_server.py` (real MCP v2 protocol over stdio): 15 tools, 16 resource templates (`company://` + `auth://` dual-URI), 6 prompts; per-call `auth_token`/`client_id` against `MCP_AUTH_TOKEN`/`MCP_CLIENT_SCOPES_JSON`; stdout kept protocol-clean |
| Resources | Read-only, company-scoped, redacted, size-limited with metadata; prompts render live company context and grant no permissions |
| UI | Framework view gains a Tool Registry & Recent Calls card |

Run the server with `python mcp_server.py` (env `AGENT_DB_PATH`, `MCP_AUTH_TOKEN`, `MCP_CLIENT_SCOPES_JSON`); any MCP client can `initialize → tools/list → resources/list → prompts/list → tools/call` against it.

Planning engine (goal → validated DAG; execution stays with orchestrator/runner):

| Method | Endpoint | Purpose |
| --- | --- | --- |
| POST | `/api/planning/goals` | Normalized goal envelope (unknown types → WAITING_FOR_HUMAN + clarification) |
| POST | `/api/planning/plan` | Build DAG plan from goal + live state (no jobs, no writes but the plan row) |
| POST | `/api/planning/validate` | 20-check validator → READY or PLAN_REJECTED with named checks |
| POST | `/api/planning/replan/:plan_id` | New version from current state (history SUPERSEDED, never overwritten; budget/no-progress guarded) |
| POST | `/api/planning/evaluate/:plan_id` | Verdict from actual step states + success conditions |
| GET | `/api/planning/:plan_id` | Plan detail (steps, levels, skipped/blocked/failed, events, success conditions) |
| GET | `/api/planning/:plan_id/history` | All versions |
| GET | `/api/planning/company/:company_id` | Plans per company |
| GET | `/api/planning/dashboard` | KPIs + plan table from real rows |
| POST | `/api/planning/run-once/:company_id` | Goal → plan → validate; never creates jobs |

Planning rules: 9 explicit goal types with deterministic templates (operation, description, failure policy, dependency seqs); CUSTOM_ANALYSIS derives steps from reasoning candidates. Steps carry agent (registry lookup, never hardcoded), capability, MCP tool refs, inputs, deps, priority, failure policy (RETRY/SKIP/REPLAN/WAIT_FOR_HUMAN/FAIL_PLAN). Data-aware skips with reasons (fresh evidence skips collection; existing website skips discovery; dependents of skipped steps rewire). DAG validated (cycles → PLAN_CYCLE_DETECTED), parallel levels computed, limits enforced (20 steps / depth 10 / 5 replans / configurable parallel width, else WAITING_FOR_HUMAN). Versioning preserves history; fingerprint cache reuses identical contexts and invalidates on drift; no-progress protection (3 repeated failures or budget → human review). Evaluator verdicts from step states + DB-checked success conditions. Orchestrator consumes READY steps via job-type mapping (observation-only steps noted, never forced into jobs). RAG-prep `retrieve_relevant_context()` is SQL/keyword-based with honest metadata (`vector_backend: deferred-phase-11`). LLM involvement is optional (`PLANNING_LLM_ASSIST=0` default) with sanitized inputs; all LLM-shaped plans pass the same deterministic validator.

## Autonomous Runner & Job Queue

- **Job types**: `DISCOVER_COMPANY`, `COLLECT_WEBSITE_DATA`, `VALIDATE_DATA`, `GENERATE_QUERIES`, `RUN_AI_SEARCH`, `ANALYZE_BRAND`, `ANALYZE_COMPETITORS`, `DETECT_CONTENT_GAPS`, `GENERATE_RECOMMENDATIONS`, `DETECT_CHANGES`, `UPDATE_LEARNING`, `REANALYZE_COMPANY`, plus internal `STORE_ANALYSIS` (persists the run's analysis; runs after `DETECT_CHANGES` so change detection compares against the true prior snapshot).
- **Statuses**: `PENDING → RUNNING → COMPLETED / RETRYING / FAILED_PERMANENTLY`, plus user `CANCELLED`. Legacy v1 `QUEUED`/`FAILED` rows are migrated on launch.
- **Dependencies**: each job runs only after its prerequisites COMPLETED (created recursively; enforced again at selection time).
- **Priority** `HIGH/MEDIUM/LOW` is computed from real conditions: never analyzed, profile changed, previous permanent failure, stale/expired evidence or analysis (thresholds configurable: `evidence_fresh_days`, `evidence_stale_days`, `evidence_expired_days`, `analysis_stale_days`, `analysis_expired_days`, `max_jobs_per_tick`).
- **Automatic scheduling**: adding a company (manual form, CSV import) automatically queues its analysis jobs; the loop (default every 30 s) also runs STARTUP once, then DAILY freshness and WEEKLY full runs, and always drains any remaining queue so manual retries/cancels never stall.
- **Failure isolation**: one company's failure (or cancellation) never stops the agent; blocked job chains are cascade-cancelled with a logged reason, and everything is persisted (`runs`, `jobs`, `agent_activity`).
- No fake progress: every number shown (progress, counts, activity, errors) is computed from actual database records.

## Automation & Scheduler

The scheduler **creates jobs only** — it never executes analysis itself. The runner executes whatever the scheduler (or a manual RUN NOW / RUN AGENT NOW) queues.

- **Per-company automations** are created automatically when a company is added and kept aligned with its automation settings: `FULL_ANALYSIS` (mirrors the company's `analysis_frequency`), `MONITOR` and `CHANGE_DETECTION` (event-driven), `QUERY_REFRESH` and `DATA_REFRESH` (daily). `AUTONOMOUS_CYCLE` is never created by default — it is explicit opt-in per company (Automation view → Autonomous Scheduling, or `POST /api/automations` with `automation_type: AUTONOMOUS_CYCLE`). When due and enabled, the scheduler starts one bounded observe→decide→execute→reassess cycle for that company instead of a blind pipeline: at most one autonomous cycle in flight (re-entrant calls and overlapping fires are refused with a logged reason), pause switches and `AUTONOMOUS_ENABLED=0` block firing, bookkeeping (`last_run_at`/`next_run_at`/`run_count`) advances exactly like other automations, and the run carries the automation id so automation history shows autonomous runs. Manual Run Now works on autonomous schedules too.
- **Schedule types**: `MANUAL`, `DAILY`, `WEEKLY`, `MONTHLY` (time-based, `next_run_at` computed from the last fire) and `ON_CHANGE` / `ON_NEW_EVIDENCE` (event-driven, no timer).
- **Idempotent creation**: a type is never duplicated per company — re-creating re-uses (and optionally re-enables) the existing automation, preserving manual enable/disable state. Settings sync never silently re-enables a user-disabled automation; a feature turned OFF forces its automation disabled.
- **Dedup gate**: the scheduler never creates an equivalent job set while matching jobs are still `PENDING/RUNNING/RETRYING/FAILED`, and full analyses never stack while a run for that company is still active. `next_run_at` fires once, then advances by the schedule period.
- **Freshness / staleness** (`data_fresh_days` / `data_stale_days` defaults 7/30): full analysis is skipped when data is fresh; ON_CHANGE monitoring re-analyzes when evidence/profile actually changed or evidence is stale/expired, and skips honestly when nothing meaningful changed (the reason is logged).
- **No external dependency is assumed**: `RUN_AI_SEARCH` completes as "OK, no integrations connected" without Api keys; nothing is fabricated.
- **Company discovery** (`DISCOVER_COMPANY` job / `/agent/run-discover`): when Gemini is connected, the agent queries Gemini for notable companies in a brand's industry/region, avoids duplicates against tracked brands and prior candidates, and stores them in `discovery_candidates` (source `gemini:<model>`); candidates can then be reviewed/imported. Never fabricates entries — it only records what a connected provider returns.
- **Gemini failover**: `_gemini_complete()` tries the primary model, then automatically falls back to the backup model on quota/rate errors (both are real providers, so observations still come from Gemini — templates are the last resort only).
- **Run Now** creates a real run + job set immediately, tied to the automation, and hands it to the runner; per-run stats and history are reused from the existing `runs` table.
- **Honest KPIs**: automation status is derived live (a `RUNNING` run for that company makes it RUNNING; disabled → PAUSED; last failed run → FAILED); jobs created/completed today and next scheduled run are real `jobs`/`automations` rows, never guesses.
- Configuration the scheduler honours (all in `/agent/config` or `.env`): `scheduler_interval_minutes` (default 5), `scheduler_paused`, `scheduler_auto_start`, `automation_enabled`, `data_fresh_days`, `data_stale_days`, `AUTO_START_SCHEDULER`.

## RAG / Vector Knowledge Engine (Phase 11)

Real semantic retrieval layer that makes every previous phase smarter without changing their interfaces.

- **16-source document pipeline**: all approved data sources (brand profile, evidence, analyses, observations, queries, recommendations, learning patterns, etc.) are normalized into semantic documents with full provenance metadata.
- **Local embeddings**: ChromaDB's built-in `all-MiniLM-L6-v2` (384-dim) via `DefaultEmbeddingFunction` — zero external API quota, deterministic, always available. Optional Gemini provider kept for diagnostics.
- **Persistent ChromaDB backend**: cosine similarity, company-scoped filtering, chunked storage with overlap, content-hash dedup, incremental re-indexing.
- **Freshness enforcement**: search results are cross-checked against live SQL rows; stale vectors (source updated after indexing) are excluded and counted, never silently used.
- **Source deletion**: `rag_handle_source_delete()` retires vectors by `source_record_id`, marks `INACTIVE`, keeps event history.
- **MCP integration**: `search_knowledge` tool + `knowledge://` resource for other agents; `rag_health`/`rag_dashboard_data` for UI.
- **Planning/Reasoning integration**: `retrieve_relevant_context()` replaces keyword fallback with real vectors; falls back to keyword path only when RAG is explicitly disabled.
- **Secret redaction**: API keys, tokens, passwords stripped before embedding (regex-based).
- **Schema**: `rag_documents`, `rag_index_events`, `rag_retrieval_events` — full audit trail of every index and retrieval operation.
- **Threshold**: calibrated at 0.4 cosine similarity for `all-MiniLM-L6-v2`; tunable via `RAG_MIN_SIMILARITY` config.
- **54/54 tests pass**, full regression across all 13 suites: **514/514**.

## Autonomous Execution Loop (Phase 12)

Full end-to-end autonomous agent loop that coordinates ALL existing components into a single executable lifecycle.

- **Lifecycle**: GOAL → PLANNER → REASONING → RAG CONTEXT → DECISION → TOOL SELECTION → MCP TOOL → FRAMEWORK → ORCHESTRATOR → RUNNER → OBSERVATION → PLAN EVALUATOR → LEARNING → REPLAN IF REQUIRED → GOAL COMPLETE/FAILED/WAITING_FOR_HUMAN
- **State machine**: 13 states with explicit valid transitions; invalid transitions rejected with error codes. Terminal states (COMPLETED, FAILED, CANCELLED, TIMEOUT) block further transitions.
- **Bounded autonomy**: Configurable limits — `AUTONOMOUS_MAX_ITERATIONS` (10), `AUTONOMOUS_MAX_TOOL_CALLS` (20), `AUTONOMOUS_MAX_REPLANS` (5), `AUTONOMOUS_MAX_DURATION_SECONDS` (600), `AUTONOMOUS_NO_PROGRESS_LIMIT` (3). All enforced server-side.
- **No-progress detection**: Deterministic fingerprint from company state + plan version + step + evidence count + score. Repeated fingerprint triggers termination.
- **Success evaluation**: Uses existing planning success conditions; evaluates against real DB state (evidence, analysis, recommendations). No fake completion.
- **Replanning**: Creates new plan version N+1, marks old as SUPERSEDED, preserves previous plan. Replan trigger logged.
- **Human approval**: `WAITING_FOR_HUMAN` state pauses execution; approve resumes, reject terminates safely.
- **Schema**: `autonomous_runs` (persistent run state), `autonomous_events` (typed timeline of every lifecycle event).
- **11 API endpoints**: POST run, resume, cancel, approve, reject; GET detail, events, timeline, runs list, dashboard, config.
- **Dashboard UI**: "Autonomous Loop" tab with run interface, metrics, run list, and lifecycle timeline view.
- **89/89 tests pass** — full lifecycle proven: goal accepted → plan created → reasoning invoked → RAG retrieved 5 docs → tool selected → tool executed → observation captured → goal evaluated → COMPLETED.
- **Full regression**: 603/603 tests pass (514 baseline + 89 autonomous).

### Proven execution trace (live server):
```
RUN_CREATED → LOOP_START → RAG_RETRIEVED(5 docs) → PLANNING_STARTED →
PLANNING_COMPLETED(plan_id=PLAN-10055708 v=1) → REASONING_STARTED →
REASONING_COMPLETED(GENERATE_RECOMMENDATIONS) → TOOL_SELECTION_STARTED →
TOOL_SELECTED(get_company_profile) → TOOL_EXECUTION_STARTED →
OBSERVATION_RECORDED(SUCCESS) → TOOL_EXECUTION_COMPLETED →
EVALUATION_COMPLETED(Goal conditions met) → RUN_COMPLETED
```

## Notes

- Storage defaults to a local **SQLite** file (`agent_storage.db`). Existing v1 data is migrated automatically on first launch.
- MySQL mode is used only when `AGENT_DB=mysql` and the server is reachable.
- Accuracy relies on real data: without Gemini/SerpAPI keys the agent scores only from scraped website evidence and correctly reports integrations as NOT CONNECTED.