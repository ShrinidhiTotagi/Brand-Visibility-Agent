# FINAL WORKFLOW VALIDATION REPORT
# AI Search Visibility Agent — Two Real Workflows
Date: 2026-09-23. Backend: SQLite (`agent_storage.db`). All evidence from live runs/logs/DB.

## 1. Workflow 1 definition
- ID: `brand_visibility_standard` · Name: `Workflow 1 — Standard Analysis` · v1 ACTIVE
- Visible: Company Data → Website → AI Search → Brand Analysis → Competitors → Recommendations
- Real ops (11): VALIDATE_DATA, COLLECT_WEBSITE_DATA, GENERATE_QUERIES, RUN_AI_SEARCH,
  ANALYZE_BRAND, ANALYZE_COMPETITORS, DETECT_CONTENT_GAPS, GENERATE_RECOMMENDATIONS,
  DETECT_CHANGES, STORE_ANALYSIS, UPDATE_LEARNING

## 2. Workflow 2 definition
- ID: `rag_enhanced_analysis` · Name: `Workflow 2 — RAG-Enhanced Analysis` · v1 ACTIVE
- Visible: Company Data → Website → RAG → AI Search → Competitors → Reasoning → Recommendations
- Real ops (12): VALIDATE_DATA, COLLECT_WEBSITE_DATA, RAG_INDEX, RAG_RETRIEVE,
  GENERATE_QUERIES, RUN_AI_SEARCH, ANALYZE_COMPETITORS, REASONING,
  GENERATE_RECOMMENDATIONS, DETECT_CHANGES, STORE_ANALYSIS, UPDATE_LEARNING
- WF2 has NO Brand Analysis step; WF1 has NO RAG/Reasoning steps. Different code paths, not labels.

## 3. Workflow switching validation (AT-05/07/09/10)
- `POST /api/workflow/active {workflow_id}` switches the global selection (validated
  against the two spec IDs; unknown IDs rejected). Verified live: switched to
  `rag_enhanced_analysis` and back; `/api/workflow/active` reports id+name+visible+version.
- Every run records its `workflow_id` in `workflow_runs`; execution branches on it.
- UI: Start-view dropdown + workflow-view cards; selection highlight, viewing banner,
  switch toast, auto-load. AT-09/AT-10 proven by ledger rows below.

## 4. Company discovery validation (AT-01/02)
- `POST /agent/run-discover {industry: Dairy, region: Karnataka}` → 10 candidates in 24.5s,
  5 VERIFIED (live HTTP reachability probes), 5 PARTIALLY_VERIFIED/INSUFFICIENT_DATA, 0 invalid.
- Regions endpoint serves 8 regions. No hardcoded company lists; LLM-sourced only.

## 5. Internet data source validation (AT-11 source honesty)
- Providers: Gemini 2.5-flash (+lite failover), Groq qwen3, SerpAPI, stdlib website scraper.
- Fresh WEBSITE_SCRAPER evidence collected 2026-09-22/23 (e.g. brand 8, brand 56 headings).
- When providers 429: Groq fails fast (SDK retries off, one 8s retry) → template fallback;
  discovery returns a clear rate-limit message instead of a raw dump. No fake observations:
  RAG-less retrieval records NO_RELEVANT_RAG_CONTEXT.

## 6. Data quality results (§23, AT-18/19)
- Brands carry verification_status (VERIFIED/PARTIALLY_VERIFIED/UNVERIFIED); candidates carry
  verification_status + validation_json + source_url + verified_at.
- Import refuses INVALID candidates. PDF/detail views show stored data only, with
  `needs_analysis` flag when no analysis exists. Nothing is presented as verified unless checked.

## 7. Automatic monitoring validation (AT-14)
- Scheduler runs every 5 min: checks 50 companies + 250 automations, fires only due/inflight-free
  work, capped at 30 jobs/cycle. Observed: 3 created / 149 skipped per cycle.
- Agent loop ticks every 10s; daily batches of 5 (never-analyzed first), weekly batches of 10.

## 8. Change detection validation (AT-15)
- 6,372 change_log events total (CONTENT_ADDED 3094, CONTENT_CHANGED 2885, PROFILE_CHANGED 393),
  including same-day website heading changes (brand 56, AgroStar, 2026-09-23T11:51).
- DETECT_CHANGES is a real pipeline step reading evidence snapshots vs stored history.

## 9. Replanning validation (AT-16/17, §19)
- `impact_ops()`: website/content-only changes + existing queries → partial re-execution
  (skips GENERATE_QUERIES + RUN_AI_SEARCH) with logged reason; anything else → full run + reason.
- Observed live (company 3, run 2026-09-23T11-54): mode=changed, 9 steps, 7.5s (vs 60s+ full),
  fresh analysis stored (score 82 @ 11:54:34). Partial reason recorded in ledger.

## 10. RAG validation (AT-11)
- WF2 RAG_INDEX: real `rag_index_company` (company 6 run indexed docs, 10.64s).
- WF2 RAG_RETRIEVE: real `rag_search` → 5 items with provenance
  (document_id, company_id=6, source_type KEYWORD, source_record_id, content).
  Ledger stores compacted items. Empty retrieval records NO_RELEVANT_RAG_CONTEXT (never faked).

## 11. Reasoning validation (AT-12)
- WF2 REASONING: real `reason_about_company(use_rag=True, store=True)` → RSN-000009,
  decision GENERATE_RECOMMENDATIONS, confidence 0.85, persisted to reasoning_events.
- WF1 ledger rows contain no reasoning record (step absent by design).

## 12. Learning validation (§33)
- 890 learning_events (PATTERN_CONFIRMED 435, QUERY_SUCCESS 158, PATTERN_DISCOVERED 161…),
  19+ learning_memory rows. Writes verified live.
- Consumption path exists (historical query blend in GENERATE_QUERIES, learning-assisted
  reasoning notes). Per-run reuse counts logged. Honest note: long-horizon learning lift
  (do resolved recommendations measurably improve scores?) is not yet statistically proven —
  tracked, not claimed.

## 13. Performance before/after (§25)
- Baseline full pipeline (Zerodha, 11 steps, direct): 52s start→stored analysis.
- WF1 full: ~60s. WF2 full: ~101s (RAG index + reasoning included).
- WF1 partial (website-change): 7.5s. Per-step timings stored per run (e.g. RUN_AI_SEARCH
  53.23s dominates — Groq-bound). Endpoint: agent-state 26ms cached; companies instant.
- Bottleneck measured, not guessed: Groq free-tier 429s (~3 jobs/min background).
  Mitigations: fail-fast retry, template fallbacks, flood caps, direct path (zero queue hops).

## 14. Companies tested
Zerodha (baseline 52s, score 40), Mokobara/3 (WF2 101s + WF1-partial 7.5s, score 82),
CRED/5 (fresh score 77 via fixed STORE_ANALYSIS), Myblocks/6 (WF2 with RAG proof),
AgriSolutions/52, AgroStar/56, KisanKraft/55 (URL typo fixes verified), HCL/49,
Krutrim/47 (reasoning traces), Nykaa (planning demo), plus scheduler fleet coverage
(87 brands, 2852 background jobs completed, 0 failed at last count).

## 15. Successful executions
- WF1 full + WF1 partial + WF2 full ledgers COMPLETED with per-step ok/durations.
- Discovery 10/10 stored+validated. PDF renders real data (score 82, 5608 chars).
- 50/50 automated tests pass. All ~40 UI endpoints live-tested.

## 16. Failed executions
- Pre-fix era: STORE_ANALYSIS SQL 1064 (reserved word), jobs PRIMARY duplicates,
  strict-mode rejects — all fixed and verified (company 5 fresh analysis landed).
- Groq 429s: handled (retry→fallback), never fatal. 1 Razorpay RUN_AI_SEARCH failure
  observed; auto-retried.
- A 723-job stale backlog (self-inflicted during 500-limit test) was cancelled and
  deleted; guards added so it cannot recur.

## 17. Known limitations
- Groq/Gemini free tiers cap bulk throughput (~3 jobs/min; 50-company fleet ≈ 3h first pass).
- Discovery depends on LLM providers (rate-limited) — Manual/CSV import always available.
- Plans (planner module) are advisory blueprints; execution flows through runs (documented in UI).
- Scale tested to 87 companies / ~2900 jobs; 250–500 progressive scale test not yet run (free-tier time cost).

## 18. Remaining issues
- Frontend Start view is code-reviewed + brace-balanced but not browser-click-tested here
  (no browser automation in this environment) — needs one human click-through.
- `datetime('now')` SQLite-isms remain in two brain-observation queries (harmless on SQLite
  backend; would need porting only if MySQL is re-enabled).
- `agent_storage.db.bak` (28MB pre-migration backup) deleted after verification; MySQL `temp`
  DB retains a second copy of migrated data.
