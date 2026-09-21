# Technical Requirements Document (TRD)

## Project: AI Search Visibility Intelligence Agent

**Version:** 2.0
**Date:** September 2026
**Author:** Shrinidhi Mahalingappa Totagi

---

## 1. System Architecture

### 1.1 High-Level Architecture

Client Browser (index.html - SPA) sends HTTP/REST API requests to Python HTTP Server (agent.py) which handles Auth(JWT), CORS, Rate Limiter, Multi-Tenant, Brand Analysis, Agent Brain, Orchestrator, Database(SQLite), LLM Clients, and External APIs. The server connects to Gemini AI (Primary), Groq AI (Failover), and SerpAPI (Search).

### 1.2 Technology Stack

| Layer | Technology | Version |
|-------|-----------|---------|
| Frontend | Vanilla JS + Chart.js | ES2020+ |
| Backend | Python HTTP Server | 3.10+ |
| Database | SQLite (primary), MySQL (optional) | 3.x / 8.x |
| Auth | JWT (HMAC-SHA256 custom) | - |
| LLM Primary | Google Gemini AI | gemini-2.5-flash |
| LLM Failover | Groq AI | qwen/qwen3.8-27b |
| Search | SerpAPI | - |
| AI Protocol | MCP (Model Context Protocol) | 2.2.0 |
| Vector Store | ChromaDB | 1.5.9 |
| Containerization | Docker | - |

---

## 2. Database Schema

### 2.1 Core Tables

**brands** - Company/brand profiles
- id, brand_name, website, industry, region, company_type, description, keywords, target_audience, competitors, data_source, source_detail, verification_status, confidence, is_active, created_at, last_updated_at

**analysis_results** - Visibility analysis output
- id, brand_id (FK), run_id, visibility_score, mention_frequency, sentiment_score, competitor_index, content_gap_score, profile_completeness, metrics_json, recommendations_json, created_at

**evidence** - Raw AI search evidence
- id, brand_id (FK), source, source_detail, content, mentions_brand, mentions_competitors, sentiment, url, created_at

**query_memory** - Search queries and results
- id, brand_id (FK), query_text, platform, mentioned, position, competitors_seen, created_at

### 2.2 Agent Brain Tables

**ai_observations** - Agent observations (15 types)
- id, brand_id (FK), observation_type, summary, details, severity, observed_at

**agent_decisions** - Agent decisions and actions
- id, decision_id (unique), company_id (FK), action, reason, signals_json, confidence, status, outcome, executed_at, created_at

**agent_outcomes** - Decision outcomes and reflections
- id, decision_id (FK), outcome_type, result_summary, metrics_before, metrics_after, reflection, lesson_learned, created_at

**agent_strategy** - Adaptive strategy storage
- strategy_key, strategy_value, updated_at

### 2.3 Multi-Tenancy Tables

**tenants** - Tenant configuration
- id, name, slug (unique), logo_url, primary_color, company_name, plan, max_companies, api_key (unique), created_at

**tenant_users** - User accounts
- id, tenant_id (FK), username (unique), password_hash, role, created_at

### 2.4 System Tables

**jobs** - Background job queue
- id, company_id (FK), job_type, status, priority, result_json, error_message, created_at, started_at, completed_at

**learning_memory** - Knowledge base
- id, company_id (FK), memory_type, memory_key, memory_value, source, confidence, status, created_at, updated_at

**usage_log** - API usage tracking
- id, endpoint, method, user_id, tenant_id, response_time_ms, status_code, created_at

**audit_log** - Audit trail
- id, action, entity_type, entity_id, user_id, tenant_id, details, created_at

---

## 3. API Specification

### 3.1 Public Endpoints (No Auth)

| Endpoint | Method | Description |
|----------|--------|-------------|
| /api/login | POST | Authenticate, returns JWT |
| /api/health | GET | Health check |

### 3.2 Core Endpoints (Auth Required)

| Endpoint | Method | Description |
|----------|--------|-------------|
| /companies | GET | List all companies |
| /companies/import | POST | Import (CSV or JSON array) |
| /run-agent | POST | Run analysis for a brand |
| /agent-state | GET | Agent loop status |
| /history | GET | Analysis history |
| /history-detail?id= | GET | Detailed analysis |
| /evidence?brand_id= | GET | Brand evidence |
| /queries?brand_id= | GET | Query history |
| /observations?brand_id= | GET | Agent observations |
| /changes?brand_id= | GET | Change log |
| /learning | GET | Learning data |
| /feedback | GET | User feedback |

### 3.3 Agent Brain Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| /api/agent-brain/status | GET | Brain status |
| /api/agent/decisions | GET | List decisions |
| /api/agent/decisions/{id} | GET | Decision detail |
| /api/agent/decisions/{id}/skip | POST | Skip decision |
| /api/agent/decisions/{id}/approve | POST | Approve decision |
| /api/agent/run | POST | Run agent now |
| /api/agent/pause | POST | Pause agent |
| /api/agent/resume | POST | Resume agent |
| /api/agent/start-loop | POST | Start auto loop |
| /api/agent/stop | POST | Stop auto loop |

### 3.4 Orchestrator Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| /api/orchestrator/state | GET | Orchestrator state |
| /api/orchestrator/metrics | GET | Performance metrics |
| /api/orchestrator/activity | GET | Recent activity |
| /api/orchestrator/company/{id}/state | GET | Company state |
| /api/orchestrator/next-action/{id} | GET | Next recommended action |
| /api/orchestrator/decisions | GET | All orchestrator decisions |

### 3.5 Learning Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| /api/learning/memory | GET | Learning memories |
| /api/learning/events | GET | Learning events |
| /api/learning/patterns | GET | Detected patterns |
| /api/learning/query-performance | GET | Query performance |
| /api/learning/recommendation-performance | GET | Recommendation perf |
| /api/learning/dashboard | GET | Learning dashboard |
| /api/learning/rebuild/{id} | POST | Rebuild company learning |
| /api/learning/invalidate/{id} | POST | Invalidate memory |

### 3.6 Management Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| /api/tenants | GET | List tenants |
| /api/tenants/current | GET | Current tenant |
| /api/tenants/create | POST | Create tenant |
| /api/tenants/create-user | POST | Create tenant user |
| /api/backups | GET | List backups |
| /api/backup/create | POST | Create backup |
| /api/backup/restore | POST | Restore backup |
| /api/monitoring/health | GET | Detailed health |
| /api/docs | GET | OpenAPI spec |
| /api/report/pdf?company_id= | GET | PDF report |
| /api/alerts/test | GET | Test alerts |
| /api/usage | GET | Usage stats |
| /api/audit | GET | Audit log |

---

## 4. Security Architecture

### 4.1 Authentication Flow

1. Client sends POST /api/login with {username, password}
2. Server verifies against bcrypt password hash
3. Server creates JWT: {user, role, tenant_id, exp, iat, jti}
4. Server returns token (base64_json.hmac_signature)
5. Client stores token in localStorage
6. All subsequent requests include: Authorization: Bearer <token>
7. Server verifies HMAC signature + expiry on each request

### 4.2 Security Layers

| Layer | Implementation | Config |
|-------|---------------|--------|
| Auth | JWT HMAC-SHA256 | 24h expiry |
| Password | bcrypt hash | 12 rounds |
| CORS | Configurable origins | .env CORS_ALLOWED_ORIGINS |
| Rate Limiting | Per-IP bucket | 60 req/min |
| Headers | Security headers | X-Content-Type, X-Frame, Referrer-Policy |
| Audit | Request logging | usage_log + audit_log tables |

---

## 5. Agent Brain Architecture

### 5.1 Autonomous Loop

OBSERVE -> REASON -> DECIDE -> ACT -> REFLECT
- Scan DB (15 observation types)
- LLM Call (strategy reasoning)
- Store Decision
- Execute Job
- Score Effectiveness

### 5.2 Observation Types (15)

| Type | Severity | Trigger |
|------|----------|---------|
| STALE_EVIDENCE | WARNING | Evidence older than 30 days |
| CONTINUOUS_DECLINE | CRITICAL | Score dropping 3+ cycles |
| LOW_AI_VISIBILITY | WARNING | Score below 30 |
| FEW_QUERIES | INFO | Less than 5 tracked queries |
| NO_COMPETITORS | INFO | No competitor data |
| JOB_QUEUE_BACKLOG | WARNING | 10+ pending jobs |
| HIGH_FAILURE_RATE | CRITICAL | 50%+ job failures |
| JOB_TYPE_FAILING | WARNING | Specific job type failing |
| HIGH_DECISION_SKIP_RATE | WARNING | 80%+ decisions skipped |
| MANY_OPEN_RECS | INFO | 10+ open recommendations |

### 5.3 Decision Actions

| Action | Description |
|--------|-------------|
| REANALYZE | Trigger full brand re-analysis |
| UPDATE_PROFILE | Suggest profile improvements |
| ADD_QUERY | Add new tracking queries |
| TRACK_COMPETITOR | Start competitor monitoring |
| ESCALATE | Flag for human review |
| PIVOT | Change strategy based on outcomes |
| ADJUST | Fine-tune existing approach |

---

## 6. Deployment

### 6.1 Requirements

- Python 3.10+
- 2GB RAM minimum
- 10GB disk space
- Internet access (for LLM APIs)

### 6.2 Environment Variables (.env)

GEMINI_API_KEY=your_key
GROQ_API_KEY=your_key
GROQ_MODEL=qwen/qwen3.8-27b
SERPAPI_KEY=your_key
AGENT_DB=sqlite
AUTH_SECRET_KEY=random_string
AUTH_DEFAULT_USER=admin
AUTH_DEFAULT_PASS=changeme123
CORS_ALLOWED_ORIGINS=http://localhost:8000
RATE_LIMIT_PER_MINUTE=60

### 6.3 Docker Deployment

docker-compose up -d

### 6.4 Manual Deployment

pip install -r requirements.txt
python agent.py
Server runs at http://localhost:8000

### 6.5 File Structure

project/
  agent.py          - Backend server (~16K lines)
  index.html        - Frontend SPA (~3.8K lines)
  .env              - Configuration (secrets)
  .env.example      - Template
  requirements.txt  - Python dependencies
  Dockerfile        - Container build
  docker-compose.yml
  mcp_server.py     - MCP protocol server
  tests/
    test_agent.py   - 14 tests
  backups/          - Auto-backups directory

---

## 7. LLM Integration

### 7.1 Primary: Gemini AI

- Model: gemini-2.5-flash
- Max tokens: 800 (for Groq compatibility)
- Fallback: gemini-2.5-flash-lite
- Used for: Analysis, observations, decisions, recommendations

### 7.2 Failover: Groq AI

- Model: qwen/qwen3.8-27b
- Max tokens: 800
- Triggered when: Gemini quota exceeded or unavailable
- Rate limit: 429 retry with exponential backoff

### 7.3 Search: SerpAPI

- Used for: Real search result data
- Queries: Brand-specific + competitor queries
- Rate limit: 100 searches/month (free tier)

---

## 8. Performance Targets

| Metric | Target |
|--------|--------|
| API Response Time | < 2s (p95) |
| Analysis Time | < 60s per brand |
| Database Size | < 1GB |
| Concurrent Users | 50+ |
| Uptime | 99.5% |

---

*End of TRD*

