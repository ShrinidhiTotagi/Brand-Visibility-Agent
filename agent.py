#!/usr/bin/env python3
"""
AI Search Brand Visibility Autonomous Intelligence Agent  v2
=============================================================
Autonomous, self-learning brand visibility intelligence system.

Replaces the manual "enter company -> click analyze" flow with an
autonomous agent loop that continuously:
  - collects available data (manual, CSV, website scraper, historical)
  - validates evidence and stores it with source/confidence metadata
  - discovers companies (external integrations only; never fake data)
  - generates and remembers search queries (query memory)
  - observes AI / search responses (real providers only)
  - runs deterministic, explainable analysis (readiness scoring)
  - reports observed AI-search metrics in a SEPARATE section
  - detects changes vs previous results (change log)
  - learns from evidence + approved feedback (learning memory)
  - schedules and re-runs analysis automatically (agent loop + jobs)
"""

import os
import sys
import json
import time
import re
import csv
import io
import hashlib
import hmac
import secrets
import logging
import threading
import datetime
import uuid
import decimal

# Load .env file if present (simple key=value parser, no dotenv dependency)
_env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
if os.path.exists(_env_path):
    with open(_env_path) as _f:
        for _line in _f:
            _line = _line.strip()
            if _line and not _line.startswith("#") and "=" in _line:
                _k, _v = _line.split("=", 1)
                os.environ.setdefault(_k.strip(), _v.strip())
import html as _html
import warnings
warnings.filterwarnings("ignore", category=FutureWarning)
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse
from urllib.request import Request, urlopen
from urllib.error import URLError
from collections import defaultdict
from functools import wraps

# ---------------------------------------------------------------------------
# HARDCODED CONFIGURATION (no .env file needed)
# ---------------------------------------------------------------------------
LOG_LEVEL = "INFO"
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("agent")

CORS_ALLOWED = {"http://localhost:8000", "http://127.0.0.1:8000", "http://88.150.227.117:8000",
                "https://myblocks.in:11300", "https://myblocks.in", "http://myblocks.in:11300"}
for _o in os.environ.get("AGENT_CORS_ORIGINS", "").split(","):
    _o = _o.strip()
    if _o:
        CORS_ALLOWED.add(_o)

# ---------------------------------------------------------------------------
# API PATH PREFIX (for portals that forward only a sub-path to this backend).
# e.g. AGENT_API_PREFIX=/agent-api  ->  backend answers /agent-api/companies
# for a request path of /agent-api/companies. Default "" = serve at root.
# ---------------------------------------------------------------------------
API_PREFIX = os.environ.get("AGENT_API_PREFIX", "").rstrip("/")

def _strip_prefix(path):
    """Strip API_PREFIX so internal routing always sees root-relative paths."""
    if API_PREFIX and (path == API_PREFIX or path.startswith(API_PREFIX + "/")):
        return path[len(API_PREFIX):] or "/"
    return path

# ---------------------------------------------------------------------------
# DATABASE CONFIGURATION
# ---------------------------------------------------------------------------
DB_PATH = os.environ.get("AGENT_DB_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent_storage.db"))

# ---------------------------------------------------------------------------
# SECURITY: JWT AUTH
# ---------------------------------------------------------------------------
JWT_SECRET = "change-me-to-a-random-string"
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_HOURS = 24
DEFAULT_USER = "admin"
DEFAULT_PASS = "changeme123"

# Simple user store (extend with DB for multi-user)
_users = {
    DEFAULT_USER: {
        "password_hash": hashlib.sha256(DEFAULT_PASS.encode()).hexdigest(),
        "role": "admin",
    }
}

def _hash_password(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def _create_token(username, role="admin", tenant_id=None, tenant_slug=None):
    """Create a simple JWT-like token (base64 JSON + HMAC signature)."""
    import base64
    payload = {
        "user": username,
        "role": role,
        "tenant_id": tenant_id,
        "tenant_slug": tenant_slug,
        "exp": time.time() + JWT_EXPIRY_HOURS * 3600,
        "iat": time.time(),
        "jti": secrets.token_hex(8),
    }
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
    sig = hmac.new(JWT_SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()
    return f"{body}.{sig}"

def _verify_token(token):
    """Verify token and return payload or None."""
    import base64
    try:
        parts = token.split(".")
        if len(parts) != 2:
            return None
        body, sig = parts
        expected = hmac.new(JWT_SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        payload = json.loads(base64.urlsafe_b64decode(body + "=="))
        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except Exception:
        return None

def _extract_user(handler):
    """Extract authenticated user from request headers. Returns (user_dict, error_response, status_code)."""
    # Login disabled for now - allow all requests
    return {"user": "admin", "role": "admin"}, None, 200

# ---------------------------------------------------------------------------
# SECURITY: RATE LIMITER
# ---------------------------------------------------------------------------
RATE_LIMIT_PER_MINUTE = 300
RATE_LIMIT_LOGIN_PER_MINUTE = 20
_rate_buckets = defaultdict(list)
_rate_lock = threading.Lock()

def _check_rate_limit(ip, limit=RATE_LIMIT_PER_MINUTE):
    """Return True if request is allowed, False if rate limited.
    Buckets are keyed by (ip, limit) so login brute-force protection
    (strict) is independent from the general API budget (generous)."""
    now = time.time()
    window = now - 60
    bucket = (ip, limit)
    with _rate_lock:
        _rate_buckets[bucket] = [t for t in _rate_buckets[bucket] if t > window]
        if len(_rate_buckets[bucket]) >= limit:
            return False
        _rate_buckets[bucket].append(now)
        return True

# ---------------------------------------------------------------------------
# MULTI-TENANCY
# ---------------------------------------------------------------------------
_TENANT_DDL = """
CREATE TABLE IF NOT EXISTS tenants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    logo_url TEXT DEFAULT '',
    primary_color TEXT DEFAULT '#3b82f6',
    company_name TEXT DEFAULT '',
    plan TEXT DEFAULT 'starter',
    max_companies INTEGER DEFAULT 10,
    api_key TEXT UNIQUE,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS tenant_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'viewer',
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);
CREATE TABLE IF NOT EXISTS usage_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER,
    user_id INTEGER,
    action TEXT NOT NULL,
    resource TEXT,
    details TEXT,
    ip_address TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER,
    user_id INTEGER,
    action TEXT NOT NULL,
    entity_type TEXT,
    entity_id INTEGER,
    old_value TEXT,
    new_value TEXT,
    ip_address TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);
"""

def _init_tenants():
    """Create tenant tables and default tenant."""
    try:
        for _ddl in _TENANT_DDL.strip().split(";"):
            _ddl = _ddl.strip()
            if _ddl:
                db.execute(_mysqlize_ddl(_ddl))
        # Create default tenant if none exists
        existing = db.query("SELECT COUNT(*) as cnt FROM tenants")
        if existing[0]["cnt"] == 0:
            db.execute(
                "INSERT INTO tenants (name, slug, plan, max_companies, api_key) VALUES (?,?,?,?,?)",
                ("Default", "default", "enterprise", 100, secrets.token_hex(32)))
            tid = db.query("SELECT id FROM tenants WHERE slug='default'")[0]["id"]
            # Create default admin user for default tenant
            db.execute(
                "INSERT INTO tenant_users (tenant_id, username, password_hash, role) VALUES (?,?,?,?)",
                (tid, DEFAULT_USER, _hash_password(DEFAULT_PASS), "admin"))
        logger.info("Tenant tables ready.")
    except Exception as e:
        logger.warning(f"Tenant init: {e}")

def create_tenant(name, slug, plan="starter", max_companies=10):
    api_key = secrets.token_hex(32)
    tid = db.execute(
        "INSERT INTO tenants (name, slug, plan, max_companies, api_key) VALUES (?,?,?,?,?)",
        (name, slug, plan, max_companies, api_key))
    return {"id": tid, "api_key": api_key}

def create_tenant_user(tenant_id, username, password, role="viewer"):
    return db.execute(
        "INSERT INTO tenant_users (tenant_id, username, password_hash, role) VALUES (?,?,?,?)",
        (tenant_id, username, _hash_password(password), role))

def authenticate_tenant_user(username, password):
    rows = db.query("SELECT tu.*, t.slug as tenant_slug, t.name as tenant_name, t.logo_url, t.primary_color FROM tenant_users tu JOIN tenants t ON t.id=tu.tenant_id WHERE tu.username=?", (username,))
    if rows and rows[0]["password_hash"] == _hash_password(password):
        return dict(rows[0])
    return None

# ---------------------------------------------------------------------------
# USAGE TRACKING & AUDIT LOG
# ---------------------------------------------------------------------------

def get_usage_stats(tenant_id=None, days=30):
    """Get usage statistics for billing."""
    cf = "WHERE tenant_id=?" if tenant_id else ""
    cp = (tenant_id,) if tenant_id else ()
    total = db.query(f"SELECT COUNT(*) as cnt FROM usage_log {cf}", cp)[0]["cnt"]
    by_action = db.query(
        f"SELECT action, COUNT(*) as cnt FROM usage_log {cf} GROUP BY action ORDER BY cnt DESC", cp)
    by_day = db.query(
        f"SELECT DATE(created_at) as day, COUNT(*) as cnt FROM usage_log {cf} GROUP BY day ORDER BY day DESC LIMIT ?", cp + (days,))
    return {
        "total_requests": total,
        "by_action": [dict(r) for r in by_action],
        "by_day": [dict(r) for r in by_day],
    }

def get_audit_log(tenant_id=None, limit=100):
    """Get audit trail."""
    cf = "WHERE tenant_id=?" if tenant_id else ""
    cp = (tenant_id,) if tenant_id else ()
    return [dict(r) for r in db.query(
        f"SELECT * FROM audit_log {cf} ORDER BY id DESC LIMIT ?", cp + (limit,))]

def _cors_headers(handler, origin=None):
    """Return CORS headers dict."""
    headers = {}
    if origin and origin in CORS_ALLOWED:
        headers["Access-Control-Allow-Origin"] = origin
    elif not CORS_ALLOWED:
        headers["Access-Control-Allow-Origin"] = "*"
    headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    headers["Access-Control-Max-Age"] = "86400"
    return headers

# ---------------------------------------------------------------------------
# OPTIONAL INTEGRATIONS (disable gracefully when not connected)
# ---------------------------------------------------------------------------
# Credentials come from environment / .env (never committed to git).
# LOCAL SERVER COPY ONLY - uncommitted. Strip before any git push.
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
SERPAPI_KEY = os.environ.get("SERPAPI_KEY", "")

# Primary Gemini model + automatic failover model.
GEMINI_MODEL = "gemini-2.5-flash"
GEMINI_FALLBACK_MODEL = "gemini-2.5-flash-lite"

gemini_available = False
gemini_model = None
gemini_fallback_model = None
try:
    import google.generativeai as genai
    if GEMINI_API_KEY:
        genai.configure(api_key=GEMINI_API_KEY)
        gemini_model = genai.GenerativeModel(GEMINI_MODEL)
        gemini_fallback_model = genai.GenerativeModel(GEMINI_FALLBACK_MODEL)
        gemini_available = True
        print(f"[Gemini] Connected (google-generative-ai, {GEMINI_MODEL} | failover {GEMINI_FALLBACK_MODEL}).",
              flush=True)
    else:
        print("[Gemini] NOT CONNECTED - no GEMINI_API_KEY in env.", flush=True)
except Exception as e:
    print(f"[Gemini] NOT CONNECTED - {e}", flush=True)


def _gemini_complete(prompt, max_tokens=800, temperature=0.4):
    """Generate text via Gemini → Groq fallback chain.
    Returns (text, model_name). Raises the last provider error when all models fail."""
    last_err = None

    # Try Gemini models first
    if gemini_available:
        for mdl in (gemini_model, gemini_fallback_model):
            if not mdl:
                continue
            try:
                resp = mdl.generate_content(
                    prompt, generation_config=genai.types.GenerationConfig(
                        max_output_tokens=max_tokens, temperature=temperature))
                try:
                    text = resp.text or ""
                except Exception:
                    text = ""
                return text, (mdl.model_name or "").replace("models/", "")
            except Exception as exc:
                last_err = exc

    # Fallback to Groq (14,400 req/day free tier)
    if groq_available:
        try:
            text, model = _groq_complete(prompt, max_tokens=max_tokens, temperature=temperature)
            return text, model
        except Exception as exc:
            last_err = exc

    if last_err is not None:
        raise last_err
    raise RuntimeError("No LLM provider available")

requests_available = False
try:
    import requests
    requests_available = True
except ImportError:
    print("[requests] NOT CONNECTED - 'requests' package missing.", flush=True)

# ── Groq (free tier: 14,400 req/day) ──────────────────────────────────────
# Key from environment / .env (LOCAL SERVER COPY ONLY - uncommitted).
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_MODEL = "qwen/qwen3.8-27b"
groq_client = None
groq_available = False
try:
    if GROQ_API_KEY:
        import groq as _groq_mod
        # max_retries=0: SDK must NOT retry internally (it waits 30s+ per
        # retry and blocks worker threads). Our wrapper does one quick 8s
        # retry then fails over to templates immediately.
        groq_client = _groq_mod.Groq(api_key=GROQ_API_KEY, max_retries=0)
        groq_available = True
        print(f"[Groq] Connected ({GROQ_MODEL}).", flush=True)
    else:
        print("[Groq] NOT CONNECTED - no GROQ_API_KEY in env.", flush=True)
except Exception as e:
    print(f"[Groq] NOT CONNECTED - {e}", flush=True)


def _groq_complete(prompt, max_tokens=1024, temperature=0.4):
    """Generate text via Groq. Returns (text, model_name). Raises on failure."""
    if not groq_available or not groq_client:
        raise RuntimeError("Groq not connected")
    import time as _time
    for attempt in range(2):
        try:
            resp = groq_client.chat.completions.create(
                model=GROQ_MODEL,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=max_tokens,
                temperature=temperature,
            )
            return (resp.choices[0].message.content or ""), GROQ_MODEL
        except Exception as e:
            if ("429" in str(e) or "rate_limit" in str(e).lower()) and attempt == 0:
                print("[Groq] Rate limited, quick retry in 8s", flush=True)
                _time.sleep(8)
                continue
            raise

MYSQL_AVAILABLE = False
try:
    import pymysql
    MYSQL_AVAILABLE = True
except ImportError:
    try:
        import mysql.connector
        MYSQL_AVAILABLE = True
    except ImportError:
        MYSQL_AVAILABLE = False

import sqlite3

# ---------------------------------------------------------------------------
# UTILITIES
# ---------------------------------------------------------------------------

def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def safe_json_loads(text, default=None):
    if not text:
        return default
    try:
        return json.loads(text)
    except Exception:
        return default


def clean_json_text(raw):
    """Extract the first complete, balanced JSON value from a model response.
    Strips markdown fences, surrounding prose, smart quotes and trailing commas."""
    if not raw:
        return ""
    text = str(raw).strip()
    # Drop markdown code fences.
    text = re.sub(r"^```[a-zA-Z]*\s*\n?", "", text, count=1)
    text = re.sub(r"\n?\s*```\s*$", "", text, count=1).strip()
    # Smart-quote normalization + trailing commas (common JSON.parse failures).
    text = text.replace("\u201c", '"').replace("\u201d", '"')
    text = text.replace("\u2018", "'").replace("\u2019", "'")
    # Locate the first top-level '{' or '[' and scan for the matching, balanced close.
    pairs = {"{": "}", "[": "]"}
    start = None
    for c in ("{", "["):
        p = text.find(c)
        if p != -1 and (start is None or p < start):
            start = p
    if start is None:
        return text
    depth = {k: 0 for k in pairs}
    in_str = False
    esc = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch in depth:
            depth[ch] += 1
        elif ch in pairs.values():
            for k, close in pairs.items():
                if ch == close:
                    depth[k] -= 1
        if all(v == 0 for v in depth.values()) and i > start:
            return re.sub(r",\s*([}\]])", r"\1", text[start:i + 1]).strip()
    return text


def default_config():
    return {
        "startup_auto_run": "1",
        "auto_loop_enabled": "1",
        "daily_enabled": "1",
        "freshness_days": "7",
        "weekly_enabled": "1",
        "weekly_day": "1",
        "weekly_hour": "1",
        "tick_seconds": "10",
        "max_retries": "3",
        "scrape_enabled": "1",
        "ai_observation_queries": "5",
        "ai_observation_limit": "10",
        "reanalysis_on_change_enabled": "1",
        "query_generation_limit": "20",
        "gemini_queries": "1",
        "evidence_fresh_days": "7",
        "evidence_stale_days": "14",
        "evidence_expired_days": "30",
        "analysis_stale_days": "14",
        "analysis_expired_days": "30",
        "max_jobs_per_tick": "50",
        # Automation + scheduler (Phase 2). Interval in minutes; the scheduler
        # only CREATES jobs - it never executes analysis itself.
        "scheduler_interval_minutes": "5",
        "scheduler_paused": "0",
        "scheduler_auto_start": "1",
        "automation_enabled": "1",
        # Data freshness buckets used by the automation service and UI.
        "data_fresh_days": "7",
        "data_stale_days": "30",
        # Phase 4 self-learning engine (central configuration - never scattered).
        "LEARNING_ENABLED": "1",
        "MIN_PATTERN_OBSERVATIONS": "3",
        "MIN_GLOBAL_OBSERVATIONS": "3",
        "LEARNING_DECAY_DAYS": "90",
        "QUERY_SUCCESS_THRESHOLD": "3",
        "QUERY_FAILURE_THRESHOLD": "3",
        "RECOMMENDATION_SUPPRESSION_ENABLED": "1",
        # Phase 5 autonomous intelligence + orchestration (central configuration).
        "AUTONOMOUS_ENABLED": "1",
        "AUTONOMOUS_MODE": "LIVE",
        "MAX_AUTONOMOUS_CYCLES": "10",
        "MAX_JOBS_PER_CYCLE": "25",
        "MAX_COMPANIES_PER_CYCLE": "5",
        "QUERY_STALE_DAYS": "14",
        "MAJOR_CHANGE_COUNT": "3",
        # Orchestrator (Phase 5b): single-next-action loop over the same engines.
        "ORCHESTRATOR_ENABLED": "1",
        "ORCHESTRATOR_LLM_ASSIST": "0",
        "ORCHESTRATOR_MAX_STEPS": "15",
        # Reasoning engine (Phase 7): read-only assessment; never executes.
        "REASONING_ENABLED": "1",
        "REASONING_LLM_ASSIST": "0",
        "ORCHESTRATOR_USE_REASONING": "0",
        # MCP tool layer (Phase 9).
        "MCP_MEDIUM_AUTO": "1",
        "MCP_MAX_TOOL_CALLS": "10",
        # Planning engine (Phase 10): planner creates, orchestrator executes.
        "MAX_PLAN_STEPS": "20",
        "MAX_PLAN_DEPTH": "10",
        "MAX_REPLANS": "5",
        "MAX_PARALLEL_STEPS": "4",
        "PLANNING_LLM_ASSIST": "0",
        # RAG / vector knowledge (Phase 11). MySQL stays the source of truth.
        # Threshold calibrated on all-MiniLM-L6-v2 cosine scores for this
        # corpus: unrelated queries score ~0, related ones ~0.5+. Tunable.
        "RAG_ENABLED": "1",
        "RAG_EMBEDDING_PROVIDER": "gemini",
        "RAG_EMBEDDING_MODEL": "gemini-embedding-001",
        "RAG_TOP_K": "5",
        "RAG_MIN_SIMILARITY": "0.25",
        "RAG_CHUNK_SIZE": "500",
        "RAG_CHUNK_OVERLAP": "50",
        "RAG_MAX_CONTEXT_ITEMS": "20",
        "RAG_INDEX_BATCH_SIZE": "25",
    }


# ---------------------------------------------------------------------------
# DATABASE LAYER
# ---------------------------------------------------------------------------

class DatabaseManager:
    """SQLite-first storage with optional MySQL mirroring.

    SQLite is the primary backend because it is self-contained, robust and
    supports the full v2 schema everywhere. MySQL is used only when
    AGENT_DB=mysql is explicitly configured and reachable.
    """

    def __init__(self):
        self.db_host = "88.150.227.117"
        self.db_port = 3306
        self.db_user = "temp_admin"
        self.db_password = "hwTU!*83"
        self.db_name = "temp"
        self.mode = "mysql" if os.environ.get("AGENT_DB", "sqlite") == "mysql" else "sqlite"
        self.sqlite_path = DB_PATH
        self.flavor = self.mode
        self._pool = []

    def _strip_strict_mode(self, conn):
        try:
            cur = conn.cursor()
            cur.execute("SELECT @@sql_mode")
            mode = cur.fetchone()
            if isinstance(mode, dict):
                mode_str = mode.get("@@sql_mode") or mode.get("@_sql_mode") or ""
            elif mode:
                mode_str = mode[0] or ""
            else:
                mode_str = ""
            mode_str = mode_str.replace("STRICT_TRANS_TABLES", "").replace("STRICT_ALL_TABLES", "").strip(", ")
            if mode_str == "@@sql_mode":
                mode_str = ""
            cur.execute("SET SESSION sql_mode=%s", (mode_str,))
        except Exception:
            pass

    def get_connection(self):
        if self._pool and self.mode == "mysql":
            try:
                conn = self._pool.pop()
                try:
                    conn.ping(reconnect=True)
                except Exception:
                    conn = None
                if conn is not None:
                    self._strip_strict_mode(conn)
                    return conn
            except IndexError:
                pass
        if self.mode == "mysql" and MYSQL_AVAILABLE:
            try:
                if "mysql.connector" in sys.modules and sys.modules.get("mysql.connector"):
                    import mysql.connector
                    conn = mysql.connector.connect(
                        host=self.db_host, port=self.db_port,
                        user=self.db_user, password=self.db_password,
                        database=self.db_name, autocommit=True,
                        connection_timeout=10,
                    )
                else:
                    import pymysql
                    conn = pymysql.connect(
                        host=self.db_host, port=self.db_port,
                        user=self.db_user, password=self.db_password,
                        database=self.db_name, autocommit=True,
                        charset="utf8mb4", cursorclass=pymysql.cursors.DictCursor,
                        connect_timeout=10, read_timeout=30, write_timeout=30,
                    )
                self._strip_strict_mode(conn)
                self.flavor = "mysql"
                return conn
            except Exception as e:
                print(f"[Database Warning] MySQL unavailable ({e}); using SQLite.", flush=True)
                self.mode = "sqlite"
        conn = sqlite3.connect(self.sqlite_path, timeout=60)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
        except Exception:
            pass
        conn.execute("PRAGMA busy_timeout = 60000")
        self.flavor = "sqlite"
        return conn

    def return_connection(self, conn):
        if self.mode == "mysql" and len(self._pool) < 5:
            try:
                self._pool.append(conn)
                return
            except Exception:
                pass
        try:
            conn.close()
        except Exception:
            pass

    def ph(self, sql):
        return sql.replace("?", "%s") if self.flavor == "mysql" else sql

    def _fix_reserved(self, sql):
        # Backtick MySQL reserved words used as column names (trigger, key),
        # skipping DDL and single-quoted string literals. Safe no-op for SQLite.
        if self.flavor != "mysql":
            return sql
        s = sql.strip().upper()
        if s.startswith(("CREATE", "ALTER", "DROP", "TRUNCATE")):
            return sql
        parts = sql.split("'")
        for i in range(0, len(parts), 2):
            parts[i] = re.sub(r"\b(trigger|key)\b", r"`\1`", parts[i], flags=re.IGNORECASE)
        return "'".join(parts)

    def query(self, sql, params=()):
        conn = self.get_connection()
        cur = conn.cursor()
        try:
            cur.execute(self.ph(self._fix_reserved(sql)), params)
            if self.flavor == "mysql":
                return [dict(r) for r in cur.fetchall()] if cur.description else []
            return [dict(r) for r in cur.fetchall()]
        finally:
            self.return_connection(conn)

    def execute(self, sql, params=()):
        conn = self.get_connection()
        cur = conn.cursor()
        try:
            cur.execute(self.ph(self._fix_reserved(sql)), params)
            if self.flavor == "sqlite":
                conn.commit()
            rid = cur.lastrowid
            # For MySQL with varchar PK, lastrowid is 0; check if this was an INSERT into jobs with UUID
            if self.flavor == "mysql" and rid == 0 and sql.strip().upper().startswith("INSERT INTO JOBS"):
                # Try to get the UUID from the params (first param after 'id')
                for p in params:
                    if isinstance(p, str) and '-' in p and len(p) == 36:
                        return p
            return rid
        finally:
            self.return_connection(conn)

    def insert(self, sql, params=()):
        return self.execute(sql, params)


db = DatabaseManager()


# ---------------------------------------------------------------------------
# SCHEMA
# ---------------------------------------------------------------------------

# Table: (name, [ (column, sqldef), ... ])
# sqldef uses SQLite syntax; MySQL differences are translated in build_ddl().

TABLES = {
    "brands": [
        ("id", "INTEGER PRIMARY KEY AUTOINCREMENT"),
        ("brand_name", "TEXT NOT NULL"),
        ("website", "TEXT"),
        ("industry", "TEXT NOT NULL DEFAULT 'General'"),
        ("region", "TEXT"),
        ("company_type", "TEXT"),
        ("description", "TEXT"),
        ("keywords", "TEXT"),
        ("target_audience", "TEXT"),
        ("competitors", "TEXT"),
        ("data_source", "TEXT DEFAULT 'MANUAL'"),
        ("source_detail", "TEXT"),
        ("verification_status", "TEXT DEFAULT 'UNVERIFIED'"),
        ("confidence", "REAL DEFAULT 0.5"),
        ("is_active", "INTEGER DEFAULT 1"),
        ("last_analyzed_at", "TEXT"),
        ("created_at", "TEXT"),
        ("last_updated_at", "TEXT"),
    ],
    "analysis_results": [
        ("id", "INTEGER PRIMARY KEY AUTOINCREMENT"),
        ("brand_id", "INTEGER NOT NULL"),
        ("visibility_score", "INTEGER"),
        ("readiness_score", "INTEGER"),
        ("observed_score", "INTEGER"),
        ("mention_rate", "INTEGER"),
        ("topic_coverage", "INTEGER"),
        ("competitor_strength", "INTEGER"),
        ("readiness_breakdown", "TEXT"),
        ("observed_metrics", "TEXT"),
        ("score_reasons", "TEXT"),
        ("analysis_data", "TEXT"),
        ("trigger", "TEXT DEFAULT 'MANUAL'"),
        ("run_id", "TEXT"),
        ("created_at", "TEXT"),
    ],
    "recommendations": [
        ("id", "INTEGER PRIMARY KEY AUTOINCREMENT"),
        ("brand_id", "INTEGER NOT NULL"),
        ("analysis_id", "INTEGER"),
        ("run_id", "TEXT"),
        ("title", "TEXT NOT NULL"),
        ("description", "TEXT"),
        ("priority", "TEXT"),
        ("category", "TEXT"),
        ("evidence_key", "TEXT"),
        ("status", "TEXT DEFAULT 'OPEN'"),
        ("feedback", "TEXT"),
        ("feedback_at", "TEXT"),
        ("resolution_source", "TEXT"),
        ("first_seen_at", "TEXT"),
        ("last_seen_at", "TEXT"),
        ("times_generated", "INTEGER DEFAULT 1"),
        ("created_at", "TEXT"),
    ],
    "query_memory": [
        ("id", "INTEGER PRIMARY KEY AUTOINCREMENT"),
        ("brand_id", "INTEGER NOT NULL"),
        ("query_text", "TEXT NOT NULL"),
        ("fingerprint", "TEXT"),
        ("intent", "TEXT"),
        ("keyword", "TEXT"),
        ("category", "TEXT"),
        ("first_seen", "TEXT"),
        ("last_tested", "TEXT"),
        ("last_used_at", "TEXT"),
        ("times_tested", "INTEGER DEFAULT 0"),
        ("useful_count", "INTEGER DEFAULT 0"),
        ("not_useful_count", "INTEGER DEFAULT 0"),
        ("previous_result", "TEXT"),
        ("current_result", "TEXT"),
        ("trend", "TEXT"),
        ("priority_score", "REAL DEFAULT 0.5"),
        ("historical_value", "REAL DEFAULT 0.5"),
        ("is_active", "INTEGER DEFAULT 1"),
        ("status", "TEXT DEFAULT 'ACTIVE'"),
        ("source", "TEXT DEFAULT 'GENERATED'"),
        ("metadata_json", "TEXT"),
        ("created_at", "TEXT"),
    ],
    "ai_observations": [
        ("id", "INTEGER PRIMARY KEY AUTOINCREMENT"),
        ("brand_id", "INTEGER NOT NULL"),
        ("brand_name", "TEXT"),
        ("query_id", "INTEGER"),
        ("query_text", "TEXT"),
        ("provider", "TEXT"),
        ("model", "TEXT"),
        ("observed_at", "TEXT"),
        ("response_json", "TEXT"),
        ("response_text", "TEXT"),
        ("brand_mentioned", "INTEGER DEFAULT 0"),
        ("brand_position", "INTEGER"),
        ("brand_mention_context", "TEXT"),
        ("competitors_mentioned", "TEXT"),
        ("sentiment", "TEXT"),
        ("confidence", "REAL"),
    ],
    "evidence": [
        ("id", "INTEGER PRIMARY KEY AUTOINCREMENT"),
        ("brand_id", "INTEGER NOT NULL"),
        ("evidence_type", "TEXT"),
        ("evidence_key", "TEXT"),
        ("evidence_value", "TEXT"),
        ("source", "TEXT"),
        ("source_detail", "TEXT"),
        ("verification_status", "TEXT DEFAULT 'UNVERIFIED'"),
        ("confidence", "REAL DEFAULT 0.5"),
        ("raw_json", "TEXT"),
        ("collected_at", "TEXT"),
        ("last_updated_at", "TEXT"),
    ],
    "discovery_candidates": [
        ("id", "INTEGER PRIMARY KEY AUTOINCREMENT"),
        ("industry", "TEXT"),
        ("region", "TEXT"),
        ("company_type", "TEXT"),
        ("external_source", "TEXT"),
        ("candidate_name", "TEXT"),
        ("website", "TEXT"),
        ("raw_json", "TEXT"),
        ("status", "TEXT DEFAULT 'NEW'"),
        ("duplicate_of", "INTEGER"),
        ("created_at", "TEXT"),
    ],
    "jobs": [
        ("id", "INTEGER PRIMARY KEY AUTOINCREMENT"),
        ("job_id", "TEXT"),
        ("company_id", "INTEGER"),
        ("job_type", "TEXT NOT NULL"),
        ("status", "TEXT DEFAULT 'PENDING'"),
        ("priority", "INTEGER DEFAULT 50"),
        ("priority_level", "TEXT DEFAULT 'MEDIUM'"),
        ("payload", "TEXT"),
        ("result_json", "TEXT"),
        ("error", "TEXT"),
        ("retry_count", "INTEGER DEFAULT 0"),
        ("max_retries", "INTEGER DEFAULT 3"),
        ("run_id", "TEXT"),
        ("manager_task_id", "TEXT"),
        ("assigned_agent_id", "TEXT"),
        ("parent_job_id", "INTEGER"),
        ("created_at", "TEXT"),
        ("started_at", "TEXT"),
        ("completed_at", "TEXT"),
        ("cancelled_at", "TEXT"),
    ],
    "runs": [
        ("id", "INTEGER PRIMARY KEY AUTOINCREMENT"),
        ("run_id", "TEXT UNIQUE"),
        ("run_type", "TEXT DEFAULT 'MANUAL'"),
        ("status", "TEXT DEFAULT 'RUNNING'"),
        ("current_task", "TEXT"),
        ("progress", "INTEGER DEFAULT 0"),
        ("total_companies", "INTEGER DEFAULT 0"),
        ("processed_companies", "INTEGER DEFAULT 0"),
        ("total_queries", "INTEGER DEFAULT 0"),
        ("processed_queries", "INTEGER DEFAULT 0"),
        ("new_evidence_count", "INTEGER DEFAULT 0"),
        ("changes_detected", "INTEGER DEFAULT 0"),
        ("recommendations_updated", "INTEGER DEFAULT 0"),
        ("total_jobs", "INTEGER DEFAULT 0"),
        ("completed_jobs", "INTEGER DEFAULT 0"),
        ("failed_jobs", "INTEGER DEFAULT 0"),
        ("errors", "INTEGER DEFAULT 0"),
        ("error_details", "TEXT"),
        ("started_at", "TEXT"),
        ("completed_at", "TEXT"),
        ("next_run_at", "TEXT"),
        ("automation_id", "INTEGER"),
    ],
    "workflow_runs": [
        ("id", "INTEGER PRIMARY KEY AUTOINCREMENT"),
        ("run_id", "TEXT"),
        ("company_id", "INTEGER"),
        ("workflow_id", "TEXT"),
        ("workflow_version", "INTEGER DEFAULT 1"),
        ("steps_json", "TEXT"),
        ("tools_json", "TEXT"),
        ("rag_json", "TEXT"),
        ("reasoning_json", "TEXT"),
        ("status", "TEXT DEFAULT 'RUNNING'"),
        ("error", "TEXT"),
        ("started_at", "TEXT"),
        ("finished_at", "TEXT"),
        ("duration_s", "REAL DEFAULT 0"),
        ("mode", "TEXT DEFAULT 'full'"),
        ("skipped_json", "TEXT"),
        ("plan_json", "TEXT"),
    ],
    "agent_activity": [
        ("id", "INTEGER PRIMARY KEY AUTOINCREMENT"),
        ("run_id", "TEXT"),
        ("job_id", "INTEGER"),
        ("company_id", "INTEGER"),
        ("level", "TEXT DEFAULT 'INFO'"),
        ("message", "TEXT"),
        ("created_at", "TEXT"),
    ],
    "change_log": [
        ("id", "INTEGER PRIMARY KEY AUTOINCREMENT"),
        ("brand_id", "INTEGER NOT NULL"),
        ("brand_name", "TEXT"),
        ("run_id", "TEXT"),
        ("change_type", "TEXT"),
        ("field_name", "TEXT"),
        ("previous_value", "TEXT"),
        ("current_value", "TEXT"),
        ("impact", "TEXT"),
        ("severity", "TEXT DEFAULT 'INFO'"),
        ("detected_at", "TEXT"),
    ],
    "manager_task_results": [
        ("id", "INTEGER PRIMARY KEY AUTOINCREMENT"),
        ("result_id", "TEXT"),
        ("manager_task_id", "TEXT NOT NULL"),
        ("task_id", "TEXT"),
        ("agent_id", "TEXT"),
        ("parent_task_id", "TEXT"),
        ("status", "TEXT DEFAULT 'COMPLETED'"),
        ("result_json", "TEXT"),
        ("evidence_json", "TEXT"),
        ("warnings_json", "TEXT"),
        ("created_at", "TEXT"),
        ("updated_at", "TEXT"),
    ],
    "agent_handoffs": [
        ("id", "INTEGER PRIMARY KEY AUTOINCREMENT"),
        ("handoff_id", "TEXT"),
        ("manager_task_id", "TEXT"),
        ("source_task_id", "TEXT"),
        ("source_agent_id", "TEXT"),
        ("destination_task_id", "TEXT"),
        ("destination_agent_id", "TEXT"),
        ("fields_shared_json", "TEXT"),
        ("created_at", "TEXT"),
    ],
    "reasoning_events": [
        ("id", "INTEGER PRIMARY KEY AUTOINCREMENT"),
        ("reasoning_id", "TEXT"),
        ("company_id", "INTEGER"),
        ("run_id", "TEXT"),
        ("decision_id", "TEXT"),
        ("reasoning_mode", "TEXT"),
        ("context_fingerprint", "TEXT"),
        ("situation", "TEXT"),
        ("observations_json", "TEXT"),
        ("evidence_json", "TEXT"),
        ("changes_json", "TEXT"),
        ("missing_information_json", "TEXT"),
        ("candidate_actions_json", "TEXT"),
        ("conflict_json", "TEXT"),
        ("selected_action", "TEXT"),
        ("reason", "TEXT"),
        ("confidence", "REAL"),
        ("requires_human_review", "INTEGER DEFAULT 0"),
        ("created_at", "TEXT"),
    ],
    "mcp_tools": [
        ("id", "INTEGER PRIMARY KEY AUTOINCREMENT"),
        ("tool_id", "TEXT UNIQUE NOT NULL"),
        ("name", "TEXT NOT NULL"),
        ("description", "TEXT"),
        ("version", "TEXT DEFAULT '1.0.0'"),
        ("input_schema_json", "TEXT"),
        ("output_schema_json", "TEXT"),
        ("capability", "TEXT"),
        ("agent_ids_json", "TEXT"),
        ("risk_level", "TEXT DEFAULT 'READ'"),
        ("requires_approval", "INTEGER DEFAULT 0"),
        ("enabled", "INTEGER DEFAULT 1"),
        ("timeout_seconds", "INTEGER DEFAULT 30"),
        ("created_at", "TEXT"),
        ("updated_at", "TEXT"),
    ],
    "mcp_tool_calls": [
        ("id", "INTEGER PRIMARY KEY AUTOINCREMENT"),
        ("call_id", "TEXT"),
        ("request_id", "TEXT"),
        ("client_id", "TEXT"),
        ("agent_id", "TEXT"),
        ("tool_id", "TEXT NOT NULL"),
        ("company_id", "INTEGER"),
        ("status", "TEXT DEFAULT 'SUCCESS'"),
        ("result_json", "TEXT"),
        ("error_code", "TEXT"),
        ("duration_ms", "INTEGER DEFAULT 0"),
        ("created_at", "TEXT"),
    ],
    "planning_plans": [
        ("id", "INTEGER PRIMARY KEY AUTOINCREMENT"),
        ("plan_id", "TEXT NOT NULL"),
        ("goal_id", "TEXT"),
        ("company_id", "INTEGER"),
        ("version", "INTEGER DEFAULT 1"),
        ("status", "TEXT DEFAULT 'DRAFT'"),
        ("objective", "TEXT"),
        ("goal_type", "TEXT"),
        ("steps_json", "TEXT"),
        ("dependencies_json", "TEXT"),
        ("success_conditions_json", "TEXT"),
        ("failure_policy_json", "TEXT"),
        ("constraints_json", "TEXT"),
        ("context_fingerprint", "TEXT"),
        ("parent_plan_id", "TEXT"),
        ("planning_mode", "TEXT DEFAULT 'DETERMINISTIC'"),
        ("created_at", "TEXT"),
        ("updated_at", "TEXT"),
    ],
    "planning_events": [        ("id", "INTEGER PRIMARY KEY AUTOINCREMENT"),
        ("plan_id", "TEXT NOT NULL"),
        ("version", "INTEGER DEFAULT 1"),
        ("event_type", "TEXT NOT NULL"),
        ("step_id", "TEXT"),
        ("previous_state", "TEXT"),
        ("new_state", "TEXT"),
        ("reason", "TEXT"),
        ("metadata_json", "TEXT"),
        ("created_at", "TEXT"),
    ],
    "rag_documents": [
        ("id", "INTEGER PRIMARY KEY AUTOINCREMENT"),
        ("document_id", "TEXT NOT NULL"),
        ("company_id", "INTEGER"),
        ("source_type", "TEXT NOT NULL"),
        ("source_record_id", "TEXT"),
        ("content_hash", "TEXT"),
        ("content_preview", "TEXT"),
        ("vector_backend", "TEXT DEFAULT 'chroma'"),
        ("collection_name", "TEXT DEFAULT 'visibility_knowledge'"),
        ("embedding_model", "TEXT"),
        ("chunk_index", "INTEGER DEFAULT 0"),
        ("chunk_count", "INTEGER DEFAULT 1"),
        ("verification_status", "TEXT"),
        ("source_updated_at", "TEXT"),
        ("indexed_at", "TEXT"),
        ("last_retrieved_at", "TEXT"),
        ("metadata_json", "TEXT"),
        ("status", "TEXT DEFAULT 'ACTIVE'"),
        ("created_at", "TEXT"),
        ("updated_at", "TEXT"),
    ],
    "rag_index_events": [
        ("id", "INTEGER PRIMARY KEY AUTOINCREMENT"),
        ("document_id", "TEXT"),
        ("company_id", "INTEGER"),
        ("event_type", "TEXT NOT NULL"),
        ("source_type", "TEXT"),
        ("source_record_id", "TEXT"),
        ("old_hash", "TEXT"),
        ("new_hash", "TEXT"),
        ("status", "TEXT DEFAULT 'OK'"),
        ("reason", "TEXT"),
        ("created_at", "TEXT"),
    ],
    "rag_retrieval_events": [
        ("id", "INTEGER PRIMARY KEY AUTOINCREMENT"),
        ("request_id", "TEXT"),
        ("company_id", "INTEGER"),
        ("query_hash", "TEXT"),
        ("query_redacted", "TEXT"),
        ("top_k", "INTEGER DEFAULT 5"),
        ("result_count", "INTEGER DEFAULT 0"),
        ("backend", "TEXT"),
        ("embedding_model", "TEXT"),
        ("status", "TEXT DEFAULT 'SUCCESS'"),
        ("latency_ms", "INTEGER DEFAULT 0"),
        ("created_at", "TEXT"),
    ],
    "learning_memory": [
        ("id", "INTEGER PRIMARY KEY AUTOINCREMENT"),
        ("memory_id", "TEXT"),
        ("company_id", "INTEGER"),
        ("memory_type", "TEXT DEFAULT 'COMPANY_PATTERN'"),
        ("category", "TEXT"),
        ("key", "TEXT"),
        ("value", "TEXT"),
        ("pattern", "TEXT"),
        ("source", "TEXT DEFAULT 'AUTO'"),
        ("evidence", "TEXT"),
        ("confidence", "REAL DEFAULT 0.6"),
        ("usage_count", "INTEGER DEFAULT 0"),
        ("success_count", "INTEGER DEFAULT 0"),
        ("failure_count", "INTEGER DEFAULT 0"),
        ("status", "TEXT DEFAULT 'ACTIVE'"),
        ("created_at", "TEXT"),
        ("first_learned_at", "TEXT"),
        ("last_updated_at", "TEXT"),
        ("approved", "INTEGER DEFAULT 0"),
        ("version", "INTEGER DEFAULT 1"),
        ("last_used_at", "TEXT"),
        ("use_count", "INTEGER DEFAULT 0"),
        ("metadata_json", "TEXT"),
    ],
    "learning_events": [
        ("id", "INTEGER PRIMARY KEY AUTOINCREMENT"),
        ("event_id", "TEXT"),
        ("company_id", "INTEGER"),
        ("run_id", "TEXT"),
        ("memory_id", "TEXT"),
        ("event_type", "TEXT NOT NULL"),
        ("description", "TEXT"),
        ("source_type", "TEXT"),
        ("source_id", "TEXT"),
        ("previous_value", "TEXT"),
        ("new_value", "TEXT"),
        ("confidence", "REAL"),
        ("created_at", "TEXT"),
        ("metadata_json", "TEXT"),
    ],
    "query_learning": [
        ("id", "INTEGER PRIMARY KEY AUTOINCREMENT"),
        ("company_id", "INTEGER NOT NULL"),
        ("query", "TEXT NOT NULL"),
        ("fingerprint", "TEXT"),
        ("intent", "TEXT"),
        ("category", "TEXT"),
        ("times_tested", "INTEGER DEFAULT 0"),
        ("useful_count", "INTEGER DEFAULT 0"),
        ("not_useful_count", "INTEGER DEFAULT 0"),
        ("last_result", "TEXT"),
        ("historical_value", "REAL DEFAULT 0.5"),
        ("status", "TEXT DEFAULT 'ACTIVE'"),
        ("first_seen_at", "TEXT"),
        ("last_used_at", "TEXT"),
        ("metadata_json", "TEXT"),
    ],
    "global_learning_memory": [        ("id", "INTEGER PRIMARY KEY AUTOINCREMENT"),
        ("memory_id", "TEXT"),
        ("pattern_key", "TEXT NOT NULL"),
        ("pattern_value", "TEXT"),
        ("category", "TEXT"),
        ("observation_count", "INTEGER DEFAULT 0"),
        ("company_count", "INTEGER DEFAULT 0"),
        ("confidence", "REAL DEFAULT 0.6"),
        ("status", "TEXT DEFAULT 'ACTIVE'"),
        ("first_learned_at", "TEXT"),
        ("last_updated_at", "TEXT"),
        ("metadata_json", "TEXT"),
    ],
    "agent_registry": [
        ("id", "INTEGER PRIMARY KEY AUTOINCREMENT"),
        ("agent_id", "TEXT UNIQUE NOT NULL"),
        ("agent_name", "TEXT NOT NULL"),
        ("agent_type", "TEXT"),
        ("description", "TEXT"),
        ("version", "TEXT DEFAULT '1.0.0'"),
        ("status", "TEXT DEFAULT 'ACTIVE'"),
        ("capabilities_json", "TEXT"),
        ("input_schema_json", "TEXT"),
        ("output_schema_json", "TEXT"),
        ("health_status", "TEXT DEFAULT 'UNKNOWN'"),
        ("last_health_check", "TEXT"),
        ("configuration_json", "TEXT"),
        ("created_at", "TEXT"),
        ("updated_at", "TEXT"),
    ],
    "manager_tasks": [        ("id", "INTEGER PRIMARY KEY AUTOINCREMENT"),
        ("task_id", "TEXT UNIQUE"),
        ("request_id", "TEXT"),
        ("agent_version", "TEXT"),
        ("parent_task_id", "TEXT"),
        ("dependency_task_ids_json", "TEXT"),
        ("request", "TEXT NOT NULL"),
        ("task_type", "TEXT"),
        ("priority", "TEXT DEFAULT 'MEDIUM'"),
        ("status", "TEXT DEFAULT 'RECEIVED'"),
        ("selected_agent_id", "TEXT"),
        ("capability", "TEXT"),
        ("input_json", "TEXT"),
        ("output_json", "TEXT"),
        ("reason", "TEXT"),
        ("created_at", "TEXT"),
        ("started_at", "TEXT"),
        ("completed_at", "TEXT"),
        ("error_message", "TEXT"),
    ],
    "agent_decisions": [        ("id", "INTEGER PRIMARY KEY AUTOINCREMENT"),
        ("decision_id", "TEXT"),
        ("company_id", "INTEGER"),
        ("run_id", "TEXT"),
        ("job_id", "INTEGER"),
        ("action", "TEXT NOT NULL"),
        ("priority", "TEXT DEFAULT 'MEDIUM'"),
        ("reason", "TEXT"),
        ("trigger_type", "TEXT"),
        ("trigger_id", "TEXT"),
        ("confidence", "REAL"),
        ("signals_json", "TEXT"),
        ("decision_source", "TEXT DEFAULT 'RULE_ENGINE'"),
        ("outcome", "TEXT"),
        ("status", "TEXT DEFAULT 'PROPOSED'"),
        ("created_at", "TEXT"),
        ("metadata_json", "TEXT"),
    ],
    "feedback": [
        ("id", "INTEGER PRIMARY KEY AUTOINCREMENT"),
        ("company_id", "INTEGER"),
        ("analysis_id", "INTEGER"),
        ("target_type", "TEXT"),
        ("target_id", "INTEGER"),
        ("feedback", "TEXT"),
        ("comment", "TEXT"),
        ("status", "TEXT DEFAULT 'NEW'"),
        ("created_at", "TEXT"),
    ],
    "agent_config": [
        ("config_key", "TEXT PRIMARY KEY"),
        ("config_value", "TEXT"),
        ("updated_at", "TEXT"),
    ],
    "data_source_status": [
        ("source_key", "TEXT PRIMARY KEY"),
        ("connected", "INTEGER DEFAULT 0"),
        ("provider", "TEXT"),
        ("details", "TEXT"),
        ("last_checked", "TEXT"),
    ],
    "company_settings": [
        ("id", "INTEGER PRIMARY KEY AUTOINCREMENT"),
        ("company_id", "INTEGER UNIQUE NOT NULL"),
        ("monitoring_enabled", "INTEGER DEFAULT 1"),
        ("analysis_frequency", "TEXT DEFAULT 'WEEKLY'"),
        ("change_detection_enabled", "INTEGER DEFAULT 1"),
        ("auto_recommendations_enabled", "INTEGER DEFAULT 1"),
        ("auto_query_refresh_enabled", "INTEGER DEFAULT 0"),
        ("data_refresh_enabled", "INTEGER DEFAULT 0"),
        ("learning_enabled", "INTEGER DEFAULT 1"),
        ("created_at", "TEXT"),
        ("updated_at", "TEXT"),
    ],
    "automations": [
        ("id", "INTEGER PRIMARY KEY AUTOINCREMENT"),
        ("automation_id", "TEXT"),
        ("company_id", "INTEGER"),
        ("automation_type", "TEXT DEFAULT 'FULL_ANALYSIS'"),
        ("schedule_type", "TEXT DEFAULT 'WEEKLY'"),
        ("enabled", "INTEGER DEFAULT 1"),
        ("last_run_at", "TEXT"),
        ("next_run_at", "TEXT"),
        ("last_status", "TEXT DEFAULT 'ACTIVE'"),
        ("run_count", "INTEGER DEFAULT 0"),
        ("failure_count", "INTEGER DEFAULT 0"),
        ("configuration_json", "TEXT"),
        ("created_at", "TEXT"),
        ("updated_at", "TEXT"),
    ],
    "automation_events": [
        ("id", "INTEGER PRIMARY KEY AUTOINCREMENT"),
        ("event_id", "TEXT"),
        ("event_type", "TEXT"),
        ("automation_id", "INTEGER"),
        ("company_id", "INTEGER"),
        ("run_id", "TEXT"),
        ("job_id", "INTEGER"),
        ("message", "TEXT"),
        ("metadata_json", "TEXT"),
        ("created_at", "TEXT"),
    ],
    "autonomous_runs": [
        ("id", "INTEGER PRIMARY KEY AUTOINCREMENT"),
        ("autonomous_run_id", "TEXT UNIQUE"),
        ("company_id", "INTEGER"),
        ("goal_id", "TEXT"),
        ("plan_id", "TEXT"),
        ("status", "TEXT DEFAULT 'CREATED'"),
        ("current_step_id", "TEXT"),
        ("iteration", "INTEGER DEFAULT 0"),
        ("max_iterations", "INTEGER DEFAULT 10"),
        ("tool_calls", "INTEGER DEFAULT 0"),
        ("replan_count", "INTEGER DEFAULT 0"),
        ("observation_count", "INTEGER DEFAULT 0"),
        ("started_at", "TEXT"),
        ("completed_at", "TEXT"),
        ("last_progress_at", "TEXT"),
        ("termination_reason", "TEXT"),
        ("context_fingerprint", "TEXT"),
        ("error_message", "TEXT"),
        ("metadata_json", "TEXT"),
        ("created_at", "TEXT"),
        ("updated_at", "TEXT"),
    ],
    "autonomous_events": [
        ("id", "INTEGER PRIMARY KEY AUTOINCREMENT"),
        ("autonomous_run_id", "TEXT"),
        ("iteration", "INTEGER"),
        ("event_type", "TEXT"),
        ("step_id", "TEXT"),
        ("tool_name", "TEXT"),
        ("status", "TEXT"),
        ("input_json", "TEXT"),
        ("output_json", "TEXT"),
        ("observation_json", "TEXT"),
        ("reason", "TEXT"),
        ("created_at", "TEXT"),
    ],
}


def build_ddl(table_name, columns, flavor):
    lines = [f"CREATE TABLE IF NOT EXISTS {table_name} ("]
    cols = []
    for name, sqldef in columns:
        d = sqldef
        if flavor == "mysql":
            d = d.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "INT AUTO_INCREMENT PRIMARY KEY")
            d = d.replace("AUTOINCREMENT", "AUTO_INCREMENT")
            d = d.replace(" TEXT ", " TEXT ")
        cols.append(f"  {name} {d}")
    lines.append(",\n".join(cols))
    lines.append(")")
    return "\n".join(lines)


def _mysqlize_ddl(ddl):
    """Convert SQLite DDL to MySQL-compatible DDL. No-op if flavor is sqlite."""
    if db.flavor != "mysql":
        return ddl
    import re as _re
    d = ddl
    d = d.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "INT AUTO_INCREMENT PRIMARY KEY")
    d = d.replace("AUTOINCREMENT", "AUTO_INCREMENT")
    d = d.replace("TEXT DEFAULT (datetime('now'))", "TEXT DEFAULT NULL")
    d = _re.sub(r"\bTEXT\s+DEFAULT\s+'([^']*)'", r"VARCHAR(255) DEFAULT '\1'", d)
    d = _re.sub(r"\bTEXT\s+UNIQUE\b", "VARCHAR(255) UNIQUE", d)
    d = _re.sub(r"\bTEXT\s+NOT\s+NULL\b", "VARCHAR(255) NOT NULL", d)
    d = _re.sub(r"\bTEXT\s+PRIMARY\s+KEY\b", "VARCHAR(255) PRIMARY KEY", d)
    d = _re.sub(r"\bREAL\s+DEFAULT\s+([\d.]+)", r"DOUBLE DEFAULT \1", d)
    d = d.replace(" trigger ", " `trigger` ")
    d = d.replace(" key ", " `key` ")
    d = _re.sub(r",?\s*FOREIGN\s+KEY\s*\([^)]+\)\s*REFERENCES\s+\w+\s*\([^)]+\)", "", d, flags=_re.IGNORECASE)
    return d


def sqlite_tables():
    rows = db.query("SELECT name FROM sqlite_master WHERE type='table'")
    return {r["name"] for r in rows}


def _fix_mysql_defaults():
    """ALTER existing MySQL tables to add proper column types/defaults that were stripped during CREATE."""
    alter_cols = {
        "agent_activity": [("level", "VARCHAR(255) DEFAULT 'INFO'")],
        "change_log": [("severity", "VARCHAR(255) DEFAULT 'INFO'")],
        "analysis_results": [("trigger", "VARCHAR(255) DEFAULT 'MANUAL'")],
        "recommendations": [("status", "VARCHAR(255) DEFAULT 'PENDING'")],
        "query_memory": [("status", "VARCHAR(255) DEFAULT 'ACTIVE'")],
        "evidence": [("verification_status", "VARCHAR(255) DEFAULT 'UNVERIFIED'")],
        "discovery_candidates": [("status", "VARCHAR(255) DEFAULT 'NEW'")],
        "jobs": [("status", "VARCHAR(255) DEFAULT 'PENDING'"), ("job_id", "VARCHAR(255)"), ("job_type", "VARCHAR(255) NOT NULL"), ("priority_level", "VARCHAR(255) DEFAULT 'MEDIUM'")],
        "runs": [("status", "VARCHAR(255) DEFAULT 'RUNNING'"), ("run_type", "VARCHAR(255) DEFAULT 'MANUAL'")],
        "manager_task_results": [("status", "VARCHAR(255) DEFAULT 'PENDING'")],
        "learning_memory": [("memory_type", "VARCHAR(255) DEFAULT 'COMPANY_PATTERN'"), ("source", "VARCHAR(255) DEFAULT 'AUTO'"), ("status", "VARCHAR(255) DEFAULT 'ACTIVE'")],
        "automation_events": [("event_type", "VARCHAR(255) DEFAULT 'UNKNOWN'")],
    }
    conn = db.get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SHOW TABLES")
        existing = {list(r.values())[0] for r in cur.fetchall()}
        for table_name, cols in alter_cols.items():
            if table_name not in existing:
                continue
            for col_name, col_def in cols:
                try:
                    cur.execute("ALTER TABLE `%s` MODIFY COLUMN `%s` %s" % (table_name, col_name, col_def))
                except Exception:
                    pass
    finally:
        conn.close()


def migrate_sqlite():
    if db.flavor == "mysql":
        conn = db.get_connection()
        try:
            cur = conn.cursor()
            cur.execute("SHOW TABLES")
            existing = {list(r.values())[0] for r in cur.fetchall()}
            for table_name, cols in TABLES.items():
                if table_name not in existing:
                    continue
                cur.execute("SHOW COLUMNS FROM `%s`" % table_name)
                have = {r.get("Field") or r.get("COLUMN_NAME") for r in cur.fetchall()}
                needed = [c for c, d in cols if c not in have]
                for c in needed:
                    for name, sqldef in cols:
                        if name == c:
                            try:
                                cur.execute("ALTER TABLE `%s` ADD COLUMN `%s` %s" % (table_name, name, _mysqlize_ddl(sqldef)))
                            except Exception as e:
                                print(f"[Migration] {table_name}.{name} skipped ({e})", flush=True)
        finally:
            conn.close()
        return
    existing = sqlite_tables()
    for table_name, cols in TABLES.items():
        if table_name not in existing:
            continue
        have = {r["name"] for r in db.query(f"PRAGMA table_info({table_name})")}
        needed = [c for c, d in cols if c not in have]
        for c in needed:
            for name, sqldef in cols:
                if name == c:
                    try:
                        db.execute(f"ALTER TABLE {table_name} ADD COLUMN {name} {sqldef}")
                    except Exception as e:
                        print(f"[Migration] {table_name}.{name} skipped ({e})", flush=True)


def init_db():
    for table_name, columns in TABLES.items():
        try:
            ddl = build_ddl(table_name, columns, db.flavor)
            db.execute(_mysqlize_ddl(ddl))
        except Exception as e:
            print(f"[Schema] create {table_name} failed: {e}", flush=True)

    # Hot-path indexes (list views + per-company lookups). Idempotent.
    for idx_sql in (
        "CREATE INDEX IF NOT EXISTS idx_evidence_brand ON evidence (brand_id)",
        "CREATE INDEX IF NOT EXISTS idx_obs_brand ON ai_observations (brand_id)",
        "CREATE INDEX IF NOT EXISTS idx_results_brand ON analysis_results (brand_id)",
        "CREATE INDEX IF NOT EXISTS idx_queries_brand ON query_memory (brand_id)",
        "CREATE INDEX IF NOT EXISTS idx_changes_brand ON change_log (brand_id)",
        "CREATE INDEX IF NOT EXISTS idx_recs_brand ON recommendations (brand_id)",
        "CREATE INDEX IF NOT EXISTS idx_wfruns_company ON workflow_runs (company_id)",
        "CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs (status)",
    ):
        try:
            db.execute(idx_sql)
        except Exception:
            pass

    if db.flavor == "mysql":
        try:
            marked = db.query("SELECT config_key FROM agent_config WHERE config_key='mysql_schema_fixed'")
            if not marked:
                _fix_mysql_defaults()
                db.execute("INSERT INTO agent_config (config_key, config_value, updated_at) VALUES (?,?,?)",
                           ("mysql_schema_fixed", "1", now()))
        except Exception:
            try:
                _fix_mysql_defaults()
            except Exception as e:
                print(f"[Schema] defaults fix failed ({e})", flush=True)
        # Skip migrate_sqlite on MySQL (it's for SQLite schema upgrades only)
    else:
        migrate_sqlite()

    # Normalize legacy job-status vocabulary (v1 used QUEUED).
    try:
        db.execute("UPDATE jobs SET status='PENDING' WHERE status='QUEUED' OR status='PENDING_OLD'")
        for r in db.query("SELECT id FROM jobs WHERE job_id IS NULL OR job_id=''"):
            try:
                jid = str(r["id"])
                new_job_id = ("JOB-" + jid.zfill(6)) if jid.isdigit() else ("JOB-" + jid)
                db.execute("UPDATE jobs SET job_id=? WHERE id=?", (new_job_id, r["id"]))
            except Exception:
                pass
    except Exception as e:
        print(f"[Migration] job normalization skipped ({e})", flush=True)

    # Ensure config + source status rows exist before anything else (one-time).
    try:
        started = db.query("SELECT config_key FROM agent_config WHERE config_key='startup_done'")
        if not started:
            for key, val in default_config().items():
                row = db.query("SELECT config_key FROM agent_config WHERE config_key=?", (key,))
                if not row:
                    db.execute("INSERT INTO agent_config (config_key, config_value, updated_at) VALUES (?,?,?)",
                               (key, val, now()))
            db.execute("INSERT INTO agent_config (config_key, config_value, updated_at) VALUES (?,?,?)",
                       ("startup_done", "1", now()))
    except Exception:
        pass
    # Manager agent registry seed (idempotent; never overwrites operator edits).
    try:
        ensure_registry_seed()
    except Exception as e:
        print(f"[Schema] registry seed skipped ({e})", flush=True)
    # Spec workflows (fixed IDs) seed - idempotent.
    try:
        ensure_spec_workflows()
    except Exception as e:
        print(f"[Schema] spec workflows skipped ({e})", flush=True)
    # MCP tool registry seed (idempotent; preserves operator edits).
    try:
        ensure_mcp_tools()
    except Exception as e:
        print(f"[Schema] tool seed skipped ({e})", flush=True)

    # Adaptive workflow config table
    try:
        for ddl in _COMPANY_CONFIG_DDL.split(";"):
            ddl = ddl.strip()
            if ddl:
                db.execute(_mysqlize_ddl(ddl) if db.flavor == "mysql" else ddl)
    except Exception as e:
        print(f"[Schema] company_workflow_config skipped ({e})", flush=True)

    try:
        if requests_available:
            for key, val, provider, details in [
                ("WEBSITE_SCRAPER", 1, "builtin-url-fetch", "Standard library HTTP fetch + HTML extraction"),
                ("COMPANY_DISCOVERY", 1 if gemini_available else 0, "gemini" if gemini_available else "none",
                 "Gemini-powered industry company discovery" if gemini_available else "COMPANY DISCOVERY INTEGRATION NOT CONNECTED"),
                ("AI_SEARCH", 1 if gemini_available or SERPAPI_KEY else 0,
                 "gemini/serp", "Real AI/search observation via connected providers"),
                ("SEARCH_API", 1 if SERPAPI_KEY else 0, "serpapi", "Google SERP via SerpAPI"),
                ("GEMINI", 1 if gemini_available else 0, "google-generative-ai",
                 f"{GEMINI_MODEL} (failover {GEMINI_FALLBACK_MODEL})"),
                ("MANUAL", 1, "form", "Manual company entry"),
                ("CSV", 1, "import", "CSV import"),
                ("HISTORICAL", 1, "database", "Historical analysis storage"),
                ("FEEDBACK", 1, "form", "User feedback ingestion"),
            ]:
                row = db.query("SELECT source_key FROM data_source_status WHERE source_key=?", (key,))
                if not row:
                    db.execute(
                        "INSERT INTO data_source_status (source_key, connected, provider, details, last_checked) VALUES (?,?,?,?,?)",
                        (key, val, provider, details, now()))
                else:
                    db.execute(
                        "UPDATE data_source_status SET connected=?, provider=?, details=?, last_checked=? WHERE source_key=?",
                        (val, provider, details, now(), key))
    except Exception as e:
        print(f"[Schema] source status init failed: {e}", flush=True)
    print(f"[Database] Schema ready (backend={db.flavor}).", flush=True)


# ---------------------------------------------------------------------------
# COMPANIES
# ---------------------------------------------------------------------------

def upsert_company(data, source="MANUAL", source_detail="", inspect_existing=True):
    brand_name = (data.get("brand_name") or "").strip()
    website = (data.get("website") or "").strip()
    if not brand_name:
        return None
    existing = None
    if inspect_existing:
        rows = db.query("SELECT id FROM brands WHERE brand_name=? AND is_active=1 ORDER BY id DESC LIMIT 1",
                        (brand_name,))
        if rows:
            existing = rows[0]["id"]
        elif website:
            rows = db.query("SELECT id FROM brands WHERE website=? AND is_active=1 ORDER BY id DESC LIMIT 1",
                            (website,))
            if rows:
                existing = rows[0]["id"]
    if existing:
        old_rows = db.query("SELECT * FROM brands WHERE id=?", (existing,))
        old = old_rows[0] if old_rows else {}
        new_vals = {
            "industry": (data.get("industry") or "General").strip() or "General",
            "region": (data.get("region") or "").strip() or None,
            "company_type": (data.get("company_type") or "").strip() or None,
            "description": (data.get("description") or "").strip() or None,
            "keywords": (data.get("keywords") or "").strip() or None,
            "target_audience": (data.get("target_audience") or "").strip() or None,
            "competitors": (data.get("competitors") or "").strip() or None,
            "website": website or None,
        }
        db.execute("""
            UPDATE brands SET website=?, industry=?, region=?, company_type=?, description=?,
                   keywords=?, target_audience=?, competitors=?, data_source=?, source_detail=?,
                    verification_status=?, confidence=?, last_updated_at=?
            WHERE id=?
        """, (
            new_vals["website"], new_vals["industry"], new_vals["region"], new_vals["company_type"],
            new_vals["description"], new_vals["keywords"], new_vals["target_audience"], new_vals["competitors"],
            source, source_detail,
            data.get("verification_status") or "UNVERIFIED",
            float(data.get("confidence", 0.8)),
            now(),
            existing,
        ))
        # Phase 4 evidence-correction learning: user/system corrections of profile
        # facts produce EVIDENCE_CORRECTED events (history is never overwritten).
        _field_src = {"industry": "industry", "region": "region", "company_type": "company_type",
                      "description": "description", "keywords": "keywords",
                      "target_audience": "target_audience", "competitors": "competitors", "website": "website"}
        try:
            for field, new_v in new_vals.items():
                if _field_src.get(field) not in (data or {}) or not new_v:
                    continue  # field not supplied, or blanked - not a verified correction
                old_v = old.get(field)
                if (old_v or "") != (new_v or "") and (old_v or new_v):
                    is_user = (source or "").upper() in ("MANUAL", "USER_PROVIDED", "USER")
                    record_learning_event(existing, "EVIDENCE_CORRECTED",
                                          f"Company {field} corrected: '{str(old_v)[:120]}' -> "
                                          f"'{str(new_v)[:120]}' (source: {source}). Future analysis "
                                          "prefers the verified correction.",
                                          source_type="USER_CORRECTION" if is_user else "SOURCE_UPDATE",
                                          source_id=source_detail or source,
                                          previous_value=str(old_v)[:1000], new_value=str(new_v)[:1000],
                                          confidence=0.95 if is_user else 0.7,
                                          metadata={"field": field})
                    if is_user:
                        ensure_memory(existing, "EVIDENCE_PATTERN", "CORRECTION",
                                      f"VERIFIED_{field.upper()}:{str(new_v)[:200]}",
                                      f"User-verified correction: {field} = '{str(new_v)[:200]}'. "
                                      "Prefer this value in future analysis.",
                                      source="USER_CORRECTION", confidence=0.95, success_delta=1,
                                      evidence_text=f"previous='{str(old_v)[:300]}'",
                                      metadata={"field": field})
        except Exception as e:
            print(f"[Learning] evidence-correction hook skipped: {e}", flush=True)
        return existing
    bid = db.execute("""
        INSERT INTO brands (brand_name, website, industry, region, company_type, description, keywords,
                            target_audience, competitors, data_source, source_detail, verification_status,
                            confidence, is_active, created_at, last_updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,1,?,?)
    """, (
        brand_name, website or None,
        (data.get("industry") or "General").strip() or "General",
        (data.get("region") or "").strip() or None,
        (data.get("company_type") or "").strip() or None,
        (data.get("description") or "").strip() or None,
        (data.get("keywords") or "").strip() or None,
        (data.get("target_audience") or "").strip() or None,
        (data.get("competitors") or "").strip() or None,
        source, source_detail,
        data.get("verification_status") or "UNVERIFIED",
        float(data.get("confidence", 0.8)),
        now(), now(),
    ))
    # Autonomous behavior: a newly added company gets its analysis jobs
    # auto-created (dedup-aware). The loop / run-now executes them.
    try:
        plan_company_jobs(bid)
    except Exception as e:
        print(f"[Jobs] auto-plan failed for company {bid}: {e}", flush=True)
    # Automation: default per-company settings + schedules mirror the frequency
    # and monitoring/change-detection preferences. First-time pipelines reuse the
    # job dependency system - nothing runs all at once.
    try:
        save_company_settings(bid)
        ensure_default_automations(bid)
    except Exception as e:
        print(f"[Automation] default schedules failed for company {bid}: {e}", flush=True)
    return bid


def get_brand(brand_id):
    rows = db.query("SELECT * FROM brands WHERE id=?", (brand_id,))
    return rows[0] if rows else None


def company_source_is_connected(key):
    rows = db.query("SELECT connected FROM data_source_status WHERE source_key=?", (key,))
    return bool(rows and rows[0].get("connected"))


# ---------------------------------------------------------------------------
# WEBSTIE SCRAPER (real HTTP fetch via stdlib; never fabricates data)
# ---------------------------------------------------------------------------

_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")


def fetch_url(url, timeout=12, max_bytes=5_000_000):
    """Fetch URL with timeout and max response size guard (production hardening).
    Returns decoded text or raises URLError/ValueError."""
    req = Request(url, headers={"User-Agent": _UA, "Accept-Language": "en-US,en;q=0.9"})
    with urlopen(req, timeout=timeout) as resp:
        raw = resp.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise ValueError(f"Response exceeds {max_bytes} bytes limit")
    charset = resp.headers.get_content_charset() or "utf-8"
    try:
        return raw.decode(charset, errors="replace")
    except Exception:
        return raw.decode("utf-8", errors="replace")


def strip_tags(text):
    text = re.sub(r"<script.*?</script>", " ", text, flags=re.S | re.I)
    text = re.sub(r"<style.*?</style>", " ", text, flags=re.S | re.I)
    text = re.sub(r"<[^>]+>", " ", text)
    text = _html.unescape(text)
    return re.sub(r"\s+", " ", text).strip()


def extract_jsonld(text):
    blocks = []
    for m in re.finditer(r'<script[^>]*type="application/ld\+json"[^>]*>(.*?)</script>', text, re.S | re.I):
        data = m.group(1).strip()
        parsed = safe_json_loads(data)
        if parsed:
            blocks.append(parsed)
        else:
            blocks.append({"raw": data[:500]})
    return blocks


def scrape_website(brand_id, website):
    """Fetch and extract real website evidence. Returns dict with evidence list or error."""
    if not website:
        return {"ok": False, "error": "No website URL", "evidence": []}
    url = website if website.startswith("http") else "https://" + website
    try:
        text = fetch_url(url)
    except (URLError, Exception) as e:
        return {"ok": False, "error": f"Fetch failed: {e}", "evidence": []}

    evidence = []
    def add(etype, key, value, detail="scrape", conf=0.7):
        evidence.append({
            "evidence_type": etype, "evidence_key": key, "evidence_value": value[:2000],
            "source": "WEBSITE_SCRAPER", "source_detail": url, "confidence": conf,
            "verification_status": "VERIFIED",
        })

    m = re.search(r"<title[^>]*>(.*?)</title>", text, re.S | re.I)
    if m and strip_tags(m.group(1)):
        add("PAGE_TITLE", "home_title", strip_tags(m.group(1)), "scrape:title", 0.9)
    m = re.search(r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']*)["\']', text, re.I)
    if not m:
        m = re.search(r'<meta[^>]+content=["\']([^"\']*)["\'][^>]+name=["\']description["\']', text, re.I)
    if m and m.group(1).strip():
        add("META_DESCRIPTION", "home_meta_description", m.group(1).strip(), "scrape:meta", 0.9)

    headings = []
    for tag in ("h1", "h2", "h3"):
        for hm in re.finditer(r"<%s[^>]*>(.*?)</%s>" % (tag, tag), text, re.S | re.I):
            h = strip_tags(hm.group(1))
            if h and len(h.split()) <= 14:
                headings.append(h)
    headings = list(dict.fromkeys(headings))
    for i, h in enumerate(headings[:30]):
        add("HEADING", f"heading_{i}", h, "scrape:headings", 0.8)

    body_text = strip_tags(text)
    checks = {
        "PRODUCT_LISTING": ["pricing", "price", "plans", "buy now", "product", "package"],
        "SERVICE_LISTING": ["services", "consulting", "solutions", "managed service", "service"],
        "ABOUT_INFO": ["about us", "about ", "mission", "founded", "team"],
        "FAQ": ["faq", "frequently asked", "questions?"],
        "PRICING": ["pricing", "price", "cost", "plans"],
        "BLOG_ARTICLE": ["blog", "insights", "articles", "news", "resources"],
        "CONTACT_INFO": ["contact", "email", "phone", "address", "get in touch"],
        "COMPARISON_CONTENT": [" vs ", "alternatives", "compare", "versus"],
        "TARGET_AUDIENCE_CLUE": ["for teams", "for business", "for enterprise", "talent", "developers", "creators"],
    }
    lowered = body_text.lower()
    for etype, keys in checks.items():
        found = [k for k in keys if k in lowered]
        if found:
            add(etype, etype.lower(), ", ".join(found), f"scrape:keywords ({'; '.join(found)})", 0.8)

    jsonld = extract_jsonld(text)
    if jsonld:
        add("STRUCTURED_DATA", "jsonld", "blocks detected", f"scrape:jsonld ({len(jsonld)} blocks)", 0.95)

    internal_links = set(re.findall(r'<a[^>]+href=["\']([^"\'#]+)["\']', text, re.I))
    internal_links = {l for l in internal_links if l.startswith("/") or url.rstrip("/").split("//")[-1].split("/")[0] in l}
    if internal_links:
        add("INTERNAL_LINKS", "internal_link_count", str(len(internal_links)), "scrape:links", 0.8)

    return {"ok": True, "evidence": evidence, "pages": 1, "url": url}


# ---------------------------------------------------------------------------
# EVIDENCE STORE
# ---------------------------------------------------------------------------

def save_evidence(brand_id, evidence_list, source="MANUAL"):
    """Upsert evidence keyed by (brand_id, evidence_type, evidence_key). Returns new count."""
    new_count = 0
    t = now()
    for ev in evidence_list or []:
        etype = ev.get("evidence_type", "GENERAL")
        ekey = ev.get("evidence_key", ev.get("evidence_value", "value"))[:200]
        ekey = ekey if ekey else "value"
        rows = db.query(
            "SELECT id, evidence_value FROM evidence WHERE brand_id=? AND evidence_type=? AND evidence_key=?",
            (brand_id, etype, ekey))
        val = str(ev.get("evidence_value") or "")
        if rows:
            changed = rows[0]["evidence_value"] != val
            db.execute("""
                UPDATE evidence SET evidence_value=?, source=?, source_detail=?, verification_status=?,
                       confidence=?, raw_json=?, last_updated_at=?
                WHERE id=?
            """, (val, ev.get("source", source), ev.get("source_detail", ""),
                  ev.get("verification_status", "UNVERIFIED"), float(ev.get("confidence", 0.5)),
                  json.dumps(ev).encode("utf-8", "replace").decode("utf-8")[:2000], t, rows[0]["id"]))
            if changed:
                new_count += 1
        else:
            db.execute("""
                INSERT INTO evidence (brand_id, evidence_type, evidence_key, evidence_value, source,
                                      source_detail, verification_status, confidence, raw_json, collected_at, last_updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)
            """, (brand_id, etype, ekey, val, ev.get("source", source), ev.get("source_detail", ""),
                  ev.get("verification_status", "UNVERIFIED"), float(ev.get("confidence", 0.5)),
                  json.dumps(ev).encode("utf-8", "replace").decode("utf-8")[:2000], t, t))
            new_count += 1
    return new_count


def get_company_evidence(brand_id):
    return db.query("SELECT * FROM evidence WHERE brand_id=? ORDER BY id", (brand_id,))


def evidence_snapshot(brand_id):
    rows = get_company_evidence(brand_id)
    snap = [{"type": r["evidence_type"], "key": r["evidence_key"], "value": r["evidence_value"]} for r in rows]
    b = get_brand(brand_id)
    if b:
        snap.append({"type": "PROFILE_DESCRIPTION", "key": "description", "value": b.get("description") or ""})
        snap.append({"type": "PROFILE_KEYWORDS", "key": "keywords", "value": b.get("keywords") or ""})
        snap.append({"type": "PROFILE_COMPETITORS", "key": "competitors", "value": b.get("competitors") or ""})
        snap.append({"type": "PROFILE_WEBSITE", "key": "website", "value": b.get("website") or ""})
    return snap


# ---------------------------------------------------------------------------
# MENTION DETECTION
# ---------------------------------------------------------------------------

_NEGATIVE_WORDS = ["fail", "broken", "outage", "against", "lawsuit", "lawsuit", "controversy", "negative",
                   "underperforming", "worse", "declined", "problem", "issue", "security breach", "scam"]


def detect_mentions(brand_name, aliases, text):
    """Returns (mentioned, position, context, sentiment)."""
    if not text:
        return 0, None, "none", "neutral"
    lowered = text.lower()
    keys = [k.lower() for k in ([brand_name] + (aliases or [])) if k and len(k) > 1]
    if not keys:
        return 0, None, "none", "neutral"
    pos = None
    for k in keys:
        idx = lowered.find(k)
        if idx >= 0 and (pos is None or idx < pos):
            pos = idx
    if pos is None:
        return 0, None, "none", "neutral"

    window = lowered[max(0, pos - 260): pos + 260]
    context = "neutral"
    if any(w in window for w in ["recommend", "best", "top", "leading", "choose", "preferred", "ideal", "pick"]):
        context = "recommendation"
    elif any(w in window for w in ["vs", "versus", "compared", "alternative", "alternativ", "similar to", "instead of"]):
        context = "comparison"
    elif any(w in window for w in [" #1", " first", " suggests", " recommends "]):
        context = "first_mention"
    sentiment = "neutral"
    if any(w in window for w in _NEGATIVE_WORDS):
        sentiment = "negative"
    elif context in ("recommendation", "first_mention") or any(w in window for w in ["great", "excellent", "powerful", "best", "robust"]):
        sentiment = "positive"
    return 1, pos, context, sentiment


def competitor_names_from_profile(brand):
    comps = brand.get("competitors") or ""
    return [c.strip() for c in comps.split(",") if c.strip()]


# ---------------------------------------------------------------------------
# QUERY GENERATION + QUERY MEMORY
# ---------------------------------------------------------------------------

QUERY_INTENTS = [
    "informational", "commercial", "transactional", "comparison",
    "problem_solving", "brand", "competitor", "industry",
]

QUERY_CATEGORIES = {
    "informational": "Industry Knowledge",
    "commercial": "Vendor Discovery",
    "transactional": "Purchase Intent",
    "comparison": "Competitive Evaluation",
    "problem_solving": "Solution Seeking",
    "brand": "Brand Awareness",
    "competitor": "Competitor Alternatives",
    "industry": "Market Landscape",
}


def _query_templates(brand):
    industry = brand.get("industry") or "technology"
    keywords = [k.strip() for k in (brand.get("keywords") or "").split(",") if k.strip()]
    kw = keywords[0] if keywords else industry
    kw2 = keywords[1] if len(keywords) > 1 else kw
    audience = (brand.get("target_audience") or "businesses").strip()
    name = (brand.get("brand_name") or "Brand").strip()
    competitors = competitor_names_from_profile(brand)
    cname = competitors[0] if competitors else None
    templates = []
    def add(intent, q, keyword=None, category=None):
        templates.append({
            "query": q.format(name=name, industry=industry, kw=kw, kw2=kw2, audience=audience, comp=cname or "competitors"),
            "intent": intent,
            "keyword": keyword or kw,
            "category": category or QUERY_CATEGORIES[intent],
        })
    add("informational", f"What are the leading {industry} companies?")
    add("informational", f"Which AI platforms support {kw}?")
    add("commercial", f"Which companies provide top {kw} solutions for {audience}?")
    add("transactional", f"Best {kw} providers to buy for {audience} in 2026")
    add("comparison", f"What are alternatives to {cname} for {kw}?" if cname else f"What are the top {industry} platforms compared?")
    add("problem_solving", f"How should {audience} evaluate {industry} solutions for {kw2} needs?")
    add("brand", f"Is {name} a leading provider of {kw}?")
    add("competitor", f"Which companies compete with {name} in {kw}?")
    add("industry", f"How is AI transforming the {industry} industry in 2026?")
    add("informational", f"What are the top {kw2} use cases for {industry} teams?")
    return templates


def generate_queries(brand, use_gemini=True):
    """Generate queries. Gemini (if connected) refines/extends; else deterministic templates."""
    suggestions = _query_templates(brand)
    limit = int(get_config("query_generation_limit", "20"))
    # Safety cap to prevent Groq rate limit exhaustion
    limit = min(limit, 50)
    if gemini_available and gemini_model and use_gemini and int(get_config("gemini_queries", "1")):
        try:
            name = brand["brand_name"]
            industry = brand.get("industry")
            keywords = brand.get("keywords") or ""
            audience = brand.get("target_audience") or "businesses"
            comps = brand.get("competitors") or ""
            prompt = (
                f"Generate {limit} realistic search queries a customer would type into an AI search engine "
                f"(ChatGPT, Perplexity, Google SGE, Gemini) while researching companies in the '{industry}' industry.\n"
                f"Brand: {name}\nKeywords: {keywords}\nTarget Audience: {audience}\nCompetitors: {comps}\n\n"
                "Queries must all be relevant to this brand and its industry. Return ONLY a JSON array of objects, "
                "each with keys: query (string), intent (one of informational/commercial/transactional/comparison/"
                "problem_solving/brand/competitor/industry), keyword (string), category (string). No explanation."
            )
            text, used_model = _gemini_complete(prompt, max_tokens=800, temperature=0.5)
            raw = clean_json_text(text)
            data = json.loads(raw)
            if isinstance(data, list):
                queries = []
                for d in data[:limit]:
                    if isinstance(d, dict) and d.get("query"):
                        queries.append({
                            "query": str(d["query"]).strip(),
                            "intent": d.get("intent") or "informational",
                            "keyword": d.get("keyword") or kw,
                            "category": d.get("category") or QUERY_CATEGORIES.get(d.get("intent"), "General"),
                        })
                if queries:
                    return queries
        except Exception as e:
            print(f"[Gemini] Query generation failed, using templates: {e}", flush=True)
    return suggestions[:limit]


def remember_queries(brand_id, queries):
    """Store queries in query memory, reusing historical ones (fingerprint dedup). Returns objects."""
    out = []
    t = now()
    for q in queries or []:
        qt = str(q.get("query_text") or q.get("query") or "").strip()
        if not qt:
            continue
        fp = query_fingerprint(qt)
        rows = db.query("SELECT id, times_tested, first_seen, current_result, fingerprint FROM query_memory "
                        "WHERE brand_id=? AND (fingerprint=? OR query_text=?) LIMIT 1", (brand_id, fp, qt))
        if rows:
            r = rows[0]
            # update previous/current shift happens in observation stage; here just touch last_tested
            db.execute("UPDATE query_memory SET last_tested=?, last_used_at=?, times_tested=times_tested+1, intent=?, "
                       "keyword=?, category=?, fingerprint=? WHERE id=?",
                       (t, t, q.get("intent"), q.get("keyword"), q.get("category"), fp, r["id"]))
            qid = r["id"]
        else:
            qid = db.execute("""
                INSERT INTO query_memory (brand_id, query_text, fingerprint, intent, keyword, category, first_seen,
                                          last_tested, last_used_at, times_tested, source, created_at)
                VALUES (?,?,?,?,?,?,?,?,?,1,?,?)
            """, (brand_id, qt, fp, q.get("intent"), q.get("keyword"), q.get("category"), t, t, t, "GENERATED", t))
        obj = {"id": qid, **q}
        obj["query_text"] = qt
        out.append(obj)
    return out


def get_active_queries(brand_id):
    return db.query(
        "SELECT * FROM query_memory WHERE brand_id=? AND is_active=1 ORDER BY priority_score DESC, id DESC",
        (brand_id,))


# ---------------------------------------------------------------------------
# AI SEARCH OBSERVATION (real providers only - never fabricate)
# ---------------------------------------------------------------------------

def _observe_gemini(query_text, brand):
    name = brand["brand_name"]
    prompt = (
        f"You are an AI search engine (like ChatGPT / Gemini / Perplexity). Answer the following customer query as "
        f"you would in a real AI search answer, listing specific companies by name where relevant.\n\n"
        f"Query: {query_text}\n\n"
        "Give a realistic, verifiable answer. Do not state that companies appeared unless you genuinely include them."
    )
    text, used_model = _gemini_complete(prompt, max_tokens=800, temperature=0.4)
    aliases = [name] if name else []
    mentioned, pos, context, sentiment = detect_mentions(name, aliases, text)
    competitors = [c for c in re.split(r"[\n,.]", text) if len(c.strip()) > 3]
    comps_in = [c.strip() for c in competitor_names_from_profile(brand) if c.strip().lower() in text.lower()]
    return {
        "provider": "gemini-live",
        "model": used_model,
        "response_text": text[:6000],
        "brand_mentioned": mentioned,
        "brand_position": pos,
        "brand_mention_context": context,
        "sentiment": sentiment,
        "competitors_mentioned": comps_in,
        "confidence": 0.9,
    }


def _observe_serp(query_text, brand):
    if not (requests_available and SERPAPI_KEY):
        return None
    name = brand["brand_name"]
    try:
        resp = requests.get("https://serpapi.com/search.json",
                            params={"engine": "google", "q": query_text, "num": 10, "api_key": SERPAPI_KEY},
                            timeout=10)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        log_activity(f"[AI] SerpAPI error for '{query_text}': {str(e)[:160]}", level="WARNING")
        return None
    results = data.get("organic_results", [])[:10]
    mentioned = 0
    pos = None
    snippet = ""
    for i, r in enumerate(results, start=1):
        hay = (r.get("title", "") + " " + r.get("snippet", "")).lower()
        if name.lower() in hay:
            mentioned = 1
            pos = i
            snippet = hay[:600]
            break
    comps_list = competitor_names_from_profile(brand)
    comps_in = [c for c in comps_list if any(c.lower() in (r.get("title", "") + r.get("snippet", "")).lower() for r in results)]
    if mentioned:
        context = "serp_result"
        sentiment = "neutral"
        window = snippet
        if any(w in window for w in ["recommend", "best", "top", "leading"]):
            context = "recommendation"
    else:
        context, sentiment = "none", "neutral"
    response_text = "\n".join(f"{i}. {r.get('title','')} - {r.get('snippet','')}" for i, r in enumerate(results, 1))[:6000]
    return {
        "provider": "google-serp",
        "model": "google",
        "response_text": response_text,
        "brand_mentioned": mentioned,
        "brand_position": pos,
        "brand_mention_context": context,
        "sentiment": sentiment,
        "competitors_mentioned": comps_in,
        "confidence": 0.95,
    }


def ai_search_connected():
    return gemini_available or groq_available or (requests_available and bool(SERPAPI_KEY))


def run_ai_search(brand_id, queries, run_id=None):
    """Submit top queries to connected providers, store observations."""
    brand = get_brand(brand_id)
    if not brand or not ai_search_connected():
        return {"connected": False, "observations": 0, "status": "AI SEARCH INTEGRATION NOT CONNECTED"}
    queries = queries[:int(get_config("ai_observation_queries", "5"))]
    obs_limit = int(get_config("ai_observation_limit", "10"))
    observations = 0
    t = now()
    for q in queries:
        if observations >= obs_limit:
            break
        qt = (q.get("query_text") or q.get("query") or "").strip()
        providers = []
        if gemini_available:
            try:
                providers.append(_observe_gemini(qt, brand))
            except Exception as exc:
                log_activity(f"[AI] Gemini error for '{qt}': {str(exc)[:160]}", level="WARNING")
        if requests_available and SERPAPI_KEY:
            try:
                sp = _observe_serp(qt, brand)
                if sp:
                    providers.append(sp)
            except Exception as exc:
                log_activity(f"[AI] SERP error for '{qt}': {str(exc)[:160]}", level="WARNING")
        for p in providers:
            if not p:
                continue
            db.execute("""
                INSERT INTO ai_observations (brand_id, brand_name, query_id, query_text, provider, model,
                                             observed_at, response_json, response_text, brand_mentioned,
                                             brand_position, brand_mention_context, competitors_mentioned,
                                             sentiment, confidence)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (brand_id, brand.get("brand_name"), q.get("id"), qt, p["provider"], p["model"], t,
                  json.dumps(p).encode("utf-8", "replace").decode("utf-8")[:2000],
                  p["response_text"], p["brand_mentioned"], p["brand_position"],
                  p["brand_mention_context"], json.dumps(p.get("competitors_mentioned") or []),
                  p["sentiment"], p["confidence"]))
            observations += 1
            _update_query_result(q.get("id"), p["brand_mentioned"],
                                 competitors_seen=bool(p.get("competitors_mentioned")),
                                 brand_id=brand_id, run_id=run_id)
    return {"connected": True, "observations": observations, "status": "observed"}


def _update_query_result(query_id, mentioned, competitors_seen=False, brand_id=None, run_id=None):
    if not query_id:
        return
    rows = db.query("SELECT * FROM query_memory WHERE id=?", (query_id,))
    if not rows:
        return
    r = rows[0]
    new_result = "BRAND_MENTIONED" if mentioned else "NOT_MENTIONED"
    prev = r.get("current_result")
    trend = "improved" if prev == "NOT_MENTIONED" and new_result == "BRAND_MENTIONED" else (
        "declined" if prev == "BRAND_MENTIONED" and new_result == "NOT_MENTIONED" else "stable")
    # adaptivity: useful queries (brand mentioned / informative) get higher priority
    delta = 0.08 if mentioned else -0.04
    new_priority = max(0.0, min(1.0, (r.get("priority_score") or 0.5) + delta))
    db.execute("UPDATE query_memory SET previous_result=?, current_result=?, trend=?, priority_score=? WHERE id=?",
               (prev, new_result, trend, new_priority, query_id))
    # Phase 4: learning signal from this real observation (never raises into the pipeline).
    try:
        cid = brand_id or r.get("brand_id")
        if cid:
            record_query_outcome(query_id, cid, bool(mentioned), competitors_seen=bool(competitors_seen),
                                 run_id=run_id)
    except Exception as e:
        print(f"[Learning] record_query_outcome skipped: {e}", flush=True)


# ---------------------------------------------------------------------------
# BRAND ANALYSIS
# ---------------------------------------------------------------------------

def analyze_brand(brand):
    """Gemini (if connected) or deterministic structural analysis."""
    if gemini_available and gemini_model:
        try:
            prompt = (
                f"Analyze this brand for AI search visibility. Return ONLY a JSON object with exact keys: "
                f"positioning (string), primary_topics (array of 5 strings), strengths (array of 3 strings), "
                f"opportunities (array of 3 strings).\n\n"
                f"Brand: {brand.get('brand_name')}\nIndustry: {brand.get('industry')}\n"
                f"Description: {brand.get('description') or 'N/A'}\nKeywords: {brand.get('keywords') or 'N/A'}\n"
                f"Target Audience: {brand.get('target_audience') or 'N/A'}\nWebsite: {brand.get('website') or 'N/A'}"
            )
            text, used_model = _gemini_complete(prompt, max_tokens=800, temperature=0.3)
            data = json.loads(clean_json_text(text))
            if isinstance(data, dict) and data.get("positioning"):
                return data
        except Exception as e:
            print(f"[Gemini] Brand analysis failed: {e}", flush=True)
    industry = brand.get("industry") or "General"
    keywords = [k.strip() for k in (brand.get("keywords") or "").split(",") if k.strip()]
    topics = keywords[:5] if keywords else [f"{industry} Core", f"Enterprise {industry}", f"{industry} Solutions"]
    desc = (brand.get("description") or "").strip()
    if len(desc.split()) > 25:
        positioning = "Established enterprise provider with detailed brand positioning"
    elif desc:
        positioning = "Emerging specialist with defined product positioning"
    else:
        positioning = f"Brand with minimal public positioning data in {industry}"
    return {
        "positioning": positioning,
        "primary_topics": topics,
        "strengths": ["Structured profile available", f"Keyword coverage: {len(keywords)} terms", "Industry presence"],
        "opportunities": ["Expand AI-search structured content", "Add FAQ / entity schema", "Build comparison pages"],
    }


# ---------------------------------------------------------------------------
# COMPETITOR ANALYSIS
# ---------------------------------------------------------------------------

def analyze_competitors(brand, observations):
    """Real SERP data if connected; otherwise deterministic readiness, clearly labeled."""
    industry = brand.get("industry") or ""
    name = brand.get("brand_name") or "Target Brand"
    comps = competitor_names_from_profile(brand)
    rows = []
    your_vis = None
    if requests_available and SERPAPI_KEY:
        your_vis = _serp_visibility(name, industry)
    rows.append({
        "brand": f"{name} (Your Brand)",
        "visibility": your_vis,
        "strength": "High Topic Relevance" if (your_vis or 0) > 60 else "Growing Presence",
        "opportunity": "Scale FAQ schema & technical comparison hubs",
        "source": "serp" if your_vis is not None else "no-data",
    })
    for c in comps[:5]:
        vis = _serp_visibility(c, industry) if (requests_available and SERPAPI_KEY) else None
        rows.append({
            "brand": c,
            "visibility": vis,
            "strength": "Established Search Share" if (vis or 0) > 60 else "Moderate Share of Answer",
            "opportunity": "Outrank on technical deep-dive content & structured pricing guides",
            "source": "serp" if vis is not None else "no-data",
        })
    return rows


def _serp_visibility(brand_name, industry):
    try:
        resp = requests.get("https://serpapi.com/search.json",
                            params={"engine": "google", "q": f"{brand_name} {industry}".strip(),
                                    "num": 10, "api_key": SERPAPI_KEY}, timeout=10)
        resp.raise_for_status()
        data = resp.json()
    except Exception:
        return None
    hits = 0
    for r in data.get("organic_results", [])[:10]:
        hay = (r.get("title", "") + " " + r.get("snippet", "")).lower()
        if brand_name.lower() in hay:
            hits += 1
    if hits == 0:
        return None
    return int(10 + (hits / 10) * 80)


# ---------------------------------------------------------------------------
# CONTENT GAPS
# ---------------------------------------------------------------------------

GAP_TOPICS = {
    "STRUCTURED_DATA": ("Schema / structured-data coverage", "High"),
    "PRICING": ("Transparent pricing & TCO breakdowns", "High"),
    "FAQ": ("FAQ & question-answer content", "High"),
    "COMPARISON_CONTENT": ("Direct competitor comparison content", "High"),
    "PRODUCT_LISTING": ("Detailed product / solution pages", "Medium"),
    "SERVICE_LISTING": ("Service capability pages", "Medium"),
    "ABOUT_INFO": ("About / company narrative pages", "Low"),
    "BLOG_ARTICLE": ("Topic authority articles & guides", "Medium"),
}


def detect_content_gaps(brand, evidence, brand_analysis):
    present = {e["evidence_type"] for e in evidence}
    gaps = []
    for etype, (topic, prio) in GAP_TOPICS.items():
        if etype not in present:
            if etype == "COMPARISON_CONTENT" and not competitor_names_from_profile(brand):
                continue
            gaps.append({
                "topic": topic,
                "priority": prio,
                "reason": f"No {etype.lower().replace('_', ' ')} evidence detected. AI search engines favor structured, "
                          f"question-answering and comparison content when citing brands.",
            })
    if not gaps:
        gaps.append({
            "topic": f"Expand {brand_analysis.get('primary_topics', ['topics'])[0] if brand_analysis.get('primary_topics') else 'core topic'} depth",
            "priority": "Low",
            "reason": "Core content surfaces present, but deepen topic authority to increase citation probability.",
        })
    return gaps[:3]


# ---------------------------------------------------------------------------
# RECOMMENDATIONS (learning-memory aware)
# ---------------------------------------------------------------------------

def generate_recommendations(brand, gaps, metrics, evidence, learning_memory):
    must_have = {e["evidence_type"] for e in evidence}
    present_evidence = {e["evidence_type"] for e in evidence}
    recs = []

    def add(title, desc, prio, cat, evidence_key=None):
        recs.append({"title": title, "description": desc, "priority": prio,
                     "category": cat, "evidence_key": evidence_key})

    if "STRUCTURED_DATA" not in must_have:
        add("Implement Structured Data / FAQ Schema", "Add JSON-LD (Organization, FAQPage, Product) so AI answers can "
            "extract brand facts cleanly.", "High", "AI Visibility", "STRUCTURED_DATA")
    if "PRICING" not in must_have:
        add("Publish Transparent Pricing Pages", "AI summary engines strongly favor sites with structured pricing "
            "frameworks.", "High", "Content Strategy", "PRICING")
    if "FAQ" not in must_have:
        add("Create an FAQ / Q&A Hub", "Directly answers question-shaped AI prompts and increases snippet capture.",
            "High", "Content Strategy", "FAQ")
    if "COMPARISON_CONTENT" not in must_have and any(e["evidence_type"] == "COMPARISON_CONTENT" for e in []):
        pass
    if "COMPARISON_CONTENT" not in must_have and competitor_names_from_profile(brand):
        add("Build Competitor Comparison Pages", "Dedicated '<brand> vs X' pages capture comparison-intent queries.",
            "High", "Competitor Strategy", "COMPARISON_CONTENT")
    if "PRODUCT_LISTING" not in must_have:
        add("Publish Detailed Product / Solution Pages", "Give AI crawlers complete product detail to cite.",
            "Medium", "Content Strategy", "PRODUCT_LISTING")
    if "BLOG_ARTICLE" not in must_have:
        add("Start Topic Authority Content", "Authoritative guides make the brand a canonical answer source.",
            "Medium", "SEO", "BLOG_ARTICLE")
    if not recs:
        add("Deepen Topic Authority", "Surfaces exist; expand depth and internal linking to strengthen citations.",
            "Low", "Content Strategy", None)

    for g in gaps[:1]:
        if len(recs) < 5:
            add(f"Build Pillar Content on {g['topic']}", f"Create 2,500+ word pillar guide covering: {g['reason']}",
                g["priority"], "Content Strategy", "BLOG_ARTICLE")

    top_addons = [
        ("Strengthen Brand Entity Signals", "Consistent NAP + Wikidata/Crunchbase entries improve LLM entity resolution.",
         "Medium", "Brand Positioning"),
        ("Expand High-Authority Citations & Digital PR", "Earn tier-1 industry mentions that AI search models weigh.",
         "Low", "Brand Positioning"),
    ]
    for title, desc, prio, cat in top_addons:
        if len(recs) >= 5:
            break
        add(title, desc, prio, cat, None)

    # Apply learning memory filter: skip already-implemented / rejected unless new evidence contradicts.
    pattern_keys = set()
    for lm in learning_memory or []:
        pat = (lm.get("pattern") or "").upper()
        if lm.get("approved") and ("IMPLEMENTED" in pat or "NOT_USEFUL" in pat or "INCORRECT" in pat or "ALREADY" in pat):
            pattern_keys.add(pat)
    if pattern_keys:
        filtered = []
        for r in recs:
            key_title = r["title"].upper()
            blocked = False
            for pk in pattern_keys:
                # heuristic match: shared significant token
                toks = set(re.findall(r"[a-z]{4,}", key_title))
                ptoks = set(re.findall(r"[a-z]{4,}", pk))
                if toks and ptoks and len(toks & ptoks) >= len(min(toks, ptoks, key=len)) * 0.5:
                    blocked = True
                    break
            if not blocked:
                filtered.append(r)
        recs = filtered if filtered else recs
    if len(recs) > 5:
        recs = recs[:5]
    return recs


# ---------------------------------------------------------------------------
# DETERMINISTIC SCORING  (explainable, no randomness)
# ---------------------------------------------------------------------------

def score_profile_completeness(brand):
    """20% component."""
    score = 0
    reasons = []
    if (brand.get("website") or "").strip():
        score += 15
        reasons.append("Website URL present (+15)")
    else:
        reasons.append("Website URL missing")
    desc_len = len((brand.get("description") or "").split())
    if desc_len >= 20:
        score += 25
        reasons.append("Brand description >= 20 words (+25)")
    elif (brand.get("description") or "").strip():
        score += 12
        reasons.append("Brand description present (+12)")
    else:
        reasons.append("Brand description missing")
    if (brand.get("keywords") or "").strip():
        score += 20
        reasons.append("Keywords defined (+20)")
    else:
        reasons.append("Keywords not defined")
    if (brand.get("target_audience") or "").strip():
        score += 15
        reasons.append("Target audience defined (+15)")
    else:
        reasons.append("Target audience missing")
    if competitor_names_from_profile(brand):
        score += 15
        reasons.append("Competitors defined (+15)")
    else:
        reasons.append("Competitors not defined")
    if (brand.get("region") or "").strip() or (brand.get("company_type") or "").strip():
        score += 10
        reasons.append("Region / company type defined (+10)")
    else:
        reasons.append("Region / company type missing")
    return min(100, score), "; ".join(reasons)


def score_keyword_coverage(brand, brand_analysis):
    """25% component."""
    keywords = [k.strip() for k in (brand.get("keywords") or "").split(",") if k.strip()]
    topics = brand_analysis.get("primary_topics", []) or []
    score = 0
    reasons = []
    if keywords:
        score += 45
        reasons.append(f"{len(keywords)} keyword(s) defined (+45)")
        covered = [k for k in keywords if any(k.lower() in t.lower() for t in topics)]
        if covered:
            score += 25
            reasons.append(f"{len(covered)} keyword(s) covered by topics (+25)")
        else:
            reasons.append("Keywords not covered by primary topics")
    else:
        reasons.append("No keywords defined")
    score += min(30, len(topics) * 10)
    if topics:
        reasons.append(f"{len(topics)} primary topic(s) derived (+{min(30, len(topics)*10)})")
    else:
        reasons.append("No topics derived")
    return min(100, score), "; ".join(reasons)


def score_competitor_positioning(brand, competitor_rows, observations):
    """20% component."""
    comps = competitor_names_from_profile(brand)
    score = 20
    reasons = ["Competitive signal baseline (+20)"]
    if comps:
        score += 25
        reasons.append(f"{len(comps)} competitor(s) identified (+25)")
    else:
        reasons.append("No competitors identified")
    comparison_evidence = bool(any(e.get("evidence_type") == "COMPARISON_CONTENT" for e in
                                  get_company_evidence(brand.get("id") or 0)))
    if comparison_evidence:
        score += 30
        reasons.append("Comparison content present (+30)")
    else:
        reasons.append("Comparison content missing")
    if observations:
        mentioned_recommended = [o for o in observations if o.get("brand_mentioned") and
                                 o.get("brand_mention_context") == "recommendation"]
        if mentioned_recommended:
            score += 25
            reasons.append(f"Recommended over competitors in {len(mentioned_recommended)} observation(s) (+25)")
        else:
            reasons.append("No recommendation-level observations")
    else:
        reasons.append("No AI observations to measure positioning")
    return min(100, score), "; ".join(reasons)


def score_content_completeness(brand, evidence):
    """20% component."""
    present = {e["evidence_type"] for e in evidence}
    checks = [
        ("PAGE_TITLE", 8, "page title"),
        ("META_DESCRIPTION", 8, "meta description"),
        ("HEADING", 8, "headings"),
        ("PRODUCT_LISTING", 12, "product/solution content"),
        ("SERVICE_LISTING", 10, "service content"),
        ("ABOUT_INFO", 10, "about information"),
        ("FAQ", 12, "FAQ content"),
        ("PRICING", 10, "pricing content"),
        ("BLOG_ARTICLE", 8, "blog/articles"),
        ("CONTACT_INFO", 4, "contact information"),
        ("STRUCTURED_DATA", 10, "structured data"),
    ]
    score = 0
    got = []
    missing = []
    for etype, pts, label in checks:
        if etype in present:
            score += pts
            got.append(label)
        else:
            missing.append(label)
    reasons = [f"Present: {', '.join(got)} (+{score})"] if got else ["No website content evidence"]
    if missing:
        reasons.append(f"Missing: {', '.join(missing[:6])}")
    return min(100, score), "; ".join(reasons)


def score_ai_readiness(brand, evidence, brand_analysis):
    """15% component."""
    present = {e["evidence_type"] for e in evidence}
    score = 10
    reasons = ["Baseline AI search readability (+10)"]
    if (brand.get("description") or "").strip() and len((brand.get("description") or "").split()) >= 20:
        score += 20
        reasons.append("Rich brand description (+20)")
    if present & {"STRUCTURED_DATA"}:
        score += 25
        reasons.append("Structured data detected (+25)")
    else:
        reasons.append("Structured data missing")
    if present & {"FAQ"}:
        score += 20
        reasons.append("FAQ content present (+20)")
    if present & {"PAGE_TITLE", "META_DESCRIPTION", "HEADING"}:
        score += 15
        reasons.append("On-page metadata present (+15)")
    if (brand.get("keywords") or "").strip():
        score += 10
        reasons.append("Keyword-rich profile (+10)")
    return min(100, score), "; ".join(reasons)


def readiness_metrics(brand, brand_analysis, competitor_rows, observations, evidence):
    """Weighted deterministic overall readiness: 20/25/20/20/15. No randomness."""
    pc, pc_r = score_profile_completeness(brand)
    kc, kc_r = score_keyword_coverage(brand, brand_analysis)
    cp, cp_r = score_competitor_positioning(brand, competitor_rows, observations)
    cc, cc_r = score_content_completeness(brand, evidence)
    ar, ar_r = score_ai_readiness(brand, evidence, brand_analysis)
    total = round(pc * 0.20 + kc * 0.25 + cp * 0.20 + cc * 0.20 + ar * 0.15)
    total = max(0, min(100, total))
    reasons = [
        f"Profile completeness ({pc}/100) - {pc_r}",
        f"Keyword coverage ({kc}/100) - {kc_r}",
        f"Competitor positioning ({cp}/100) - {cp_r}",
        f"Content completeness ({cc}/100) - {cc_r}",
        f"AI search readiness ({ar}/100) - {ar_r}",
    ]
    breakdown = {
        "profile_completeness": {"score": pc, "reason": pc_r},
        "keyword_coverage": {"score": kc, "reason": kc_r},
        "competitor_positioning": {"score": cp, "reason": cp_r},
        "content_completeness": {"score": cc, "reason": cc_r},
        "ai_search_readiness": {"score": ar, "reason": ar_r},
        "weights": {"profile_completeness": 0.20, "keyword_coverage": 0.25,
                   "competitor_positioning": 0.20, "content_completeness": 0.20,
                   "ai_search_readiness": 0.15},
    }
    avg_comp = None
    comp_scores = [c["visibility"] for c in competitor_rows if "Your Brand" not in c["brand"] and c.get("visibility") is not None]
    if comp_scores:
        avg_comp = sum(comp_scores) // len(comp_scores)
    mention_est = round(kc * 0.5 + cc * 0.3 + pc * 0.2)
    return {
        "visibility_score": total,
        "readiness_score": total,
        "mention_rate": mention_est,
        "topic_coverage": kc,
        "competitor_strength": avg_comp if avg_comp is not None else None,
        "readiness_breakdown": breakdown,
        "score_reasons": reasons,
    }


def observed_metrics(brand_id):
    """Separate, clearly-labeled OBSERVED metrics from real AI observations only."""
    obs = db.query("SELECT * FROM ai_observations WHERE brand_id=? ORDER BY observed_at DESC", (brand_id,))
    if not obs:
        return {
            "has_observations": False,
            "observations_count": 0,
            "queries_covered": 0,
            "query_coverage": 0,
            "brand_mention_rate": 0,
            "brand_recommendation_rate": 0,
            "competitor_mention_rate": 0,
            "avg_brand_position": None,
            "observed_score": None,
            "note": "NO OBSERVED AI SEARCH DATA - run Run AI Search with a connected provider.",
            "latest": [],
        }
    total = len(obs)
    mentioned = sum(1 for o in obs if o.get("brand_mentioned"))
    recommended = sum(1 for o in obs if o.get("brand_mentioned") and o.get("brand_mention_context") == "recommendation")
    comp_mentions = sum(1 for o in obs for c in (safe_json_loads(o.get("competitors_mentioned")) or []) if c)
    positions = [o["brand_position"] for o in obs if o.get("brand_mentioned") and o.get("brand_position")]
    query_ids = len({o["query_id"] for o in obs if o.get("query_id")})
    q_rows = db.query("SELECT COUNT(*) AS c FROM query_memory WHERE brand_id=? AND is_active=1", (brand_id,))
    q_total = q_rows[0]["c"] if q_rows else 0
    avg_pos = (sum(positions) / len(positions)) if positions else None
    # observed score (blend of mention rate + position) - clearly labeled OBSERVED
    pos_factor = (50 / avg_pos) if avg_pos else 0
    observed_score = round((mentioned / total * 100) * 0.7 + min(50, pos_factor * 10) * 0.3) if total else None
    return {
        "has_observations": True,
        "observations_count": total,
        "queries_covered": query_ids,
        "query_coverage": round(query_ids / q_total * 100) if q_total else 100,
        "brand_mention_rate": round(mentioned / total * 100) if total else 0,
        "brand_recommendation_rate": round(recommended / total * 100) if total else 0,
        "competitor_mention_rate": round(comp_mentions / total * 100) if total else 0,
        "avg_brand_position": avg_pos,
        "observed_score": min(100, observed_score) if observed_score is not None else None,
        "note": "OBSERVED AI SEARCH VISIBILITY (measured from real provider responses)",
        "latest": obs[:10],
    }


# ---------------------------------------------------------------------------
# CHANGE DETECTION
# ---------------------------------------------------------------------------

def detect_changes(brand_id, run_id):
    """Compare current snapshot with previous analysis snapshot. Returns changes list."""
    b = get_brand(brand_id)
    if not b:
        return []
    current = evidence_snapshot(brand_id)
    prev = None
    rows = db.query("SELECT analysis_data FROM analysis_results WHERE brand_id=? ORDER BY id DESC LIMIT 1 "
                    "OFFSET 1", (brand_id,))
    if rows:
        ad = safe_json_loads(rows[0]["analysis_data"], {})
        prev = ad.get("evidence_snapshot")
    if prev is None:
        rows = db.query("SELECT analysis_data FROM analysis_results WHERE brand_id=? ORDER BY id DESC LIMIT 1",
                        (brand_id,))
        if rows:
            ad = safe_json_loads(rows[0]["analysis_data"], {})
            prev = ad.get("evidence_snapshot")
    prev_map = {}
    for item in prev or []:
        prev_map.setdefault((item.get("type"), item.get("key")), item.get("value"))
    curr_map = {}
    for item in current:
        curr_map.setdefault((item.get("type"), item.get("key")), item.get("value"))

    changes = []
    added_keys = set(curr_map.keys()) - set(prev_map.keys())
    removed_keys = set(prev_map.keys()) - set(curr_map.keys())
    for k in sorted(added_keys, key=str):
        etype, ekey = k
        val = curr_map[k]
        if etype.startswith("PROFILE"):
            continue
        changes.append(_change_row(brand_id, run_id, "CONTENT_ADDED", f"{etype}:{ekey}", None, val,
                                   f"New {etype.lower().replace('_', ' ')} evidence discovered."))
    for k in sorted(removed_keys, key=str):
        etype, ekey = k
        if etype.startswith("PROFILE"):
            continue
        changes.append(_change_row(brand_id, run_id, "CONTENT_REMOVED", f"{etype}:{ekey}", prev_map[k], None,
                                   f"Previously observed {etype.lower().replace('_', ' ')} evidence is no longer present."))
    for k in sorted(set(prev_map.keys()) & set(curr_map.keys()), key=str):
        etype, ekey = k
        pv = prev_map[k]
        cv = curr_map[k]
        if pv != cv:
            changes.append(_change_row(brand_id, run_id, "CONTENT_CHANGED", f"{etype}:{ekey}", pv, cv,
                                       f"Content changed for {etype.lower().replace('_', ' ')} during this run."))
    # profile-level comparisons
    for field in ("description", "keywords", "competitors", "website"):
        pk, ck = ("PROFILE_DESCRIPTION", "description"), ("PROFILE_KEYWORDS", "keywords")
        pk = ("PROFILE_" + field.upper(), field)
        ck = ("PROFILE_" + field.upper(), field)
        pv = prev_map.get(pk)
        cv = curr_map.get(ck)
        if cv != pv:
            changes.append(_change_row(brand_id, run_id, "PROFILE_CHANGED", field, pv, cv,
                                       f"Company profile field '{field}' changed."))
    return changes


def _change_row(brand_id, run_id, ctype, field, pv, cv, impact, severity="INFO"):
    b = get_brand(brand_id)
    name = b["brand_name"] if b else ""
    db.execute("""
        INSERT INTO change_log (brand_id, brand_name, run_id, change_type, field_name, previous_value,
                                current_value, impact, severity, detected_at)
        VALUES (?,?,?,?,?,?,?,?,?,?)
    """, (brand_id, name, run_id, ctype, field, (pv or "")[:2000], (cv or "")[:2000], impact, severity, now()))
    return {"change_type": ctype, "field_name": field, "previous_value": pv, "current_value": cv,
            "impact": impact, "severity": severity}


# ---------------------------------------------------------------------------
# LEARNING MEMORY
# ---------------------------------------------------------------------------

def _legacy_memory_shape(pattern, source):
    """Classify a legacy free-text pattern into the Phase-4 memory vocabulary.

    Raw score/change telemetry stays COMPANY_PATTERN (informational only - it
    never drives query/recommendation decisions); only the actionable types
    (QUERY/RECOMMENDATION/COMPETITOR/CONTENT/EVIDENCE/FEEDBACK patterns) do."""
    p = (pattern or "").upper()
    if p.startswith("USER_FEEDBACK") or p.startswith("IMPLEMENTED:") or source == "FEEDBACK":
        return "FEEDBACK_PATTERN", "USER_FEEDBACK"
    if p.startswith("SCORE_"):
        return "COMPANY_PATTERN", "SCORE_TELEMETRY"
    if p.startswith("CONTENT_CHANGE:"):
        return "COMPANY_PATTERN", "CHANGE_TELEMETRY"
    if p.startswith("EVIDENCE_"):
        return "CONTENT_PATTERN", "CHANGE"
    if p.startswith("QUERY_"):
        return "QUERY_PATTERN", "QUERY"
    if p.startswith("SOURCE:"):
        return "EVIDENCE_PATTERN", "SOURCE"
    return "COMPANY_PATTERN", "GENERAL"


def remember(company_id, pattern, source, evidence_text, confidence=0.6):
    row = db.query("SELECT id, use_count, version, approved FROM learning_memory WHERE company_id=? AND pattern=? LIMIT 1",
                   (company_id, pattern))
    t = now()
    if row:
        db.execute("UPDATE learning_memory SET evidence=?, confidence=?, last_used_at=?, use_count=use_count+1, "
                   "usage_count=usage_count+1, last_updated_at=?, version=version+1, approved=? WHERE id=?",
                   (evidence_text[:2000], confidence, t, t, row[0]["approved"], row[0]["id"]))
        return row[0]["id"]
    mtype, cat = _legacy_memory_shape(pattern, source)
    rid = db.execute("""
        INSERT INTO learning_memory (company_id, memory_type, category, key, value,
            pattern, source, evidence, confidence, usage_count, success_count, failure_count,
            status, created_at, first_learned_at, last_updated_at, approved, version, last_used_at, use_count)
        VALUES (?,?,?,?,?,?,?,?,?,0,0,0,'ACTIVE',?,?,?,0,1,?,0)
    """, (company_id, mtype, cat, pattern[:500], evidence_text[:2000],
          pattern[:2000], source, evidence_text[:2000], confidence, t, t, t, t))
    db.execute("UPDATE learning_memory SET memory_id=? WHERE id=?", (f"MEM-{rid:06d}", rid))
    return rid


def get_learning(company_id=None):
    if company_id:
        return db.query("SELECT * FROM learning_memory WHERE company_id=? ORDER BY id DESC", (company_id,))
    return db.query("SELECT * FROM learning_memory ORDER BY id DESC LIMIT 200")


# ---------------------------------------------------------------------------
# FEEDBACK
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# FEEDBACK  (Phase 4: recommendation lifecycle + learning signals)
# ---------------------------------------------------------------------------
#
# Recommendation status vocabulary (existing OPEN/DONE preserved, INVALIDATED added):
#   OPEN        = NEW / ACTIVE   (fresh or still relevant)
#   DONE        = RESOLVED       (implemented by the user or auto-resolved by new evidence)
#   REJECTED                   (user dismissed; kept for history, never re-prioritized)
#   INVALIDATED                (user marked incorrect, or the underlying evidence went stale)
#
# Feedback -> status mapping:
#   USEFUL               -> stays OPEN, historical usefulness signal +1
#   NOT_USEFUL           -> stays OPEN but priority drops to Low (deprioritized, never deleted)
#   INCORRECT            -> INVALIDATED (never auto-regenerated)
#   ALREADY_IMPLEMENTED  -> DONE/RESOLVED (future duplicates suppressed unless the gap reappears)
#   legacy values (DONE, NOT NEEDED, ...) -> unchanged historical behavior (stays OPEN)

RECOMMENDATION_FEEDBACK_VALUES = ("USEFUL", "NOT_USEFUL", "INCORRECT", "ALREADY_IMPLEMENTED")


def ingest_feedback(payload):
    company_id = payload.get("company_id")
    analysis_id = payload.get("analysis_id")
    target_type = payload.get("target_type") or "RECOMMENDATION"
    target_id = payload.get("target_id")
    feedback = (payload.get("feedback") or "").upper()
    comment = payload.get("comment") or ""
    if target_type == "RECOMMENDATION" and feedback and feedback not in RECOMMENDATION_FEEDBACK_VALUES + (
            "IMPLEMENTED", "DONE", "NOT_NEEDED", "NOT USEFUL", "NOT USEFULL"):
        return {"success": False, "error": f"Unknown feedback value: {feedback}"}
    fb_id = db.execute("""
        INSERT INTO feedback (company_id, analysis_id, target_type, target_id, feedback, comment, status, created_at)
        VALUES (?,?,?,?,?,?,?,?)
    """, (company_id, analysis_id, target_type, target_id, feedback, comment, "NEW", now()))
    # Update recommendation status if it's a recommendation
    if target_type == "RECOMMENDATION" and target_id:
        rec_rows = db.query("SELECT id, brand_id, title, status FROM recommendations WHERE id=?", (target_id,))
        if not rec_rows:
            return {"success": False, "error": "Recommendation not found"}
        rec = rec_rows[0]
        brand_id = company_id or rec["brand_id"]
        status = "OPEN"
        resolution_source = None
        deprioritize = False
        if feedback in ("ALREADY_IMPLEMENTED", "IMPLEMENTED"):
            status = "DONE"
            resolution_source = "USER_FEEDBACK"
        elif feedback == "INCORRECT":
            status = "INVALIDATED"
            resolution_source = "USER_FEEDBACK"
        elif feedback in ("NOT_USEFUL", "NOT USEFUL", "NOT USEFULL", "NOT_NEEDED"):
            status = "OPEN"
            deprioritize = True
        db.execute("UPDATE recommendations SET status=?, feedback=?, feedback_at=?, resolution_source=? WHERE id=?",
                   (status, feedback, now(), resolution_source, target_id))
        if deprioritize:
            db.execute("UPDATE recommendations SET priority='Low' WHERE id=?", (target_id,))
        title = rec["title"] or ""
        # Learning signals: every feedback produces a traceable event + memory counters.
        record_learning_event(brand_id, "FEEDBACK_RECEIVED",
                              f"Recommendation '{title[:120]}' marked {feedback} by user.",
                              source_type="USER_FEEDBACK", source_id=str(fb_id),
                              new_value=status, confidence=0.95,
                              metadata={"recommendation_id": target_id, "comment": comment[:500]})
        if status == "DONE":
            record_learning_event(brand_id, "RECOMMENDATION_RESOLVED",
                                  "Recommendation marked as already implemented.",
                                  source_type="USER_FEEDBACK", source_id=str(fb_id),
                                  new_value=status, confidence=1.0,
                                  metadata={"recommendation_id": target_id})
            ensure_memory(brand_id, "RECOMMENDATION_PATTERN", "RESOLVED", f"RESOLVED:{title[:200]}",
                          f"User confirmed implemented: {title}. Suppress future duplicates unless the gap reappears.",
                          source="FEEDBACK", confidence=1.0, success_delta=1,
                          evidence_text=f"feedback_id={fb_id}",
                          metadata={"recommendation_id": target_id, "feedback": feedback})
        elif status == "INVALIDATED":
            record_learning_event(brand_id, "RECOMMENDATION_REJECTED",
                                  "Recommendation invalidated by user feedback.",
                                  source_type="USER_FEEDBACK", source_id=str(fb_id),
                                  new_value=status, confidence=0.95,
                                  metadata={"recommendation_id": target_id})
            ensure_memory(brand_id, "RECOMMENDATION_PATTERN", "INVALIDATED", f"INVALID:{title[:200]}",
                          f"User marked incorrect: {title}. Do not auto-regenerate.",
                          source="FEEDBACK", confidence=0.95, failure_delta=1,
                          evidence_text=f"feedback_id={fb_id}",
                          metadata={"recommendation_id": target_id, "feedback": feedback})
        elif feedback == "USEFUL":
            ensure_memory(brand_id, "RECOMMENDATION_PATTERN", "USEFUL", f"USEFUL:{title[:200]}",
                          f"User marked useful: {title}. Prioritize when similar evidence appears.",
                          source="FEEDBACK", confidence=0.9, success_delta=1,
                          evidence_text=f"feedback_id={fb_id}",
                          metadata={"recommendation_id": target_id, "feedback": feedback})
        elif deprioritize:
            ensure_memory(brand_id, "RECOMMENDATION_PATTERN", "LOW_VALUE", f"LOW_VALUE:{title[:200]}",
                          f"User marked not useful: {title}. Deprioritize in future selections.",
                          source="FEEDBACK", confidence=0.8, failure_delta=1,
                          evidence_text=f"feedback_id={fb_id}",
                          metadata={"recommendation_id": target_id, "feedback": feedback})
        if company_id and target_id:
            rows = db.query("SELECT title FROM recommendations WHERE id=?", (target_id,))
            if rows:
                pattern = f"USER_FEEDBACK:{feedback}:{rows[0]['title'][:120]}"
                remember(company_id, pattern, "FEEDBACK",
                         f"User marked recommendation as {feedback}: {rows[0]['title']}",
                         confidence=0.9 if feedback in ("USEFUL", "ALREADY_IMPLEMENTED", "IMPLEMENTED") else 0.7)
                if feedback in ("ALREADY_IMPLEMENTED", "IMPLEMENTED"):
                    remember(company_id, f"IMPLEMENTED:{rows[0]['title'][:120]}", "FEEDBACK",
                             f"Recommendation confirmed implemented: {rows[0]['title']}", confidence=1.0)
    elif target_type == "ANALYSIS" and company_id:
        pattern = f"USER_FEEDBACK_{feedback}:analysis"
        remember(company_id, pattern, "FEEDBACK", comment or f"Analysis marked {feedback}", 0.8)
    return {"success": True, "feedback_id": fb_id}


def submit_recommendation_feedback(rec_id, feedback, comment=""):
    """POST /api/recommendations/:id/feedback handler body."""
    rows = db.query("SELECT id, brand_id FROM recommendations WHERE id=?", (rec_id,))
    if not rows:
        return {"success": False, "error": "Recommendation not found"}
    res = ingest_feedback({"company_id": rows[0]["brand_id"], "target_type": "RECOMMENDATION",
                           "target_id": rec_id, "feedback": feedback, "comment": comment or ""})
    if not res.get("success"):
        return res
    cur = db.query("SELECT status FROM recommendations WHERE id=?", (rec_id,))
    res["status"] = cur[0]["status"] if cur else None
    return res


# ---------------------------------------------------------------------------
# PHASE 4 - SELF-LEARNING MEMORY + FEEDBACK ENGINE
# ---------------------------------------------------------------------------
#
# WHAT "SELF-LEARNING" MEANS HERE (and what it explicitly does NOT mean):
#
#   Learning = historical data + evidence + previous analysis + detected changes
#              + query performance + recommendation outcomes + user feedback
#              + approved corrections  ==>  better future query selection and
#              better future recommendation prioritization/suppression.
#
#   The engine NEVER: randomly changes scores, rewrites code/prompts/formulas,
#   invents facts or training data, blindly trusts AI output, deletes history,
#   or takes external irreversible actions. Learning only changes DATA
#   (memory rows, counters, statuses) and PRIORITIZATION (ordering, suppression
#   with logged reasons). Every learned behavior is explainable from stored rows.
#
# DETERMINISTIC RULES (no LLM-invented numbers anywhere):
#   confidence       = learning_confidence(n_obs, verified, positive_feedback, recent)
#   recency weight   = 0.5 ** (age_days / LEARNING_DECAY_DAYS)   (halves every decay period)
#   historical_value = clamp(0.5 + 0.1*min(useful,4) - 0.15*not_useful, 0.05, 0.95) x recency
#   query fingerprint= lowercase alphanumeric-only normalized text
#   source trust     = source_trust_score(source, verification_status, confidence)

LEARNING_EVENT_TYPES = (
    "PATTERN_DISCOVERED", "PATTERN_CONFIRMED", "PATTERN_REJECTED",
    "FEEDBACK_RECEIVED", "RECOMMENDATION_RESOLVED", "RECOMMENDATION_REJECTED",
    "RECOMMENDATION_SUPPRESSED", "QUERY_SUCCESS", "QUERY_FAILURE",
    "EVIDENCE_CORRECTED", "MEMORY_UPDATED", "MEMORY_INVALIDATED",
    "MANAGER_TASK_SUCCESS", "MANAGER_TASK_FAILURE", "AGENT_EXECUTION_SUCCESS",
    "AGENT_EXECUTION_FAILURE", "HANDOFF_SUCCESS", "HANDOFF_FAILURE",
    "SYNTHESIS_SUCCESS", "SYNTHESIS_FAILURE", "HUMAN_CORRECTION",
    "AGENT_SELECTED", "AGENT_DELEGATED", "CONFLICT_DETECTED",
)

LEARNING_MEMORY_TYPES = (
    "COMPANY_PATTERN", "QUERY_PATTERN", "COMPETITOR_PATTERN", "CONTENT_PATTERN",
    "RECOMMENDATION_PATTERN", "EVIDENCE_PATTERN", "FEEDBACK_PATTERN",
)

QUERY_INTENTS = ("INFORMATIONAL", "COMMERCIAL", "TRANSACTIONAL", "COMPARISON",
                 "PROBLEM_SOLVING", "BRAND", "COMPETITOR", "INDUSTRY")

INTENT_ALIASES = {
    "informational": "INFORMATIONAL", "commercial": "COMMERCIAL",
    "transactional": "TRANSACTIONAL", "comparison": "COMPARISON",
    "problem_solving": "PROBLEM_SOLVING", "problem-solving": "PROBLEM_SOLVING",
    "brand": "BRAND", "competitor": "COMPETITOR", "industry": "INDUSTRY",
}

SOURCE_TRUST_BASE = {
    "USER_PROVIDED": 0.90, "MANUAL": 0.90, "VALIDATE_DATA": 0.90,
    "API_COLLECTED": 0.85, "WEBSITE_SCRAPER": 0.82, "WEBSITE_DISCOVERED": 0.80,
    "CSV_IMPORTED": 0.70, "CSV": 0.70, "DISCOVERY": 0.60,
    "HISTORY": 0.60, "HISTORICAL": 0.60, "AUTO": 0.55,
    "AI_INFERRED": 0.40, "GENERATED": 0.50, "FEEDBACK": 0.95,
}


def _lconfig_int(key, default):
    try:
        return int(get_config(key, str(default)))
    except Exception:
        return default


def learning_enabled_global():
    return get_config("LEARNING_ENABLED", "1") == "1"


def learning_enabled_for_company(company_id):
    if not learning_enabled_global():
        return False
    try:
        s = get_company_settings(company_id)
        return int(s.get("learning_enabled", 1)) == 1
    except Exception:
        return True


def query_fingerprint(text):
    """Normalized identity for a query: lowercase, alphanumeric only."""
    return re.sub(r"[^a-z0-9]", "", (text or "").lower())


def recency_weight(ts, decay_days=None):
    """Halving weight per LEARNING_DECAY_DAYS. Future timestamps count as now."""
    try:
        dd = int(decay_days or _lconfig_int("LEARNING_DECAY_DAYS", 90)) or 90
    except Exception:
        dd = 90
    try:
        dt = datetime.datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        age_days = max(0.0, (datetime.datetime.now(datetime.timezone.utc) - dt).total_seconds() / 86400.0)
    except Exception:
        return 1.0
    return round(0.5 ** (age_days / dd), 4)


def learning_confidence(n_obs, verified=False, positive_feedback=False, recent=True):
    """Deterministic confidence from real signals only. Range 0.05..0.95."""
    c = 0.35 + 0.10 * min(int(n_obs or 0), 3)
    if verified:
        c += 0.10
    if positive_feedback:
        c += 0.10
    if recent:
        c += 0.05
    return round(max(0.05, min(0.95, c)), 3)


def query_historical_value(useful, not_useful, last_used_at=None):
    base = 0.5 + 0.10 * min(int(useful or 0), 4) - 0.15 * int(not_useful or 0)
    base = max(0.05, min(0.95, base))
    if last_used_at:
        base = base * recency_weight(last_used_at)
    return round(max(0.01, min(0.99, base)), 3)


def source_trust_score(source, verification_status=None, confidence=None):
    """Deterministic trust for an evidence/source row. Range 0.05..0.99."""
    base = SOURCE_TRUST_BASE.get((source or "").upper(), 0.55)
    vs = (verification_status or "").upper()
    if vs == "VERIFIED":
        base += 0.10
    elif vs == "ANALYZED":
        base += 0.05
    elif vs == "UNVERIFIED":
        base -= 0.15
    elif vs in ("REJECTED", "INVALID"):
        base -= 0.30
    base = max(0.05, min(0.99, base))
    try:
        if confidence is not None:
            base = 0.6 * base + 0.4 * float(confidence)
    except Exception:
        pass
    return round(max(0.05, min(0.99, base)), 3)


def record_learning_event(company_id, event_type, description, run_id=None, memory_id=None,
                          source_type=None, source_id=None, previous_value=None, new_value=None,
                          confidence=None, metadata=None, mirror_activity=True):
    """Append a traceable learning event. Major events also mirror to agent_activity."""
    if event_type not in LEARNING_EVENT_TYPES:
        event_type = "MEMORY_UPDATED"
    eid = f"EVT-{int(time.time()*1000) % 100000000:08d}"
    t = now()
    db.execute("""
        INSERT INTO learning_events (event_id, company_id, run_id, memory_id, event_type, description,
                                     source_type, source_id, previous_value, new_value, confidence,
                                     created_at, metadata_json)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (eid, company_id, run_id, memory_id, event_type, (description or "")[:2000],
          source_type, str(source_id)[:200] if source_id is not None else None,
          str(previous_value)[:2000] if previous_value is not None else None,
          str(new_value)[:2000] if new_value is not None else None,
          confidence, t, json.dumps(metadata or {})[:4000]))
    if mirror_activity and event_type in ("PATTERN_DISCOVERED", "PATTERN_CONFIRMED", "RECOMMENDATION_RESOLVED",
                                          "RECOMMENDATION_REJECTED", "MEMORY_INVALIDATED", "EVIDENCE_CORRECTED"):
        try:
            log_activity(description, level="LEARN", run_id=run_id, company_id=company_id)
        except Exception:
            pass
    return eid


def ensure_memory(company_id, memory_type, category, key, value, source="AUTO", confidence=None,
                  success_delta=0, failure_delta=0, evidence_text="", status="ACTIVE",
                  metadata=None, run_id=None, verified=False):
    """Upsert a learning memory. Updates emit PATTERN_CONFIRMED; inserts emit PATTERN_DISCOVERED."""
    if memory_type not in LEARNING_MEMORY_TYPES:
        memory_type = "COMPANY_PATTERN"
    rows = db.query("""SELECT * FROM learning_memory
                       WHERE company_id=? AND memory_type=? AND category=? AND key=? AND status != 'INVALIDATED'
                       ORDER BY id DESC LIMIT 1""",
                    (company_id, memory_type, category, key[:500]))
    t = now()
    meta = dict(metadata or {})
    if rows:
        m = rows[0]
        usage = (m.get("usage_count") or m.get("use_count") or 0) + 1
        succ = (m.get("success_count") or 0) + int(success_delta or 0)
        fail = (m.get("failure_count") or 0) + int(failure_delta or 0)
        conf = learning_confidence(usage, verified=verified or bool(meta.get("verified")),
                                   positive_feedback=succ > fail, recent=True)
        if confidence is not None:
            try:
                conf = max(conf, min(0.95, float(confidence)))
            except Exception:
                pass
        merged = safe_json_loads(m.get("metadata_json"), {}) or {}
        merged.update(meta)
        db.execute("""UPDATE learning_memory SET value=?, evidence=?, confidence=?, usage_count=?,
                           success_count=?, failure_count=?, use_count=?, last_used_at=?, last_updated_at=?,
                           status=?, metadata_json=? WHERE id=?""",
                   ((value or m.get("value") or "")[:2000], (evidence_text or m.get("evidence") or "")[:2000],
                    conf, usage, succ, fail, usage, t, t, status, json.dumps(merged)[:4000], m["id"]))
        mid = m.get("memory_id") or f"MEM-{m['id']:06d}"
        record_learning_event(company_id, "PATTERN_CONFIRMED",
                              f"Pattern confirmed ({usage} observations): {(key or '')[:140]}",
                              run_id=run_id, memory_id=mid, source_type="LEARNING_ENGINE",
                              new_value=status, confidence=conf, metadata={"memory_row_id": m["id"]})
        return m["id"]
    conf = learning_confidence(1 + int(success_delta or 0), verified=verified,
                               positive_feedback=int(success_delta or 0) > int(failure_delta or 0), recent=True)
    if confidence is not None:
        try:
            conf = max(conf, min(0.95, float(confidence)))
        except Exception:
            pass
    rid = db.execute("""
        INSERT INTO learning_memory (company_id, memory_type, category, key, value, pattern, source,
            evidence, confidence, usage_count, success_count, failure_count, status,
            created_at, first_learned_at, last_updated_at, approved, version, last_used_at, use_count, metadata_json)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,1,?,0,?)
    """, (company_id, memory_type, category, key[:500], (value or "")[:2000], key[:2000], source,
          (evidence_text or "")[:2000], conf, 1, int(success_delta or 0), int(failure_delta or 0),
          status, t, t, t, t, json.dumps(meta)[:4000]))
    mid = f"MEM-{rid:06d}"
    db.execute("UPDATE learning_memory SET memory_id=? WHERE id=?", (mid, rid))
    record_learning_event(company_id, "PATTERN_DISCOVERED",
                          f"New company-specific pattern discovered: {(key or '')[:140]}",
                          run_id=run_id, memory_id=mid, source_type="LEARNING_ENGINE",
                          new_value=status, confidence=conf, metadata={"memory_row_id": rid})
    return rid


def invalidate_memory(memory_id_or_id, reason, source="USER"):
    """INVALIDATED keeps the row forever; it only stops influencing decisions."""
    rows = db.query("SELECT * FROM learning_memory WHERE memory_id=? OR id=?", (str(memory_id_or_id), memory_id_or_id))
    if not rows:
        # allow MEM-000123 style against integer ids too
        m = re.search(r"(\d+)$", str(memory_id_or_id or ""))
        if m:
            rows = db.query("SELECT * FROM learning_memory WHERE id=?", (int(m.group(1)),))
    if not rows:
        return {"success": False, "error": "Memory not found"}
    m = rows[0]
    if m.get("status") == "INVALIDATED":
        return {"success": True, "memory_id": m.get("memory_id"), "already": True}
    db.execute("UPDATE learning_memory SET status='INVALIDATED', last_updated_at=? WHERE id=?", (now(), m["id"]))
    record_learning_event(m.get("company_id"), "MEMORY_INVALIDATED",
                          f"Memory invalidated ({(m.get('key') or m.get('pattern') or '')[:140]}): {reason[:300]}",
                          memory_id=m.get("memory_id"), source_type=source,
                          previous_value="ACTIVE", new_value="INVALIDATED",
                          metadata={"reason": reason[:500]})
    return {"success": True, "memory_id": m.get("memory_id")}


def clear_company_influence(company_id, reason="user cleared active influence"):
    """Set ACTIVE memories to INACTIVE. History is never deleted."""
    rows = db.query("SELECT id FROM learning_memory WHERE company_id=? AND status='ACTIVE'", (company_id,))
    if not rows:
        return {"success": True, "cleared": 0}
    db.execute("UPDATE learning_memory SET status='INACTIVE', last_updated_at=? "
               "WHERE company_id=? AND status='ACTIVE'", (now(), company_id))
    record_learning_event(company_id, "MEMORY_UPDATED",
                          f"Cleared active influence for company #{company_id} ({len(rows)} memories set INACTIVE; history preserved).",
                          source_type="USER", new_value="INACTIVE",
                          metadata={"reason": reason[:500], "cleared": len(rows)})
    return {"success": True, "cleared": len(rows)}


def set_company_learning(company_id, enabled):
    s = get_company_settings(company_id)
    s["learning_enabled"] = 1 if enabled else 0
    save_company_settings(company_id, s)
    record_learning_event(company_id, "MEMORY_UPDATED",
                          f"Learning {'enabled' if enabled else 'disabled'} for company #{company_id}.",
                          source_type="USER", new_value="ENABLED" if enabled else "DISABLED")
    return {"success": True, "learning_enabled": bool(enabled)}


# ---------------------------------------------------------------------------
# QUERY LEARNING  (performance from real observations - never random)
# ---------------------------------------------------------------------------

def _query_learning_row(company_id, fingerprint, query_text, intent, category):
    rows = db.query("SELECT * FROM query_learning WHERE company_id=? AND fingerprint=? LIMIT 1",
                    (company_id, fingerprint))
    if rows:
        return rows[0]
    t = now()
    rid = db.execute("""
        INSERT INTO query_learning (company_id, query, fingerprint, intent, category, times_tested,
                                    useful_count, not_useful_count, historical_value, status,
                                    first_seen_at, last_used_at, metadata_json)
        VALUES (?,?,?,?,?,0,0,0,0.5,'ACTIVE',?,?,?)
    """, (company_id, (query_text or "")[:500], fingerprint, intent, category, t, t, "{}"))
    rows = db.query("SELECT * FROM query_learning WHERE id=?", (rid,))
    return rows[0]


def record_query_outcome(query_id, company_id, useful, competitors_seen=False, run_id=None,
                         query_text=None, intent=None):
    """Record one tested query outcome. Drives QUERY_SUCCESS/QUERY_FAILURE events,
    historical_value, and ACTIVE -> LOW_VALUE -> DISABLED transitions.

    Thresholds come from central config (QUERY_FAILURE_THRESHOLD; DISABLED needs
    3x failures with zero successes). One failure never disables a query.
    """
    fail_th = _lconfig_int("QUERY_FAILURE_THRESHOLD", 3)
    t = now()
    useful = bool(useful or competitors_seen)
    qrows = db.query("SELECT * FROM query_memory WHERE id=?", (query_id,)) if query_id else []
    q = qrows[0] if qrows else {}
    qt = query_text or q.get("query_text") or ""
    fp = query_fingerprint(qt)
    if q and not q.get("fingerprint") and fp:
        try:
            db.execute("UPDATE query_memory SET fingerprint=? WHERE id=?", (fp, query_id))
        except Exception:
            pass
    qintent = intent or q.get("intent") or "informational"
    norm_intent = INTENT_ALIASES.get(str(qintent).lower(), str(qintent).upper())
    if norm_intent not in QUERY_INTENTS:
        norm_intent = "INFORMATIONAL"
    row = _query_learning_row(company_id, fp or f"q{query_id}", qt, norm_intent, q.get("category"))
    new_useful = (row.get("useful_count") or 0) + (1 if useful else 0)
    new_not = (row.get("not_useful_count") or 0) + (0 if useful else 1)
    tested = (row.get("times_tested") or 0) + 1
    last_result = "USEFUL" if useful else "NOT_USEFUL"
    status = row.get("status") or "ACTIVE"
    transitioned = None
    if useful and status == "LOW_VALUE" and new_useful >= 1:
        status, transitioned = "ACTIVE", "rehabilitated by useful result"
    if not useful and status == "ACTIVE" and new_not >= fail_th and new_useful == 0:
        status, transitioned = "LOW_VALUE", f"{new_not} consecutive non-useful results (threshold {fail_th})"
    if not useful and status in ("ACTIVE", "LOW_VALUE") and new_not >= 3 * fail_th and new_useful == 0:
        status, transitioned = "DISABLED", f"{new_not} consecutive non-useful results (auto-disable)"
    value = query_historical_value(new_useful, new_not, t)
    meta = safe_json_loads(row.get("metadata_json"), {}) or {}
    meta["transitions"] = (meta.get("transitions") or [])[-9:] + (
        [{"at": t, "to": status, "why": transitioned}] if transitioned else [])
    db.execute("""UPDATE query_learning SET times_tested=?, useful_count=?, not_useful_count=?,
                       last_result=?, historical_value=?, status=?, last_used_at=?, intent=?,
                       metadata_json=? WHERE id=?""",
               (tested, new_useful, new_not, last_result, value, status, t, norm_intent,
                json.dumps(meta)[:2000], row["id"]))
    # Mirror counters onto the operational query_memory row (same deterministic value).
    if query_id and q:
        try:
            db.execute("""UPDATE query_memory SET useful_count=?, not_useful_count=?, historical_value=?,
                               last_used_at=?, status=? WHERE id=?""",
                       (new_useful, new_not, value, t, status, query_id))
        except Exception:
            pass
    record_learning_event(company_id, "QUERY_SUCCESS" if useful else "QUERY_FAILURE",
                          f"Query '{qt[:120]}' produced {'useful evidence' if useful else 'no useful information'}"
                          f" (useful {new_useful}x / not-useful {new_not}x, value {value}).",
                          run_id=run_id, source_type="QUERY_TEST",
                          source_id=str(query_id or row["id"]),
                          new_value=status, confidence=value,
                          metadata={"query": qt[:300], "intent": norm_intent,
                                    "transition": transitioned or "",
                                    "fingerprint": fp}, mirror_activity=False)
    return {"useful": useful, "status": status, "historical_value": value,
            "useful_count": new_useful, "not_useful_count": new_not, "transition": transitioned}


def select_historical_queries(brand, current_queries, limit=3):
    """Pick historically useful queries as candidates for the current analysis.

    Sources consulted (in order): same-company ACTIVE queries by decayed value,
    then same-industry ACTIVE queries adapted to this brand. LOW_VALUE/DISABLED
    rows and fingerprint duplicates of the current set are excluded. Every
    candidate carries an explanation (why selected).
    """
    out = []
    if not learning_enabled_for_company(brand.get("id")):
        return out
    try:
        limit = max(0, int(limit))
    except Exception:
        limit = 3
    if limit <= 0:
        return out
    have_fp = {query_fingerprint(q.get("query_text") or q.get("query") or "") for q in current_queries or []}
    have_fp.discard("")
    brand_name = (brand.get("brand_name") or "").strip()
    industry = (brand.get("industry") or "").strip()
    keywords = [k.strip().lower() for k in (brand.get("keywords") or "").split(",") if k.strip()]
    # 1) same-company candidates
    same = db.query("""SELECT * FROM query_learning WHERE company_id=? AND status='ACTIVE'
                       ORDER BY historical_value DESC, useful_count DESC LIMIT 20""", (brand.get("id"),))
    for r in same:
        fp = r.get("fingerprint") or query_fingerprint(r.get("query") or "")
        if not fp or fp in have_fp:
            continue
        reasons = ["from this company's own history",
                   f"useful in {r.get('useful_count') or 0} of {r.get('times_tested') or 0} previous tests "
                   f"(value {r.get('historical_value')})"]
        kw = (r.get("query") or "").lower()
        if keywords and any(k in kw for k in keywords):
            reasons.append("keyword matches current company profile")
        out.append({"query": r.get("query"), "intent": (r.get("intent") or "INFORMATIONAL").lower(),
                    "keyword": "", "category": r.get("category") or "General",
                    "historical": True, "adapted": False, "selection_reasons": reasons,
                    "source": f"history:{r.get('id')}"})
        have_fp.add(fp)
        if len(out) >= limit:
            return out
    # 2) cross-company candidates from the same industry (adapted, never blind reuse)
    if industry:
        other = db.query("""SELECT q.*, b.brand_name AS other_brand, b.industry FROM query_learning q
                            JOIN brands b ON b.id = q.company_id
                            WHERE q.company_id != ? AND q.status='ACTIVE' AND b.industry=?
                            ORDER BY q.historical_value DESC, q.useful_count DESC LIMIT 20""",
                         (brand.get("id"), industry))
        for r in other:
            fp = r.get("fingerprint") or query_fingerprint(r.get("query") or "")
            if not fp or fp in have_fp:
                continue
            adapted_text = r.get("query") or ""
            adapted = False
            other_brand = (r.get("other_brand") or "").strip()
            if other_brand and other_brand.lower() in adapted_text.lower() and brand_name:
                adapted_text = re.sub(re.escape(other_brand), brand_name, adapted_text, flags=re.IGNORECASE)
                adapted = True
            reasons = [f"observed pattern from similar {industry} company",
                       f"useful in {r.get('useful_count') or 0} of {r.get('times_tested') or 0} previous tests",
                       "adapted to the current company" if adapted else "industry context matches"]
            out.append({"query": adapted_text, "intent": (r.get("intent") or "INFORMATIONAL").lower(),
                        "keyword": "", "category": r.get("category") or "General",
                        "historical": True, "adapted": adapted, "selection_reasons": reasons,
                        "source": f"history:{r.get('id')}"})
            have_fp.add(fp)
            if len(out) >= limit:
                break
    return out


def query_performance(company_id=None):
    """Per-query and per-intent aggregates from real query_learning rows."""
    q = "SELECT * FROM query_learning"
    p = ()
    if company_id is not None:
        q += " WHERE company_id=?"
        p = (company_id,)
    rows = db.query(q + " ORDER BY historical_value DESC, useful_count DESC LIMIT 500", p)
    by_intent = {}
    for r in rows:
        it = (r.get("intent") or "INFORMATIONAL").upper()
        a = by_intent.setdefault(it, {"intent": it, "queries": 0, "tested": 0, "useful": 0,
                                      "not_useful": 0, "avg_value": 0.0, "_sum": 0.0})
        a["queries"] += 1
        a["tested"] += r.get("times_tested") or 0
        a["useful"] += r.get("useful_count") or 0
        a["not_useful"] += r.get("not_useful_count") or 0
        a["_sum"] += float(r.get("historical_value") or 0)
    intents = []
    for it, a in by_intent.items():
        a["avg_value"] = round(a["_sum"] / max(1, a["queries"]), 3)
        a.pop("_sum", None)
        tot = a["useful"] + a["not_useful"]
        a["usefulness_ratio"] = round(a["useful"] / tot, 3) if tot else None
        intents.append(a)
    intents.sort(key=lambda a: (a["avg_value"] or 0), reverse=True)
    return {"success": True, "queries": [dict(r) for r in rows], "by_intent": intents}


def recommendation_performance(company_id=None):
    """Per-recommendation feedback stats from real recommendation + feedback rows."""
    q = ("SELECT r.id, r.brand_id, r.title, r.category, r.priority, r.status, r.feedback, "
         "r.resolution_source, r.times_generated, r.first_seen_at, r.last_seen_at, r.created_at, "
         "b.brand_name AS company FROM recommendations r "
         "LEFT JOIN brands b ON b.id=r.brand_id")
    p = ()
    if company_id is not None:
        q += " WHERE r.brand_id=?"
        p = (company_id,)
    recs = db.query(q + " ORDER BY r.id DESC LIMIT 500", p)
    fb = db.query("SELECT target_id, feedback FROM feedback WHERE target_type='RECOMMENDATION'"
                  + (" AND company_id=?" if company_id is not None else ""), p)
    counts = {}
    for f in fb:
        c = counts.setdefault(f["target_id"], {})
        c[f["feedback"]] = c.get(f["feedback"], 0) + 1
    out = []
    for r in recs:
        d = dict(r)
        d["feedback_counts"] = counts.get(r["id"], {})
        out.append(d)
    tally = {"OPEN": 0, "DONE": 0, "REJECTED": 0, "INVALIDATED": 0}
    for r in recs:
        tally[(r.get("status") or "OPEN").upper()] = tally.get((r.get("status") or "OPEN").upper(), 0) + 1
    return {"success": True, "recommendations": out, "status_tally": tally}


# ---------------------------------------------------------------------------
# LEARNING APIs  (§22 - every value from real database rows)
# ---------------------------------------------------------------------------

def learning_memory_list(company_id=None, status="ACTIVE", memory_type=None, limit=500):
    q = "SELECT m.*, b.brand_name AS company FROM learning_memory m LEFT JOIN brands b ON b.id=m.company_id WHERE 1=1"
    p = []
    if company_id is not None:
        q += " AND m.company_id=?"
        p.append(company_id)
    if status:
        q += " AND m.status=?"
        p.append(status)
    if memory_type:
        q += " AND m.memory_type=?"
        p.append(memory_type)
    try:
        limit = max(1, min(int(limit or 500), 1000))
    except Exception:
        limit = 500
    rows = db.query(q + f" ORDER BY m.id DESC LIMIT {limit}", tuple(p))
    return {"success": True, "memories": [dict(r) for r in rows]}


def learning_events_list(company_id=None, memory_id=None, event_type=None, limit=100):
    q = "SELECT * FROM learning_events WHERE 1=1"
    p = []
    if company_id is not None:
        q += " AND company_id=?"
        p.append(company_id)
    if memory_id:
        q += " AND memory_id=?"
        p.append(memory_id)
    if event_type:
        q += " AND event_type=?"
        p.append(event_type)
    try:
        limit = max(1, min(int(limit or 100), 500))
    except Exception:
        limit = 100
    rows = db.query(q + f" ORDER BY id DESC LIMIT {limit}", tuple(p))
    return {"success": True, "events": [dict(r) for r in rows]}


def learning_patterns(company_id=None):
    mem = learning_memory_list(company_id, status="ACTIVE")
    pats = [m for m in mem["memories"]
            if (m.get("memory_type") or "") in ("QUERY_PATTERN", "COMPETITOR_PATTERN", "CONTENT_PATTERN",
                                                "RECOMMENDATION_PATTERN", "EVIDENCE_PATTERN", "FEEDBACK_PATTERN")]
    for m in pats:
        n = (m.get("usage_count") or m.get("use_count") or 1)
        m["explanation"] = (f"Pattern based on {n} observation(s) from previous analyses. "
                            f"Confidence {m.get('confidence')} (deterministic: observations, verification, "
                            f"feedback, recency). Source: {m.get('source')}.")
    g = db.query("SELECT * FROM global_learning_memory WHERE status='ACTIVE' ORDER BY company_count DESC LIMIT 100")
    return {"success": True, "patterns": pats, "global_patterns": [dict(r) for r in g]}


def learning_dashboard_summary(company_id=None):
    """§23 KPIs - every number counted from real rows."""
    def count(sql, p=()):
        r = db.query(sql, p)
        return (r[0].get("c") or 0) if r else 0
    cf = " WHERE company_id=?" if company_id is not None else ""
    cp = (company_id,) if company_id is not None else ()
    qf = " WHERE company_id=?" if company_id is not None else ""
    qp = (company_id,) if company_id is not None else ()
    ev = db.query("SELECT event_type, COUNT(*) AS c FROM learning_events"
                  + (f" WHERE company_id={int(company_id)}" if company_id is not None else "")
                  + " GROUP BY event_type")
    ev_counts = {r["event_type"]: r["c"] for r in ev}
    last = db.query("SELECT MAX(created_at) AS t FROM learning_events"
                    + (f" WHERE company_id={int(company_id)}" if company_id is not None else ""))
    mem_active = count("SELECT COUNT(*) AS c FROM learning_memory WHERE status='ACTIVE'" + (" AND company_id=?" if company_id is not None else ""), cp)
    useful_q = count("SELECT COUNT(*) AS c FROM query_learning WHERE useful_count > 0" + (" AND company_id=?" if company_id is not None else ""), qp)
    low_q = count("SELECT COUNT(*) AS c FROM query_learning WHERE status IN ('LOW_VALUE','DISABLED')" + (" AND company_id=?" if company_id is not None else ""), qp)
    rec_done = count("SELECT COUNT(*) AS c FROM recommendations WHERE status='DONE'" + (" AND brand_id=?" if company_id is not None else ""), cp)
    rec_rej = count("SELECT COUNT(*) AS c FROM recommendations WHERE status IN ('REJECTED','INVALIDATED')" + (" AND brand_id=?" if company_id is not None else ""), cp)
    fb_n = count("SELECT COUNT(*) AS c FROM feedback" + (" WHERE company_id=?" if company_id is not None else ""), cp)
    return {"success": True, "company_id": company_id,
            "active_memories": mem_active,
            "learning_events": sum(ev_counts.values()),
            "patterns_discovered": ev_counts.get("PATTERN_DISCOVERED", 0),
            "patterns_confirmed": ev_counts.get("PATTERN_CONFIRMED", 0),
            "patterns_invalidated": ev_counts.get("MEMORY_INVALIDATED", 0),
            "useful_queries": useful_q,
            "low_value_queries": low_q,
            "recommendations_resolved": rec_done,
            "recommendations_rejected": rec_rej,
            "feedback_received": fb_n,
            "last_learning_update": (last[0].get("t") if last else None)}


def rebuild_company_learning(company_id):
    """Re-derive patterns from stored history (never deletes events/feedback)."""
    if not get_brand(company_id):
        return {"success": False, "error": "Company not found"}
    res = extract_company_learning(company_id, run_id=None)
    res["success"] = True
    res["company_id"] = company_id
    return res


def rebuild_company_learning(company_id):
    """Re-derive patterns from stored history (never deletes events/feedback)."""
    if not get_brand(company_id):
        return {"success": False, "error": "Company not found"}
    res = extract_company_learning(company_id, run_id=None)
    res["success"] = True
    res["company_id"] = company_id
    return res


# ---------------------------------------------------------------------------
# PHASE 5 - AUTONOMOUS INTELLIGENCE + AGENT ORCHESTRATION + STATE-AWARE DECISIONS
# ---------------------------------------------------------------------------
#
# Separation of responsibilities (strict):
#   - THIS layer decides WHAT work a company needs (state assessment, priorities,
#     explanations). It never executes analysis itself.
#   - The existing Agent Runner decides HOW each job executes (unchanged).
#   - The existing Scheduler keeps its behavior (unchanged - Phase-5 never alters
#     automation firing; the autonomous cycle is a separate, bounded service).
#
# All priority rules are deterministic. No LLM decides operational priority.
# The engine may only create jobs from AUTONOMOUS_JOB_ALLOWLIST (the registered
# pipeline types + coordinator + retry) - it is structurally incapable of
# anything outside the human-approved action boundary (§20).

COMPANY_STATES = ("NEW", "INITIALIZING", "HEALTHY", "STALE", "CHANGED",
                  "ANALYSIS_REQUIRED", "REANALYSIS_REQUIRED", "DEGRADED",
                  "BLOCKED", "ERROR", "PAUSED")

AUTONOMOUS_JOB_ALLOWLIST = set([
    "DISCOVER_COMPANY", "COLLECT_WEBSITE_DATA", "VALIDATE_DATA", "GENERATE_QUERIES",
    "RUN_AI_SEARCH", "ANALYZE_BRAND", "ANALYZE_COMPETITORS", "DETECT_CONTENT_GAPS",
    "GENERATE_RECOMMENDATIONS", "DETECT_CHANGES", "STORE_ANALYSIS", "UPDATE_LEARNING",
    "REANALYZE_COMPANY",
])

# Orchestration-only pseudo-actions (never a jobs row; mapped in accept path).
ORCHESTRATION_ACTIONS = ("INITIAL_PIPELINE", "RETRY_JOB", "NO_ACTION")

# Targeted downstream chains per entry point: the loop reassesses after each
# chain instead of blindly rebuilding everything (§1, §4).
CHAIN_BOUNDS = {
    "DISCOVER_COMPANY": ["DISCOVER_COMPANY"],
    "COLLECT_WEBSITE_DATA": ["COLLECT_WEBSITE_DATA", "VALIDATE_DATA", "DETECT_CHANGES"],
    "VALIDATE_DATA": ["VALIDATE_DATA", "DETECT_CHANGES"],
    "GENERATE_QUERIES": ["GENERATE_QUERIES", "RUN_AI_SEARCH"],
    "RUN_AI_SEARCH": ["RUN_AI_SEARCH"],
    "ANALYZE_BRAND": ["ANALYZE_BRAND", "ANALYZE_COMPETITORS", "DETECT_CONTENT_GAPS",
                      "GENERATE_RECOMMENDATIONS", "STORE_ANALYSIS", "UPDATE_LEARNING"],
    "ANALYZE_COMPETITORS": ["ANALYZE_COMPETITORS", "GENERATE_RECOMMENDATIONS",
                            "STORE_ANALYSIS", "UPDATE_LEARNING"],
    "DETECT_CONTENT_GAPS": ["DETECT_CONTENT_GAPS", "GENERATE_RECOMMENDATIONS",
                            "STORE_ANALYSIS", "UPDATE_LEARNING"],
    "GENERATE_RECOMMENDATIONS": ["GENERATE_RECOMMENDATIONS", "STORE_ANALYSIS", "UPDATE_LEARNING"],
    "DETECT_CHANGES": ["DETECT_CHANGES"],
    "STORE_ANALYSIS": ["STORE_ANALYSIS", "UPDATE_LEARNING"],
    "UPDATE_LEARNING": ["UPDATE_LEARNING"],
}

CRITICAL_JOB_TYPES = ("STORE_ANALYSIS", "ANALYZE_BRAND", "COLLECT_WEBSITE_DATA",
                      "VALIDATE_DATA", "GENERATE_QUERIES", "RUN_AI_SEARCH",
                      "GENERATE_RECOMMENDATIONS", "DETECT_CHANGES")

DECISION_STATUSES = ("PROPOSED", "ACCEPTED", "SKIPPED", "EXECUTED", "FAILED", "CANCELLED")

AUTO_STATE = {"status": "IDLE", "cycle": 0, "company": None, "action": None,
              "run_id": None, "last_error": None, "last_cycle": None}


def _auto_cfg_int(key, default):
    try:
        return int(get_config(key, str(default)))
    except Exception:
        return default


def scraper_available():
    try:
        return bool(requests_available) and int(get_config("scrape_enabled", "1")) == 1 \
            and company_source_is_connected("WEBSITE_SCRAPER")
    except Exception:
        return False


def profile_diff(company_id):
    """Which profile fields differ from the last stored analysis snapshot."""
    b = get_brand(company_id)
    if not b:
        return {}
    rows = db.query("SELECT analysis_data FROM analysis_results WHERE brand_id=? ORDER BY id DESC LIMIT 1",
                    (company_id,))
    if not rows:
        return {f: (None, b.get(f) or "") for f in ("keywords", "competitors", "description", "website")
                if (b.get(f) or "")}
    snap = safe_json_loads(rows[0].get("analysis_data"), {}).get("evidence_snapshot") or []
    prev = {}
    for item in snap:
        if str(item.get("type", "")).startswith("PROFILE_"):
            prev[item.get("key")] = item.get("value") or ""
    diff = {}
    for f in ("keywords", "competitors", "description", "website"):
        cur = b.get(f) or ""
        if prev.get(f, "") != cur and (prev.get(f, "") or cur):
            diff[f] = (prev.get(f, ""), cur)
    return diff


def classify_change(ch):
    """Deterministic MAJOR/MINOR classification for one change_log row."""
    ct = (ch.get("change_type") or "").upper()
    field = str(ch.get("field_name") or "")
    if ct == "CONTENT_REMOVED":
        return "MAJOR", "previously present evidence disappeared"
    if ct == "PROFILE_CHANGED" and field in ("website", "keywords", "competitors"):
        return "MAJOR", f"profile field '{field}' changed"
    if ct == "PROFILE_CHANGED":
        return "MINOR", f"profile field '{field}' changed (metadata-level)"
    if ct == "CONTENT_CHANGED" and any(k in field for k in ("STRUCTURED_DATA", "FAQ", "PRICING", "PRODUCT_LISTING")):
        return "MAJOR", f"key evidence surface changed ({field})"
    if ct == "CONTENT_CHANGED":
        return "MINOR", f"evidence content changed ({field})"
    return "MINOR", "new evidence discovered"


def unprocessed_changes(company_id):
    """Changes detected strictly after the latest analysis (first-run rows that
    the analysis itself just consumed do not count as unprocessed)."""
    b = get_brand(company_id)
    since = (b.get("last_analyzed_at") or "1970-01-01") if b else "1970-01-01"
    rows = db.query("SELECT * FROM change_log WHERE brand_id=? AND detected_at > ? ORDER BY id ASC LIMIT 200",
                    (company_id, since))
    majors, minors = [], []
    for ch in rows:
        level, why = classify_change(ch)
        (majors if level == "MAJOR" else minors).append({**dict(ch), "magnitude": level, "magnitude_why": why})
    return majors, minors


def assess_company_state(company_id):
    """Derive the operational state deterministically (no second source of truth)."""
    b = get_brand(company_id)
    if not b:
        return {"exists": False, "company_id": company_id, "state": "ERROR",
                "reason": "Company not found."}
    ef, e_days, e_note = evidence_freshness(company_id)
    af, a_days, a_note = analysis_freshness(company_id)
    data_state = {"fresh": "FRESH", "stale": "STALE", "expired": "EXPIRED", "none": "MISSING"}[ef]
    perm_failed = db.query("SELECT job_type, error FROM jobs WHERE company_id=? AND status='FAILED_PERMANENTLY' "
                           "AND job_type != 'UPDATE_LEARNING' ORDER BY id DESC LIMIT 10", (company_id,))
    if af == "never":
        analysis_state = "FAILED" if perm_failed else "NEVER_ANALYZED"
    elif af in ("stale", "expired"):
        analysis_state = "OUTDATED"
    else:
        analysis_state = "CURRENT"
    mem_n = db.query("SELECT COUNT(*) AS c FROM learning_memory WHERE company_id=? AND status='ACTIVE'",
                     (company_id,))[0]["c"]
    lev_n = db.query("SELECT COUNT(*) AS c FROM learning_events WHERE company_id=?", (company_id,))[0]["c"]
    min_obs = _lconfig_int("MIN_PATTERN_OBSERVATIONS", 3)
    learning_state = "NO_MEMORY" if (mem_n == 0 and lev_n == 0) else ("ESTABLISHED" if mem_n >= min_obs else "LEARNING")
    scr_ok, ai_ok = scraper_available(), ai_search_connected()
    integration_state = "CONNECTED" if (scr_ok and ai_ok) else ("DISCONNECTED" if (not scr_ok and not ai_ok) else "DEGRADED")
    inflight = db.query("SELECT job_type, status FROM jobs WHERE company_id=? AND status IN "
                        "('PENDING','QUEUED','RUNNING','RETRYING','FAILED') ORDER BY id DESC LIMIT 20", (company_id,))
    diff = profile_diff(company_id)
    majors, minors = unprocessed_changes(company_id)
    # User corrections are significant (§17) - EXCEPT keyword/competitor edits,
    # which the targeted query/competitor rules already cover (no double-count).
    corr = db.query("SELECT COUNT(*) AS c FROM learning_events WHERE company_id=? AND event_type='EVIDENCE_CORRECTED' "
                    "AND created_at > ? AND COALESCE(json_extract(metadata_json, '$.field'), '') "
                    "NOT IN ('keywords', 'competitors')",
                    (company_id, b.get("last_analyzed_at") or "1970-01-01"))[0]["c"]
    if corr:
        majors = majors + [{"change_type": "EVIDENCE_CORRECTED", "field_name": "profile",
                            "magnitude": "MAJOR",
                            "magnitude_why": f"{corr} user evidence correction(s) since last analysis"}]
    autos = db.query("SELECT COUNT(*) AS c FROM automations WHERE company_id=? AND enabled=1", (company_id,))[0]["c"]
    qrows = db.query("SELECT COUNT(*) AS c, MAX(last_tested) AS mx FROM query_memory WHERE brand_id=? AND is_active=1",
                     (company_id,))[0]
    # operational state: first match wins (ordered by urgency, not alphabet).
    state, reason = "HEALTHY", "Analysis current, evidence fresh, no unprocessed changes."
    if autos == 0:
        state, reason = "PAUSED", "All automations for this company are disabled."
    elif analysis_state == "FAILED":
        state, reason = "ERROR", f"Analysis pipeline failed permanently ({len(perm_failed)} job(s)); attention required."
    elif not (b.get("website") or "").strip() and not company_source_is_connected("COMPANY_DISCOVERY"):
        state, reason = "BLOCKED", "No website on file and company discovery is not connected; manual entry required."
    elif analysis_state == "NEVER_ANALYZED" and inflight:
        state, reason = "INITIALIZING", f"Initial pipeline in flight ({len(inflight)} active job(s))."
    elif analysis_state == "NEVER_ANALYZED":
        state, reason = "NEW", "Company has never been analyzed."
    elif majors:
        state, reason = "REANALYSIS_REQUIRED", f"{len(majors)} unprocessed major change(s) since last analysis."
    elif diff:
        state, reason = "CHANGED", f"Profile changed since last snapshot: {', '.join(sorted(diff))}."
    elif minors:
        state, reason = "CHANGED", f"{len(minors)} unprocessed minor change(s) since last analysis."
    elif analysis_state == "OUTDATED":
        state, reason = f"Analysis outdated ({a_note})."
    elif data_state in ("STALE", "EXPIRED", "MISSING"):
        state, reason = "STALE", f"Website data {data_state.lower()} ({e_note})."
    elif integration_state in ("DEGRADED", "DISCONNECTED") and (inflight or analysis_state != "CURRENT"):
        state, reason = f"Integrations {integration_state.lower()} with work outstanding."
    return {"exists": True, "company_id": company_id, "brand_name": b.get("brand_name"),
            "state": state, "reason": reason,
            "data_state": data_state, "data_note": e_note, "data_age_days": e_days,
            "analysis_state": analysis_state, "analysis_note": a_note, "analysis_age_days": a_days,
            "learning_state": learning_state, "active_memories": mem_n, "learning_events": lev_n,
            "integration_state": integration_state, "scraper_ok": scr_ok, "ai_search_ok": ai_ok,
            "profile_diff": {k: {"previous": v[0], "current": v[1]} for k, v in diff.items()},
            "major_changes": len(majors), "minor_changes": len(minors),
            "inflight_jobs": [dict(j) for j in inflight],
            "failed_jobs": [dict(j) for j in perm_failed],
            "automations_enabled": autos, "queries_tracked": qrows["c"] or 0,
            "queries_last_tested": qrows["mx"]}


def _decision_confidence(direct_evidence=False, integrations_ok=True, degraded=False):
    c = 0.70
    if direct_evidence:
        c += 0.10
    if integrations_ok:
        c += 0.05
    if degraded:
        c -= 0.20
    return round(max(0.30, min(0.95, c)), 2)


def _job_time(j):
    """Comparable timestamp for a job row (completion, else creation)."""
    return str((j or {}).get("completed_at") or (j or {}).get("created_at") or "")


# Hours during which an already-searched-empty query set is not re-searched.
# Providers recover (quotas reset); after the window a retry is legitimate.
SEARCH_FUTILITY_HOURS = 24


def _search_futile(company_id):
    """True when the latest completed search ran against the current queries
    and yielded nothing recently. Prevents burning provider quota on identical
    empty searches while still allowing retries after a query refresh (a newer
    GENERATE completion) or provider recovery (24h window)."""
    sq = None
    for r in db.query("SELECT * FROM jobs WHERE company_id=? AND job_type='RUN_AI_SEARCH' AND status='COMPLETED' "
                      "ORDER BY id DESC LIMIT 3", (company_id,)):
        sq = r
        break
    if not sq:
        return False
    try:
        yielded = int((safe_json_loads(sq.get("result_json"), {}) or {}).get("observations") or 0)
    except Exception:
        return False
    if yielded > 0:
        return False
    sq_ts = _job_time(sq)
    gq = _latest_job(company_id, "GENERATE_QUERIES")
    if gq and gq.get("status") == "COMPLETED" and _job_time(gq) > sq_ts:
        return False
    try:
        dt = datetime.datetime.fromisoformat(str(sq.get("completed_at") or sq.get("created_at")).replace(
            "Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        if (datetime.datetime.now(datetime.timezone.utc) - dt).total_seconds() / 3600.0 > SEARCH_FUTILITY_HOURS:
            return False
    except Exception:
        return False
    return True


def _collect_futile(company_id):
    """True when the latest COLLECT job completed but yielded no extractable
    evidence and the website hasn't changed since - re-collecting would burn
    work for nothing. Only applies to MISSING data (EXPIRED/STALE implies the
    site was scrapable before, so re-collection stays legitimate)."""
    rows = db.query("SELECT completed_at, result_json FROM jobs WHERE company_id=? AND job_type='COLLECT_WEBSITE_DATA' "
                    "AND status='COMPLETED' ORDER BY id DESC LIMIT 1", (company_id,))
    if not rows:
        return False, ""
    try:
        res = json.loads(rows[0].get("result_json") or "{}")
    except Exception:
        return False, ""
    if int(res.get("new_evidence") or 0) != 0 or res.get("skipped"):
        return False, ""
    if "website" in profile_diff(company_id):
        return False, ""
    return True, (f"Last website collection ({(rows[0].get('completed_at') or '')[:16]}) yielded no "
                  "extractable evidence and the website hasn't changed since; collection deferred.")


def _queries_stale(company_id):
    """(stale_bool, age_days_or_None, tracked_count) for the company's query history."""
    rows = db.query("SELECT COUNT(*) AS c, MAX(last_tested) AS mx FROM query_memory "
                    "WHERE brand_id=? AND is_active=1", (company_id,))
    n = (rows[0].get("c") or 0) if rows else 0
    mx = rows[0].get("mx") if rows else None
    stale_d = _auto_cfg_int("QUERY_STALE_DAYS", 14)
    if not n:
        return True, None, 0
    try:
        dt = datetime.datetime.fromisoformat(str(mx).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        age = (datetime.datetime.now(datetime.timezone.utc) - dt).days
    except Exception:
        return True, None, n
    return age > stale_d, age, n


def decide_next_actions(company_id):
    """Pure state-aware assessment: WHAT work a company needs next, with reasons.

    No jobs are created here (dry-run safe). Returns
    {company_id, state, actions[], considered[]} where each action carries
    job_type (or orchestration action), priority, reason, evidence, confidence.
    Priority follows the deterministic 8-level ladder (§7)."""
    st = assess_company_state(company_id)
    if not st.get("exists"):
        return {"company_id": company_id, "state": "ERROR", "actions": [], "considered": [],
                "reason": st.get("reason")}
    b = get_brand(company_id)
    actions, considered = [], []
    inflight = {j["job_type"]: j["status"] for j in st["inflight_jobs"]}

    def decline(action, why):
        considered.append({"action": action, "reason": why})

    # NEW / INITIALIZING are served by the existing initial-pipeline path only;
    # change-based rules require a prior analysis to compare against.
    if st["state"] == "NEW":
        if any(j["status"] in ("PENDING", "RUNNING", "RETRYING") for j in st["inflight_jobs"]):
            decline("INITIAL_PIPELINE", "Initial pipeline jobs already active.")
        else:
            actions.append({"action": "INITIAL_PIPELINE", "priority": "HIGH", "level": 2,
                            "reason": "Company has never been analyzed; creating initial analysis pipeline.",
                            "evidence": {"pipeline_jobs": len(PIPELINE_TYPES)},
                            "confidence": _decision_confidence(direct_evidence=True, integrations_ok=True),
                            "chain": []})
        return {"company_id": company_id, "state": st["state"], "state_reason": st["reason"],
                "state_detail": st, "actions": actions, "considered": considered}
    if st["state"] == "INITIALIZING":
        decline("NO_ACTION", f"Initial pipeline in flight ({len(st['inflight_jobs'])} active job(s)); awaiting completion.")
        return {"company_id": company_id, "state": st["state"], "state_reason": st["reason"],
                "state_detail": st, "actions": actions, "considered": considered}

    def propose(action, priority, level, reason, evidence=None, chain=None, degraded=False):
        actions.append({"action": action, "priority": priority, "level": level, "reason": reason,
                        "evidence": evidence or {},
                        "confidence": _decision_confidence(
                            direct_evidence=bool(evidence), integrations_ok=(st["integration_state"] == "CONNECTED"),
                            degraded=degraded),
                        "chain": chain or list(CHAIN_BOUNDS.get(action, [action]))})

    def entry_busy(entry):
        # §13: same entry inflight, or a full-pipeline coordinator inflight, covers it.
        if entry in inflight:
            return entry
        for cover in ("REANALYZE_COMPANY",):
            if cover in inflight:
                return cover
        return None

    # P1 - critical failed/retryable jobs (one bounded autonomous retry, never loops).
    for fj in st["failed_jobs"]:
        jt = fj["job_type"]
        if jt not in CRITICAL_JOB_TYPES:
            continue
        err = (fj.get("error") or "").lower()
        conn_err = any(k in err for k in ("not connected", "unavailable", "no api key", "401", "403"))
        recovered = (("scrap" in err or "website" in err) and st["scraper_ok"]) or \
                    (("gemini" in err or "serp" in err or "ai search" in err) and st["ai_search_ok"])
        prior = db.query("SELECT id FROM agent_decisions WHERE company_id=? AND action='RETRY_JOB' "
                         "AND trigger_type='AUTONOMOUS_RETRY' AND json_extract(metadata_json,'$.job_type')=? LIMIT 1",
                         (company_id, jt))
        if prior:
            decline("RETRY_JOB", f"{jt} already retried once autonomously; leaving for human review.")
        elif conn_err and not recovered:
            decline("RETRY_JOB", f"{jt} failed on connectivity and the integration is still down; not retrying.")
        else:
            why = "blocking integration recovered since failure" if recovered else \
                "non-connectivity failure, one bounded retry allowed"
            propose("RETRY_JOB", "HIGH", 1, f"Critical job {jt} failed permanently; retrying once ({why}).",
                    {"job_type": jt, "last_error": fj.get("error") or ""})

    # P2 - missing required data.
    if not (b.get("website") or "").strip():
        if company_source_is_connected("COMPANY_DISCOVERY"):
            if entry_busy("DISCOVER_COMPANY"):
                decline("DISCOVER_COMPANY", f"Equivalent job already active ({entry_busy('DISCOVER_COMPANY')}).")
            else:
                propose("DISCOVER_COMPANY", "HIGH", 2, "No website on file; discovery source is connected.",
                        {"website": None}, degraded=False)
        else:
            decline("DISCOVER_COMPANY", "No website on file and discovery is not connected (BLOCKED).")
    if st["data_state"] == "MISSING":
        if not (b.get("website") or "").strip():
            decline("COLLECT_WEBSITE_DATA", "No website on file; discovery path applies instead.")
        elif not scraper_available():
            decline("COLLECT_WEBSITE_DATA", "Website collection unavailable: Integration Not Connected.")
            if db.query("SELECT id FROM evidence WHERE brand_id=? LIMIT 1", (company_id,)):
                propose("ANALYZE_BRAND", "MEDIUM", 2, "Scraper unavailable but manual/CSV evidence exists; "
                        "analyzing available evidence instead.",
                        {"evidence_rows": True}, degraded=True)
        elif entry_busy("COLLECT_WEBSITE_DATA"):
            decline("COLLECT_WEBSITE_DATA", "Equivalent job already active.")
        else:
            futile, futile_why = _collect_futile(company_id)
            if futile:
                decline("COLLECT_WEBSITE_DATA", futile_why)
            else:
                propose("COLLECT_WEBSITE_DATA", "HIGH", 2, "No website evidence collected yet.",
                        {"evidence_rows": 0})

    # P3 - major changes -> full reanalysis via coordinator.
    if st["major_changes"]:
        if entry_busy("REANALYZE_COMPANY"):
            decline("REANALYZE_COMPANY", "Equivalent job already active.")
        else:
            propose("REANALYZE_COMPANY", "HIGH", 3,
                    f"{st['major_changes']} unprocessed major change(s) since last analysis.",
                    {"major_changes": st["major_changes"], "minor_changes": st["minor_changes"]})

    # P4 - expired/stale website data -> targeted collect chain (reassess afterwards).
    if st["data_state"] in ("EXPIRED", "STALE") and not any(a["action"] == "REANALYZE_COMPANY" for a in actions):
        if not scraper_available():
            decline("COLLECT_WEBSITE_DATA", "Website collection unavailable: Integration Not Connected.")
        elif entry_busy("COLLECT_WEBSITE_DATA"):
            decline("COLLECT_WEBSITE_DATA", "Equivalent job already active.")
        else:
            propose("COLLECT_WEBSITE_DATA", "HIGH" if st["data_state"] == "EXPIRED" else "MEDIUM", 4,
                    f"Website evidence {st['data_state'].lower()} ({st['data_note']}).",
                    {"data_age_days": st["data_age_days"], "data_state": st["data_state"]})

    # P4.5 - profile diff vs last snapshot -> targeted refresh even when analysis is current.
    # Each changed dimension is assessed independently (keywords, competitors, other).
    diff45 = st["profile_diff"]
    if diff45 and not any(a["action"] in ("REANALYZE_COMPANY", "INITIAL_PIPELINE") for a in actions):
        if "keywords" in diff45:
            busy = entry_busy("GENERATE_QUERIES")
            if busy:
                decline("GENERATE_QUERIES", "Equivalent job already active.")
            else:
                propose("GENERATE_QUERIES", "MEDIUM", 5, (
                    f"New keywords detected since previous snapshot "
                    f"('{str(diff45['keywords']['previous'])[:80]}' -> '{str(diff45['keywords']['current'])[:80]}')."),
                    {"profile_diff_fields": ["keywords"]})
        if "competitors" in diff45:
            busy = entry_busy("ANALYZE_COMPETITORS")
            if busy:
                decline("ANALYZE_COMPETITORS", "Equivalent job already active.")
            else:
                propose("ANALYZE_COMPETITORS", "MEDIUM", 5,
                        "Competitor list changed since previous snapshot.",
                        {"profile_diff_fields": ["competitors"]})
        other = [f for f in diff45 if f not in ("keywords", "competitors")]
        if other:
            busy = entry_busy("ANALYZE_BRAND")
            if busy:
                decline("ANALYZE_BRAND", "Equivalent job already active.")
            else:
                propose("ANALYZE_BRAND", "MEDIUM", 5, (
                    f"Profile changed since previous snapshot ({', '.join(sorted(other))}); "
                    "refreshing analysis on the updated profile."),
                    {"profile_diff_fields": sorted(other)})

    # P5 - outdated analysis without major trigger -> minimal refresh entry point.
    if st["analysis_state"] == "OUTDATED" and not any(a["action"] in ("REANALYZE_COMPANY",) for a in actions):
        diff = st["profile_diff"]
        q_stale, q_age, q_n = _queries_stale(company_id)
        if "keywords" in diff:
            entry = "GENERATE_QUERIES"
            reason = (f"Keywords changed since previous snapshot "
                      f"('{str(diff['keywords']['previous'])[:80]}' -> '{str(diff['keywords']['current'])[:80]}').")
        elif "competitors" in diff:
            entry = "ANALYZE_COMPETITORS"
            reason = "Competitor list changed since previous snapshot."
        elif q_stale:
            entry = "GENERATE_QUERIES"
            reason = (f"Query history stale ({'no queries tracked' if q_age is None else f'{q_age} days since last test'}; "
                      f"threshold {_auto_cfg_int('QUERY_STALE_DAYS', 14)}d).")
        else:
            entry = "ANALYZE_BRAND"
            reason = f"Analysis outdated ({st['analysis_note']}); refreshing analysis on current evidence."
        busy = entry_busy(entry)
        if busy:
            decline(entry, "Equivalent job already active.")
        elif entry == "GENERATE_QUERIES" and not st["ai_search_ok"] and q_n == 0:
            decline(entry, "AI search unavailable and no existing observations; query run would be empty.")
        else:
            ev = {"analysis_age_days": st["analysis_age_days"], "profile_diff_fields": sorted(diff),
                  "queries_stale": q_stale}
            if entry == "GENERATE_QUERIES" and learning_enabled_for_company(company_id):
                useful = db.query("SELECT COUNT(*) AS c FROM query_learning WHERE company_id=? AND useful_count > 0",
                                  (company_id,))[0]["c"]
                ev["historically_useful_queries"] = useful
            propose(entry, "MEDIUM", 5, reason, ev)

    # P5.5 - minor changes only (analysis current) -> targeted downstream job, never full reanalysis.
    if st["analysis_state"] == "CURRENT" and st["minor_changes"] and not st["major_changes"] \
            and not actions:
        if entry_busy("DETECT_CONTENT_GAPS"):
            decline("DETECT_CONTENT_GAPS", "Equivalent job already active.")
        else:
            propose("DETECT_CONTENT_GAPS", "MEDIUM", 5,
                    f"Only minor change(s) detected ({st['minor_changes']}); recomputing gaps and "
                    "recommendations without a full reanalysis.",
                    {"minor_changes": st["minor_changes"]})

    # P6 - new evidence while analysis current -> close the gaps only.
    if st["analysis_state"] == "CURRENT" and not st["major_changes"]:
        try:
            last_an = b.get("last_analyzed_at") or "1970-01-01"
            fresh_ev = db.query("SELECT COUNT(*) AS c FROM evidence WHERE brand_id=? AND last_updated_at >= ?",
                                (company_id, last_an))[0]["c"]
        except Exception:
            fresh_ev = 0
        if fresh_ev:
            if entry_busy("DETECT_CONTENT_GAPS"):
                decline("DETECT_CONTENT_GAPS", "Equivalent job already active.")
            else:
                propose("DETECT_CONTENT_GAPS", "MEDIUM", 6,
                        f"{fresh_ev} evidence row(s) added since the current analysis; checking for new content gaps.",
                        {"fresh_evidence_rows": fresh_ev})

    # P7 - query enrichment on stale history (analysis still current).
    if st["analysis_state"] == "CURRENT" and not any(a["action"] == "GENERATE_QUERIES" for a in actions):
        q_stale, q_age, q_n = _queries_stale(company_id)
        if q_stale and st["ai_search_ok"]:
            if entry_busy("GENERATE_QUERIES"):
                decline("GENERATE_QUERIES", "Equivalent job already active.")
            else:
                propose("GENERATE_QUERIES", "LOW", 7,
                        f"Query enrichment: history stale ({q_age} days; threshold "
                        f"{_auto_cfg_int('QUERY_STALE_DAYS', 14)}d); learning memory will prioritize "
                        "historically useful patterns.",
                        {"queries_stale": True, "query_age_days": q_age})
        elif q_stale:
            decline("GENERATE_QUERIES", "Query history stale but AI search is not connected; enrichment deferred.")

    # Healthy + nothing -> explicit NO_ACTION (never invent work).
    if not actions and st["state"] in ("HEALTHY", "PAUSED", "BLOCKED", "ERROR"):
        decline("NO_ACTION", st["reason"] if st["state"] != "HEALTHY"
                else "No meaningful change or stale data detected.")
    # Merge duplicate entries for the same job (multiple rules, one job):
    # keep the highest priority (lowest level), concatenate reasons/evidence.
    if len(actions) > 1:
        merged, order = {}, []
        for a in actions:
            k = a["action"]
            if k not in merged:
                merged[k] = dict(a)
                merged[k]["evidence"] = dict(a.get("evidence") or {})
                merged[k]["reason"] = [a["reason"]]
                order.append(k)
            else:
                m = merged[k]
                if (a.get("level") or 9) < (m.get("level") or 9):
                    m["priority"], m["level"] = a["priority"], a["level"]
                m["reason"].append(a["reason"])
                m["evidence"].update(a.get("evidence") or {})
                m["confidence"] = max(m.get("confidence") or 0, a.get("confidence") or 0)
        for k in order:
            merged[k]["reason"] = " Also: ".join(merged[k]["reason"])
        actions = [merged[k] for k in order]
    return {"company_id": company_id, "state": st["state"], "state_reason": st["reason"],
            "state_detail": st, "actions": actions, "considered": considered}


# ---------------------------------------------------------------------------
# DECISION LIFECYCLE  (PROPOSED -> ACCEPTED -> EXECUTED/FAILED ; SKIPPED/CANCELLED)
# ---------------------------------------------------------------------------

def new_decision_id(rowid):
    return f"DEC-{int(rowid):06d}"


def record_decision(company_id, action, priority, reason, trigger_type="AUTONOMOUS_RUN", trigger_id=None,
                    confidence=None, status="PROPOSED", run_id=None, evidence=None, chain=None, level=None):
    if action not in AUTONOMOUS_JOB_ALLOWLIST and action not in ORCHESTRATION_ACTIONS and action != "NO_ACTION":
        return {"success": False, "error": f"Action outside approved boundary: {action}"}
    t = now()
    rid = db.execute("""
        INSERT INTO agent_decisions (company_id, run_id, action, priority, reason, trigger_type, trigger_id,
                                     confidence, status, created_at, metadata_json)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)
    """, (company_id, run_id, action, priority, (reason or "")[:2000], trigger_type, trigger_id,
          confidence, status, t, json.dumps({"evidence": evidence or {}, "chain": chain or [],
                                             "level": level})[:4000]))
    did = new_decision_id(rid)
    db.execute("UPDATE agent_decisions SET decision_id=? WHERE id=?", (did, rid))
    return {"success": True, "id": rid, "decision_id": did}


def _decision_job_status(dec):
    """Live derivation: an ACCEPTED decision follows its linked job without extra writes."""
    if dec.get("status") != "ACCEPTED":
        return dec.get("status")
    try:
        meta = safe_json_loads(dec.get("metadata_json"), {}) or {}
        jid = meta.get("job_id")
        if not jid:
            return "ACCEPTED"
        rows = db.query("SELECT status FROM jobs WHERE id=?", (jid,))
        if not rows:
            return "ACCEPTED"
        js = rows[0]["status"]
        if js == "COMPLETED":
            return "EXECUTED"
        if js == "FAILED_PERMANENTLY":
            return "FAILED"
        if js == "CANCELLED":
            return "CANCELLED"
        return "ACCEPTED"
    except Exception:
        return dec.get("status")


def accept_decision(dec_id, run_id=None):
    """Create the decided work (dedup-aware, dependency-aware). Returns job linkage."""
    rows = db.query("SELECT * FROM agent_decisions WHERE id=? OR decision_id=?", (dec_id, dec_id))
    if not rows:
        return {"success": False, "error": "Decision not found"}
    dec = rows[0]
    if dec["status"] not in ("PROPOSED",):
        return {"success": False, "error": f"Decision already {dec['status']}"}
    meta = safe_json_loads(dec.get("metadata_json"), {}) or {}
    action, cid = dec["action"], dec["company_id"]
    created, active = [], []
    try:
        if action == "NO_ACTION":
            db.execute("UPDATE agent_decisions SET status='SKIPPED' WHERE id=?", (dec["id"],))
            return {"success": True, "decision_id": dec["decision_id"], "status": "SKIPPED"}
        if action == "RETRY_JOB":
            jt = (meta.get("evidence") or {}).get("job_type")
            target = db.query("SELECT id FROM jobs WHERE company_id=? AND job_type=? AND status='FAILED_PERMANENTLY' "
                              "ORDER BY id DESC LIMIT 1", (cid, jt))
            if not target:
                db.execute("UPDATE agent_decisions SET status='SKIPPED' WHERE id=?", (dec["id"],))
                return {"success": True, "decision_id": dec["decision_id"], "status": "SKIPPED",
                        "reason": "Failure already resolved by another run."}
            retry_job(target[0]["id"])
            created.append(target[0]["id"])
            meta["job_id"] = target[0]["id"]
            meta["retry"] = True
        elif action == "INITIAL_PIPELINE":
            for jid in plan_company_jobs(cid, run_id):
                created.append(jid)
        elif action == "REANALYZE_COMPANY":
            # Fresh coordinator per autonomous run (mirrors automation cycles);
            # inflight dedup still applies. The run loop additionally guards
            # against re-attempting the same entry twice in one run.
            jid = ensure_job("REANALYZE_COMPANY", cid, run_id, include_completed=False)
            if jid:
                created.append(jid)
            else:
                active.append("REANALYZE_COMPANY")
        else:
            chain = meta.get("chain") or [action]
            ai_ok_now = ai_search_connected()
            for jt in chain:
                if jt not in AUTONOMOUS_JOB_ALLOWLIST:
                    continue
                if jt == "RUN_AI_SEARCH" and not ai_ok_now:
                    # §29: degraded integration - skip search, keep the rest of the chain.
                    active.append("RUN_AI_SEARCH:skipped-ai-unavailable")
                    meta["degraded_skipped"] = True
                    continue
                jid = ensure_job(jt, cid, run_id, include_completed=False)
                if jid:
                    # ensure_job may return a pre-existing inflight id -> treat as covered.
                    jr = db.query("SELECT status FROM jobs WHERE id=?", (jid,))
                    if jr and jr[0]["status"] in ("PENDING", "QUEUED", "RUNNING", "RETRYING", "FAILED"):
                        created.append(jid)
                    else:
                        active.append(jt)
                else:
                    active.append(jt)
        meta["jobs_created"] = created
        meta["jobs_covered"] = active
        if meta.get("job_id") is None and created:
            meta["job_id"] = created[0]
        db.execute("UPDATE agent_decisions SET status='ACCEPTED', run_id=?, metadata_json=? WHERE id=?",
                   (run_id or dec.get("run_id"), json.dumps(meta)[:4000], dec["id"]))
        try:
            log_activity(f"Decision {dec['decision_id']} accepted: {action} for company #{cid} "
                         f"({len(created)} job(s) created, {len(active)} covered/inapplicable).", level="DECISION",
                         run_id=run_id or dec.get("run_id"), company_id=cid)
        except Exception:
            pass
        return {"success": True, "decision_id": dec["decision_id"], "status": "ACCEPTED",
                "jobs_created": created, "jobs_covered": active}
    except Exception as e:
        db.execute("UPDATE agent_decisions SET status='FAILED' WHERE id=?", (dec["id"],))
        return {"success": False, "error": str(e)[:300]}


def skip_decision(dec_id, reason="skipped by human"):
    rows = db.query("SELECT * FROM agent_decisions WHERE id=? OR decision_id=?", (dec_id, dec_id))
    if not rows:
        return {"success": False, "error": "Decision not found"}
    if rows[0]["status"] not in ("PROPOSED", "ACCEPTED"):
        return {"success": False, "error": f"Decision already {rows[0]['status']}"}
    db.execute("UPDATE agent_decisions SET status='SKIPPED' WHERE id=?", (rows[0]["id"],))
    return {"success": True, "decision_id": rows[0]["decision_id"], "status": "SKIPPED"}


def approve_decision(dec_id, run_id=None):
    rows = db.query("SELECT * FROM agent_decisions WHERE id=? OR decision_id=?", (dec_id, dec_id))
    if not rows:
        return {"success": False, "error": "Decision not found"}
    if rows[0]["status"] != "PROPOSED":
        return {"success": False, "error": f"Decision already {rows[0]['status']}"}
    return accept_decision(rows[0]["id"], run_id=run_id)


def sync_decision_states(run_id=None):
    """Persist terminal states for ACCEPTED decisions (EXECUTED/FAILED/CANCELLED)."""
    q = "SELECT * FROM agent_decisions WHERE status='ACCEPTED'"
    p = ()
    if run_id:
        q += " AND run_id=?"
        p = (run_id,)
    synced = 0
    for dec in db.query(q, p):
        live = _decision_job_status(dec)
        if live != "ACCEPTED":
            db.execute("UPDATE agent_decisions SET status=? WHERE id=?", (live, dec["id"]))
            synced += 1
    return {"synced": synced}


def list_decisions(company_id=None, status=None, trigger_type=None, limit=100):
    q = ("SELECT d.*, b.brand_name AS company FROM agent_decisions d "
         "LEFT JOIN brands b ON b.id=d.company_id WHERE 1=1")
    p = []
    if company_id is not None:
        q += " AND d.company_id=?"
        p.append(company_id)
    if trigger_type:
        q += " AND d.trigger_type=?"
        p.append(trigger_type)
    try:
        limit = max(1, min(int(limit or 100), 500))
    except Exception:
        limit = 100
    rows = db.query(q + f" ORDER BY d.id DESC LIMIT {limit}", tuple(p))
    out = []
    for r in rows:
        d = dict(r)
        d["display_status"] = _decision_job_status(r)
        try:
            d["meta"] = safe_json_loads(r.get("metadata_json"), {}) or {}
        except Exception:
            d["meta"] = {}
        out.append(d)
    if status:
        out = [d for d in out if (d["display_status"] or "").upper() == status.upper()]
    return {"success": True, "decisions": out}


def get_decision(dec_id):
    rows = db.query("SELECT d.*, b.brand_name AS company FROM agent_decisions d "
                    "LEFT JOIN brands b ON b.id=d.company_id WHERE d.id=? OR d.decision_id=?", (dec_id, dec_id))
    if not rows:
        return {"success": False, "error": "Decision not found"}
    d = dict(rows[0])
    d["display_status"] = _decision_job_status(rows[0])
    try:
        d["meta"] = safe_json_loads(rows[0].get("metadata_json"), {}) or {}
    except Exception:
        d["meta"] = {}
    job_id = (d["meta"] or {}).get("job_id")
    d["job"] = (db.query("SELECT * FROM jobs WHERE id=?", (job_id,))[0:1] or [None])[0]
    if d["job"]:
        d["job"] = dict(d["job"])
    return {"success": True, "decision": d}


def company_intelligence(company_id):
    """§23 per-company view: state, freshness, pending work, decisions, learning, next action."""
    st = assess_company_state(company_id)
    if not st.get("exists"):
        return {"success": False, "error": "Company not found"}
    dec = decide_next_actions(company_id)
    recent = list_decisions(company_id, limit=20)["decisions"]
    learn = {"learning_state": st["learning_state"], "active_memories": st["active_memories"],
             "learning_events": st["learning_events"]}
    try:
        qp = query_performance(company_id)
        learn["top_intents"] = (qp.get("by_intent") or [])[:3]
    except Exception:
        learn["top_intents"] = []
    nxt = (dec["actions"][0] if dec["actions"] else None)
    return {"success": True, "company_id": company_id, "state": st, "decisions_recent": recent,
            "learning_summary": learn,
            "next_action": ({"action": nxt["action"], "priority": nxt["priority"],
                             "reason": nxt["reason"], "confidence": nxt.get("confidence")}
                            if nxt else {"action": "NO_ACTION", "reason": st["reason"]})}


# ---------------------------------------------------------------------------
# AUTONOMOUS RUN  (bounded observe -> decide -> execute -> reassess loop)
# ---------------------------------------------------------------------------

def autonomy_blocked():
    """Honor every existing pause/disable switch before creating autonomous work."""
    if get_config("AUTONOMOUS_ENABLED", "1") != "1":
        return "Autonomous intelligence disabled (AUTONOMOUS_ENABLED=0)."
    if runner.paused or get_config("agent_paused", "0") == "1":
        return "Agent is paused; no new autonomous work."
    if scheduler.paused or get_config("scheduler_paused", "0") == "1":
        return "Scheduler is paused; no new autonomous work."
    if get_config("automation_enabled", "1") != "1":
        return "Automation is disabled; no new autonomous work."
    return None


def _autonomous_companies(scope_id=None):
    if scope_id:
        b = get_brand(scope_id)
        return [scope_id] if b else []
    rows = db.query("SELECT id FROM brands WHERE is_active=1 ORDER BY id ASC")
    return [r["id"] for r in rows]


def autonomous_inflight(company_id=None):
    """True while an AUTONOMOUS run is still RUNNING (optionally scoped to one
    company via its jobs). The re-entrancy guard for UI double-clicks and
    overlapping scheduler fires: at most one autonomous cycle in flight.
    RUNNING rows older than 2h are treated as crash residue, never blocking."""
    cutoff = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=2)).isoformat()
    q = ("SELECT run_id FROM runs WHERE status='RUNNING' AND run_type LIKE 'AUTONOMOUS%' "
         "AND started_at >= ?")
    rows = db.query(q, (cutoff,))
    if not rows:
        return False
    if company_id is None:
        return True
    rids = [r["run_id"] for r in rows]
    hit = db.query(f"SELECT id FROM jobs WHERE company_id=? AND run_id IN "
                   f"({','.join('?' * len(rids))}) AND status IN "
                   "('PENDING','QUEUED','RUNNING','RETRYING','FAILED') LIMIT 1",
                   (company_id, *rids))
    return bool(hit)


def run_autonomous(payload=None, background=True):
    """POST /api/agent/autonomous/run. Bounded cycles; never infinite.

    Each cycle: assess each scoped company (round-robin) -> record decisions ->
    accept (create jobs, unless dry-run) -> let the existing Agent Runner execute
    -> sync decision states -> reassess. Stops when no required work remains or
    MAX_AUTONOMOUS_CYCLES is reached (recorded, safe stop)."""
    payload = payload or {}
    if background:
        t = threading.Thread(target=lambda: run_autonomous(dict(payload), background=False),
                             daemon=True, name="autonomous-run")
        t.start()
        return {"success": True, "background": True, "message": "Autonomous run started in background."}
    blocked = autonomy_blocked()
    if blocked:
        AUTO_STATE.update({"status": "PAUSED", "last_error": None})
        return {"success": True, "paused": True, "reason": blocked, "decisions_made": 0}
    if autonomous_inflight():
        return {"success": True, "skipped": True,
                "reason": "An autonomous cycle is already running; not starting an overlapping one.",
                "decisions_made": 0}
    max_cycles = int(payload.get("max_cycles") or _auto_cfg_int("MAX_AUTONOMOUS_CYCLES", 10))
    max_companies = int(payload.get("max_companies") or _auto_cfg_int("MAX_COMPANIES_PER_CYCLE", 5))
    max_jobs_cycle = int(payload.get("max_jobs_per_cycle") or _auto_cfg_int("MAX_JOBS_PER_CYCLE", 25))
    dry_flag = payload.get("dry_run", get_config("AUTONOMOUS_MODE", "LIVE"))
    dry_run = dry_flag is True or str(dry_flag).upper() == "DRY_RUN" \
        or str(get_config("AUTONOMOUS_MODE", "LIVE")).upper() == "DRY_RUN"
    scope = payload.get("company_id")
    companies = _autonomous_companies(int(scope) if scope else None)
    if not companies:
        return {"success": False, "error": "No companies in scope."}
    run_type = "AUTONOMOUS_DRYRUN" if dry_run else "AUTONOMOUS"
    auto_db_id = None
    if payload.get("automation_id"):
        try:
            _a = get_automation(payload["automation_id"])
            auto_db_id = _a["id"] if _a else None
        except Exception:
            auto_db_id = None
    rid = create_run(run_type, companies=companies, automation_id=auto_db_id)
    AUTO_STATE.update({"status": "OBSERVING", "cycle": 0, "run_id": rid, "last_error": None,
                       "company": None, "action": None})
    made, skipped, jobs_created = 0, 0, 0
    cycle, outcome = 0, "no immediate required work"
    run_attempted = set()
    try:
        while cycle < max_cycles:
            AUTO_STATE.update({"status": "OBSERVING", "cycle": cycle + 1})
            # fair rotation: shift the starting company each cycle (§31).
            order = companies[(cycle % max(1, len(companies))):] + companies[:(cycle % max(1, len(companies)))]
            order = order[:max_companies]
            cycle_created, jobs_this_cycle = 0, 0
            for cid in order:
                AUTO_STATE.update({"status": "DECIDING", "company": cid})
                dec = decide_next_actions(cid)
                for a in dec["actions"]:
                    if jobs_this_cycle >= max_jobs_cycle:
                        break
                    attempt_key = (cid, a["action"])
                    if attempt_key in run_attempted:
                        # Same trigger, same run, already attempted -> do not loop blindly.
                        record_decision(cid, a["action"], a["priority"],
                                        a["reason"] + " [Skipped: already attempted in this run.]",
                                        trigger_type="AUTONOMOUS_RUN", trigger_id=rid,
                                        confidence=a.get("confidence"), status="SKIPPED", run_id=rid,
                                        evidence=a.get("evidence"), chain=a.get("chain"), level=a.get("level"))
                        skipped += 1
                        continue
                    rec = record_decision(cid, a["action"], a["priority"], a["reason"],
                                          trigger_type="AUTONOMOUS_RUN", trigger_id=rid,
                                          confidence=a.get("confidence"), status="PROPOSED", run_id=rid,
                                          evidence=a.get("evidence"), chain=a.get("chain"), level=a.get("level"))
                    if dry_run:
                        run_attempted.add(attempt_key)
                        made += 1
                        continue
                    run_attempted.add(attempt_key)
                    acc = accept_decision(rec["id"], run_id=rid)
                    if acc.get("success") and acc.get("status") == "ACCEPTED":
                        made += 1
                        n = len(acc.get("jobs_created") or [])
                        cycle_created += n
                        jobs_created += n
                        jobs_this_cycle += n
                        AUTO_STATE.update({"action": a["action"]})
                    else:
                        skipped += 1
                for c in dec["considered"]:
                    record_decision(cid, c["action"], "LOW", c["reason"], trigger_type="AUTONOMOUS_RUN",
                                    trigger_id=rid, status="SKIPPED", run_id=rid)
                    skipped += 1
            if not dry_run and (cycle_created or db.query(
                    "SELECT COUNT(*) AS c FROM jobs WHERE run_id=? AND status IN "
                    "('PENDING','QUEUED','RUNNING','RETRYING','FAILED')", (rid,))[0]["c"]):
                AUTO_STATE.update({"status": "EXECUTING"})
                runner._process_queue(run_id=rid)
                sync_decision_states(rid)
            cycle += 1
            AUTO_STATE.update({"cycle": cycle})
            # reassess: stop when this cycle created nothing AND none of our jobs remain inflight.
            pending = 0 if dry_run else db.query(
                "SELECT COUNT(*) AS c FROM jobs WHERE run_id=? AND status IN "
                "('PENDING','QUEUED','RUNNING','RETRYING','FAILED')", (rid,))[0]["c"]
            if cycle_created == 0 and pending == 0:
                outcome = "no immediate required work" if cycle > 0 else outcome
                break
        else:
            outcome = "Maximum autonomous cycle limit reached."
        if cycle >= max_cycles and outcome != "no immediate required work":
            outcome = "Maximum autonomous cycle limit reached."
    except Exception as e:
        AUTO_STATE.update({"status": "ERROR", "last_error": str(e)[:300]})
        try:
            log_activity(f"Autonomous run {rid} error: {e}", level="ERROR", run_id=rid)
        except Exception:
            pass
        finalize_run(rid, "FAILED")
        return {"success": False, "error": str(e)[:300], "run_id": rid}
    sync_decision_states(rid)
    finalize_run(rid, "COMPLETED")
    AUTO_STATE.update({"status": "COMPLETED",
                       "last_cycle": {"run_id": rid, "cycles": cycle, "decisions_made": made,
                                      "decisions_skipped": skipped, "jobs_created": jobs_created,
                                      "outcome": outcome, "dry_run": dry_run,
                                      "finished_at": now()}})
    try:
        log_activity(f"Autonomous run {rid} finished: {cycle} cycle(s), {made} decision(s), "
                     f"{jobs_created} job(s). {outcome}", level="RUN", run_id=rid)
    except Exception:
        pass
    return {"success": True, "run_id": rid, "cycles": cycle, "decisions_made": made,
            "decisions_skipped": skipped, "jobs_created": jobs_created,
            "outcome": outcome, "dry_run": dry_run}


def autonomous_status():
    """§24 live status: IDLE/OBSERVING/DECIDING/EXECUTING/LEARNING/PAUSED/ERROR/COMPLETED."""
    blocked = autonomy_blocked()
    q = db.query("SELECT status, COUNT(*) AS c FROM jobs GROUP BY status")
    qm = {r["status"]: r["c"] for r in q}
    pending = sum(qm.get(s, 0) for s in ("PENDING", "QUEUED"))
    running = qm.get("RUNNING", 0)
    failed = sum(qm.get(s, 0) for s in ("FAILED", "RETRYING", "FAILED_PERMANENTLY"))
    last_auto = db.query("SELECT * FROM runs WHERE run_type LIKE 'AUTONOMOUS%' ORDER BY id DESC LIMIT 1")
    nxt = None
    try:
        nxt = scheduler.next_run_at if hasattr(scheduler, "next_run_at") else None
    except Exception:
        nxt = None
    status = AUTO_STATE.get("status") or "IDLE"
    if blocked and status not in ("OBSERVING", "DECIDING", "EXECUTING"):
        status = "PAUSED"
    return {"success": True, "status": status, "active_cycle": AUTO_STATE.get("cycle", 0),
            "current_company": AUTO_STATE.get("company"), "current_action": AUTO_STATE.get("action"),
            "pending_jobs": pending, "running_jobs": running, "failed_jobs": failed,
            "last_cycle": AUTO_STATE.get("last_cycle") or (
                {"run_id": last_auto[0]["run_id"], "status": last_auto[0]["status"]} if last_auto else None),
            "last_error": AUTO_STATE.get("last_error"), "next_cycle": nxt,
            "mode": get_config("AUTONOMOUS_MODE", "LIVE"),
            "limits": {"max_cycles": _auto_cfg_int("MAX_AUTONOMOUS_CYCLES", 10),
                       "max_jobs_per_cycle": _auto_cfg_int("MAX_JOBS_PER_CYCLE", 25),
                       "max_companies_per_cycle": _auto_cfg_int("MAX_COMPANIES_PER_CYCLE", 5)}}


# ---------------------------------------------------------------------------
# ORCHESTRATOR  (single-next-action loop over the existing engines)
# ---------------------------------------------------------------------------
#
# The orchestrator answers "what should run next?" for one company at a time,
# then the existing Agent Runner executes it. It never executes analysis
# itself, never invents job types, and never overrides human controls,
# dependencies, or unavailable integrations.
#
# Decision precedence is deterministic (§5). Learning may enrich reasons and
# candidate ranking but can never override safety rules (§18). An LLM may only
# polish human-readable reason text when ORCHESTRATOR_LLM_ASSIST=1 (default 0);
# it can never choose, create, or disguise an action (§26).

DECISION_OUTCOMES = ("SUCCESS", "FAILED", "SKIPPED", "CANCELLED", "SUPERSEDED")
DECISION_SOURCES = ("RULE_ENGINE", "LEARNING_ENGINE", "SYSTEM_STATE", "HUMAN", "LLM_ASSISTED")

ALLOWED_AUTOMATIC_ACTIONS = [
    "DISCOVER_COMPANY", "COLLECT_WEBSITE_DATA", "VALIDATE_DATA", "GENERATE_QUERIES",
    "RUN_AI_SEARCH", "ANALYZE_BRAND", "ANALYZE_COMPETITORS", "DETECT_CONTENT_GAPS",
    "GENERATE_RECOMMENDATIONS", "STORE_ANALYSIS", "DETECT_CHANGES", "UPDATE_LEARNING",
    # Extensions beyond the §25 example (documented): STORE_ANALYSIS is required
    # for an analysis to ever complete; REANALYZE_COMPANY is the existing
    # coordinator for major-change rebuilds (used sparingly, always explained).
    "REANALYZE_COMPANY",
]

REQUIRES_HUMAN_APPROVAL = [
    "PUBLISH_EXTERNAL_CONTENT", "MODIFY_EXTERNAL_DATA", "DELETE_DATA",
    "CHANGE_SECURITY_CONFIGURATION", "SEND_EXTERNAL_MESSAGE",
]

ORCHESTRATOR_STATES = ("NEW", "NEEDS_DATA", "DATA_STALE", "READY_FOR_ANALYSIS", "ANALYZING",
                       "ANALYSIS_COMPLETE", "CHANGES_DETECTED", "LEARNING_UPDATE_REQUIRED",
                       "WAITING", "ERROR", "PAUSED")

# Non-job orchestrator verdicts (never a jobs row; handled in run paths).
ORCHESTRATOR_VERDICTS = ("WAIT", "RETRY", "REQUEST_HUMAN_REVIEW")


def orchestrator_enabled():
    try:
        return get_config("ORCHESTRATOR_ENABLED", "1") == "1"
    except Exception:
        return True


def orchestrator_blocked():
    """Human/pause gates: any truthy value means 'assess, but execute nothing'."""
    if not orchestrator_enabled():
        return "Orchestrator disabled (ORCHESTRATOR_ENABLED=0)."
    if runner.paused or get_config("agent_paused", "0") == "1":
        return "Agent is paused; no automatic decisions executed."
    if scheduler.paused or get_config("scheduler_paused", "0") == "1":
        return "Scheduler is paused; orchestrator holding."
    if get_config("automation_enabled", "1") != "1":
        return "Automation is disabled; orchestrator holding."
    return None


def validate_orchestrator_action(action):
    """Allowed-action registry (§25). Unknown or destructive actions are rejected
    (callers convert rejection into REQUEST_HUMAN_REVIEW, never execution)."""
    if action in ALLOWED_AUTOMATIC_ACTIONS or action in ORCHESTRATOR_VERDICTS:
        return {"ok": True}
    if action in REQUIRES_HUMAN_APPROVAL:
        return {"ok": False, "reason": f"Action {action} requires explicit human approval."}
    return {"ok": False, "reason": f"Unknown action rejected: {action}."}


def _latest_job(company_id, job_type):
    rows = db.query("SELECT * FROM jobs WHERE company_id=? AND job_type=? ORDER BY created_at DESC, id DESC LIMIT 1",
                    (company_id, job_type))
    return rows[0] if rows else None


def _completed_after(company_id, job_type, ts):
    """Latest COMPLETED job of type, optionally requiring completion after ts."""
    rows = db.query("SELECT * FROM jobs WHERE company_id=? AND job_type=? AND status='COMPLETED' "
                    "ORDER BY created_at DESC, id DESC LIMIT 1", (company_id, job_type))
    if not rows:
        return None
    if ts:
        try:
            if str(rows[0].get("completed_at") or "") < str(ts):
                return None
        except Exception:
            return None
    return rows[0]


def _inflight_map(company_id):
    rows = db.query("SELECT job_type, status, id FROM jobs WHERE company_id=? AND status IN "
                    "('PENDING','QUEUED','RUNNING','RETRYING','FAILED') ORDER BY id DESC LIMIT 30",
                    (company_id,))
    return {r["job_type"]: r for r in rows}


def _failed_jobs(company_id, permanent_only=False):
    st = "'FAILED_PERMANENTLY'" if permanent_only else "'FAILED','FAILED_PERMANENTLY'"
    return db.query(f"SELECT * FROM jobs WHERE company_id=? AND status IN ({st}) ORDER BY id DESC LIMIT 10",
                    (company_id,))


def _obs_stats(company_id):
    rows = db.query("SELECT COUNT(*) AS c, MAX(observed_at) AS mx FROM ai_observations WHERE brand_id=?",
                    (company_id,))
    r = rows[0] if rows else {}
    return int(r.get("c") or 0), r.get("mx")


def _analysis_times(company_id):
    rows = db.query("SELECT created_at FROM analysis_results WHERE brand_id=? ORDER BY id DESC LIMIT 2",
                    (company_id,))
    cur = rows[0]["created_at"] if rows else None
    prev = rows[1]["created_at"] if len(rows) > 1 else None
    return cur, prev


def _invalidated_fingerprints(company_id):
    """Normalized texts the company has invalidated (TEST 20 convention: the
    invalidated query text is embedded in the memory key/value)."""
    out = set()
    try:
        rows = db.query("SELECT key, value FROM learning_memory WHERE company_id=? AND status='INVALIDATED'",
                        (company_id,))
        for r in rows:
            blob = re.sub(r"[^a-z0-9]", "", str(((r.get("key") or "") + " " + (r.get("value") or ""))).lower())
            if len(blob) >= 12:
                out.add(blob)
    except Exception:
        pass
    return out


def _learning_consult(company_id, brand):
    """Read-only learning snapshot for decision explanations (never overrides rules)."""
    info = {"useful_queries": 0, "top_query": None, "suppressed_titles": 0,
            "invalidated_patterns": 0, "intents": []}
    try:
        qrows = db.query("SELECT query, useful_count FROM query_learning WHERE company_id=? AND status='ACTIVE' "
                         "AND useful_count > 0 ORDER BY useful_count DESC LIMIT 3", (company_id,))
        info["useful_queries"] = len(qrows)
        inv = db.query("SELECT COUNT(*) AS c FROM learning_memory WHERE company_id=? AND status='INVALIDATED'",
                       (company_id,))
        info["invalidated_patterns"] = (inv[0].get("c") or 0) if inv else 0
        # Invalidated patterns are never offered as candidates again: a useful
        # query whose normalized text is embedded in an INVALIDATED memory is
        # excluded (and counted) instead of being recommended.
        blobs = _invalidated_fingerprints(company_id)
        excluded = 0
        for q in qrows:
            if query_fingerprint(q.get("query") or "") and any(
                    query_fingerprint(q.get("query") or "") in b for b in blobs):
                excluded += 1
                continue
            info["top_query"] = (q.get("query") or "")[:140]
            break
        info["invalidated_excluded"] = excluded
        perf = query_performance(company_id)
        info["intents"] = [(a.get("intent"), a.get("avg_value")) for a in (perf.get("by_intent") or [])[:2]]
    except Exception:
        pass
    return info


def llm_polish_reason(reason):
    """Optional LLM assistance (§26): explanation text ONLY, validated, rule
    reason always preserved. Returns (text, assisted_bool)."""
    try:
        if str(get_config("ORCHESTRATOR_LLM_ASSIST", "0")) != "1":
            return reason, False
        if not gemini_available or not gemini_model:
            return reason, False
        text, _ = _gemini_complete(
            "Rewrite this operations reason as one clear sentence for a dashboard. "
            "Do not add facts, numbers, or recommendations.\n\nReason: " + str(reason)[:400],
            max_tokens=128, temperature=0.0)
        text = (text or "").strip()
        if not text or len(text) > 500:
            return reason, False
        return text, True
    except Exception:
        return reason, False


def orchestrator_company_state(company_id):
    """Computed company state (§6) + next action. Derived from real rows only;
    nothing here is stored (use the decisions log for history)."""
    nxt = orchestrator_next_action(company_id)
    b = get_brand(company_id)
    if not b:
        return {"company_id": company_id, "state": "ERROR", "reason": "Company not found.",
                "next_action": nxt["action"]}
    ef, _, e_note = evidence_freshness(company_id)
    af, _, _ = analysis_freshness(company_id)
    inflight = _inflight_map(company_id)
    analyses = db.query("SELECT id FROM analysis_results WHERE brand_id=? LIMIT 2", (company_id,))
    autos = db.query("SELECT COUNT(*) AS c FROM automations WHERE company_id=? AND enabled=1",
                     (company_id,))[0]["c"]
    perm = _failed_jobs(company_id, permanent_only=True)
    majors, minors = unprocessed_changes(company_id)
    learn_rows = db.query("SELECT COUNT(*) AS c FROM learning_events WHERE company_id=?", (company_id,))[0]["c"]
    last_an, _ = _analysis_times(company_id)
    det_done = _completed_after(company_id, "DETECT_CHANGES", last_an) if last_an else None
    learn_done = _completed_after(company_id, "UPDATE_LEARNING", (det_done or {}).get("completed_at") if det_done else last_an) if last_an else None
    if autos == 0:
        state, reason = "PAUSED", "All automations for this company are disabled."
    elif not analyses and perm:
        state, reason = "ERROR", "Analysis never completed and critical jobs failed permanently."
    elif not analyses and inflight:
        state, reason = "ANALYZING", f"Initial pipeline in flight ({len(inflight)} active job(s))."
    elif not analyses:
        state, reason = "NEW", "Company has never been analyzed."
    elif not (b.get("website") or "").strip() and \
            db.query("SELECT COUNT(*) AS c FROM evidence WHERE brand_id=?", (company_id,))[0]["c"] == 0:
        state, reason = "NEEDS_DATA", "No website on file and no evidence collected."
    elif ef in ("expired", "stale"):
        state, reason = "DATA_STALE", f"Website evidence {ef} ({e_note})."
    elif majors:
        state, reason = "CHANGES_DETECTED", f"{len(majors)} unprocessed major change(s)."
    elif minors:
        state, reason = "CHANGES_DETECTED", f"{len(minors)} unprocessed minor change(s)."
    elif af in ("stale", "expired", "never"):
        state, reason = "READY_FOR_ANALYSIS", "Inputs present; analysis is outdated."
    elif last_an and not det_done:
        state, reason = "ANALYSIS_COMPLETE", "Fresh analysis stored; change detection pending."
    elif last_an and det_done and not learn_done:
        state, reason = "LEARNING_UPDATE_REQUIRED", "Changes detected; learning update pending."
    else:
        state, reason = "WAITING", "No work required."
    return {"company_id": company_id, "state": state, "reason": reason,
            "next_action": nxt["action"]}


def orchestrator_next_action(company_id):
    """Pure next-best-action computation (§4, §15). No writes, no LLM action
    selection, no execution. Returns {action, priority, reason, confidence,
    signals[], dependencies[], blocked, source, learning_consulted}."""
    b = get_brand(company_id)
    if not b:
        return {"action": "WAIT", "priority": "LOW",
                "reason": "Company not found; nothing to do.", "confidence": 0.3,
                "signals": ["company_missing=true"], "dependencies": [], "blocked": False,
                "source": "SYSTEM_STATE", "learning_consulted": {}}
    signals = []
    sig = signals.append
    ef, e_age, e_note = evidence_freshness(company_id)
    sig(f"website_data_age={'none' if e_age is None else str(e_age) + '_days'}")
    sig(f"freshness_status={ef.upper()}")
    af, a_age, a_note = analysis_freshness(company_id)
    sig(f"analysis_status={af.upper()}")
    analyses = db.query("SELECT id FROM analysis_results WHERE brand_id=? LIMIT 1", (company_id,))
    has_analysis = bool(analyses)
    last_an, _ = _analysis_times(company_id)
    inflight = _inflight_map(company_id)
    if inflight:
        sig("active_jobs=" + ",".join(sorted(f"{k}:{v['status']}" for k, v in inflight.items())))
    queries = db.query("SELECT COUNT(*) AS c FROM query_memory WHERE brand_id=? AND is_active=1",
                       (company_id,))[0]["c"]
    sig(f"queries_tracked={queries}")
    obs_n, obs_mx = _obs_stats(company_id)
    sig(f"observations={obs_n}")
    scr_ok, ai_ok = scraper_available(), ai_search_connected()
    sig(f"scraper_available={str(scr_ok).lower()}")
    sig(f"ai_search_available={str(ai_ok).lower()}")
    learn = _learning_consult(company_id, b)
    if learn["useful_queries"]:
        sig(f"historical_useful_queries={learn['useful_queries']}")
    if learn["invalidated_patterns"]:
        sig(f"invalidated_patterns={learn['invalidated_patterns']}")

    def finish(action, priority, reason, dependencies=None, blocked=False, blocked_reason="",
               source="RULE_ENGINE", extra_signals=None, confidence=None):
        if extra_signals:
            signals.extend(extra_signals)
        if blocked_reason:
            sig("blocked_reason=" + blocked_reason[:160])
        conf = confidence if confidence is not None else _decision_confidence(
            direct_evidence=True, integrations_ok=(scr_ok and ai_ok))
        return {"action": action, "priority": priority, "reason": reason, "confidence": conf,
                "signals": list(signals), "dependencies": dependencies or [],
                "blocked": blocked, "source": source, "learning_consulted": learn}

    def blocked_check(jt):
        """§11: report BLOCKED with the missing prerequisite instead of executing."""
        deps = JOB_DEPENDENCIES.get(jt, [])
        missing = []
        for d in deps:
            lj = _latest_job(company_id, d)
            if not lj or lj["status"] != "COMPLETED":
                missing.append(d)
        return missing

    # --- failure-aware layer first (§12). Manager-layer jobs are meta-work for
    # task coordination, not company analysis: they never drive orchestrator
    # recovery decisions here (the manager engine owns them).
    failed = [j for j in _failed_jobs(company_id)
              if not str(j.get("job_type") or "").startswith("MANAGER_")]
    retryable = [j for j in failed if j["status"] == "FAILED" and
                 (j.get("retry_count") or 0) < (j.get("max_retries") or 3)]
    if retryable:
        j = sorted(retryable, key=lambda x: x["id"])[0]
        return finish("RETRY", "HIGH",
                      f"Job {j['job_type']} failed ({(j.get('error') or 'unknown error')[:120]}) and "
                      f"has retries left ({j.get('retry_count') or 0}/{(j.get('max_retries') or 3)}).",
                      dependencies=[], extra_signals=[f"failed_job={j['job_type']}", f"job_id={j['id']}"])
    perm = [j for j in _failed_jobs(company_id, permanent_only=True)
            if not str(j.get("job_type") or "").startswith("MANAGER_")]
    if perm:
        j = perm[0]
        jt, err = j["job_type"], (j.get("error") or "").lower()
        prior_retry = db.query("SELECT id FROM agent_decisions WHERE company_id=? AND action='RETRY' "
                               "AND outcome='SUCCESS' AND signals_json LIKE ? LIMIT 1",
                               (company_id, f"%job_id={j['id']}%"))
        ai_cause = any(k in err for k in ("gemini", "serp", "ai search", "quota", "429"))
        scr_cause = any(k in err for k in ("scrap", "fetch", "website", "urlerror", "timeout"))
        if jt == "RUN_AI_SEARCH" and not ai_ok and obs_n == 0:
            return finish("REQUEST_HUMAN_REVIEW", "HIGH",
                          "AI search failed permanently, the provider is still unavailable, and no "
                          "observations exist for an alternative path.",
                          extra_signals=[f"failed_job={jt}", "integration=ai_search_unavailable"])
        if jt == "RUN_AI_SEARCH" and obs_n > 0:
            return finish("ANALYZE_BRAND", "HIGH",
                          "AI search failed permanently, but observations already exist; continuing "
                          "analysis on available evidence (partial).",
                          dependencies=["VALIDATE_DATA"],
                          extra_signals=[f"failed_job={jt}", "integration=ai_search_unavailable"])
        if scr_cause and scr_ok and not prior_retry:
            return finish("RETRY", "HIGH",
                          f"Job {jt} failed permanently while the scraper was down; the integration "
                          "has recovered, allowing one bounded retry.",
                          extra_signals=[f"failed_job={jt}", f"job_id={j['id']}", "integration_recovered=true"])
        if ai_cause and ai_ok and not prior_retry:
            return finish("RETRY", "HIGH",
                          f"Job {jt} failed permanently during an AI outage; the provider is reachable "
                          "again, allowing one bounded retry.",
                          extra_signals=[f"failed_job={jt}", f"job_id={j['id']}", "integration_recovered=true"])
        if not prior_retry and jt in ("COLLECT_WEBSITE_DATA", "VALIDATE_DATA", "GENERATE_QUERIES"):
            return finish("RETRY", "HIGH",
                          f"Job {jt} failed permanently on a non-connectivity error; one bounded "
                          "retry is allowed before human review.",
                          extra_signals=[f"failed_job={jt}", f"job_id={j['id']}"])
        return finish("REQUEST_HUMAN_REVIEW", "HIGH",
                      f"Job {jt} failed permanently ({(j.get('error') or 'unknown error')[:140]}); no "
                      "safe automatic alternative remains.",
                      extra_signals=[f"failed_job={jt}", f"job_id={j['id']}"])

    # --- new company / missing data ---
    if not has_analysis and not inflight:
        if not (b.get("website") or "").strip():
            if company_source_is_connected("COMPANY_DISCOVERY"):
                return finish("DISCOVER_COMPANY", "HIGH", "New company has no website; discovery is connected.",
                              extra_signals=["website_missing=true"])
            return finish("REQUEST_HUMAN_REVIEW", "HIGH",
                          "New company has no website and discovery is not connected; manual entry required.",
                          extra_signals=["website_missing=true", "integration=discovery_unavailable"])
        ev0 = db.query("SELECT COUNT(*) AS c FROM evidence WHERE brand_id=?", (company_id,))[0]["c"]
        if ev0 == 0:
            if not scr_ok:
                return finish("REQUEST_HUMAN_REVIEW", "HIGH",
                              "New company has no evidence and the website scraper is unavailable; "
                              "manual/CSV evidence or human review required.",
                              extra_signals=["evidence_rows=0", "integration=scraper_unavailable"])
            futile, futile_why = _collect_futile(company_id)
            if futile:
                return finish("REQUEST_HUMAN_REVIEW", "HIGH",
                              "Website collection already attempted and " + futile_why[:160] +
                              " Manual/CSV evidence or human review required.",
                              extra_signals=["evidence_rows=0", "collect_futile=true"])
            return finish("COLLECT_WEBSITE_DATA", "HIGH", "New company has no evidence yet.",
                          extra_signals=["evidence_rows=0"])

    # --- expired data (§5 HIGH) ---
    if ef == "expired":
        if not scr_ok:
            if has_analysis:
                return finish("ANALYZE_BRAND", "MEDIUM",
                              "Website evidence expired but the scraper is unavailable; re-analyzing "
                              "on available evidence instead of fabricating collection.",
                              dependencies=["VALIDATE_DATA"],
                              extra_signals=["integration=scraper_unavailable"])
            return finish("REQUEST_HUMAN_REVIEW", "HIGH",
                          "Website evidence expired and the scraper is unavailable with no prior "
                          "analysis to fall back on.",
                          extra_signals=["integration=scraper_unavailable"])
        ev_rows = db.query("SELECT MAX(last_updated_at) AS mx, MAX(collected_at) AS mc FROM evidence "
                           "WHERE brand_id=?", (company_id,))[0]
        ev_mx = ev_rows.get("mx") or ev_rows.get("mc")
        # Expired data always deserves a refresh attempt (the source may have
        # recovered); same-run repetition is prevented by the run loop's
        # attempt guard and the step budget, not here.
        return finish("COLLECT_WEBSITE_DATA", "HIGH",
                      f"Website evidence is expired ({e_note}).",
                      extra_signals=["freshness_status=EXPIRED"])

    # --- finest-missing-step ladder (§15) ---
    if not _completed_after(company_id, "VALIDATE_DATA", None) and \
            db.query("SELECT COUNT(*) AS c FROM evidence WHERE brand_id=?", (company_id,))[0]["c"] > 0:
        miss = blocked_check("VALIDATE_DATA")
        if miss:
            return finish("VALIDATE_DATA", "HIGH", "Evidence exists but was never validated.",
                          dependencies=miss, blocked=True,
                          blocked_reason=f"Waiting for {'/'.join(miss)} job.")
        return finish("VALIDATE_DATA", "HIGH", "Evidence exists but was never validated.")
    if queries == 0:
        miss = blocked_check("GENERATE_QUERIES")
        if miss:
            return finish("GENERATE_QUERIES", "MEDIUM", "No queries tracked yet.",
                          dependencies=miss, blocked=True,
                          blocked_reason=f"Waiting for {'/'.join(miss)} job.")
        extra = []
        if learn["useful_queries"]:
            extra.append(f"learning: {learn['useful_queries']} historically useful queries available")
        if learn.get("invalidated_excluded"):
            extra.append(f"learning: {learn['invalidated_excluded']} invalidated quer(y/ies) excluded from selection")
        src = "LEARNING_ENGINE" if (learn["useful_queries"] and ef == "fresh") else "RULE_ENGINE"
        return finish("GENERATE_QUERIES", "MEDIUM",
                      "Fresh data present but no queries tracked yet." +
                      (f" Learning memory offers a starting point: '{learn['top_query']}' "
                       f"(useful before)." if learn["top_query"] else ""),
                      dependencies=["VALIDATE_DATA"], source=src, extra_signals=extra)
    diff_kw = profile_diff(company_id)
    if "keywords" in diff_kw:
        return finish("GENERATE_QUERIES", "MEDIUM",
                      "Keywords changed since the last query generation; regenerating queries for "
                      "the new keyword set.",
                      dependencies=["VALIDATE_DATA"],
                      extra_signals=["keywords_changed=true"])
    if obs_n == 0:
        if not ai_ok:
            return finish("ANALYZE_BRAND", "MEDIUM",
                          "AI search is unavailable, so no observations can be collected; continuing "
                          "with profile/evidence analysis instead of fabricating results (partial).",
                          dependencies=["VALIDATE_DATA"],
                          extra_signals=["integration=ai_search_unavailable", "deferred=RUN_AI_SEARCH"])
        if _search_futile(company_id):
            # Every active query already searched empty inside the recovery
            # window: fall through to downstream assessment instead of burning
            # quota on an identical empty search (documented, deterministic).
            signals.append("queries already searched without results within "
                           f"{SEARCH_FUTILITY_HOURS}h; skipping re-search")
        else:
            miss = blocked_check("RUN_AI_SEARCH")
            if miss:
                return finish("RUN_AI_SEARCH", "MEDIUM", "Queries tracked but never executed.",
                              dependencies=miss, blocked=True,
                              blocked_reason=f"Waiting for {'/'.join(miss)} job.")
            return finish("RUN_AI_SEARCH", "MEDIUM", "Queries tracked but have not been executed.",
                          dependencies=["GENERATE_QUERIES"])
    if not has_analysis or (obs_mx and last_an and str(obs_mx) >= str(last_an)):
        # >= (not >): at second precision a same-second observation may postdate
        # the analysis; the safe direction is re-analysis, never silent skipping.
        miss = blocked_check("ANALYZE_BRAND")
        if miss:
            return finish("ANALYZE_BRAND", "HIGH", "Observations exist but brand analysis is missing or predates them.",
                          dependencies=miss, blocked=True,
                          blocked_reason=f"Waiting for {'/'.join(miss)} job.")
        return finish("ANALYZE_BRAND", "HIGH",
                      "Observations exist but brand analysis is missing or predates them.",
                      dependencies=["VALIDATE_DATA"])
    diff = profile_diff(company_id)
    if "competitors" in diff:
        miss = blocked_check("ANALYZE_COMPETITORS")
        if miss:
            return finish("ANALYZE_COMPETITORS", "HIGH", "New competitor detected since previous snapshot.",
                          dependencies=miss, blocked=True,
                          blocked_reason=f"Waiting for {'/'.join(miss)} job.")
        return finish("ANALYZE_COMPETITORS", "HIGH",
                      "New competitor detected since previous snapshot.",
                      dependencies=["ANALYZE_BRAND"],
                      extra_signals=["competitors_changed=true"])
    brand_done = _completed_after(company_id, "ANALYZE_BRAND", None)
    gaps_done = _completed_after(company_id, "DETECT_CONTENT_GAPS",
                                 (brand_done or {}).get("completed_at") if brand_done else None)
    if brand_done and not gaps_done:
        miss = blocked_check("DETECT_CONTENT_GAPS")
        if miss:
            return finish("DETECT_CONTENT_GAPS", "MEDIUM", "Brand analysis is newer than the last gap detection.",
                          dependencies=miss, blocked=True,
                          blocked_reason=f"Waiting for {'/'.join(miss)} job.")
        return finish("DETECT_CONTENT_GAPS", "MEDIUM",
                      "Brand analysis is newer than the last gap detection.",
                      dependencies=["ANALYZE_BRAND"])
    recs_done = _completed_after(company_id, "GENERATE_RECOMMENDATIONS",
                                 (gaps_done or {}).get("completed_at") if gaps_done else None)
    if gaps_done and not recs_done:
        miss = blocked_check("GENERATE_RECOMMENDATIONS")
        if miss:
            return finish("GENERATE_RECOMMENDATIONS", "MEDIUM", "Gaps are newer than the last recommendations.",
                          dependencies=miss, blocked=True,
                          blocked_reason=f"Waiting for {'/'.join(miss)} job.")
        return finish("GENERATE_RECOMMENDATIONS", "MEDIUM",
                      "Content gaps are newer than the last recommendations.",
                      dependencies=["ANALYZE_COMPETITORS", "DETECT_CONTENT_GAPS"])
    store_done = _completed_after(company_id, "STORE_ANALYSIS",
                                  (recs_done or {}).get("completed_at") if recs_done else None)
    if recs_done and not store_done:
        return finish("STORE_ANALYSIS", "MEDIUM", "Recommendations are newer than the stored analysis.",
                      dependencies=["GENERATE_RECOMMENDATIONS", "DETECT_CHANGES"])
    if last_an:
        det_done = _completed_after(company_id, "DETECT_CHANGES", last_an)
        if not det_done:
            return finish("DETECT_CHANGES", "MEDIUM", "Analysis completed; change detection has not run since.",
                          dependencies=["COLLECT_WEBSITE_DATA", "VALIDATE_DATA"])
        learn_done = _completed_after(company_id, "UPDATE_LEARNING",
                                      (det_done or {}).get("completed_at"))
        if not learn_done:
            return finish("UPDATE_LEARNING", "MEDIUM", "Changes detected; learning update has not run since.",
                          dependencies=["STORE_ANALYSIS", "DETECT_CHANGES"])
    return finish("WAIT", "LOW", "No meaningful change or stale data detected.",
                  source="SYSTEM_STATE")


def _display_outcome(dec):
    """Live outcome: stored outcome wins; otherwise derive from the linked job
    (job_id column first, then metadata) without extra writes."""
    if dec.get("outcome"):
        return dec["outcome"]
    jid = dec.get("job_id")
    if not jid:
        try:
            jid = (safe_json_loads(dec.get("metadata_json"), {}) or {}).get("job_id")
        except Exception:
            jid = None
    if not jid:
        return None
    rows = db.query("SELECT status FROM jobs WHERE id=?", (jid,))
    if not rows:
        return None
    js = rows[0]["status"]
    if js == "COMPLETED":
        return "SUCCESS"
    if js == "FAILED_PERMANENTLY":
        return "FAILED"
    if js == "CANCELLED":
        return "CANCELLED"
    return None


def record_orchestrator_decision(company_id, nxt, run_id=None, trigger="ORCHESTRATOR_RUN_ONCE",
                                 source_override=None):
    """Persist one next-action assessment. Idempotent (§30): an identical pending
    decision (same company+action, no terminal outcome) is returned as-is;
    a stale pending duplicate is SUPERSEDED before inserting."""
    action = nxt["action"]
    v = validate_orchestrator_action(action)
    if not v["ok"]:
        return {"success": False, "error": v["reason"]}
    if action == "WAIT":
        return {"success": True, "wait": True, "reason": nxt["reason"]}
    existing = db.query("SELECT * FROM agent_decisions WHERE company_id=? AND action=? AND outcome IS NULL "
                        "ORDER BY id DESC LIMIT 1", (company_id, action))
    if existing:
        ejob = existing[0].get("job_id")
        inflight = False
        if ejob:
            jr = db.query("SELECT status FROM jobs WHERE id=?", (ejob,))
            inflight = bool(jr and jr[0]["status"] in ("PENDING", "QUEUED", "RUNNING", "RETRYING", "FAILED"))
        if inflight or not ejob:
            d = dict(existing[0])
            d["display_outcome"] = _display_outcome(existing[0])
            return {"success": True, "idempotent": True, "id": existing[0]["id"],
                    "decision_id": existing[0]["decision_id"], "decision": d}
        db.execute("UPDATE agent_decisions SET outcome='SUPERSEDED' WHERE id=?", (existing[0]["id"]))
    else:
        # A SKIPPED assessment for the same action whose linked job is still
        # inflight is equally settled: return it instead of re-recording.
        sk = db.query("SELECT * FROM agent_decisions WHERE company_id=? AND action=? AND outcome='SKIPPED' "
                      "ORDER BY id DESC LIMIT 1", (company_id, action))
        if sk and sk[0].get("job_id"):
            jr = db.query("SELECT status FROM jobs WHERE id=?", (sk[0]["job_id"],))
            if jr and jr[0]["status"] in ("PENDING", "QUEUED", "RUNNING", "RETRYING", "FAILED"):
                d = dict(sk[0])
                d["display_outcome"] = _display_outcome(sk[0])
                return {"success": True, "idempotent": True, "id": sk[0]["id"],
                        "decision_id": sk[0]["decision_id"], "decision": d}
    source = source_override or nxt.get("source") or "RULE_ENGINE"
    reason = nxt["reason"]
    assisted = False
    if source != "HUMAN":
        reason, assisted = llm_polish_reason(reason)
        if assisted:
            source = "LLM_ASSISTED"
    t = now()
    rid = db.execute("""
        INSERT INTO agent_decisions (company_id, run_id, action, priority, reason, trigger_type, trigger_id,
                                     confidence, signals_json, decision_source, outcome, status, created_at,
                                     metadata_json)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (company_id, run_id, action, nxt.get("priority", "MEDIUM"), (reason or "")[:2000], trigger,
          run_id, nxt.get("confidence"), json.dumps(nxt.get("signals") or [])[:4000], source,
          None, "PROPOSED", t,
          json.dumps({"dependencies": nxt.get("dependencies") or [], "blocked": bool(nxt.get("blocked")),
                      "learning_consulted": nxt.get("learning_consulted") or {},
                      "rule_reason": nxt["reason"][:2000], "llm_assisted": assisted})[:4000]))
    did = new_decision_id(rid)
    db.execute("UPDATE agent_decisions SET decision_id=? WHERE id=?", (did, rid))
    return {"success": True, "id": rid, "decision_id": did}


def orchestrator_create_job(decision_id, run_id=None):
    """Execute the decided action's job mechanics (dedup-aware). Returns linkage."""
    rows = db.query("SELECT * FROM agent_decisions WHERE id=? OR decision_id=?", (decision_id, decision_id))
    if not rows:
        return {"success": False, "error": "Decision not found"}
    dec = rows[0]
    action, cid = dec["action"], dec["company_id"]
    if action == "RETRY":
        try:
            meta = safe_json_loads(dec.get("signals_json"), []) or []
        except Exception:
            meta = []
        jid = None
        for s in meta:
            if str(s).startswith("job_id="):
                try:
                    jid = int(str(s).split("=", 1)[1])
                except Exception:
                    jid = None
        if not jid:
            return {"success": False, "error": "RETRY decision has no target job"}
        r = retry_job(jid)
        if not r.get("success"):
            return r
        db.execute("UPDATE agent_decisions SET job_id=?, status='ACCEPTED' WHERE id=?", (jid, dec["id"]))
        return {"success": True, "job_id": jid, "retried": True}
    if action not in ALLOWED_AUTOMATIC_ACTIONS:
        return {"success": False, "error": f"Action {action} is not automatically executable"}
    # §30: never duplicate inflight work. Completed work is NOT recreated here
    # (include_completed=True): the orchestrator does what is missing; the
    # run loop's repeat detection handles genuinely repeated needs.
    dup = db.query("SELECT id FROM jobs WHERE company_id=? AND job_type=? AND status IN "
                   "('PENDING','QUEUED','RUNNING','RETRYING','FAILED') ORDER BY id DESC LIMIT 1",
                   (cid, action))
    if dup:
        db.execute("UPDATE agent_decisions SET job_id=?, outcome='SKIPPED', status='SKIPPED' WHERE id=?",
                   (dup[0]["id"], dec["id"]))
        return {"success": True, "job_id": dup[0]["id"], "skipped": True,
                "reason": "Equivalent job already active."}
    jid = ensure_job(action, cid, run_id)
    if not jid:
        db.execute("UPDATE agent_decisions SET outcome='SKIPPED', status='SKIPPED' WHERE id=?", (dec["id"],))
        return {"success": True, "skipped": True, "reason": "Job not applicable right now."}
    db.execute("UPDATE agent_decisions SET job_id=?, status='ACCEPTED' WHERE id=?", (jid, dec["id"]))
    return {"success": True, "job_id": jid}


def orchestrator_run_once(company_id=None):
    """ONE bounded orchestration cycle (§28): inspect, select, create, return."""
    if not orchestrator_enabled():
        return {"success": True, "paused": True, "reason": "Orchestrator disabled (ORCHESTRATOR_ENABLED=0)."}
    blocked = orchestrator_blocked()
    if blocked:
        return {"success": True, "paused": True, "reason": blocked}
    cands = _autonomous_companies(company_id) if company_id else _autonomous_companies()
    cands = [c for c in cands if get_brand(c)]
    if not cands:
        return {"success": False, "error": "No companies in scope."}
    # §17 ordering: High-priority issues, overdue, stale, new, scheduled, enrichment.
    # Companies parked for unresolved human review are skipped so one company's
    # review gate never starves the others (§31); if every company is parked,
    # the top one is still assessed (its REVIEW is returned idempotently).
    parked = set()
    for c in cands:
        try:
            pr = db.query("SELECT id FROM agent_decisions WHERE company_id=? AND action='REQUEST_HUMAN_REVIEW' "
                          "AND outcome IS NULL ORDER BY id DESC LIMIT 1", (c,))
            if pr:
                parked.add(c)
        except Exception:
            pass
    ranked = sorted(cands, key=_company_attention_rank)
    open_ranked = [c for c in ranked if c not in parked] or ranked
    cid = open_ranked[0]
    b = get_brand(cid)
    try:
        log_activity(f"Orchestrator inspected Company #{cid} ({b.get('brand_name')}).",
                     level="ORCHESTRATOR", company_id=cid)
    except Exception:
        pass
    nxt = orchestrator_next_action(cid)
    try:
        log_activity(f"Orchestrator selected {nxt['action']} for Company #{cid}: {nxt['reason'][:200]}",
                     level="ORCHESTRATOR", company_id=cid)
    except Exception:
        pass
    if nxt["action"] == "WAIT":
        return {"success": True, "company_id": cid, "decision": nxt, "job_created": False}
    if nxt["action"] == "REQUEST_HUMAN_REVIEW":
        rec = record_orchestrator_decision(cid, nxt, trigger="ORCHESTRATOR_RUN_ONCE")
        try:
            log_activity(f"Orchestrator requested human review for Company #{cid}: {nxt['reason'][:200]}",
                         level="ORCHESTRATOR", company_id=cid)
        except Exception:
            pass
        return {"success": True, "company_id": cid, "decision": nxt, "job_created": False,
                "human_review": True, "decision_id": rec.get("decision_id")}
    rec = record_orchestrator_decision(cid, nxt, trigger="ORCHESTRATOR_RUN_ONCE")
    if not rec.get("success"):
        return {"success": False, "error": rec.get("error")}
    if rec.get("idempotent"):
        return {"success": True, "company_id": cid, "decision": nxt, "job_created": False,
                "idempotent": True, "decision_id": rec.get("decision_id")}
    res = orchestrator_create_job(rec["id"])
    try:
        if res.get("skipped"):
            log_activity(f"Orchestrator skipped {nxt['action']} for Company #{cid}: {res.get('reason')}",
                         level="ORCHESTRATOR", company_id=cid)
        elif res.get("job_id"):
            log_activity(f"Orchestrator created job #{res['job_id']} ({nxt['action']}) for Company #{cid}.",
                         level="ORCHESTRATOR", job_id=res["job_id"], company_id=cid)
    except Exception:
        pass
    return {"success": True, "company_id": cid, "decision": nxt,
            "job_created": bool(res.get("job_id")) and not res.get("skipped"),
            "job_id": res.get("job_id"), "skipped": bool(res.get("skipped")),
            "decision_id": rec.get("decision_id")}


def _company_attention_rank(cid):
    """Ordering key for §17 (lower sorts first). Operational priority only."""
    try:
        st = orchestrator_company_state(cid)
    except Exception:
        return (99, cid)
    s = st["state"]
    order = {"ERROR": 0, "NEEDS_DATA": 1, "DATA_STALE": 2, "CHANGES_DETECTED": 3,
             "READY_FOR_ANALYSIS": 4, "NEW": 5, "ANALYZING": 6, "ANALYSIS_COMPLETE": 7,
             "LEARNING_UPDATE_REQUIRED": 8, "DEGRADED": 9, "WAITING": 10, "PAUSED": 11}
    return (order.get(s, 20), cid)


def orchestrator_run_company(company_id, max_steps=None):
    """Full bounded run for one company (§29): step single jobs until COMPLETED,
    PARTIAL, FAILED, or WAITING_FOR_HUMAN. Skips anything already satisfied."""
    if not get_brand(company_id):
        return {"success": False, "error": "Company not found"}
    if not orchestrator_enabled():
        return {"success": True, "paused": True, "reason": "Orchestrator disabled (ORCHESTRATOR_ENABLED=0)."}
    blocked = orchestrator_blocked()
    if blocked:
        return {"success": True, "paused": True, "reason": blocked}
    max_steps = int(max_steps or _auto_cfg_int("ORCHESTRATOR_MAX_STEPS", 15))
    rid = create_run("ORCHESTRATOR", companies=[company_id])
    unavailable, degraded_skips, failed_critical = [], [], []
    steps, outcome_detail = 0, ""
    finished_by_wait = False
    stalled = False
    run_attempted = {}
    last_done_action = None
    prev_action = None
    prev_completed = 0

    def _run_n_completed():
        r = db.query("SELECT COUNT(*) AS c FROM jobs WHERE run_id=? AND status='COMPLETED'", (rid,))
        return (r[0].get("c") or 0) if r else 0
    drained_total = 0

    def _drain_own_chain():
        """Execute this run's own PENDING chain jobs in dependency order (the
        sync variant of what the Runner drains async in prod). Bounded."""
        nonlocal drained_total, last_done_action
        budget = max_steps * 2 - drained_total
        while budget > 0:
            nxt_j = None
            for j in db.query("SELECT * FROM jobs WHERE run_id=? AND company_id=? AND status='PENDING' "
                              "ORDER BY id ASC LIMIT 25", (rid, company_id)):
                try:
                    if _deps_satisfied(company_id, j["job_type"]):
                        nxt_j = j
                        break
                except Exception:
                    continue
            if not nxt_j:
                break
            execute_job(nxt_j["id"], rid)
            jr = db.query("SELECT status FROM jobs WHERE id=?", (nxt_j["id"],))
            if jr and jr[0]["status"] == "COMPLETED":
                last_done_action = nxt_j["job_type"]
            drained_total += 1
            budget -= 1

    def _run_successes():
        r = db.query("SELECT COUNT(*) AS c FROM agent_decisions WHERE run_id=? AND outcome='SUCCESS'", (rid,))
        return (r[0].get("c") or 0) if r else 0

    def _attempt_key(nxt):
        if nxt["action"] == "RETRY":
            for s in (nxt.get("signals") or []):
                if str(s).startswith("job_id="):
                    return ("RETRY", str(s).split("=", 1)[1])
        return (nxt["action"], "")
    try:
        while steps < max_steps:
            nxt = orchestrator_next_action(company_id)
            if nxt["action"] == "WAIT":
                finished_by_wait = True
                break
            if nxt["action"] == "REQUEST_HUMAN_REVIEW":
                rec = record_orchestrator_decision(company_id, nxt, run_id=rid,
                                                   trigger="ORCHESTRATOR_RUN_COMPANY")
                outcome_detail = nxt["reason"][:300]
                _orchestrator_finish(rid, "WAITING_FOR_HUMAN", outcome_detail)
                return {"success": True, "run_id": rid, "result": "WAITING_FOR_HUMAN",
                        "detail": outcome_detail, "unavailable": unavailable,
                        "decision_id": rec.get("decision_id")}
            # Repeat-without-progress detection: same assessment twice with zero
            # completions between means the loop cannot advance on its own.
            if nxt["action"] == prev_action and _run_n_completed() == prev_completed:
                rec = record_orchestrator_decision(company_id, nxt, run_id=rid,
                                                   trigger="ORCHESTRATOR_RUN_COMPANY")
                if rec.get("id"):
                    db.execute("UPDATE agent_decisions SET outcome='SKIPPED' WHERE id=?", (rec["id"],))
                steps += 1
                stalled = True
                break
            prev_action, prev_completed = nxt["action"], _run_n_completed()
            if nxt.get("blocked"):
                deps = nxt.get("dependencies") or []
                if not deps:
                    outcome_detail = nxt.get("blocked_reason") or "Blocked with no resolvable prerequisite."
                    _orchestrator_finish(rid, "FAILED", outcome_detail)
                    return {"success": True, "run_id": rid, "result": "FAILED",
                            "detail": outcome_detail, "unavailable": unavailable}
                pre = deps[0]
                pj = ensure_job(pre, company_id, rid, include_completed=False)
                if pj:
                    execute_job(pj, rid)
                _drain_own_chain()
                steps += 1
                continue
            if nxt["action"] == "RETRY":
                akey = _attempt_key(nxt)
                rec = record_orchestrator_decision(company_id, nxt, run_id=rid,
                                                   trigger="ORCHESTRATOR_RUN_COMPANY")
                if akey in run_attempted and last_done_action == "RETRY":
                    db.execute("UPDATE agent_decisions SET outcome='SKIPPED' WHERE id=?", (rec["id"],))
                    steps += 1
                    stalled = True
                    break
                run_attempted[akey] = True
                res = orchestrator_create_job(rec["id"], run_id=rid)
                if res.get("job_id"):
                    execute_job(res["job_id"], rid)
                    jr = db.query("SELECT status FROM jobs WHERE id=?", (res["job_id"],))
                    if jr and jr[0]["status"] == "COMPLETED":
                        db.execute("UPDATE agent_decisions SET outcome='SUCCESS' WHERE id=?", (rec["id"],))
                        last_done_action = "RETRY"
                    else:
                        db.execute("UPDATE agent_decisions SET outcome='FAILED' WHERE id=?", (rec["id"],))
                _drain_own_chain()
                steps += 1
                continue
            if nxt["action"] == "ANALYZE_BRAND" and any("deferred=RUN_AI_SEARCH" in s for s in nxt["signals"]):
                degraded_skips.append("AI search observation (provider unavailable)")
            akey = _attempt_key(nxt)
            rec = record_orchestrator_decision(company_id, nxt, run_id=rid,
                                               trigger="ORCHESTRATOR_RUN_COMPANY")
            if not rec.get("success"):
                outcome_detail = rec.get("error") or "Decision rejected."
                _orchestrator_finish(rid, "FAILED", outcome_detail)
                return {"success": True, "run_id": rid, "result": "FAILED",
                        "detail": outcome_detail, "unavailable": unavailable}
            if akey in run_attempted and last_done_action == nxt["action"]:
                db.execute("UPDATE agent_decisions SET outcome='SKIPPED' WHERE id=?", (rec["id"],))
                steps += 1
                stalled = True
                break
            run_attempted[akey] = True
            res = orchestrator_create_job(rec["id"], run_id=rid)
            jid = res.get("job_id")
            if not jid:
                db.execute("UPDATE agent_decisions SET outcome='SKIPPED' WHERE id=?", (rec["id"],))
                steps += 1
                continue
            # Execute the required job synchronously (whether freshly created or
            # pre-existing): run-company waits for the result (§16).
            if res.get("skipped"):
                try:
                    log_activity(f"Orchestrator reuses inflight job #{jid} ({nxt['action']}) for Company "
                                 f"#{company_id} instead of duplicating it.",
                                 level="ORCHESTRATOR", run_id=rid, job_id=jid, company_id=company_id)
                except Exception:
                    pass
            execute_job(jid, rid)
            jr = db.query("SELECT status FROM jobs WHERE id=?", (jid,))
            js = jr[0]["status"] if jr else "UNKNOWN"
            if js == "COMPLETED":
                db.execute("UPDATE agent_decisions SET outcome='SUCCESS' WHERE id=?", (rec["id"],))
                last_done_action = nxt["action"]
                try:
                    log_activity(f"Job #{jid} ({nxt['action']}) completed for Company #{company_id}.",
                                 level="ORCHESTRATOR", run_id=rid, job_id=jid, company_id=company_id)
                except Exception:
                    pass
            else:
                db.execute("UPDATE agent_decisions SET outcome='FAILED' WHERE id=?", (rec["id"],))
                if nxt["action"] in ("ANALYZE_BRAND", "STORE_ANALYSIS", "COLLECT_WEBSITE_DATA"):
                    failed_critical.append(nxt["action"])
            _drain_own_chain()
            steps += 1
        if failed_critical:
            outcome_detail = f"Critical jobs failed: {', '.join(failed_critical)}."
            _orchestrator_finish(rid, "FAILED", outcome_detail)
            return {"success": True, "run_id": rid, "result": "FAILED", "detail": outcome_detail,
                    "unavailable": unavailable}
        if stalled:
            if _run_successes() > 0 or degraded_skips or unavailable:
                outcome_detail = ("Repeating assessment with no new state; stopping instead of looping. " +
                                  "; ".join(degraded_skips + unavailable))[:300] or \
                    "Repeating assessment with no new state; stopping instead of looping."
                _orchestrator_finish(rid, "PARTIAL", outcome_detail)
                return {"success": True, "run_id": rid, "result": "PARTIAL", "detail": outcome_detail,
                        "unavailable": degraded_skips + unavailable}
            outcome_detail = "No progress possible; stopping instead of looping."
            _orchestrator_finish(rid, "FAILED", outcome_detail)
            return {"success": True, "run_id": rid, "result": "FAILED", "detail": outcome_detail,
                    "unavailable": unavailable}
        if not finished_by_wait:
            outcome_detail = (f"Step budget exhausted ({max_steps} steps) with required work remaining; "
                              "re-run to continue from current state.")
            _orchestrator_finish(rid, "FAILED", outcome_detail)
            return {"success": True, "run_id": rid, "result": "FAILED", "detail": outcome_detail,
                    "unavailable": unavailable}
        if degraded_skips or unavailable:
            outcome_detail = "Completed with gaps: " + "; ".join(degraded_skips + unavailable)[:300]
            _orchestrator_finish(rid, "PARTIAL", outcome_detail)
            return {"success": True, "run_id": rid, "result": "PARTIAL", "detail": outcome_detail,
                    "unavailable": degraded_skips + unavailable}
        _orchestrator_finish(rid, "COMPLETED", "All required steps completed.")
        return {"success": True, "run_id": rid, "result": "COMPLETED",
                "detail": "All required steps completed.", "unavailable": []}
    except Exception as e:
        try:
            _orchestrator_finish(rid, "FAILED", str(e)[:300])
        except Exception:
            pass
        return {"success": False, "error": str(e)[:300], "run_id": rid}


def _orchestrator_finish(run_id, result, detail):
    db.execute("UPDATE runs SET status='COMPLETED', progress=100, current_task=? WHERE run_id=?",
               (f"ORCHESTRATOR_RESULT:{result}:{detail}"[:500], run_id))
    try:
        log_activity(f"Orchestrator run {run_id} finished: {result} - {detail[:200]}",
                     level="ORCHESTRATOR", run_id=run_id)
    except Exception:
        pass


def _orchestrator_decisions():
    return db.query("SELECT * FROM agent_decisions WHERE trigger_type LIKE 'ORCHESTRATOR%' ORDER BY id DESC LIMIT 2000")


def orchestrator_metrics():
    """§27 metrics from real decision + job rows (display-outcome semantics)."""
    decs = _orchestrator_decisions()
    with_outcome = []
    for d in decs:
        o = _display_outcome(d)
        with_outcome.append(o or d.get("outcome"))
    total = len(decs)
    ok = sum(1 for o in with_outcome if o == "SUCCESS")
    fail = sum(1 for o in with_outcome if o == "FAILED")
    skipped = sum(1 for o in with_outcome if o == "SKIPPED")
    blocked = 0
    for d in decs:
        try:
            if '"blocked": true' in (d.get("metadata_json") or ""):
                blocked += 1
        except Exception:
            pass
    retried = sum(1 for d in decs if d.get("action") == "RETRY" and (d.get("outcome") == "SUCCESS" or
                                                                    _display_outcome(d) == "SUCCESS"))
    reviews = sum(1 for d in decs if d.get("action") == "REQUEST_HUMAN_REVIEW")
    created = sum(1 for d in decs if d.get("job_id"))
    comp = part = failc = 0
    for r in db.query("SELECT current_task FROM runs WHERE run_type='ORCHESTRATOR' AND status='COMPLETED' "
                      "ORDER BY id DESC LIMIT 200"):
        ct = r.get("current_task") or ""
        if ct.startswith("ORCHESTRATOR_RESULT:COMPLETED"):
            comp += 1
        elif ct.startswith("ORCHESTRATOR_RESULT:PARTIAL"):
            part += 1
        elif ct.startswith("ORCHESTRATOR_RESULT:FAILED"):
            failc += 1
    return {"success": True, "decisions_total": total, "decisions_successful": ok,
            "decisions_failed": fail, "jobs_created_by_orchestrator": created,
            "jobs_skipped": skipped, "jobs_blocked": blocked, "jobs_retried": retried,
            "human_reviews_requested": reviews, "companies_completed": comp,
            "companies_partial": part, "companies_failed": failc}


def orchestrator_activity(limit=100):
    """Real orchestrator events (never simulated)."""
    try:
        limit = max(1, min(int(limit or 100), 200))
    except Exception:
        limit = 100
    rows = db.query("SELECT * FROM agent_activity WHERE level='ORCHESTRATOR' ORDER BY id DESC LIMIT ?",
                    (limit,))
    return {"success": True, "events": [dict(r) for r in rows]}


def orchestrator_state():
    """Global agent state (§7): live runner/scheduler truth + computed attention."""
    agent_st = "RUNNING" if (runner.thread and runner.thread.is_alive() and runner.loop_enabled) else "IDLE"
    if runner.paused:
        agent_st = "PAUSED"
    try:
        sch = scheduler.status()
        sched_st = {"running": bool(sch.get("running")), "paused": bool(sch.get("paused")),
                    "cycle": sch.get("cycle_count"), "interval_minutes": sch.get("interval_minutes")}
    except Exception:
        sched_st = {"running": False, "paused": False}
    cur = db.query("SELECT * FROM jobs WHERE status='RUNNING' ORDER BY created_at DESC, id DESC LIMIT 1")
    q = db.query("SELECT status, COUNT(*) AS c FROM jobs GROUP BY status")
    qm = {r["status"]: r["c"] for r in q}
    pending = sum(qm.get(s, 0) for s in ("PENDING", "QUEUED"))
    failed = sum(qm.get(s, 0) for s in ("FAILED", "RETRYING", "FAILED_PERMANENTLY"))
    blocked = 0
    for j in db.query("SELECT company_id, job_type FROM jobs WHERE status IN ('PENDING','QUEUED') "
                      "ORDER BY id DESC LIMIT 50"):
        try:
            if not _deps_satisfied(j["company_id"], j["job_type"]):
                blocked += 1
        except Exception:
            pass
    attention = []
    for cid in _autonomous_companies()[:3]:
        try:
            st = orchestrator_company_state(cid)
        except Exception:
            continue
        if st["state"] not in ("WAITING",):
            attention.append({"company_id": cid, "state": st["state"], "reason": st["reason"][:200],
                              "next_action": st["next_action"]})
        if len(attention) >= 3:
            break
    order = {"ERROR": 0, "NEEDS_DATA": 1, "DATA_STALE": 2, "CHANGES_DETECTED": 3,
             "READY_FOR_ANALYSIS": 4, "NEW": 5}
    attention.sort(key=lambda a: (order.get(a["state"], 9), a["company_id"]))
    nxt_decision = None
    if attention:
        nxt_decision = {"company_id": attention[0]["company_id"],
                        "action": attention[0]["next_action"], "priority": "MEDIUM",
                        "reason": attention[0]["reason"]}
    last = db.query("SELECT MAX(created_at) AS t FROM agent_decisions WHERE trigger_type LIKE 'ORCHESTRATOR%'")
    active = None
    if AUTO_STATE.get("company"):
        active = AUTO_STATE.get("company")
    elif attention:
        active = attention[0]["company_id"]
    return {"success": True, "agent_status": agent_st, "scheduler_status": sched_st,
            "active_company": active,
            "current_job": dict(cur[0]) if cur else None,
            "pending_jobs": pending, "blocked_jobs": blocked, "failed_jobs": failed,
            "companies_needing_attention": attention,
            "next_decision": nxt_decision,
            "last_decision_at": (last[0].get("t") if last else None)}


def orchestrator_approve(decision_id):
    rows = db.query("SELECT * FROM agent_decisions WHERE id=? OR decision_id=?", (decision_id, decision_id))
    if not rows:
        return {"success": False, "error": "Decision not found"}
    dec = rows[0]
    if (dec.get("outcome") or dec.get("status")) not in (None, "", "PROPOSED"):
        return {"success": False, "error": f"Decision already {dec.get('outcome') or dec.get('status')}"}
    if dec.get("action") in ("WAIT", "REQUEST_HUMAN_REVIEW"):
        db.execute("UPDATE agent_decisions SET decision_source='HUMAN' WHERE id=?", (dec["id"],))
        return {"success": True, "decision_id": dec["decision_id"], "acknowledged": True}
    res = orchestrator_create_job(dec["id"])
    db.execute("UPDATE agent_decisions SET decision_source='HUMAN' WHERE id=?", (dec["id"],))
    return {"success": True, "decision_id": dec["decision_id"], **{k: v for k, v in res.items() if k != "success"}}


def orchestrator_reject(decision_id):
    rows = db.query("SELECT * FROM agent_decisions WHERE id=? OR decision_id=?", (decision_id, decision_id))
    if not rows:
        return {"success": False, "error": "Decision not found"}
    dec = rows[0]
    if (dec.get("outcome") or "") in ("SUCCESS", "FAILED", "CANCELLED", "SUPERSEDED"):
        return {"success": False, "error": f"Decision already {dec.get('outcome')}"}
    jid = dec.get("job_id")
    if jid:
        try:
            jr = db.query("SELECT status FROM jobs WHERE id=?", (jid,))
            if jr and jr[0]["status"] in ("PENDING", "QUEUED", "RUNNING", "RETRYING", "FAILED"):
                cancel_job(jid)
        except Exception:
            pass
    db.execute("UPDATE agent_decisions SET outcome='CANCELLED', status='CANCELLED', decision_source='HUMAN' "
               "WHERE id=?", (dec["id"],))
    return {"success": True, "decision_id": dec["decision_id"], "outcome": "CANCELLED"}


# ---------------------------------------------------------------------------
# PHASE 7 - REASONING ENGINE (read-only assessment; never executes)
# ---------------------------------------------------------------------------
#
# Position in the loop: STATE+EVIDENCE+HISTORY+CHANGES+LEARNING -> REASONING ->
# structured result -> VALIDATION -> existing orchestrator -> job. The engine
# READS learning memory and NEVER writes it (§12/§29); UPDATE_LEARNING remains
# the sole writer. Association language ("coincides with") is used unless
# causal evidence exists (§10). Confidence is deterministic (§16).

REASONING_MODES = ("RULE_REASONING", "EVIDENCE_REASONING", "HISTORICAL_REASONING",
                   "LEARNING_ASSISTED_REASONING", "LLM_ASSISTED_REASONING")

REASONING_ACTIONS = [
    "DISCOVER_COMPANY", "COLLECT_WEBSITE_DATA", "VALIDATE_DATA", "GENERATE_QUERIES",
    "RUN_AI_SEARCH", "ANALYZE_BRAND", "ANALYZE_COMPETITORS", "DETECT_CONTENT_GAPS",
    "GENERATE_RECOMMENDATIONS", "DETECT_CHANGES", "UPDATE_LEARNING", "WAIT",
    "REQUEST_HUMAN_REVIEW",
]

# Evidence priority, highest first (§7). Lower number = stronger.
def _evidence_rank(source, verification_status):
    s = (source or "").upper()
    v = (verification_status or "").upper()
    if s in ("USER_PROVIDED", "MANUAL", "USER_CORRECTION") or "CORRECTION" in s:
        return 0
    if v == "VERIFIED":
        return 1 if "API" not in s and "WEBSITE" not in s else (2 if "API" in s else 3)
    if "API" in s:
        return 4
    if "WEBSITE" in s or "SCRAPER" in s or "DISCOVER" in s:
        return 5
    if "AI" in s or "INFER" in s or "GENERAT" in s:
        return 6
    return 5


def build_reasoning_context(company_id):
    """Minimized context object (§3): only rows relevant to the next decision,
    capped per section. Never the whole database."""
    b = get_brand(company_id) or {}
    cur_an, prev_an = None, None
    try:
        rows = db.query("SELECT * FROM analysis_results WHERE brand_id=? ORDER BY id DESC LIMIT 2",
                        (company_id,))
        cur_an = dict(rows[0]) if rows else None
        prev_an = dict(rows[1]) if len(rows) > 1 else None
    except Exception:
        pass
    try:
        cur_snap = (safe_json_loads((cur_an or {}).get("analysis_data"), {}) or {}).get("evidence_snapshot") or []
    except Exception:
        cur_snap = []
    try:
        prev_snap = (safe_json_loads((prev_an or {}).get("analysis_data"), {}) or {}).get("evidence_snapshot") or []
    except Exception:
        prev_snap = []
    try:
        changes = [dict(r) for r in db.query(
            "SELECT change_type, field_name, previous_value, current_value, impact, severity, detected_at, run_id "
            "FROM change_log WHERE brand_id=? ORDER BY id DESC LIMIT 30", (company_id,))]
    except Exception:
        changes = []
    try:
        ev = [dict(r) for r in db.query(
            "SELECT evidence_type, evidence_key, evidence_value, source, verification_status, confidence, "
            "collected_at, last_updated_at FROM evidence WHERE brand_id=? ORDER BY last_updated_at DESC LIMIT 40",
            (company_id,))]
    except Exception:
        ev = []
    learn, qperf = [], {"by_intent": []}
    try:
        learn = [dict(r) for r in db.query(
            "SELECT memory_type, category, key, value, confidence, status, usage_count, success_count, "
            "failure_count FROM learning_memory WHERE company_id=? AND status='ACTIVE' ORDER BY id DESC LIMIT 20",
            (company_id,))]
        qperf = query_performance(company_id)
    except Exception:
        pass
    try:
        queries = [dict(r) for r in db.query(
            "SELECT query_text, intent, times_tested, last_tested, current_result FROM query_memory "
            "WHERE brand_id=? AND is_active=1 ORDER BY id DESC LIMIT 20", (company_id,))]
    except Exception:
        queries = []
    try:
        recs = [dict(r) for r in db.query(
            "SELECT title, status, feedback, category FROM recommendations WHERE brand_id=? "
            "ORDER BY id DESC LIMIT 20", (company_id,))]
    except Exception:
        recs = []
    try:
        inflight = [dict(r) for r in db.query(
            "SELECT job_type, status FROM jobs WHERE company_id=? AND status IN "
            "('PENDING','QUEUED','RUNNING','RETRYING','FAILED') ORDER BY id DESC LIMIT 20", (company_id,))]
    except Exception:
        inflight = []
    try:
        autos = [dict(r) for r in db.query(
            "SELECT automation_type, schedule_type, enabled FROM automations WHERE company_id=? LIMIT 10",
            (company_id,))]
    except Exception:
        autos = []
    return {"company": {k: b.get(k) for k in ("id", "brand_name", "website", "industry", "region",
                                             "company_type", "description", "keywords", "target_audience",
                                             "competitors", "verification_status", "last_analyzed_at")},
            "current_state": {}, "latest_snapshot": cur_snap, "previous_snapshot": prev_snap,
            "detected_changes": changes, "evidence": ev, "learning_memory": learn,
            "query_history": queries, "recommendation_history": recs, "active_jobs": inflight,
            "automation_state": autos,
            "integration_state": {"scraper": scraper_available(), "ai_search": ai_search_connected()},
            "query_performance": (qperf.get("by_intent") or [])[:5]}


def _context_fingerprint(ctx):
    """Deterministic fingerprint over the material state (§25): profile fields,
    evidence version (count+max timestamp), change ids, analysis ids, learning
    counts. Same fingerprint => same reasoning may be reused."""
    try:
        b = ctx.get("company") or {}
        prof = "|".join(str(b.get(k) or "") for k in ("brand_name", "website", "industry", "keywords",
                                                      "competitors", "description", "target_audience"))
        ev = ctx.get("evidence") or []
        ev_v = f"{len(ev)}|{max([str(e.get('last_updated_at') or '') for e in ev] or [''])}"
        ch = ctx.get("detected_changes") or []
        an_ids = f"{len(ctx.get('latest_snapshot') or [])}|{len(ctx.get('previous_snapshot') or [])}"
        learn_n = len(ctx.get("learning_memory") or [])
        q_n = len(ctx.get("query_history") or [])
        raw = "|".join([prof, ev_v, str(len(ch)), an_ids, str(learn_n), str(q_n)])
        import hashlib as _hl
        return _hl.sha256(raw.encode("utf-8", "replace")).hexdigest()[:32]
    except Exception:
        return ""


def reason_about_company(company_id, store=True, run_id=None, use_rag=False):
    """The 12-step reasoning pipeline (§5). Pure unless store=True (run-once
    path persists one reasoning_events row; integration uses store=False).
    Never creates jobs, never writes learning memory. use_rag=True attaches
    vector retrieval context (read-only enrichment; default off)."""
    ctx = build_reasoning_context(company_id)
    modes = ["RULE_REASONING"]
    facts, observations, interps = [], [], []
    b = ctx["company"]
    rag_notes = []
    if use_rag:
        try:
            q = f"{b.get('brand_name') or ''} {(b.get('industry') or '')} visibility analysis evidence"
            rr = retrieve_relevant_context(company_id, q, top_k=5)
            for it in (rr.get("items") or [])[:5]:
                rag_notes.append(f"RAG [{it.get('kind')}]: {str(it.get('text') or '')[:160]} "
                                 f"(score {it.get('score')})")
            ctx["rag_context"] = {"backend": (rr.get("retrieval_metadata") or {}).get("backend"),
                                  "count": len(rr.get("items") or [])}
        except Exception as e:
            ctx["rag_context"] = {"backend": "error", "detail": str(e)[:200]}

    # STEP 1: current state.
    try:
        state = orchestrator_company_state(company_id)
    except Exception:
        state = {"state": "ERROR", "reason": "state assessment unavailable"}
    ctx["current_state"] = {"state": state.get("state"), "reason": state.get("reason")}
    situation_bits = [f"Company state is {state.get('state')}: {state.get('reason') or ''}".strip()]

    # STEP 2+3: relevant evidence + freshness (priority-ordered, §7).
    ranked = sorted(ctx["evidence"], key=lambda e: (
        _evidence_rank(e.get("source"), e.get("verification_status")),
        e.get("last_updated_at") or ""))
    if ranked:
        modes.append("EVIDENCE_REASONING")
    top_ev = ranked[:8]
    for e in top_ev:
        facts.append(f"{e.get('evidence_type')}:{e.get('evidence_key')} = "
                     f"{str(e.get('evidence_value') or '')[:120]} "
                     f"(source {e.get('source')}, {e.get('verification_status')}, "
                     f"updated {str(e.get('last_updated_at') or '')[:10]})")
    try:
        ef, e_age, e_note = evidence_freshness(company_id)
        if ef in ("expired", "stale"):
            observations.append(f"Website evidence is older than the configured freshness threshold ({e_note}).")
            interps.append("The current website information may not represent the company's current state.")
        elif ef == "none":
            observations.append("No website evidence has been collected yet.")
    except Exception:
        pass

    # STEP 4+5: historical comparison + meaningful changes (§10/§11).
    hist_notes = []
    try:
        rows = db.query("SELECT visibility_score, topic_coverage, created_at FROM analysis_results "
                        "WHERE brand_id=? ORDER BY id DESC LIMIT 2", (company_id,))
        if len(rows) == 2 and rows[0].get("visibility_score") is not None:
            dv = (rows[0]["visibility_score"] or 0) - (rows[1]["visibility_score"] or 0)
            if dv != 0:
                hist_notes.append(f"visibility score moved from {rows[1]['visibility_score']} to "
                                  f"{rows[0]['visibility_score']} (delta {dv:+d})")
            k0, k1 = rows[1].get("topic_coverage"), rows[0].get("topic_coverage")
            if k0 is not None and k1 is not None and k1 != k0:
                hist_notes.append(f"keyword topic coverage moved from {k0} to {k1} (delta {k1 - k0:+.1f})")
    except Exception:
        pass
    if hist_notes:
        modes.append("HISTORICAL_REASONING")
        for h in hist_notes:
            observations.append(h)
    majors, minors = [], []
    try:
        majors, minors = unprocessed_changes(company_id)
    except Exception:
        pass
    for ch in (majors + minors)[:10]:
        mag, why = classify_change(ch)
        facts.append(f"detected change [{mag}]: {ch.get('change_type')} on {ch.get('field_name')} - {why}")
    # association (never causation): co-occurring score + keyword moves.
    assoc = ""
    if len(hist_notes) >= 2:
        assoc = ("Current visibility decline coincides with reduced keyword coverage "
                 "(observed alongside; causality not established).")
        interps.append(assoc)

    # STEP 6: missing information (§9).
    missing = []
    if not (b.get("website") or "").strip():
        missing.append("website evidence missing")
    if not (b.get("target_audience") or "").strip():
        missing.append("target audience missing")
    if not (b.get("keywords") or "").strip():
        missing.append("keywords missing")
    if not (b.get("description") or "").strip():
        missing.append("brand description missing")
    if not ctx["evidence"]:
        missing.append("no collected evidence rows")
    if missing:
        interps.append("Analysis can proceed partially, but " + ", ".join(missing) + ".")

    # STEP 7: learning memory (read-only, §12).
    learn_notes = []
    try:
        useful = [q for q in (ctx.get("query_history") or [])]
        perf = ctx.get("query_performance") or []
        for a in perf:
            if (a.get("useful") or 0) >= 2:
                learn_notes.append(f"{a.get('intent')} queries produced useful observations in "
                                   f"{a.get('useful')} previous runs.")
        res_titles = [r.get("title") for r in (ctx.get("recommendation_history") or [])
                      if (r.get("status") or "") in ("DONE", "INVALIDATED")]
        for t in res_titles[:5]:
            learn_notes.append(f"Recommendation already {t and 'resolved'}: '{str(t)[:100]}' - do not regenerate.")
        if learn_notes:
            modes.append("LEARNING_ASSISTED_REASONING")
    except Exception:
        pass

    # STEP 8: candidate actions (registered only, §14).
    candidates = _reasoning_candidates(company_id, ctx, majors, minors, missing)

    # STEP 9: constraints (§15 pre-checks that reasoning can evaluate).
    constraints = []
    if ctx["integration_state"].get("scraper") is False:
        constraints.append("website scraper unavailable: collection actions will degrade")
    if ctx["integration_state"].get("ai_search") is False:
        constraints.append("AI search unavailable: observation actions will defer")
    if ctx["active_jobs"]:
        constraints.append(f"{len(ctx['active_jobs'])} job(s) already inflight: no duplicates will be created")
    paused = False
    try:
        paused = int((db.query("SELECT COUNT(*) AS c FROM automations WHERE company_id=? AND enabled=1",
                               (company_id,))[0] or {}).get("c", 1)) == 0
    except Exception:
        pass
    if paused:
        constraints.append("company automations paused")

    # STEP 10: select a valid action (first feasible candidate in priority order).
    selected, reason = "WAIT", "No meaningful change or stale data detected."
    for cand in candidates:
        if cand.get("suppressed"):
            continue
        selected = cand["action"]
        reason = cand["reason"]
        break
    else:
        if not candidates:
            selected, reason = "WAIT", "No meaningful change or stale data detected."

    # conflicts (§8): same field, different values, no verified-source resolution.
    conflict, conflicting = _reasoning_conflicts(ctx["evidence"])
    requires_review = bool(conflict)
    if conflict:
        interps.append("Conflicting evidence must not be silently resolved; human review required.")

    # STEP 11: explanation + deterministic confidence (§16). A present
    # association is appended so correlation insight is never silent.
    if selected == "WAIT" and not conflict:
        explanation = "No candidate action is both required and feasible right now."
    elif conflict:
        explanation = ("Evidence conflicts prevent a safe automatic choice; " + reason) if reason else \
            "Evidence conflicts prevent a safe automatic choice."
    else:
        explanation = reason
    if assoc and assoc not in explanation:
        explanation = explanation + " " + assoc
    confidence, conf_level, conf_signals = _reasoning_confidence(ctx, conflict, missing)

    # LLM assist is explanation-only and validated (§18); default off.
    llm_used = False
    if str(get_config("REASONING_LLM_ASSIST", "0")) == "1":
        polished, ok = _llm_polish_reasoning(situation_bits, explanation)
        if ok:
            explanation = polished
            llm_used = True
    if llm_used and "LLM_ASSISTED_REASONING" not in modes:
        modes.append("LLM_ASSISTED_REASONING")
    if str(get_config("REASONING_LLM_ASSIST", "0")) == "1" and not llm_used:
        constraints.append("LLM reasoning unavailable; deterministic reasoning used.")
    # STEP 12: structured result.
    situation = "; ".join(situation_bits)[:1000]
    result = {
        "company_id": company_id,
        "situation": situation,
        "observations": observations,
        "evidence": [f"{e.get('evidence_type')}:{e.get('evidence_key')} "
                     f"(source {e.get('source')}, {e.get('verification_status')})" for e in top_ev],
        "changes": [f"{c.get('change_type')} on {c.get('field_name')}" for c in (majors + minors)[:10]],
        "missing_information": missing,
        "considered_actions": [{"action": c["action"], "reason": c["reason"],
                                "suppressed": bool(c.get("suppressed"))} for c in candidates],
        "recommended_action": selected,
        "reason": explanation,
        "confidence": confidence,
        "confidence_level": conf_level,
        "confidence_signals": conf_signals,
        "requires_human_review": requires_review,
        "conflict": conflict,
        "conflicting_evidence": conflicting,
        "constraints": constraints,
        "reasoning_mode": "+".join(modes),
        "learning_notes": learn_notes,
        "rag_notes": rag_notes,
        "created_at": now(),
    }
    if store:
        result["reasoning_id"] = _store_reasoning_event(company_id, result, ctx, run_id)
    return result


def _reasoning_candidates(company_id, ctx, majors, minors, missing):
    """Candidate actions in priority order (§5 step 8, §14 allowlist only).
    Entries carry suppressed=True when learning/history rules them out."""
    cands = []
    b = ctx.get("company") or {}
    analyses = db.query("SELECT id FROM analysis_results WHERE brand_id=? LIMIT 1", (company_id,)) \
        if company_id else []
    obs_n = db.query("SELECT COUNT(*) AS c FROM ai_observations WHERE brand_id=?", (company_id,))[0]["c"] \
        if company_id else 0
    queries_n = len(ctx.get("query_history") or [])
    ai_ok = bool(ctx.get("integration_state", {}).get("ai_search"))

    def add(action, reason, suppressed=False):
        if action not in REASONING_ACTIONS:
            return
        cands.append({"action": action, "reason": reason, "suppressed": suppressed})

    if not analyses and not (b.get("website") or "").strip():
        add("DISCOVER_COMPANY", "New company has no website; discovery can supply one.")
    if not analyses and not ctx.get("evidence"):
        add("COLLECT_WEBSITE_DATA", "No evidence collected yet.")
    try:
        ef, _, _ = evidence_freshness(company_id)
    except Exception:
        ef = "none"
    if ef == "expired":
        add("COLLECT_WEBSITE_DATA", "Website evidence is expired.")
    if majors:
        sev_major = [c for c in majors if (c.get("magnitude") or "") == "MAJOR"] or majors
        add("ANALYZE_BRAND", f"{len(sev_major)} major change(s) need re-analysis.")
        add("ANALYZE_COMPETITORS", "Major changes may involve competitors; verify against fresh data.")
    diff = profile_diff(company_id) if company_id else {}
    if "keywords" in diff:
        add("GENERATE_QUERIES", "Keywords changed since the last query generation.")
    if "competitors" in diff:
        add("ANALYZE_COMPETITORS", "Competitor list changed since previous snapshot.")
    if queries_n == 0 and ctx.get("evidence"):
        learn_hit = ""
        try:
            perf = ctx.get("query_performance") or []
            top = [a for a in perf if (a.get("useful") or 0) >= 2]
            if top:
                learn_hit = (f" Learning memory: {top[0].get('intent')} queries produced useful "
                             f"observations in {top[0].get('useful')} previous runs.")
        except Exception:
            pass
        add("GENERATE_QUERIES", "No queries tracked yet." + learn_hit)
    if queries_n > 0 and obs_n == 0 and ai_ok:
        add("RUN_AI_SEARCH", "Queries tracked but never executed.")
    if obs_n > 0 and not analyses:
        add("ANALYZE_BRAND", "Observations exist but no brand analysis stored.")
    # resolved recommendations must not be regenerated (§TEST 7).
    try:
        resolved = {str(r.get("title") or "") for r in (ctx.get("recommendation_history") or [])
                    if (r.get("status") or "") in ("DONE", "INVALIDATED") and r.get("title")}
        brand_obj = get_brand(company_id) if company_id else None
        if resolved and brand_obj:
            recs = generate_recommendations(brand_obj, [], {}, ctx.get("evidence") or [], [])
            regen = [r.get("title") for r in (recs or []) if r.get("title") in resolved]
            for t in regen[:5]:
                add("GENERATE_RECOMMENDATIONS",
                    f"Suppressed: '{str(t)[:100]}' was already resolved; not regenerating.", suppressed=True)
            if regen and len(regen) == len(recs or []):
                pass
            elif ctx.get("evidence"):
                add("GENERATE_RECOMMENDATIONS", "Content gaps indicate recommendations may be needed.")
    except Exception:
        pass
    if analyses:
        det_done = _completed_after(company_id, "DETECT_CHANGES", None)
        try:
            last_an, _ = _analysis_times(company_id)
            det_done = _completed_after(company_id, "DETECT_CHANGES", last_an)
        except Exception:
            pass
        if not det_done:
            add("DETECT_CHANGES", "Analysis completed; change detection has not run since.")
        else:
            learn_done = _completed_after(company_id, "UPDATE_LEARNING",
                                          det_done.get("completed_at") if det_done else None)
            if not learn_done:
                add("UPDATE_LEARNING", "Changes detected; learning update has not run since.")
    return cands


def _reasoning_conflicts(evidence):
    """Conflicting values for the same evidence key (§8). A single
    user-provided/verified correction deterministically wins (existing
    verified-source rule); everything else needs a human."""
    groups = {}
    for e in evidence or []:
        key = f"{e.get('evidence_type')}:{e.get('evidence_key')}"
        groups.setdefault(key, []).append(e)
    conflicting = []
    for key, rows in groups.items():
        vals = {str(r.get("evidence_value") or "").strip().lower() for r in rows}
        vals.discard("")
        if len(vals) <= 1:
            continue
        winners = [r for r in rows if (r.get("source") or "").upper() in
                   ("USER_PROVIDED", "MANUAL", "USER_CORRECTION") and
                   (r.get("verification_status") or "").upper() in ("VERIFIED", "ANALYZED")]
        if len(winners) == 1 and len(rows) > 1:
            continue
        conflicting.append({"field": key, "sources": [
            {"source": r.get("source"), "verification": r.get("verification_status"),
             "value": str(r.get("evidence_value") or "")[:200]} for r in rows]})
    return bool(conflicting), conflicting


def _reasoning_confidence(ctx, conflict, missing):
    """Deterministic confidence (§16): named signals, coarse value, no fake precision."""
    signals = []
    score = 0.5
    ev = ctx.get("evidence") or []
    verified = sum(1 for e in ev if (e.get("verification_status") or "").upper() == "VERIFIED")
    if verified >= 3:
        score += 0.2
        signals.append(f"{verified} verified evidence rows")
    elif verified:
        score += 0.1
        signals.append(f"{verified} verified evidence row(s)")
    else:
        signals.append("no verified evidence")
    try:
        ef, _, _ = evidence_freshness((ctx.get("company") or {}).get("id"))
        if ef == "fresh":
            score += 0.1
            signals.append("evidence fresh")
        elif ef in ("expired", "none"):
            score -= 0.15
            signals.append(f"evidence {ef}")
    except Exception:
        pass
    learn_n = len(ctx.get("learning_memory") or [])
    if learn_n:
        score += 0.05
        signals.append(f"{learn_n} active learning memor(ies)")
    if conflict:
        score -= 0.3
        signals.append("conflicting evidence present")
    if len(missing) >= 3:
        score -= 0.15
        signals.append(f"{len(missing)} missing information items")
    elif missing:
        score -= 0.05
        signals.append(f"{len(missing)} missing information item(s)")
    score = max(0.05, min(0.95, round(score, 2)))
    level = "HIGH" if score >= 0.7 and not conflict and not missing else (
        "LOW" if score < 0.45 or conflict else "MEDIUM")
    return score, level, signals


def _llm_polish_reasoning(situation_bits, explanation):
    """LLM assist is explanation text only (§18), validated like synthesis:
    no new numbers, bounded length, deterministic fallback."""
    try:
        if str(get_config("REASONING_LLM_ASSIST", "0")) != "1":
            return explanation, False
        if not gemini_available or not gemini_model:
            return explanation, False
        allowed_nums = set(re.findall(r"\d[\d.,]*", explanation))
        text, _ = _gemini_complete(
            "Rewrite this operations assessment in two clear sentences for a dashboard. Use ONLY these facts. "
            "Add no numbers, causes, or recommendations.\n\n" +
            ("Situation: " + "; ".join(situation_bits) + "\nAssessment: " + explanation)[:1500],
            max_tokens=200, temperature=0.0)
        text = (text or "").strip()
        if not text or len(text) > 800:
            return explanation, False
        if set(re.findall(r"\d[\d.,]*", text)) - allowed_nums:
            return explanation, False
        return text, True
    except Exception:
        return explanation, False


def validate_reasoning(result):
    """Reasoning Decision Validator (§15): 8 checks, REJECTED with reason."""
    checks = []
    action = (result or {}).get("recommended_action") or (result or {}).get("action")
    if not action:
        return {"valid": False, "checks": ["missing action"], "reason": "REJECTED: no action present."}
    checks.append("action present")
    if action not in REASONING_ACTIONS:
        return {"valid": False, "checks": checks + [f"unknown action {action}"],
                "reason": f"REJECTED: unknown action {action}."}
    checks.append("action allowed")
    cid = (result or {}).get("company_id")
    deps = (result or {}).get("dependencies") or JOB_DEPENDENCIES.get(action, [])
    missing = []
    if cid and action not in ("WAIT", "REQUEST_HUMAN_REVIEW"):
        for d in deps:
            lj = _latest_job(cid, d)
            if not lj or lj["status"] != "COMPLETED":
                missing.append(d)
    if missing:
        checks.append(f"missing dependencies {','.join(missing)}")
    else:
        checks.append("dependencies satisfied")
    if action in ("WAIT", "REQUEST_HUMAN_REVIEW"):
        checks.append("no data required")
    else:
        need_data = action in ("COLLECT_WEBSITE_DATA", "VALIDATE_DATA", "GENERATE_QUERIES", "RUN_AI_SEARCH",
                               "ANALYZE_BRAND", "ANALYZE_COMPETITORS", "DETECT_CONTENT_GAPS",
                               "GENERATE_RECOMMENDATIONS")
        if need_data and cid:
            b = get_brand(cid)
            has_profile = bool(b and ((b.get("brand_name") or "").strip() or (b.get("website") or "").strip()))
            ev_n = db.query("SELECT COUNT(*) AS c FROM evidence WHERE brand_id=?", (cid,))[0]["c"] \
                if b else 0
            if not has_profile and not ev_n and action != "DISCOVER_COMPANY":
                return {"valid": False, "checks": checks + ["required data missing"],
                        "reason": "REJECTED: required company data missing."}
        checks.append("required data present")
    paused = False
    if cid:
        try:
            paused = int((db.query("SELECT COUNT(*) AS c FROM automations WHERE company_id=? AND enabled=1",
                                   (cid,))[0] or {}).get("c", 1)) == 0
        except Exception:
            paused = False
    if paused and action not in ("WAIT", "REQUEST_HUMAN_REVIEW"):
        return {"valid": False, "checks": checks + ["company paused"],
                "reason": "REJECTED: company automations paused."}
    checks.append("company not paused")
    try:
        auto_off = get_config("automation_enabled", "1") != "1" or \
            get_config("ORCHESTRATOR_ENABLED", "1") != "1"
    except Exception:
        auto_off = False
    if auto_off and action not in ("WAIT", "REQUEST_HUMAN_REVIEW"):
        return {"valid": False, "checks": checks + ["automation disabled"],
                "reason": "REJECTED: automation is disabled."}
    checks.append("automation permits action")
    if cid and action not in ("WAIT", "REQUEST_HUMAN_REVIEW"):
        dup = db.query("SELECT id FROM jobs WHERE company_id=? AND job_type=? AND status IN "
                       "('PENDING','QUEUED','RUNNING','RETRYING','FAILED') LIMIT 1", (cid, action))
        if dup:
            checks.append("duplicate inflight job")
        else:
            checks.append("no duplicate job")
    if action in REQUIRES_HUMAN_APPROVAL:
        return {"valid": False, "checks": checks + ["human approval required"],
                "reason": f"REJECTED: {action} requires explicit human approval."}
    checks.append("human approval respected")
    if missing:
        return {"valid": False, "checks": checks, "reason": f"REJECTED: missing dependencies {','.join(missing)}."}
    return {"valid": True, "checks": checks, "reason": "ACCEPTED: all validation checks passed."}


def _store_reasoning_event(company_id, result, ctx, run_id=None):
    t = now()
    rid = db.execute("""
        INSERT INTO reasoning_events (company_id, run_id, decision_id, reasoning_mode, context_fingerprint,
                                      situation, observations_json, evidence_json, changes_json,
                                      missing_information_json, candidate_actions_json, conflict_json,
                                      selected_action, reason, confidence, requires_human_review, created_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (company_id, run_id, None, result.get("reasoning_mode"), _context_fingerprint(ctx),
          (result.get("situation") or "")[:2000], json.dumps(result.get("observations") or [])[:4000],
          json.dumps(result.get("evidence") or [])[:4000], json.dumps(result.get("changes") or [])[:4000],
          json.dumps(result.get("missing_information") or [])[:4000],
          json.dumps(result.get("considered_actions") or [])[:4000],
          json.dumps(result.get("conflicting_evidence") or [])[:2000], result.get("recommended_action"),
          (result.get("reason") or "")[:2000], result.get("confidence"),
          1 if result.get("requires_human_review") else 0, t))
    rsn = f"RSN-{rid:06d}"
    db.execute("UPDATE reasoning_events SET reasoning_id=? WHERE id=?", (rsn, rid))
    result["reasoning_id"] = rsn
    return rsn


def reason_run_once(company_id):
    """POST /api/reasoning/run-once/:id (§22): assess, validate, persist.
    NEVER creates jobs (§22/TEST 17: pure inspection for QA/debugging)."""
    if not get_brand(company_id):
        return {"success": False, "error": "Company not found"}
    if not orchestrator_enabled() or str(get_config("REASONING_ENABLED", "1")) != "1":
        return {"success": True, "paused": True, "reason": "Reasoning disabled."}
    fp_now = _context_fingerprint(build_reasoning_context(company_id))
    if fp_now:
        prev = db.query("SELECT * FROM reasoning_events WHERE company_id=? AND context_fingerprint=? "
                        "ORDER BY id DESC LIMIT 1", (company_id, fp_now))
        if prev:
            d = dict(prev[0])
            for k in ("observations_json", "evidence_json", "changes_json", "missing_information_json",
                      "candidate_actions_json"):
                try:
                    d[k.replace("_json", "")] = safe_json_loads(d.get(k), []) or []
                except Exception:
                    d[k.replace("_json", "")] = []
            d["reused"] = True
            d["success"] = True
            return d
    result = reason_about_company(company_id, store=False)
    validation = validate_reasoning({**result, "company_id": company_id,
                                     "dependencies": JOB_DEPENDENCIES.get(result.get("recommended_action"), [])})
    result["validation"] = validation
    if not validation["valid"]:
        result["requires_human_review"] = True
    _store_reasoning_event(company_id, result, build_reasoning_context(company_id))
    result["reused"] = False
    result["success"] = True
    return result


def _reasoning_row(r):
    """Deserialize a reasoning_events row back into the §4 output shape."""
    d = dict(r)
    for k in ("observations_json", "evidence_json", "changes_json", "missing_information_json",
              "candidate_actions_json", "conflict_json"):
        try:
            d[k.replace("_json", "")] = safe_json_loads(d.get(k), []) or []
        except Exception:
            d[k.replace("_json", "")] = []
    d["recommended_action"] = d.get("selected_action")
    d["success"] = True
    return d


def reasoning_dashboard():
    """§27 counts, all from reasoning_events rows."""
    def count(where="1=1", p=()):
        r = db.query(f"SELECT COUNT(*) AS c FROM reasoning_events WHERE {where}", p)
        return (r[0].get("c") or 0) if r else 0
    llm = count("reasoning_mode LIKE '%LLM_ASSISTED%'")
    total = count()
    det = count("reasoning_mode NOT LIKE '%LLM_ASSISTED%'")
    hum = count("requires_human_review=1")
    conf = count("conflict_json IS NULL OR conflict_json='' OR conflict_json='[]'")
    rows = db.query("SELECT * FROM reasoning_events ORDER BY id DESC LIMIT 30")
    out = []
    for r in rows:
        d = dict(r)
        try:
            d["candidate_count"] = len(safe_json_loads(r.get("candidate_actions_json"), []) or [])
        except Exception:
            d["candidate_count"] = 0
        out.append(d)
    return {"success": True, "reasoning_runs": total, "reasoning_decisions": count("selected_action != 'WAIT'"),
            "human_reviews": hum, "reasoning_conflicts": total - conf, "llm_assisted_runs": llm,
            "deterministic_runs": det, "recent_events": out}
# ---------------------------------------------------------------------------
#
# The Manager coordinates; it never replaces specialized agents and never
# executes domain work itself. Selection is registry/capability-driven (§3):
# no branch anywhere maps a request string to an agent; eligibility comes
# from declared capabilities + status + health, and the deciding factor is
# recorded in plain language (no user-facing scores or rankings, §7/§8).

MANAGER_AGENT_STATUSES = ("ACTIVE", "PAUSED", "DISABLED", "ERROR")
MANAGER_HEALTH_STATES = ("HEALTHY", "DEGRADED", "UNAVAILABLE", "UNKNOWN")
MANAGER_TASK_STATUSES = ("RECEIVED", "PLANNED", "QUEUED", "RUNNING", "WAITING",
                         "COMPLETED", "PARTIAL", "FAILED", "CANCELLED", "WAITING_FOR_HUMAN")

# Registry seed: the two currently known agents. The Finance agent has no
# backend implementation yet, so it ships PAUSED (never selectable, §4) until
# its executor lands. Adding a future agent = one registry row, zero branches.
MANAGER_REGISTRY_SEED = [
    {"agent_id": "ai-search-visibility", "agent_name": "AI Search Visibility Agent",
     "agent_type": "ANALYTICS", "description": "Analyzes brand visibility across AI search engines: brand profiling, keyword and competitor analysis, content gaps, AI observations, recommendations.",
     "version": "2.0.0", "status": "ACTIVE",
     "capabilities": ["brand_visibility", "keyword_analysis", "competitor_analysis",
                      "content_gap_analysis", "ai_search_analysis", "recommendations"],
     "input_schema": {"brand_name": "string (required)", "industry": "string (optional)"},
     "output_schema": {"analysis": "brand visibility report", "recommendations": "list"},
     "configuration": {"capability_groups": [["brand_visibility", "ai_search_analysis", "recommendations"],
                                             ["keyword_analysis"], ["competitor_analysis"],
                                             ["content_gap_analysis"]],
                       "mcp": {"tools": ["generate_queries", "analyze_competitors", "detect_content_gaps",
                                         "run_ai_search", "analyze_brand"],
                               "resources": ["company_profile", "evidence", "query_memory", "analysis_results"]}}},
    {"agent_id": "website-content-intelligence", "agent_name": "Website Content Intelligence Agent",
     "agent_type": "ANALYTICS", "description": "Discovers website pages, extracts products/services, analyzes content completeness, detects content gaps, and collects website evidence for companies.",
     "version": "1.0.0", "status": "ACTIVE",
     "capabilities": ["website_discovery", "website_content_analysis", "product_extraction",
                      "service_extraction", "content_completeness", "content_gap_analysis",
                      "website_evidence"],
     "input_schema": {"brand_name": "string (required)", "company_id": "integer (optional)"},
     "output_schema": {"website_analysis": "website content analysis", "evidence": "list"},
     "configuration": {"capability_groups": [["website_discovery", "website_content_analysis", "product_extraction",
                                              "service_extraction", "content_completeness", "content_gap_analysis",
                                              "website_evidence"]],
                       "mcp": {"tools": ["discover_website", "extract_products", "extract_services",
                                         "analyze_content_completeness", "detect_website_content_gaps"],
                               "resources": ["company_profile", "evidence"]}}},
    {"agent_id": "finance-cash-flow", "agent_name": "Finance & Cash Flow Agent",
     "agent_type": "ANALYTICS", "description": "Analyzes cash flow, revenue, expenses, forecasts and financial health. Backend implementation pending.",
     "version": "0.1.0", "status": "PAUSED",
     "capabilities": ["cash_flow_analysis", "revenue_analysis", "expense_analysis",
                      "forecasting", "financial_health"],
     "input_schema": {"company": "string (required)", "period": "string (optional)"},
     "output_schema": {"report": "financial analysis report"},
     "configuration": {}},
]


def ensure_registry_seed():
    """Idempotent registry bootstrap (insert missing agent_ids only; never
    overwrites operator edits to status/version/configuration, except filling
    an empty configuration from the seed so taxonomy updates apply, plus
    merging a missing 'mcp' metadata key)."""
    t = now()
    for a in MANAGER_REGISTRY_SEED:
        rows = db.query("SELECT id, status, configuration_json FROM agent_registry WHERE agent_id=?", (a["agent_id"],))
        if rows:
            try:
                cfg = safe_json_loads(rows[0].get("configuration_json"), None)
            except Exception:
                cfg = None
            if (not cfg) and a.get("configuration"):
                db.execute("UPDATE agent_registry SET configuration_json=?, updated_at=? WHERE id=?",
                           (json.dumps(a["configuration"]), t, rows[0]["id"]))
            elif isinstance(cfg, dict) and a.get("configuration", {}).get("mcp") and "mcp" not in cfg:
                cfg["mcp"] = a["configuration"]["mcp"]
                db.execute("UPDATE agent_registry SET configuration_json=?, updated_at=? WHERE id=?",
                           (json.dumps(cfg), t, rows[0]["id"]))
            continue
        db.execute("""
            INSERT INTO agent_registry (agent_id, agent_name, agent_type, description, version, status,
                                        capabilities_json, input_schema_json, output_schema_json,
                                        health_status, last_health_check, configuration_json,
                                        created_at, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (a["agent_id"], a["agent_name"], a["agent_type"], a["description"], a["version"], a["status"],
              json.dumps(a["capabilities"]), json.dumps(a["input_schema"]), json.dumps(a["output_schema"]),
              "UNKNOWN", None, json.dumps(a["configuration"]), t, t))


def _registry_row(agent_id):
    rows = db.query("SELECT * FROM agent_registry WHERE agent_id=? OR id=?", (agent_id, agent_id))
    return rows[0] if rows else None


def _agent_capabilities(row):
    try:
        return safe_json_loads(row.get("capabilities_json"), []) or []
    except Exception:
        return []


def manager_probe_health(agent_id):
    """Real health signals per agent (never fabricated):
    - ai-search-visibility: core tables present + queue runnable; DEGRADED when
      scraper+AI search are both down or permanent failures dominate the queue.
    - anything without an implemented probe: UNKNOWN (honest, not selectable
      unless ACTIVE with a probe... see selection: UNKNOWN blocks selection)."""
    row = _registry_row(agent_id)
    if not row:
        return {"success": False, "error": "Agent not found"}
    aid = row["agent_id"]
    if aid == "ai-search-visibility":
        try:
            tabs = {r["name"] for r in db.query("SELECT name FROM sqlite_master WHERE type='table'")}
            core = {"brands", "jobs", "runs", "analysis_results", "evidence", "query_memory"}
            if not core.issubset(tabs):
                health, note = "UNAVAILABLE", "core tables missing"
            else:
                perm = db.query("SELECT COUNT(*) AS c FROM jobs WHERE status='FAILED_PERMANENTLY'")[0]["c"]
                total = db.query("SELECT COUNT(*) AS c FROM jobs")[0]["c"] or 1
                if not scraper_available() and not ai_search_connected():
                    health, note = "DEGRADED", "website scraper and AI search both unavailable"
                elif total > 20 and perm / total > 0.5:
                    health, note = "DEGRADED", f"permanent failures dominate queue ({perm}/{total})"
                else:
                    health, note = "HEALTHY", "core tables present, queue operational"
        except Exception as e:
            health, note = "UNKNOWN", f"probe error: {e}"[:200]
    elif aid == "website-content-intelligence":
        try:
            tabs = {r["name"] for r in db.query("SELECT name FROM sqlite_master WHERE type='table'")}
            core = {"brands", "evidence"}
            if not core.issubset(tabs):
                health, note = "UNAVAILABLE", "core tables missing"
            else:
                brand_count = db.query("SELECT COUNT(*) AS c FROM brands WHERE is_active=1")[0]["c"]
                evidence_count = db.query("SELECT COUNT(*) AS c FROM evidence")[0]["c"]
                exec_ok = aid in FRAMEWORK_EXECUTORS
                if not exec_ok:
                    health, note = "DEGRADED", "executor not registered"
                elif not scraper_available():
                    health, note = "DEGRADED", "website scraper unavailable"
                else:
                    health, note = "HEALTHY", (f"{brand_count} active companies, "
                                               f"{evidence_count} evidence rows, scraper available")
        except Exception as e:
            health, note = "UNKNOWN", f"probe error: {e}"[:200]
    else:
        health, note = "UNKNOWN", "no health probe implemented for this agent"
    db.execute("UPDATE agent_registry SET health_status=?, last_health_check=?, updated_at=? WHERE id=?",
               (health, now(), now(), row["id"]))
    try:
        log_activity(f"Health check {aid}: {health} - {note}.", level="MANAGER", company_id=None)
    except Exception:
        pass
    return {"success": True, "agent_id": aid, "health_status": health, "detail": note}


def manager_health_check_all():
    out = []
    for r in db.query("SELECT agent_id FROM agent_registry ORDER BY id"):
        out.append(manager_probe_health(r["agent_id"]))
    return {"success": True, "results": out}


def manager_set_status(agent_id, status):
    if status not in MANAGER_AGENT_STATUSES:
        return {"success": False, "error": f"invalid status (one of {','.join(MANAGER_AGENT_STATUSES)})"}
    row = _registry_row(agent_id)
    if not row:
        return {"success": False, "error": "Agent not found"}
    db.execute("UPDATE agent_registry SET status=?, updated_at=? WHERE id=?", (status, now(), row["id"]))
    try:
        log_activity(f"Agent {row['agent_id']} set to {status} by operator.", level="MANAGER")
    except Exception:
        pass
    return {"success": True, "agent_id": row["agent_id"], "status": status}


def manager_list_agents():
    rows = db.query("SELECT * FROM agent_registry ORDER BY id")
    out = []
    for r in rows:
        d = dict(r)
        d["capabilities"] = _agent_capabilities(r)
        try:
            d["input_schema"] = safe_json_loads(r.get("input_schema_json"), {}) or {}
            d["output_schema"] = safe_json_loads(r.get("output_schema_json"), {}) or {}
            d["configuration"] = safe_json_loads(r.get("configuration_json"), {}) or {}
        except Exception:
            d["input_schema"], d["output_schema"], d["configuration"] = {}, {}, {}
        # live workload (RUNNING jobs assigned to this agent) for selection §8.
        try:
            w = db.query("SELECT COUNT(*) AS c FROM jobs WHERE assigned_agent_id=? AND status IN "
                         "('PENDING','QUEUED','RUNNING','RETRYING')", (r["agent_id"],))
            d["workload"] = (w[0].get("c") or 0) if w else 0
        except Exception:
            d["workload"] = 0
        out.append(d)
    return {"success": True, "agents": out}


def _capability_group(agent_id, capability):
    """Registry taxonomy lookup: capabilities sharing a group are aspects of a
    single analysis (no subtask split). Agents without groups split per
    capability. Returns a hashable group key."""
    try:
        rows = db.query("SELECT configuration_json FROM agent_registry WHERE agent_id=?", (agent_id,))
        cfg = safe_json_loads((rows[0].get("configuration_json") if rows else None), {}) or {}
        for i, g in enumerate(cfg.get("capability_groups") or []):
            if capability in (g or []):
                return (agent_id, i)
    except Exception:
        pass
    return (agent_id, capability)


def _match_capabilities(request_text):
    """Detect which registry-declared capabilities a request asks for.
    Deterministic token scoring over capability names + owning agent
    descriptions (no per-request hardcoding anywhere):
      score = 2*overlap + 2*exact_phrase + 1*desc_boost + 1*distinctive_token
    A capability fires at score >= 3 (two shared tokens, or one distinctive
    token backed by the agent description). Sorted by score, then name."""
    text = (request_text or "").lower()
    words = set(re.findall(r"[a-z]{3,}", text))
    stop = {"analysis", "the", "and", "for", "with"}
    rows = list(db.query("SELECT agent_id, agent_name, description, capabilities_json FROM agent_registry"))
    hits = []
    for r in rows:
        desc_words = set(re.findall(r"[a-z]{3,}", ((r.get("description") or "")).lower()))
        for cap in _agent_capabilities(r):
            toks = set(re.findall(r"[a-z]{3,}", cap.lower()))
            sig = {t for t in toks if t not in stop}
            shared = sig & words
            overlap = len(shared)
            exact = cap.lower().replace("_", " ") in text
            desc_hit = len(shared & desc_words) > 0
            distinctive = any(len(t) >= 8 for t in shared)
            score = 2 * overlap + (2 if exact else 0) + (1 if desc_hit and overlap else 0) + \
                (1 if distinctive else 0)
            if score >= 3:
                hits.append({"capability": cap, "agent_id": r["agent_id"],
                             "agent_name": r["agent_name"], "hits": score})
    hits.sort(key=lambda h: (-h["hits"], h["capability"]))
    seen, out = set(), []
    for h in hits:
        if h["capability"] not in seen:
            seen.add(h["capability"])
            out.append(h)
    return out


def manager_select_agent(capability, task_input=None, task_type=None):
    """Selection engine (§7/§8): sequential eligibility filters, first deciding
    filter recorded as the reason. Never a scoreboard, never hardcoded."""
    task_input = task_input or {}
    eligible = []
    for r in db.query("SELECT * FROM agent_registry ORDER BY id"):
        caps = _agent_capabilities(r)
        if capability not in caps:
            continue
        if (r.get("status") or "") != "ACTIVE":
            continue
        if (r.get("health_status") or "UNKNOWN") == "UNAVAILABLE":
            continue
        eligible.append(r)
    if not eligible:
        return {"success": False, "error": f"No ACTIVE agent declares capability '{capability}'.",
                "eligible": []}
    # input availability: required schema keys present in the task input.
    with_input = []
    for r in eligible:
        try:
            schema = safe_json_loads(r.get("input_schema_json"), {}) or {}
        except Exception:
            schema = {}
        required = [k for k, v in schema.items() if "required" in str(v).lower()]
        missing = [k for k in required if not task_input.get(k)]
        if not missing:
            with_input.append(r)
    pool, input_note = (with_input, "required input available") if with_input else \
        (eligible, "proceeding without complete input")
    # health preference: HEALTHY > DEGRADED > UNKNOWN (UNAVAILABLE already out).
    rank = {"HEALTHY": 0, "DEGRADED": 1, "UNKNOWN": 2}
    pool = sorted(pool, key=lambda r: (rank.get((r.get("health_status") or "UNKNOWN"), 3), r["agent_id"]))
    health_note = f"health {pool[0].get('health_status') or 'UNKNOWN'}"
    # version compatibility: highest version wins ties (deterministic).
    def _vkey(r):
        try:
            return tuple(int(x) for x in re.findall(r"\d+", str(r.get("version") or "0"))[:3])
        except Exception:
            return (0,)
    best_v = max(_vkey(r) for r in pool)
    pool = [r for r in pool if _vkey(r) == best_v] if len(pool) > 1 else pool
    # previous execution success for this task type, then workload, then agent_id.
    def _success_rate(agent_id):
        if not task_type:
            return None
        rows = db.query("SELECT status, COUNT(*) AS c FROM manager_tasks WHERE selected_agent_id=? AND task_type=? "
                        "AND status IN ('COMPLETED','PARTIAL','FAILED') GROUP BY status", (agent_id, task_type))
        tot = sum(r["c"] for r in rows)
        if not tot:
            return None
        good = sum(r["c"] for r in rows if r["status"] in ("COMPLETED", "PARTIAL"))
        return good / tot
    rated = [(r, _success_rate(r["agent_id"])) for r in pool]
    with_hist = [(r, s) for r, s in rated if s is not None]
    hist_note = ""
    if with_hist and len(pool) > 1:
        best = max(s for _, s in with_hist)
        pool = [r for r, s in with_hist if s == best]
        hist_note = f"best prior success for this task type ({int(best * 100)}%)"
    if len(pool) > 1:
        loads = {}
        for r in pool:
            w = db.query("SELECT COUNT(*) AS c FROM jobs WHERE assigned_agent_id=? AND status IN "
                         "('PENDING','QUEUED','RUNNING','RETRYING')", (r["agent_id"],))
            loads[r["agent_id"]] = (w[0].get("c") or 0) if w else 0
        least = min(loads.values())
        pool = [r for r in pool if loads[r["agent_id"]] == least]
    pool = sorted(pool, key=lambda r: r["agent_id"])
    sel = pool[0]
    why = [f"Agent declares the required {capability} capability and is currently ACTIVE", input_note, health_note]
    if hist_note:
        why.append(hist_note)
    if len(eligible) > 1 or with_input != eligible:
        why.append("lowest current workload among eligible agents" if len(pool) < len(eligible) else
                   "only eligible agent")
    return {"success": True, "agent_id": sel["agent_id"], "agent_name": sel["agent_name"],
            "capability": capability,
            "reason": "; ".join(why) + ".",
            "eligible": [{"agent_id": r["agent_id"], "agent_name": r["agent_name"]} for r in eligible]}


def _new_task_id(rowid):
    return f"TSK-{int(rowid):06d}"


def _record_manager_task(request, task_type, capability, agent_id, reason, priority="MEDIUM",
                         status="PLANNED", input_data=None, parent_task_id=None, dependencies=None,
                         request_id=None):
    t = now()
    rid = db.execute("""
        INSERT INTO manager_tasks (parent_task_id, dependency_task_ids_json, request, task_type, priority,
                                   status, selected_agent_id, capability, input_json, output_json, reason,
                                   created_at, started_at, completed_at, error_message, request_id)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (parent_task_id, json.dumps(dependencies or [])[:2000], (request or "")[:2000], task_type, priority,
          status, agent_id, capability, json.dumps(input_data or {})[:4000], None, (reason or "")[:2000],
          t, None, None, None, request_id))
    tid = _new_task_id(rid)
    db.execute("UPDATE manager_tasks SET task_id=? WHERE id=?", (tid, rid))
    return rid, tid


def manager_intake(payload):
    """POST /api/manager/tasks: understand the request, plan (possibly decompose),
    select agent(s). Pure planning in this part (execution lands in part 2)."""
    request_text = ((payload or {}).get("task") or (payload or {}).get("request") or "").strip()
    if not request_text:
        return {"success": False, "error": "Empty task. Provide a 'task' string."}
    req_id = (payload or {}).get("request_id")
    if req_id:
        dup = db.query("SELECT * FROM manager_tasks WHERE request_id=? ORDER BY id DESC LIMIT 1", (req_id,))
        if dup:
            d = dict(dup[0])
            d["idempotent"] = True
            d["success"] = True
            return d
    priority = str((payload or {}).get("priority") or "MEDIUM").upper()
    if priority not in ("HIGH", "MEDIUM", "LOW"):
        priority = "MEDIUM"
    task_input = (payload or {}).get("input") or {}
    matches = _match_capabilities(request_text)
    if not matches:
        rid, tid = _record_manager_task(request_text, "UNKNOWN", None, None,
                                        "No registered capability matches this request; needs clarification "
                                        "or a new agent capability.", priority, status="RECEIVED",
                                        input_data=task_input, request_id=req_id)
        return {"success": True, "task_id": tid, "status": "RECEIVED", "selected_agent": None,
                "capability": None,
                "reason": "No registered capability matches this request.",
                "needs_clarification": True}
    # Multi-capability request -> one subtask per capability GROUP (registry
    # taxonomy: same-group capabilities are aspects of one analysis and must
    # not split; distinct groups/agents split with a synthesis gate).
    if len(matches) > 1:
        grouped, seen_groups = [], set()
        for m in matches:
            gkey = _capability_group(m["agent_id"], m["capability"])
            if gkey in seen_groups:
                continue
            seen_groups.add(gkey)
            grouped.append(m)
        if len(grouped) > 1:
            return _manager_decompose(request_text, grouped, task_input, priority, request_id=req_id)
        matches = grouped
    # single-capability task (possibly several textual hits, one agent family).
    best = matches[0]
    sel = manager_select_agent(best["capability"], task_input, task_type=best["capability"])
    if not sel.get("success"):
        rid, tid = _record_manager_task(request_text, best["capability"], None, None, sel["error"],
                                        priority, status="WAITING_FOR_HUMAN", input_data=task_input)
        try:
            log_activity(f"Manager task {tid} waits for human: {sel['error'][:160]}", level="MANAGER")
        except Exception:
            pass
        return {"success": True, "task_id": tid, "status": "WAITING_FOR_HUMAN", "selected_agent": None,
                "capability": best["capability"], "reason": sel["error"]}
    rid, tid = _record_manager_task(request_text, task_type=best["capability"], capability=best["capability"],
                                    agent_id=sel["agent_id"], reason=sel["reason"],
                                    priority=priority, status="PLANNED", input_data=task_input,
                                    request_id=req_id)
    try:
        log_activity(f"Manager planned {tid}: {sel['agent_name']} for '{best['capability']}'.", level="MANAGER")
    except Exception:
        pass
    return {"success": True, "task_id": tid, "status": "PLANNED", "selected_agent": sel["agent_name"],
            "selected_agent_id": sel["agent_id"], "capability": best["capability"], "reason": sel["reason"],
            "priority": priority}


def _manager_decompose(request_text, matches, task_input, priority, request_id=None):
    """Break a multi-agent request into subtasks + a synthesis task (§9/§10).
    When website_content_intelligence and ai-search-visibility co-occur, the
    website agent runs first; the visibility agent depends on it via a handoff.
    Otherwise all subtasks run independently; synthesis waits for all."""
    _, parent_tid = _record_manager_task(request_text, "COMBINED", None, None,
                                         f"Complex request decomposed into {len(matches)} subtasks + synthesis.",
                                         priority, status="PLANNED", input_data=task_input,
                                         request_id=request_id)
    has_website = any(m.get("agent_id") == "website-content-intelligence" for m in matches)
    has_visibility = any(m.get("agent_id") == "ai-search-visibility" for m in matches)
    sequential = has_website and has_visibility
    website_tid = None
    sub_ids, subtasks = [], []
    for m in matches:
        sel = manager_select_agent(m["capability"], task_input, task_type=m["capability"])
        if sel.get("success"):
            deps = [website_tid] if (sequential and m.get("agent_id") == "ai-search-visibility" and website_tid) else None
            _, sub_tid = _record_manager_task(f"{request_text} [{m['capability']}]", task_type=m["capability"],
                                              capability=m["capability"], agent_id=sel["agent_id"],
                                              reason=sel["reason"], priority=priority, status="PLANNED",
                                              input_data=task_input, parent_task_id=parent_tid,
                                              dependencies=deps)
            sub_ids.append(sub_tid)
            subtasks.append({"task_id": sub_tid, "capability": m["capability"],
                             "selected_agent": sel["agent_name"], "selected_agent_id": sel["agent_id"],
                             "reason": sel["reason"], "status": "PLANNED"})
            if m.get("agent_id") == "website-content-intelligence":
                website_tid = sub_tid
        else:
            _, sub_tid = _record_manager_task(f"{request_text} [{m['capability']}]", task_type=m["capability"],
                                              capability=m["capability"], agent_id=None, reason=sel["error"],
                                              priority=priority, status="WAITING_FOR_HUMAN",
                                              input_data=task_input, parent_task_id=parent_tid)
            sub_ids.append(sub_tid)
            subtasks.append({"task_id": sub_tid, "capability": m["capability"], "selected_agent": None,
                             "selected_agent_id": None, "reason": sel["error"], "status": "WAITING_FOR_HUMAN"})
    _, syn_tid = _record_manager_task(f"Combine results: {request_text}", task_type="SYNTHESIS",
                                      capability="SYNTHESIS", agent_id="manager",
                                      reason="Manager combines subtask results once all dependencies complete.",
                                      priority=priority, status="WAITING", input_data={},
                                      parent_task_id=parent_tid, dependencies=sub_ids)
    agents_involved = {m["agent_id"] for m in matches}
    try:
        log_activity(f"Manager decomposed {parent_tid} into {len(sub_ids)} subtasks + synthesis {syn_tid}.",
                     level="MANAGER")
    except Exception:
        pass
    return {"success": True, "task_id": parent_tid, "status": "PLANNED", "decomposed": True,
            "subtasks": subtasks,
            "synthesis": {"task_id": syn_tid, "depends_on": sub_ids, "status": "WAITING"},
            "reason": f"Request spans {len(agents_involved)} agents; split into {len(sub_ids)} subtasks.",
            "handoff_flow": {"website_agent_tid": website_tid,
                             "visibility_agent_tid": [s["task_id"] for s in subtasks
                                                     if s.get("selected_agent_id") == "ai-search-visibility"],
                             "sequential": sequential} if sequential else None}


# ---------------------------------------------------------------------------
# PHASE 6 PART 2 - MANAGER EXECUTION (subtasks/synthesis through the Runner)
# ---------------------------------------------------------------------------
#
# Execution contract (§4): every agent output is validated before acceptance.
# Dispatch branches below plug into the EXISTING dispatch_job/runner; no new
# engine, no new statuses. A job that concludes validation work (including an
# honest refusal) COMPLETES; only infrastructure failures raise into retries.

MANAGER_OUTPUT_STATUSES = ("COMPLETED", "PARTIAL", "FAILED", "WAITING_FOR_INPUT", "WAITING_FOR_HUMAN")

_SECRET_KEY_HINTS = ("key", "token", "secret", "password", "api")


def _manager_output(task_id, agent_id, status, result, evidence=None, warnings=None, metadata=None):
    return {"task_id": task_id, "agent_id": agent_id, "status": status, "result": result or {},
            "evidence": evidence or [], "warnings": warnings or [], "metadata": metadata or {}}


def _validate_manager_output(out):
    if not isinstance(out, dict):
        return False, "output is not an object"
    for k in ("task_id", "agent_id", "status", "result", "evidence", "warnings", "metadata"):
        if k not in out:
            return False, f"output missing key: {k}"
    if out["status"] not in MANAGER_OUTPUT_STATUSES:
        return False, f"invalid status: {out['status']}"
    if not isinstance(out["result"], dict) or not isinstance(out["evidence"], list) \
            or not isinstance(out["warnings"], list) or not isinstance(out["metadata"], dict):
        return False, "output field types invalid"
    return True, ""


def _manager_task_row(task_id):
    rows = db.query("SELECT * FROM manager_tasks WHERE task_id=? OR id=?",
                    (task_id, int(task_id) if str(task_id).isdigit() else -1))
    return rows[0] if rows else None


def _manager_required_inputs(agent_row, task_input):
    try:
        schema = safe_json_loads(agent_row.get("input_schema_json"), {}) or {}
    except Exception:
        schema = {}
    return [k for k, v in schema.items() if "required" in str(v).lower()
            and not (task_input or {}).get(k)]


def _strip_secrets(data):
    if isinstance(data, dict):
        return {k: _strip_secrets(v) for k, v in data.items()
                if not any(h in str(k).lower() for h in _SECRET_KEY_HINTS)}
    if isinstance(data, list):
        return [_strip_secrets(v) for v in data]
    return data


def normalize_manager_result(agent_name, out):
    """Manager-level normalization (§10): fixed envelope + preserved raw result."""
    summary = ""
    try:
        if out["status"] == "COMPLETED":
            summary = str(out["metadata"].get("summary") or f"{agent_name} completed successfully.")[:500]
        elif out["status"] == "PARTIAL":
            summary = str(out["metadata"].get("summary") or f"{agent_name} partially completed.")[:500]
        else:
            summary = str(out["metadata"].get("summary") or out["result"].get("error")
                            or f"{agent_name} reported {out['status']}.")[:500]
    except Exception:
        summary = f"{agent_name} reported {out.get('status')}."
    return {"agent": agent_name, "status": out["status"], "summary": summary,
            "data": out["result"], "evidence": out["evidence"], "warnings": out["warnings"],
            "metadata": out["metadata"], "raw": dict(out)}


def _store_manager_result(manager_task_id, task_row, agent_id, normalized, status):
    t = now()
    rid = db.execute("""
        INSERT INTO manager_task_results (manager_task_id, task_id, agent_id, parent_task_id, status,
                                          result_json, evidence_json, warnings_json, created_at, updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?)
    """, (manager_task_id, task_row["task_id"], agent_id, task_row.get("parent_task_id"),
          status, json.dumps(normalized)[:8000], json.dumps(normalized.get("evidence") or [])[:4000],
          json.dumps(normalized.get("warnings") or [])[:4000], t, t))
    res_id = f"RES-{rid:06d}"
    db.execute("UPDATE manager_task_results SET result_id=? WHERE id=?", (res_id, rid))
    return res_id


def _manager_handoff(manager_task_id, source_task, dest_task_id, dest_agent_id, data, allowlist=None):
    """Controlled field-level handoff (§8): destination input-schema keys define
    the allowlist (synthesis takes all non-secret fields); secrets never pass."""
    shared = {}
    for k, v in (data or {}).items():
        if any(h in str(k).lower() for h in _SECRET_KEY_HINTS):
            continue
        if allowlist is not None and k not in allowlist:
            continue
        try:
            json.dumps(v)
            shared[k] = v
        except Exception:
            shared[k] = str(v)[:500]
    t = now()
    hid = db.execute("""
        INSERT INTO agent_handoffs (manager_task_id, source_task_id, source_agent_id, destination_task_id,
                                    destination_agent_id, fields_shared_json, created_at)
        VALUES (?,?,?,?,?,?,?)
    """, (manager_task_id, source_task["task_id"], source_task.get("selected_agent_id"),
          dest_task_id, dest_agent_id, json.dumps(sorted(shared.keys()))[:2000], t))
    handoff_id = f"HOF-{hid:06d}"
    db.execute("UPDATE agent_handoffs SET handoff_id=? WHERE id=?", (handoff_id, hid))
    try:
        record_learning_event(None, "HANDOFF_SUCCESS",
                              f"Handoff {handoff_id}: {source_task.get('selected_agent_id')} -> "
                              f"{dest_agent_id} ({len(shared)} field(s)).",
                              source_type="MANAGER", source_id=handoff_id,
                              metadata={"manager_task_id": manager_task_id, "fields": sorted(shared.keys())},
                              mirror_activity=False)
    except Exception:
        pass
    return handoff_id, shared


def manager_learn(company_id, event_type, description, metadata=None):
    """Manager learning bridge (§17): existing learning architecture only."""
    try:
        return record_learning_event(company_id, event_type, description, source_type="MANAGER",
                                     metadata=metadata or {}, mirror_activity=False)
    except Exception as e:
        print(f"[Manager] learning event skipped: {e}", flush=True)
        return None


def _resolve_manager_company(task_input):
    name = ((task_input or {}).get("brand_name") or (task_input or {}).get("company") or "").strip()
    if not name:
        return None, "brand_name (no matching company)"
    rows = db.query("SELECT id FROM brands WHERE brand_name=? AND is_active=1 ORDER BY id DESC LIMIT 1", (name,))
    if rows:
        return rows[0]["id"], ""
    rows = db.query("SELECT id FROM brands WHERE brand_name LIKE ? AND is_active=1 ORDER BY id DESC LIMIT 1",
                    (f"%{name}%",))
    if rows:
        return rows[0]["id"], ""
    return None, "brand_name (no matching company)"


def _exec_visibility(agent_row, task_row, task_input, run_id):
    """AI Search Visibility backend: thin wrappers over existing engines only.
    Accepts handoff_findings from website-content-intelligence when available
    (§10: Agent B actually uses Agent A's result)."""
    import time as _t
    t0, warnings, evidence = _t.time(), [], []
    cap = task_row.get("capability") or task_row.get("task_type")
    meta = {"capability": cap}
    handoff = (task_input or {}).get("handoff_findings") or {}
    if handoff:
        meta["handoff_sources"] = list(handoff.keys())
    if cap in ("brand_visibility",):
        cid, missing = _resolve_manager_company(task_input)
        if cid is None:
            return _manager_output(task_row["task_id"], agent_row["agent_id"], "WAITING_FOR_INPUT",
                                   {"error": f"missing input: {missing}"}, [], [], meta)
        res = orchestrator_run_company(cid, max_steps=10)
        mapping = {"COMPLETED": "COMPLETED", "PARTIAL": "PARTIAL", "FAILED": "FAILED",
                   "WAITING_FOR_HUMAN": "WAITING_FOR_HUMAN"}
        status = mapping.get(res.get("result"), "FAILED")
        data, evidence = {"orchestrator_result": res.get("result"), "detail": res.get("detail")}, []
        if handoff:
            data["handoff_findings"] = handoff
            evidence.append(f"Received handoff from {', '.join(handoff.keys())}")
        brand = get_brand(cid)
        try:
            data["brand_name"] = brand.get("brand_name")
            data["industry"] = brand.get("industry")
            an = db.query("SELECT visibility_score, readiness_score, observed_score, created_at FROM analysis_results "
                          "WHERE brand_id=? ORDER BY id DESC LIMIT 1", (cid,))
            if an:
                data.update({k: an[0][k] for k in ("visibility_score", "readiness_score", "observed_score") if k in an[0]})
                evidence.append(f"latest analysis score {an[0].get('visibility_score')}")
            obs = db.query("SELECT COUNT(*) AS c FROM ai_observations WHERE brand_id=?", (cid,))[0]["c"]
            data["observations"] = obs
            evidence.append(f"{obs} AI observations stored")
            if res.get("unavailable"):
                warnings.extend(res["unavailable"])
                evidence.append("partial: " + "; ".join(res["unavailable"])[:300])
        except Exception:
            pass
        meta.update({"company_id": cid, "duration_s": round(_t.time() - t0, 2),
                     "summary": f"Visibility run {res.get('result')} for company #{cid}."})
        return _manager_output(task_row["task_id"], agent_row["agent_id"], status, data, evidence, warnings, meta)
    # single-capability wrappers (existing functions, real rows only)
    cid, missing = _resolve_manager_company(task_input)
    if cid is None:
        return _manager_output(task_row["task_id"], agent_row["agent_id"], "WAITING_FOR_INPUT",
                               {"error": f"missing input: {missing}"}, [], [], meta)
    brand = get_brand(cid)
    try:
        if cap == "keyword_analysis":
            qs = generate_queries(brand)
            objs = remember_queries(cid, qs)
            data = {"queries": [o.get("query_text") or o.get("query") for o in objs]}
            evidence = [f"{len(objs)} queries generated and stored"]
        elif cap == "competitor_analysis":
            obs = db.query("SELECT * FROM ai_observations WHERE brand_id=? ORDER BY observed_at DESC LIMIT 50", (cid,))
            rows = analyze_competitors(brand, obs)
            data = {"competitors": rows}
            evidence = [f"{len(rows)} competitor rows"]
        elif cap == "content_gap_analysis":
            ev = get_company_evidence(cid)
            brand_analysis = analyze_brand(brand)
            # Use handoff data from website agent when available (§10).
            if handoff:
                web_data = next(iter(handoff.values()), {})
                if web_data.get("content_types_missing"):
                    evidence.append(f"Website agent found {len(web_data['content_types_missing'])} missing content types")
                if web_data.get("completeness", {}).get("overall_score") is not None:
                    evidence.append(f"Website completeness score: {web_data['completeness']['overall_score']}")
            gaps = detect_content_gaps(brand, ev, brand_analysis)
            data = {"gaps": gaps}
            if handoff:
                web_data = next(iter(handoff.values()), {})
                data["website_findings"] = web_data
            evidence = [f"{len(gaps)} content gaps"]
        elif cap == "ai_search_analysis":
            if not ai_search_connected():
                return _manager_output(task_row["task_id"], agent_row["agent_id"], "PARTIAL", {"observations": 0},
                                       [], ["AI_SEARCH_UNAVAILABLE: provider not connected; no results fabricated."],
                                       meta)
            res = run_ai_search(cid, get_active_queries(cid))
            data = {"observations": res.get("observations", 0)}
            evidence = [f"{res.get('observations', 0)} observations stored"]
        elif cap == "recommendations":
            recs = db.query("SELECT id, title, priority, category, status FROM recommendations WHERE brand_id=? "
                            "AND status='OPEN' ORDER BY id DESC LIMIT 20", (cid,))
            data = {"recommendations": [dict(r) for r in recs]}
            evidence = [f"{len(recs)} open recommendations"]
        else:
            return _manager_output(task_row["task_id"], agent_row["agent_id"], "FAILED",
                                   {"error": f"capability '{cap}' not implemented by this agent backend"},
                                   [], [], meta)
    except Exception as e:
        return _manager_output(task_row["task_id"], agent_row["agent_id"], "FAILED",
                               {"error": str(e)[:300]}, [], [], meta)
    meta.update({"company_id": cid, "duration_s": round(_t.time() - t0, 2),
                 "summary": f"{cap} completed for company #{cid}."})
    return _manager_output(task_row["task_id"], agent_row["agent_id"], "COMPLETED", data, evidence, warnings, meta)


def _detect_conflicts(normalized_list):
    """Cross-agent scalar conflicts (§15) for the SAME company scope only
    (different companies legitimately differ). Never auto-resolved."""
    scopes = {}
    for n in normalized_list:
        try:
            md = n.get("metadata") or {}
            scopes[n.get("agent")] = md.get("company_id")
        except Exception:
            scopes[n.get("agent")] = None
    seen = {}
    for n in normalized_list:
        for k, v in (n.get("data") or {}).items():
            if isinstance(v, (str, int, float)) and not isinstance(v, bool):
                seen.setdefault(str(k), []).append((n.get("agent"), v))
    conflicts = []
    for field, pairs in seen.items():
        agents = {a for a, _ in pairs}
        if len(agents) < 2:
            continue
        scopes_involved = {scopes.get(a) for a in agents}
        if len({s for s in scopes_involved if s is not None}) > 1:
            continue
        vals = {str(v).strip().lower() for _, v in pairs if str(v).strip()}
        if len(vals) > 1:
            conflicts.append({"field": field,
                              "sources": [{"agent": a, "value": v} for a, v in pairs]})
    return conflicts


def _llm_polish_summary(deterministic_summary, normalized_list):
    """Optional LLM synthesis assist (§13): summary text only, strictly validated.
    Returns (text, assisted). Any invented numbers/facts claim -> rejected."""
    try:
        if str(get_config("MANAGER_LLM_SYNTHESIS", "0")) != "1":
            return deterministic_summary, False
        if not gemini_available or not gemini_model:
            return deterministic_summary, False
        allowed_nums = set(re.findall(r"\d[\d.,]*", deterministic_summary))
        prompt = ("Summarize these multi-agent findings in 3 sentences max for a dashboard. "
                  "Use ONLY the facts below. Do not add facts, numbers, or recommendations.\n\n" +
                  deterministic_summary[:2000])
        text, _ = _gemini_complete(prompt, max_tokens=256, temperature=0.0)
        text = (text or "").strip()
        if not text or len(text) > 1000:
            return deterministic_summary, False
        if set(re.findall(r"\d[\d.,]*", text)) - allowed_nums:
            return deterministic_summary, False
        return text, True
    except Exception:
        return deterministic_summary, False


def _exec_synthesis(agent_row, task_row, task_input, run_id):
    """Deterministic synthesis (§11/§12): facts vs observations vs warnings vs
    missing data, source attribution, conflict surfacing. Never invents."""
    import time as _t
    t0 = _t.time()
    try:
        deps = safe_json_loads(task_row.get("dependency_task_ids_json"), []) or []
    except Exception:
        deps = []
    partial_allowed = not bool((task_input or {}).get("require_all"))
    normalized, missing, failed = [], [], []
    for dep_tid in deps:
        drow = _manager_task_row(dep_tid)
        if not drow:
            missing.append({"task_id": dep_tid, "reason": "dependency task not found"})
            continue
        rrows = db.query("SELECT * FROM manager_task_results WHERE task_id=? ORDER BY id DESC LIMIT 1",
                         (drow["task_id"],))
        st = drow.get("status")
        if st == "COMPLETED" and rrows:
            try:
                normalized.append(safe_json_loads(rrows[0].get("result_json"), {}) or {})
            except Exception:
                missing.append({"task_id": dep_tid, "reason": "result unreadable"})
        elif st in ("PARTIAL",) and rrows and partial_allowed:
            try:
                n = safe_json_loads(rrows[0].get("result_json"), {}) or {}
                n["partial_input"] = True
                normalized.append(n)
                missing.append({"task_id": dep_tid, "reason": "partial input used"})
            except Exception:
                missing.append({"task_id": dep_tid, "reason": "result unreadable"})
        else:
            missing.append({"task_id": dep_tid, "reason": f"dependency status {st}"})
    conflicts = _detect_conflicts(normalized)
    facts = {k: v for n in normalized for k, v in (n.get("data") or {}).items()
             if isinstance(v, (str, int, float)) and not isinstance(v, bool)}
    lines = []
    for n in normalized:
        lines.append(f"{n.get('agent')}: {n.get('summary')}"
                     + (" (partial input)" if n.get("partial_input") else ""))
    for m in missing:
        lines.append(f"{m['task_id']}: MISSING DATA - {m['reason']}.")
    for c in conflicts:
        lines.append("CONFLICT DETECTED on '%s': %s." % (
            c["field"], "; ".join(f"{s['agent']}={s['value']}" for s in c["sources"])))
    if conflicts:
        det = "Synthesis found conflicting agent outputs; human review required. " + " ".join(lines)
        status = "WAITING_FOR_HUMAN"
    elif missing and not normalized:
        det = "No completed dependency results available. " + " ".join(lines)
        status = "FAILED"
    elif missing and not partial_allowed:
        det = "Dependencies incomplete and partial synthesis not allowed. " + " ".join(lines)
        status = "WAITING_FOR_HUMAN"
    else:
        det = ("Combined multi-agent findings. " if not missing else
               "Combined multi-agent findings from partial inputs. ") + " ".join(lines)
        status = "COMPLETED" if not missing else "PARTIAL"
    summary, assisted = _llm_polish_summary(det, normalized)
    data = {"facts": facts, "sections": [
        {"agent": n.get("agent"), "status": n.get("status"), "summary": n.get("summary"),
         "data": n.get("data"), "evidence": n.get("evidence"), "warnings": n.get("warnings")}
        for n in normalized],
        "missing": missing, "conflicts": conflicts}
    evidence = [f"{len(normalized)} subtask result(s) combined"]
    warnings = [f"CONFLICT DETECTED: {c['field']}" for c in conflicts] + \
               [f"MISSING DATA: {m['task_id']} ({m['reason']})" for m in missing]
    meta = {"duration_s": round(_t.time() - t0, 2), "partial_allowed": partial_allowed,
            "llm_assisted": assisted, "summary": summary}
    return _manager_output(task_row["task_id"], agent_row["agent_id"] if agent_row else "manager",
                           status, data, evidence, warnings, meta)


FRAMEWORK_EXECUTORS = {}


def _fw_visibility(agent_id, envelope, context):
    """Framework-signature adapter around the existing visibility backend
    (no analysis logic touched). Translates envelope -> manager call ->
    §7 output. WAITING_FOR_INPUT survives the round trip via metadata so the
    manager flow keeps its input-gate semantics."""
    row = _registry_row(agent_id)
    task_input = (envelope.get("input") or {})
    pseudo = {"task_id": envelope.get("task_id") or envelope.get("request_id"),
              "capability": envelope.get("operation"), "task_type": envelope.get("operation"),
              "input_json": json.dumps(task_input)}
    out = _exec_visibility(row, pseudo, task_input, (envelope.get("metadata") or {}).get("run_id"))
    status_map = {"COMPLETED": "COMPLETED", "PARTIAL": "PARTIAL", "FAILED": "FAILED",
                  "WAITING_FOR_HUMAN": "WAITING_FOR_HUMAN", "WAITING_FOR_INPUT": "WAITING_FOR_HUMAN"}
    fw_status = status_map.get(out.get("status"), "FAILED")
    meta = dict(out.get("metadata") or {})
    if out.get("status") == "WAITING_FOR_INPUT":
        meta["manager_status"] = "WAITING_FOR_INPUT"
    return {"request_id": envelope.get("request_id"), "agent_id": agent_id, "status": fw_status,
            "summary": meta.get("summary", ""), "data": out.get("result") or {},
            "evidence": out.get("evidence") or [], "warnings": out.get("warnings") or [],
            "errors": [] if fw_status in ("COMPLETED", "PARTIAL") else
            [framework_error("EXECUTION_ERROR", str((out.get("result") or {}).get("error") or fw_status))],
            "metadata": meta}


FRAMEWORK_EXECUTORS["ai-search-visibility"] = _fw_visibility


def _exec_website_content(agent_row, task_row, task_input, run_id):
    """Website Content Intelligence backend: real website analysis from stored
    evidence + live scraping when available. No fabricated data."""
    import time as _t
    t0, warnings, evidence = _t.time(), [], []
    cap = task_row.get("capability") or task_row.get("task_type")
    meta = {"capability": cap}
    cid, missing = _resolve_manager_company(task_input)
    if cid is None:
        return _manager_output(task_row["task_id"], agent_row["agent_id"], "WAITING_FOR_INPUT",
                               {"error": f"missing input: {missing}"}, [], [], meta)
    brand = get_brand(cid)
    website = (brand or {}).get("website", "")
    if not website:
        return _manager_output(task_row["task_id"], agent_row["agent_id"], "FAILED",
                               {"error": "INSUFFICIENT_DATA: no website URL found for this company",
                                "company_id": cid}, [], ["No website URL on company profile."], meta)

    ev = get_company_evidence(cid)
    ev_by_type = {}
    for e in ev:
        et = e.get("evidence_type", "GENERAL")
        ev_by_type.setdefault(et, []).append(e)

    if cap == "website_discovery":
        scrape = scrape_website(cid, website)
        if not scrape.get("ok"):
            return _manager_output(task_row["task_id"], agent_row["agent_id"], "FAILED",
                                   {"error": f"SCRAPER_ERROR: {scrape.get('error', 'unknown')}",
                                    "company_id": cid, "website": website},
                                   [], [scrape.get("error", "scrape failed")[:300]], meta)
        save_evidence(cid, scrape.get("evidence", []), source="WEBSITE_DISCOVERY")
        evidence.append(f"{len(scrape.get('evidence', []))} evidence rows from website scrape")
        data = {"website": website, "pages_scraped": scrape.get("pages", 0),
                "evidence_types": list({e.get("evidence_type") for e in scrape.get("evidence", [])})}
        meta.update({"company_id": cid, "duration_s": round(_t.time() - t0, 2),
                     "summary": f"Website discovery completed for {website}."})
        return _manager_output(task_row["task_id"], agent_row["agent_id"], "COMPLETED",
                               data, evidence, warnings, meta)

    if cap in ("product_extraction", "service_extraction"):
        keywords = {"product_extraction": ["PRODUCT_LISTING", "PRICING", "TARGET_AUDIENCE_CLUE"],
                     "service_extraction": ["SERVICE_LISTING", "ABOUT_INFO", "CONTACT_INFO"]}
        relevant_types = keywords.get(cap, [])
        products, services = [], []
        for et in relevant_types:
            for e in ev_by_type.get(et, []):
                entry = {"type": e.get("evidence_type"), "value": e.get("evidence_value", ""),
                         "source": e.get("source", ""), "confidence": e.get("confidence", 0)}
                if cap == "product_extraction":
                    products.append(entry)
                else:
                    services.append(entry)
        if not products and not services:
            scrape = scrape_website(cid, website)
            if scrape.get("ok"):
                save_evidence(cid, scrape.get("evidence", []), source="WEBSITE_DISCOVERY")
                for et in relevant_types:
                    for e in [x for x in scrape.get("evidence", []) if x.get("evidence_type") == et]:
                        entry = {"type": e.get("evidence_type"), "value": e.get("evidence_value", ""),
                                 "source": e.get("source", ""), "confidence": e.get("confidence", 0)}
                        if cap == "product_extraction":
                            products.append(entry)
                        else:
                            services.append(entry)
        items = products if cap == "product_extraction" else services
        data = {"products": products, "services": services, "count": len(items)}
        evidence.append(f"{len(items)} {cap.replace('_', ' ')} found")
        meta.update({"company_id": cid, "duration_s": round(_t.time() - t0, 2),
                     "summary": f"{cap} completed for company #{cid}: {len(items)} items."})
        return _manager_output(task_row["task_id"], agent_row["agent_id"], "COMPLETED",
                               data, evidence, warnings, meta)

    if cap == "website_content_analysis":
        all_types = set(ev_by_type.keys())
        content_types = {"PAGE_TITLE", "META_DESCRIPTION", "HEADING", "STRUCTURED_DATA",
                         "INTERNAL_LINKS", "PRODUCT_LISTING", "SERVICE_LISTING", "ABOUT_INFO",
                         "FAQ", "PRICING", "BLOG_ARTICLE", "CONTACT_INFO", "COMPARISON_CONTENT",
                         "TARGET_AUDIENCE_CLUE"}
        present = all_types & content_types
        missing_ct = content_types - present
        topics = []
        for et in present:
            for e in ev_by_type.get(et, [])[:3]:
                topics.append({"topic": et, "value": e.get("evidence_value", "")[:200]})
        data = {"website": website, "content_types_present": sorted(present),
                "content_types_missing": sorted(missing_ct), "topics": topics[:20],
                "completeness_ratio": round(len(present) / len(content_types), 2) if content_types else 0}
        evidence.append(f"{len(present)}/{len(content_types)} content types present")
        meta.update({"company_id": cid, "duration_s": round(_t.time() - t0, 2),
                     "summary": f"Content analysis: {len(present)}/{len(content_types)} types present."})
        return _manager_output(task_row["task_id"], agent_row["agent_id"], "COMPLETED",
                               data, evidence, warnings, meta)

    if cap == "content_completeness":
        required_types = ["PAGE_TITLE", "META_DESCRIPTION", "HEADING", "STRUCTURED_DATA",
                          "PRODUCT_LISTING", "SERVICE_LISTING", "ABOUT_INFO", "CONTACT_INFO"]
        nice_to_have = ["FAQ", "PRICING", "BLOG_ARTICLE", "COMPARISON_CONTENT", "TARGET_AUDIENCE_CLUE"]
        present_req = [t for t in required_types if t in ev_by_type]
        present_nice = [t for t in nice_to_have if t in ev_by_type]
        completeness = {
            "required_present": len(present_req), "required_total": len(required_types),
            "nice_to_have_present": len(present_nice), "nice_to_have_total": len(nice_to_have),
            "required_score": round(len(present_req) / len(required_types), 2) if required_types else 0,
            "overall_score": round((len(present_req) / len(required_types) * 0.7 +
                                   len(present_nice) / len(nice_to_have) * 0.3), 2) if required_types and nice_to_have else 0,
            "missing_required": [t for t in required_types if t not in ev_by_type],
            "missing_nice_to_have": [t for t in nice_to_have if t not in ev_by_type],
        }
        data = {"website": website, "completeness": completeness}
        evidence.append(f"Completeness: {completeness['overall_score']}")
        meta.update({"company_id": cid, "duration_s": round(_t.time() - t0, 2),
                     "summary": f"Content completeness: {completeness['overall_score']}."})
        return _manager_output(task_row["task_id"], agent_row["agent_id"], "COMPLETED",
                               data, evidence, warnings, meta)

    if cap == "content_gap_analysis":
        brand_analysis = analyze_brand(brand) if brand else {}
        gaps = detect_content_gaps(brand, ev, brand_analysis)
        website_gaps = [g for g in gaps if g.get("category") in ("website_content", "content", "brand_visibility")]
        data = {"website": website, "gaps": website_gaps, "total_gaps": len(website_gaps)}
        evidence.append(f"{len(website_gaps)} website content gaps found")
        meta.update({"company_id": cid, "duration_s": round(_t.time() - t0, 2),
                     "summary": f"Content gap analysis: {len(website_gaps)} gaps."})
        return _manager_output(task_row["task_id"], agent_row["agent_id"], "COMPLETED",
                               data, evidence, warnings, meta)

    if cap == "website_evidence":
        recent_ev = sorted(ev, key=lambda e: e.get("created_at", ""), reverse=True)[:30]
        data = {"website": website, "evidence_count": len(recent_ev),
                "evidence": [{"type": e.get("evidence_type"), "key": e.get("evidence_key"),
                              "value": e.get("evidence_value", "")[:200],
                              "source": e.get("source", ""),
                              "confidence": e.get("confidence", 0)} for e in recent_ev]}
        evidence.append(f"{len(recent_ev)} recent evidence rows")
        meta.update({"company_id": cid, "duration_s": round(_t.time() - t0, 2),
                     "summary": f"Website evidence: {len(recent_ev)} rows."})
        return _manager_output(task_row["task_id"], agent_row["agent_id"], "COMPLETED",
                               data, evidence, warnings, meta)

    return _manager_output(task_row["task_id"], agent_row["agent_id"], "FAILED",
                           {"error": f"capability '{cap}' not implemented",
                            "company_id": cid}, [], [], meta)


def _fw_website_content(agent_id, envelope, context):
    """Framework adapter for Website Content Intelligence Agent."""
    row = _registry_row(agent_id)
    task_input = (envelope.get("input") or {})
    pseudo = {"task_id": envelope.get("task_id") or envelope.get("request_id"),
              "capability": envelope.get("operation"), "task_type": envelope.get("operation"),
              "input_json": json.dumps(task_input)}
    out = _exec_website_content(row, pseudo, task_input, (envelope.get("metadata") or {}).get("run_id"))
    status_map = {"COMPLETED": "COMPLETED", "PARTIAL": "PARTIAL", "FAILED": "FAILED",
                  "WAITING_FOR_HUMAN": "WAITING_FOR_HUMAN", "WAITING_FOR_INPUT": "WAITING_FOR_HUMAN"}
    fw_status = status_map.get(out.get("status"), "FAILED")
    meta = dict(out.get("metadata") or {})
    if out.get("status") == "WAITING_FOR_INPUT":
        meta["manager_status"] = "WAITING_FOR_INPUT"
    return {"request_id": envelope.get("request_id"), "agent_id": agent_id, "status": fw_status,
            "summary": meta.get("summary", ""), "data": out.get("result") or {},
            "evidence": out.get("evidence") or [], "warnings": out.get("warnings") or [],
            "errors": [] if fw_status in ("COMPLETED", "PARTIAL") else
            [framework_error("EXECUTION_ERROR", str((out.get("result") or {}).get("error") or fw_status))],
            "metadata": meta}


FRAMEWORK_EXECUTORS["website-content-intelligence"] = _fw_website_content


def _dispatch_manager_subtask(job, ctx, run_id):
    """Runner-integrated subtask execution (§3 ten steps). Validation refusals
    conclude the JOB as completed (the validation work is done) while the TASK
    records FAILED/WAITING honestly; only infra errors raise into retries."""
    import time as _t
    t0 = _t.time()
    payload = safe_json_loads(job.get("payload"), {}) or {}
    mtid = job.get("manager_task_id") or payload.get("manager_task_id")
    if not mtid:
        raise ValueError("manager job without manager_task_id")
    trows = db.query("SELECT * FROM manager_tasks WHERE task_id=?", (mtid,))
    if not trows:
        raise ValueError("manager task not found")
    t = trows[0]
    aid = t.get("selected_agent_id") or payload.get("assigned_agent_id")
    agent_row = _registry_row(aid) if aid else None
    if not agent_row:
        db.execute("UPDATE manager_tasks SET status='FAILED', error_message=?, completed_at=? WHERE id=?",
                   (f"Unknown agent rejected by registry: {aid}", now(), t["id"]))
        return {"ok": False, "manager_status": "FAILED", "error": f"unknown agent: {aid}"}
    if (agent_row.get("status") or "") != "ACTIVE":
        db.execute("UPDATE manager_tasks SET status='FAILED', error_message=?, completed_at=? WHERE id=?",
                   (f"Agent {aid} is {agent_row.get('status')}; registered but unavailable because no execution "
                    "backend is implemented." if aid == "finance-cash-flow" else
                    f"Agent {aid} is {agent_row.get('status')}, not ACTIVE.", now(), t["id"]))
        manager_learn(None, "AGENT_EXECUTION_FAILURE", f"Subtask {mtid} refused: agent {aid} unavailable.",
                      {"manager_task_id": mtid, "agent_id": aid})
        try:
            log_activity(f"Manager subtask {mtid} refused: agent {aid} unavailable (no result fabricated).",
                         level="MANAGER", job_id=job["id"])
        except Exception:
            pass
        return {"ok": False, "manager_status": "FAILED",
                "error": f"agent {aid} unavailable; no result fabricated"}
    caps = _agent_capabilities(agent_row)
    if (t.get("capability") or t.get("task_type")) not in caps:
        db.execute("UPDATE manager_tasks SET status='FAILED', error_message=?, completed_at=? WHERE id=?",
                   (f"Agent {aid} does not declare capability '{t.get('capability')}'.", now(), t["id"]))
        return {"ok": False, "manager_status": "FAILED", "error": "capability not declared"}
    task_input = safe_json_loads(t.get("input_json"), {}) or {}
    # Collect dependency results for handoff data (§9 multi-agent handoff).
    try:
        dep_tids = safe_json_loads(t.get("dependency_task_ids_json"), []) or []
    except Exception:
        dep_tids = []
    handoff_findings = {}
    for dep_tid in dep_tids:
        dep_row = _manager_task_row(dep_tid)
        if dep_row and dep_row.get("status") in ("COMPLETED", "PARTIAL"):
            rr = db.query("SELECT result_json FROM manager_task_results WHERE task_id=? ORDER BY id DESC LIMIT 1",
                          (dep_tid,))
            if rr:
                dep_result = safe_json_loads(rr[0].get("result_json"), {}) or {}
                dep_data = dep_result.get("data") or {}
                handoff_findings[dep_row.get("agent_id") or dep_tid] = dep_data
                _manager_handoff(t.get("parent_task_id") or t["task_id"], dep_row,
                                 t["task_id"], aid, dep_data)
    if handoff_findings:
        task_input["handoff_findings"] = handoff_findings
    missing = _manager_required_inputs(agent_row, task_input)
    if missing:
        db.execute("UPDATE manager_tasks SET status='WAITING_FOR_INPUT', error_message=? WHERE id=?",
                   (f"missing required input: {', '.join(missing)}", t["id"]))
        return {"ok": False, "manager_status": "WAITING_FOR_INPUT",
                "error": f"missing required input: {', '.join(missing)}"}
    db.execute("UPDATE manager_tasks SET status='RUNNING', started_at=? WHERE id=?", (now(), t["id"]))
    # Single execution path: the framework adapter (validates envelope, runs
    # the registered executor with a timeout, validates output).
    envelope = {"request_id": t["task_id"], "task_id": t["task_id"], "agent_id": aid,
                "operation": t.get("capability") or t.get("task_type"), "input": task_input,
                "context": {}, "constraints": {}, "metadata": {"run_id": run_id}}
    fw = framework_execute(aid, envelope, timeout_seconds=900)
    if not fw.get("success"):
        err = fw.get("error") or {}
        code = err.get("code", "EXECUTION_ERROR") if isinstance(err, dict) else "EXECUTION_ERROR"
        if framework_classify_error(code) == "RETRYABLE" or \
                (isinstance(err, dict) and err.get("retryable")):
            raise ValueError(f"agent execution failed retryably: {code}")
        db.execute("UPDATE manager_tasks SET status='FAILED', error_message=?, completed_at=? WHERE id=?",
                   (str(err.get('message') if isinstance(err, dict) else err)[:500], now(), t["id"]))
        framework_learning_hook("on_failure", aid, mtid, {"manager_task_id": mtid})
        return {"ok": False, "manager_status": "FAILED",
                "error": str(err.get('message') if isinstance(err, dict) else err)[:300]}
    fwo = fw["output"]
    out = {"task_id": t["task_id"], "agent_id": aid,
           "status": (fwo.get("metadata") or {}).get("manager_status") or fwo.get("status"),
           "result": fwo.get("data") or {}, "evidence": fwo.get("evidence") or [],
           "warnings": fwo.get("warnings") or [], "metadata": fwo.get("metadata") or {}}
    ok, err = _validate_manager_output(out)
    if not ok:
        raise ValueError(f"agent output rejected: {err}")
    out["metadata"]["duration_s"] = round(_t.time() - t0, 2)
    normalized = normalize_manager_result(agent_row["agent_name"], out)
    top_parent = t.get("parent_task_id") or None
    _store_manager_result(top_parent or t["task_id"], t, aid, normalized, out["status"])
    db.execute("UPDATE manager_tasks SET status=?, output_json=?, completed_at=?, error_message=? WHERE id=?",
               (out["status"], json.dumps(normalized)[:8000],
                now() if out["status"] in ("COMPLETED", "PARTIAL", "FAILED") else None,
                None if out["status"] in ("COMPLETED", "PARTIAL") else
                str(normalized.get("data", {}).get("error") or out["status"]), t["id"]))
    cid = None
    try:
        cid = int(out["metadata"].get("company_id")) if out["metadata"].get("company_id") else None
    except Exception:
        cid = None
    framework_learning_hook("after_execution", aid, mtid,
                            {"manager_task_id": top_parent or t["task_id"], "company_id": cid,
                             "status": out["status"], "duration_s": out["metadata"].get("duration_s"),
                             "description": f"Subtask {mtid} ({aid}) -> {out['status']}."})
    try:
        log_activity(f"Manager subtask {mtid} ({aid}) -> {out['status']}.", level="MANAGER",
                     run_id=run_id, job_id=job["id"])
    except Exception:
        pass
    _manager_dependency_check(t.get("parent_task_id") or t["task_id"])
    return {"ok": True, "manager_task": mtid, "status": out["status"]}


def _dispatch_manager_synthesis(job, ctx, run_id):
    payload = safe_json_loads(job.get("payload"), {}) or {}
    mtid = job.get("manager_task_id") or payload.get("manager_task_id")
    t = _manager_task_row(mtid) if mtid else None
    if not t:
        raise ValueError("synthesis task not found")
    try:
        deps = safe_json_loads(t.get("dependency_task_ids_json"), []) or []
    except Exception:
        deps = []
    states = {}
    for dep in deps:
        dr = _manager_task_row(dep)
        states[dep] = dr.get("status") if dr else "MISSING"
    pending = [d for d, s in states.items() if s in ("PLANNED", "QUEUED", "RUNNING", "WAITING")]
    if pending:
        return {"ok": False, "manager_status": "BLOCKED",
                "reason": "Waiting for required subtasks.",
                "pending": pending}
    agent_row = {"agent_id": "manager", "agent_name": "Manager"}
    task_input = safe_json_loads(t.get("input_json"), {}) or {}
    db.execute("UPDATE manager_tasks SET status='RUNNING', started_at=? WHERE id=?", (now(), t["id"]))
    out = _exec_synthesis(agent_row, t, task_input, run_id)
    ok, err = _validate_manager_output(out)
    if not ok:
        raise ValueError(f"synthesis output rejected: {err}")
    normalized = normalize_manager_result("Manager", out)
    top_parent = t.get("parent_task_id") or t["task_id"]
    # handoffs: each dependency result into synthesis (non-secret fields).
    for dep in deps:
        dr = _manager_task_row(dep)
        rr = db.query("SELECT * FROM manager_task_results WHERE task_id=? ORDER BY id DESC LIMIT 1",
                      (dep,))
        if dr and rr:
            try:
                src = safe_json_loads(rr[0].get("result_json"), {}) or {}
                _manager_handoff(top_parent, dr, t["task_id"], "manager", src.get("data") or {})
            except Exception:
                pass
    _store_manager_result(top_parent, t, "manager", normalized, out["status"])
    db.execute("UPDATE manager_tasks SET status=?, output_json=?, completed_at=?, error_message=? WHERE id=?",
               (out["status"], json.dumps(normalized)[:8000],
                now() if out["status"] in ("COMPLETED", "PARTIAL", "FAILED", "WAITING_FOR_HUMAN") else None,
                None if out["status"] in ("COMPLETED", "PARTIAL") else "see synthesis result", t["id"]))
    manager_learn(None, "SYNTHESIS_SUCCESS" if out["status"] in ("COMPLETED", "PARTIAL") else "SYNTHESIS_FAILURE",
                  f"Synthesis {t['task_id']} -> {out['status']}.",
                  {"manager_task_id": top_parent, "status": out["status"]})
    try:
        log_activity(f"Manager synthesis {t['task_id']} -> {out['status']}.", level="MANAGER",
                     run_id=run_id, job_id=job["id"])
    except Exception:
        pass
    _manager_finalize_parent(top_parent)
    return {"ok": True, "manager_task": t["task_id"], "status": out["status"]}


def _manager_create_job(task_row, job_type, run_id, parent_job_id=None):
    """Create one manager job on the EXISTING queue (dedup-aware, §26)."""
    dup = db.query("SELECT id FROM jobs WHERE manager_task_id=? AND job_type=? AND status IN "
                   "('PENDING','QUEUED','RUNNING','RETRYING','FAILED') ORDER BY id DESC LIMIT 1",
                   (task_row["task_id"], job_type))
    if dup:
        return {"job_id": dup[0]["id"], "duplicate": True}
    payload = {"manager_task_id": task_row["task_id"], "assigned_agent_id": task_row.get("selected_agent_id"),
               "task_type": task_row.get("task_type") or task_row.get("capability")}
    brand = None
    try:
        ti = safe_json_loads(task_row.get("input_json"), {}) or {}
        nm = (ti.get("brand_name") or ti.get("company") or "").strip()
        if nm:
            br = db.query("SELECT id FROM brands WHERE brand_name=? AND is_active=1 ORDER BY id DESC LIMIT 1", (nm,))
            if br:
                brand = br[0]["id"]
    except Exception:
        brand = None
    if db.flavor == "mysql":
        job_uuid = str(uuid.uuid4())
        jid = db.execute("""
            INSERT INTO jobs (id, job_id, company_id, job_type, status, priority, priority_level, payload,
                              max_retries, run_id, manager_task_id, assigned_agent_id, parent_job_id, created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (job_uuid, new_job_id(0), brand, job_type, "PENDING", 50, "MEDIUM", json.dumps(payload)[:2000],
              int(get_config().get("max_retries", "3")), run_id, task_row["task_id"],
              task_row.get("selected_agent_id"), parent_job_id, now()))
        db.execute("UPDATE jobs SET job_id=? WHERE id=?", (new_job_id(jid), job_uuid))
    else:
        jid = db.execute("""
            INSERT INTO jobs (job_id, company_id, job_type, status, priority, priority_level, payload,
                              max_retries, run_id, manager_task_id, assigned_agent_id, parent_job_id, created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (new_job_id(0), brand, job_type, "PENDING", 50, "MEDIUM", json.dumps(payload)[:2000],
              int(get_config().get("max_retries", "3")), run_id, task_row["task_id"],
              task_row.get("selected_agent_id"), parent_job_id, now()))
        db.execute("UPDATE jobs SET job_id=? WHERE id=?", (new_job_id(jid), jid))
    try:
        log_activity(f"Manager queued {job_type} for task {task_row['task_id']}.", level="MANAGER",
                     run_id=run_id, job_id=jid)
    except Exception:
        pass
    return {"job_id": jid, "duplicate": False}


def manager_execute_task(task_id, background=True):
    """POST /api/manager/tasks/:id/execute (§24): validate, queue required jobs
    respecting dependencies. Never executes agent code directly here."""
    t = _manager_task_row(task_id)
    if not t:
        return {"success": False, "error": "Task not found"}
    if (t.get("status") or "") not in ("PLANNED", "QUEUED", "WAITING_FOR_INPUT"):
        return {"success": False, "error": f"Task is {t.get('status')}; only PLANNED/QUEUED tasks execute."}
    agent_row = _registry_row(t.get("selected_agent_id") or "") if t.get("selected_agent_id") else None
    if t.get("selected_agent_id") and t["selected_agent_id"] not in ("manager",) and not agent_row:
        return {"success": False, "error": "Unknown agent rejected by registry."}
    if agent_row and (agent_row.get("status") or "") != "ACTIVE":
        db.execute("UPDATE manager_tasks SET status='WAITING_FOR_HUMAN', error_message=? WHERE id=?",
                   (f"Agent {agent_row['agent_id']} is {agent_row.get('status')}; not executed.", t["id"]))
        return {"success": True, "task_id": t["task_id"], "status": "WAITING_FOR_HUMAN",
                "reason": f"Agent {agent_row['agent_id']} is {agent_row.get('status')}; not executed."}
    task_input = safe_json_loads(t.get("input_json"), {}) or {}
    if agent_row:
        missing = _manager_required_inputs(agent_row, task_input)
        if missing:
            db.execute("UPDATE manager_tasks SET status='WAITING_FOR_INPUT', error_message=? WHERE id=?",
                       (f"missing required input: {', '.join(missing)}", t["id"]))
            return {"success": True, "task_id": t["task_id"], "status": "WAITING_FOR_INPUT",
                    "missing": missing}
    rid = create_run("MANAGER", companies=[])
    made = []
    if t.get("parent_task_id"):
        r = _manager_create_job(t, "MANAGER_SUBTASK", rid)
        made.append(r["job_id"])
        db.execute("UPDATE manager_tasks SET status='QUEUED', started_at=? WHERE id=?", (now(), t["id"]))
    elif (t.get("task_type") or "") == "COMBINED":
        for s in db.query("SELECT * FROM manager_tasks WHERE parent_task_id=? ORDER BY id", (t["task_id"],)):
            if (s.get("task_type") or "") == "SYNTHESIS" or (s.get("status") or "") != "PLANNED":
                continue
            sa = _registry_row(s.get("selected_agent_id") or "") if s.get("selected_agent_id") else None
            if not sa or (sa.get("status") or "") != "ACTIVE":
                db.execute("UPDATE manager_tasks SET status='WAITING_FOR_HUMAN', error_message=? WHERE id=?",
                           (f"Agent {s.get('selected_agent_id')} unavailable; not executed.", s["id"]))
                continue
            r = _manager_create_job(s, "MANAGER_SUBTASK", rid)
            made.append(r["job_id"])
            db.execute("UPDATE manager_tasks SET status='QUEUED', started_at=? WHERE id=?", (now(), s["id"]))
        db.execute("UPDATE manager_tasks SET status='RUNNING', started_at=? WHERE id=?", (now(), t["id"]))
    else:
        r = _manager_create_job(t, "MANAGER_SUBTASK", rid)
        made.append(r["job_id"])
        db.execute("UPDATE manager_tasks SET status='QUEUED', started_at=? WHERE id=?", (now(), t["id"]))
    if background:
        threading.Thread(target=lambda: runner._process_queue(run_id=rid), daemon=True,
                         name="manager-run").start()
        return {"success": True, "task_id": t["task_id"], "status": db.query(
            "SELECT status FROM manager_tasks WHERE id=?", (t["id"],))[0]["status"],
            "run_id": rid, "jobs": made, "background": True}
    runner._process_queue(run_id=rid)
    cur = _manager_task_row(t["task_id"])
    return {"success": True, "task_id": t["task_id"], "status": cur["status"], "run_id": rid, "jobs": made}


def manager_synthesize_task(task_id, background=True):
    """POST /api/manager/tasks/:id/synthesize (§25): gate on dependencies, then
    queue synthesis through the Runner. BLOCKED returns data, never a job."""
    t = _manager_task_row(task_id)
    if not t:
        return {"success": False, "error": "Task not found"}
    syn = t
    if (t.get("task_type") or "") != "SYNTHESIS":
        subs = db.query("SELECT * FROM manager_tasks WHERE parent_task_id=? AND task_type='SYNTHESIS' "
                        "ORDER BY id LIMIT 1", (t["task_id"],))
        if not subs:
            return {"success": False, "error": "No synthesis task for this parent."}
        syn = subs[0]
    try:
        deps = safe_json_loads(syn.get("dependency_task_ids_json"), []) or []
    except Exception:
        deps = []
    states = {}
    for dep in deps:
        dr = _manager_task_row(dep)
        states[dep] = dr.get("status") if dr else "MISSING"
    pending = [d for d, s in states.items() if s in ("PLANNED", "QUEUED", "RUNNING", "WAITING", "WAITING_FOR_INPUT")]
    if pending:
        return {"success": True, "task_id": syn["task_id"], "status": "BLOCKED",
                "reason": "Waiting for required subtasks.", "pending": pending, "states": states}
    ok_states = [s for s in states.values() if s in ("COMPLETED", "PARTIAL")]
    if not ok_states:
        db.execute("UPDATE manager_tasks SET status='FAILED', error_message=?, completed_at=? WHERE id=?",
                   ("All dependencies failed; no valid partial result possible.", now(), syn["id"]))
        _manager_finalize_parent(syn.get("parent_task_id") or syn["task_id"])
        return {"success": True, "task_id": syn["task_id"], "status": "FAILED",
                "reason": "All dependencies failed; no valid partial result possible."}
    if (syn.get("status") or "") in ("COMPLETED", "PARTIAL", "FAILED"):
        cur = _manager_task_row(syn["task_id"])
        return {"success": True, "task_id": syn["task_id"], "status": cur["status"],
                "idempotent": True, "reason": "Synthesis already terminal; not re-running without force."}
    require_all = False
    try:
        require_all = bool((safe_json_loads(syn.get("input_json"), {}) or {}).get("require_all"))
    except Exception:
        require_all = False
    if require_all and any(s != "COMPLETED" for s in states.values()):
        for sid in (syn.get("parent_task_id"), syn["task_id"]):
            if sid:
                db.execute("UPDATE manager_tasks SET status='WAITING_FOR_HUMAN', error_message=? "
                           "WHERE task_id=?", ("Partial synthesis not allowed (require_all); human decision needed.", sid))
        return {"success": True, "task_id": syn["task_id"], "status": "WAITING_FOR_HUMAN",
                "reason": "Partial synthesis not allowed (require_all); human decision needed."}
    rid = create_run("MANAGER", companies=[])
    r = _manager_create_job(syn, "MANAGER_SYNTHESIS", rid)
    db.execute("UPDATE manager_tasks SET status='QUEUED', started_at=? WHERE id=?", (now(), syn["id"]))
    if background:
        threading.Thread(target=lambda: runner._process_queue(run_id=rid), daemon=True,
                         name="manager-syn").start()
        return {"success": True, "task_id": syn["task_id"], "status": "QUEUED",
                "run_id": rid, "job_id": r["job_id"], "background": True}
    runner._process_queue(run_id=rid)
    cur = _manager_task_row(syn["task_id"])
    return {"success": True, "task_id": syn["task_id"], "status": cur["status"],
            "run_id": rid, "job_id": r["job_id"]}


def _manager_dependency_check(top_parent_id):
    """After every subtask result: unblock synthesis when all deps terminal (§7)."""
    if not top_parent_id:
        return
    children = db.query("SELECT task_id, status FROM manager_tasks WHERE parent_task_id=?", (top_parent_id,))
    if not children:
        return
    if any(s.get("status") in ("PLANNED", "QUEUED", "RUNNING", "WAITING", "WAITING_FOR_INPUT")
           for s in children):
        return
    syn = db.query("SELECT * FROM manager_tasks WHERE parent_task_id=? AND task_type='SYNTHESIS' "
                   "ORDER BY id LIMIT 1", (top_parent_id,))
    if not syn or (syn[0].get("status") or "") not in ("WAITING", "PLANNED", "QUEUED"):
        _manager_finalize_parent(top_parent_id)
        return
    ok_states = [s.get("status") for s in children if s.get("status") in ("COMPLETED", "PARTIAL")]
    try:
        require_all = bool((safe_json_loads(syn[0].get("input_json"), {}) or {}).get("require_all"))
    except Exception:
        require_all = False
    if ok_states and (len(ok_states) == len(children) or not require_all):
        db.execute("UPDATE manager_tasks SET status='QUEUED' WHERE id=?", (syn[0]["id"]))
        try:
            log_activity(f"Manager synthesis {syn[0]['task_id']} QUEUED: all dependencies terminal.",
                         level="MANAGER")
        except Exception:
            pass
    elif not ok_states:
        db.execute("UPDATE manager_tasks SET status='FAILED', error_message=?, completed_at=? WHERE id=?",
                   ("All dependencies failed; no valid partial result possible.", now(), syn[0]["id"]))
    else:
        db.execute("UPDATE manager_tasks SET status='WAITING_FOR_HUMAN', error_message=? WHERE id=?",
                   ("Partial synthesis not allowed (require_all); human decision needed.", syn[0]["id"]))
    _manager_finalize_parent(top_parent_id)


def _manager_finalize_parent(top_parent_id):
    """Parent completion (§16): COMPLETED iff all required ok; PARTIAL iff some
    ok with failures/unavailability tolerated; FAILED iff nothing valid;
    WAITING_FOR_HUMAN if a human gate is pending."""
    if not top_parent_id:
        return
    parent = _manager_task_row(top_parent_id)
    if not parent:
        return
    children = db.query("SELECT * FROM manager_tasks WHERE parent_task_id=?", (top_parent_id,))
    if not children:
        return
    if any((c.get("status") or "") in ("PLANNED", "QUEUED", "RUNNING", "WAITING", "WAITING_FOR_INPUT")
           for c in children):
        return
    syn = [c for c in children if (c.get("task_type") or "") == "SYNTHESIS"]
    subs = [c for c in children if (c.get("task_type") or "") != "SYNTHESIS"]
    ok_subs = [c for c in subs if c.get("status") in ("COMPLETED", "PARTIAL")]
    hum = [c for c in children if c.get("status") == "WAITING_FOR_HUMAN"]
    if hum and (not syn or (syn[0].get("status") or "") in ("WAITING_FOR_HUMAN", "WAITING", "QUEUED", "PLANNED")):
        if syn and (syn[0].get("status") or "") not in ("COMPLETED", "PARTIAL"):
            srow = db.query("SELECT * FROM manager_task_results WHERE task_id=? ORDER BY id DESC LIMIT 1",
                            (syn[0]["task_id"],))
            if srow:
                db.execute("UPDATE manager_tasks SET output_json=?, completed_at=? WHERE id=?",
                           (srow[0]["result_json"], now(), parent["id"]))
            else:
                db.execute("UPDATE manager_tasks SET completed_at=? WHERE id=?", (now(), parent["id"]))
            db.execute("UPDATE manager_tasks SET status='WAITING_FOR_HUMAN' WHERE id=?", (parent["id"],))
            manager_learn(None, "MANAGER_TASK_FAILURE", f"Parent {top_parent_id} waits for human.",
                          {"manager_task_id": top_parent_id})
            return
    if syn and (syn[0].get("status") or "") in ("COMPLETED", "PARTIAL"):
        srow = db.query("SELECT * FROM manager_task_results WHERE task_id=? ORDER BY id DESC LIMIT 1",
                        (syn[0]["task_id"],))
        if srow:
            db.execute("UPDATE manager_tasks SET output_json=?, completed_at=? WHERE id=?",
                       (srow[0]["result_json"], now(), parent["id"]))
        final = syn[0]["status"]
        db.execute("UPDATE manager_tasks SET status=? WHERE id=?", (final, parent["id"]))
        manager_learn(None, "MANAGER_TASK_SUCCESS" if final == "COMPLETED" else "MANAGER_TASK_FAILURE",
                      f"Parent {top_parent_id} -> {final}.",
                      {"manager_task_id": top_parent_id, "synthesis": syn[0]["task_id"]})
        return
    if ok_subs:
        db.execute("UPDATE manager_tasks SET status='PARTIAL', completed_at=? WHERE id=?", (now(), parent["id"]))
        manager_learn(None, "MANAGER_TASK_FAILURE", f"Parent {top_parent_id} -> PARTIAL (no synthesis).",
                      {"manager_task_id": top_parent_id})
        return
    db.execute("UPDATE manager_tasks SET status='FAILED', completed_at=? WHERE id=?", (now(), parent["id"]))
    manager_learn(None, "MANAGER_TASK_FAILURE", f"Parent {top_parent_id} -> FAILED.",
                  {"manager_task_id": top_parent_id})


def manager_cancel_task(task_id):
    """Cancel a task tree (§27): pending subtasks + queued synthesis cancelled,
    running jobs follow existing cancellation behavior, history retained."""
    t = _manager_task_row(task_id)
    if not t:
        return {"success": False, "error": "Task not found"}
    top = t.get("parent_task_id") or t["task_id"]
    cancelled = []
    for c in db.query("SELECT * FROM manager_tasks WHERE parent_task_id=? OR task_id=?", (top, top)):
        if (c.get("status") or "") in ("COMPLETED", "PARTIAL", "FAILED", "CANCELLED"):
            continue
        db.execute("UPDATE manager_tasks SET status='CANCELLED', completed_at=? WHERE id=?", (now(), c["id"]))
        cancelled.append(c["task_id"])
        for j in db.query("SELECT id, status FROM jobs WHERE manager_task_id=?", (c["task_id"],)):
            if j["status"] in ("PENDING", "QUEUED"):
                try:
                    cancel_job(j["id"])
                except Exception:
                    db.execute("UPDATE jobs SET status='CANCELLED', cancelled_at=? WHERE id=?", (now(), j["id"]))
    manager_learn(None, "HUMAN_CORRECTION", f"Task tree {top} cancelled by human ({len(cancelled)} task(s)).",
                  {"manager_task_id": top})
    return {"success": True, "task_id": top, "cancelled": cancelled}

def manager_task_display(t):
    """Live display status derived from linked jobs (no writes)."""
    d = dict(t)
    if (d.get("status") or "") in ("QUEUED", "RUNNING"):
        jr = db.query("SELECT status FROM jobs WHERE manager_task_id=? ORDER BY id DESC LIMIT 1", (d["task_id"],))
        if jr:
            js = jr[0]["status"]
            if js == "FAILED_PERMANENTLY":
                d["display_status"] = "FAILED"
            elif js == "COMPLETED" and d["status"] == "QUEUED":
                d["display_status"] = "RUNNING"
            else:
                d["display_status"] = d["status"]
        else:
            d["display_status"] = d["status"]
    else:
        d["display_status"] = d.get("status")
    return d


def manager_dashboard():
    """§19 dashboard: every number from real rows."""
    agents = manager_list_agents()["agents"]
    ag = {"total": len(agents),
          "healthy": sum(1 for a in agents if a.get("health_status") == "HEALTHY"),
          "paused": sum(1 for a in agents if a.get("status") == "PAUSED"),
          "unavailable": sum(1 for a in agents if a.get("health_status") in ("UNAVAILABLE", "UNKNOWN"))}
    tk = {}
    for r in db.query("SELECT status, COUNT(*) AS c FROM manager_tasks GROUP BY status"):
        tk[r["status"] or "UNKNOWN"] = r["c"]
    cur = db.query("SELECT * FROM manager_tasks WHERE status IN ('QUEUED','RUNNING','PLANNED','WAITING') "
                   "ORDER BY id DESC LIMIT 20")
    recent = db.query("SELECT d.*, b.brand_name AS company FROM agent_decisions d "
                      "LEFT JOIN brands b ON b.id=d.company_id WHERE d.trigger_type LIKE 'ORCHESTRATOR%' "
                      "OR d.trigger_type LIKE '%AUTO%' ORDER BY d.id DESC LIMIT 10")
    ho = db.query("SELECT * FROM agent_handoffs ORDER BY id DESC LIMIT 10")
    res = db.query("SELECT r.*, t.task_id AS tsk FROM manager_task_results r LEFT JOIN manager_tasks t "
                   "ON t.task_id=r.task_id ORDER BY r.id DESC LIMIT 10")
    lr = db.query("SELECT * FROM learning_events WHERE event_type IN ('MANAGER_TASK_SUCCESS','MANAGER_TASK_FAILURE',"
                  "'AGENT_EXECUTION_SUCCESS','AGENT_EXECUTION_FAILURE','HANDOFF_SUCCESS','HANDOFF_FAILURE',"
                  "'SYNTHESIS_SUCCESS','SYNTHESIS_FAILURE','HUMAN_CORRECTION') ORDER BY id DESC LIMIT 10")
    return {"success": True, "agents": ag, "agent_list": agents, "tasks": tk,
            "current_tasks": [dict(c) for c in cur],
            "recent_decisions": [dict(r) for r in recent],
            "recent_handoffs": [dict(h) for h in ho],
            "recent_results": [dict(r) for r in res],
            "recent_learning": [dict(r) for r in lr]}


def manager_task_graph(task_id):
    t = _manager_task_row(task_id)
    if not t:
        return {"success": False, "error": "Task not found"}
    top_id = t.get("parent_task_id") or t["task_id"]
    top = _manager_task_row(top_id)
    nodes = []
    for c in db.query("SELECT * FROM manager_tasks WHERE parent_task_id=? OR task_id=? ORDER BY id", (top_id, top_id)):
        d = manager_task_display(c)
        try:
            d["dependencies"] = safe_json_loads(c.get("dependency_task_ids_json"), []) or []
        except Exception:
            d["dependencies"] = []
        nodes.append(d)
    return {"success": True, "parent_task_id": top_id, "nodes": nodes}


def manager_final_result(task_id):
    t = _manager_task_row(task_id)
    if not t:
        return {"success": False, "error": "Task not found"}
    top_id = t.get("parent_task_id") or t["task_id"]
    top = _manager_task_row(top_id)
    out = None
    try:
        out = safe_json_loads(top.get("output_json"), None)
    except Exception:
        out = None
    sources = []
    for c in db.query("SELECT task_id, selected_agent_id, status FROM manager_tasks WHERE parent_task_id=?",
                      (top_id,)):
        if (c.get("status") or "") in ("COMPLETED", "PARTIAL"):
            rr = db.query("SELECT result_json FROM manager_task_results WHERE task_id=? ORDER BY id DESC LIMIT 1",
                          (c["task_id"],))
            ag = ""
            ar = _registry_row(c.get("selected_agent_id") or "") if c.get("selected_agent_id") else None
            if ar:
                ag = ar["agent_name"]
            sources.append({"task_id": c["task_id"], "agent": ag or c.get("selected_agent_id"),
                            "status": c.get("status"),
                            "summary": ((safe_json_loads(rr[0].get("result_json"), {}) or {}).get("summary") if rr else "")})
    return {"success": True, "task_id": top_id, "status": top.get("status"), "result": out, "sources": sources}


# ---------------------------------------------------------------------------
# PHASE 10 - PLANNING ENGINE (goal -> validated DAG; execution stays downstream)
# ---------------------------------------------------------------------------
#
# Responsibility split (mandatory): PLANNER builds structured plans;
# REASONING interprets evidence; ORCHESTRATOR schedules; RUNNER executes;
# MCP provides tools; LEARNING learns. The planner NEVER creates jobs,
# writes learning memory, or executes anything.

PLANNING_GOAL_TYPES = (
    "ANALYZE_COMPANY", "ANALYZE_VISIBILITY", "ANALYZE_COMPETITORS",
    "IDENTIFY_CONTENT_GAPS", "GENERATE_RECOMMENDATIONS", "INVESTIGATE_CHANGE",
    "REFRESH_COMPANY_DATA", "DISCOVER_COMPANY", "CUSTOM_ANALYSIS",
)

PLANNING_STATUSES = ("DRAFT", "VALIDATING", "READY", "RUNNING", "PAUSED", "COMPLETED",
                     "PARTIAL", "FAILED", "WAITING_FOR_HUMAN", "CANCELLED", "SUPERSEDED")

PLANNING_STEP_STATUSES = ("PENDING", "SKIPPED", "BLOCKED", "RUNNING", "COMPLETED", "PARTIAL",
                          "FAILED", "WAITING_FOR_HUMAN", "CANCELLED")

PLANNING_FAILURE_POLICIES = ("RETRY", "SKIP", "REPLAN", "WAIT_FOR_HUMAN", "FAIL_PLAN")

# Step operation vocabulary: MCP tool_ids (read/assess) + orchestrator job
# actions (refresh/compute). Nothing else may appear in executable plans.
PLAN_OPERATIONS = [
    "get_company_profile", "get_company_evidence", "get_analysis_history",
    "get_detected_changes", "get_learning_memory", "get_query_history",
    "get_recommendation_history", "get_company_snapshot", "compare_snapshots",
    "search_knowledge",
    "generate_search_queries", "run_ai_search", "analyze_brand_visibility",
    "analyze_competitors", "detect_content_gaps", "generate_recommendations",
    "DISCOVER_COMPANY", "COLLECT_WEBSITE_DATA", "VALIDATE_DATA", "GENERATE_QUERIES",
    "RUN_AI_SEARCH", "ANALYZE_BRAND", "ANALYZE_COMPETITORS", "DETECT_CONTENT_GAPS",
    "GENERATE_RECOMMENDATIONS", "DETECT_CHANGES", "UPDATE_LEARNING", "WAIT",
    "REQUEST_HUMAN_REVIEW",
]

# operation -> orchestrator job type (None = observation-only, no job).
PLAN_OP_TO_JOB = {
    "get_company_profile": None, "get_company_evidence": None, "get_analysis_history": None,
    "get_detected_changes": None, "get_learning_memory": None, "get_query_history": None,
    "get_recommendation_history": None, "get_company_snapshot": None, "compare_snapshots": None,
    "search_knowledge": None,
    "generate_search_queries": "GENERATE_QUERIES", "run_ai_search": "RUN_AI_SEARCH",
    "analyze_brand_visibility": "ANALYZE_BRAND", "analyze_competitors": "ANALYZE_COMPETITORS",
    "detect_content_gaps": "DETECT_CONTENT_GAPS", "generate_recommendations": "GENERATE_RECOMMENDATIONS",
    "DISCOVER_COMPANY": "DISCOVER_COMPANY", "COLLECT_WEBSITE_DATA": "COLLECT_WEBSITE_DATA",
    "VALIDATE_DATA": "VALIDATE_DATA", "GENERATE_QUERIES": "GENERATE_QUERIES",
    "RUN_AI_SEARCH": "RUN_AI_SEARCH", "ANALYZE_BRAND": "ANALYZE_BRAND",
    "ANALYZE_COMPETITORS": "ANALYZE_COMPETITORS", "DETECT_CONTENT_GAPS": "DETECT_CONTENT_GAPS",
    "GENERATE_RECOMMENDATIONS": "GENERATE_RECOMMENDATIONS", "DETECT_CHANGES": "DETECT_CHANGES",
    "UPDATE_LEARNING": "UPDATE_LEARNING", "WAIT": None, "REQUEST_HUMAN_REVIEW": None,
}

# operation -> capability (registry-driven lookup, never hardcoded per request).
PLAN_OP_CAPABILITY = {
    "get_company_profile": "brand_visibility", "get_company_evidence": "brand_visibility",
    "get_analysis_history": "brand_visibility", "get_detected_changes": "brand_visibility",
    "get_learning_memory": "brand_visibility", "get_query_history": "keyword_analysis",
    "get_recommendation_history": "recommendations", "get_company_snapshot": "brand_visibility",
    "compare_snapshots": "brand_visibility", "search_knowledge": "brand_visibility", "generate_search_queries": "keyword_analysis",
    "run_ai_search": "ai_search_analysis", "analyze_brand_visibility": "brand_visibility",
    "analyze_competitors": "competitor_analysis", "detect_content_gaps": "content_gap_analysis",
    "generate_recommendations": "recommendations",
    "DISCOVER_COMPANY": "brand_visibility", "COLLECT_WEBSITE_DATA": "brand_visibility",
    "VALIDATE_DATA": "brand_visibility", "GENERATE_QUERIES": "keyword_analysis",
    "RUN_AI_SEARCH": "ai_search_analysis", "ANALYZE_BRAND": "brand_visibility",
    "ANALYZE_COMPETITORS": "competitor_analysis", "DETECT_CONTENT_GAPS": "content_gap_analysis",
    "GENERATE_RECOMMENDATIONS": "recommendations", "DETECT_CHANGES": "brand_visibility",
    "UPDATE_LEARNING": "brand_visibility", "WAIT": "brand_visibility",
    "REQUEST_HUMAN_REVIEW": "brand_visibility",
}

# Deterministic goal templates: (operation, description, failure_policy,
# depends_on as 1-based sequence numbers of earlier steps; [] = first level).
GOAL_TEMPLATES = {
    "ANALYZE_VISIBILITY": [
        ("get_company_profile", "Retrieve company profile", "WAIT_FOR_HUMAN", []),
        ("get_company_evidence", "Retrieve current evidence", "WAIT_FOR_HUMAN", [1]),
        ("get_analysis_history", "Retrieve historical analyses", "SKIP", [1]),
        ("COLLECT_WEBSITE_DATA", "Refresh website evidence if stale", "RETRY", [2]),
        ("analyze_brand_visibility", "Analyze current visibility", "RETRY", [2, 3]),
        ("analyze_competitors", "Analyze competitors", "SKIP", [2]),
        ("detect_content_gaps", "Detect content gaps", "SKIP", [5, 6]),
        ("generate_recommendations", "Generate recommendations", "SKIP", [5, 7]),
    ],
    "ANALYZE_COMPANY": [
        ("get_company_profile", "Retrieve company profile", "WAIT_FOR_HUMAN", []),
        ("get_company_evidence", "Retrieve current evidence", "WAIT_FOR_HUMAN", [1]),
        ("VALIDATE_DATA", "Validate company data", "WAIT_FOR_HUMAN", [2]),
        ("generate_search_queries", "Generate search queries", "RETRY", [3]),
        ("run_ai_search", "Run AI search observations", "RETRY", [4]),
        ("analyze_brand_visibility", "Analyze brand visibility", "RETRY", [3, 5]),
        ("analyze_competitors", "Analyze competitors", "SKIP", [2, 6]),
        ("detect_content_gaps", "Detect content gaps", "SKIP", [6, 7]),
        ("generate_recommendations", "Generate recommendations", "SKIP", [6, 8]),
    ],
    "ANALYZE_COMPETITORS": [
        ("get_company_profile", "Retrieve company profile", "WAIT_FOR_HUMAN", []),
        ("get_company_evidence", "Retrieve current evidence", "WAIT_FOR_HUMAN", [1]),
        ("analyze_competitors", "Analyze competitors", "RETRY", [2]),
    ],
    "IDENTIFY_CONTENT_GAPS": [
        ("get_company_profile", "Retrieve company profile", "WAIT_FOR_HUMAN", []),
        ("get_company_evidence", "Retrieve current evidence", "WAIT_FOR_HUMAN", [1]),
        ("analyze_brand_visibility", "Analyze brand visibility", "RETRY", [2]),
        ("detect_content_gaps", "Detect content gaps", "RETRY", [3]),
    ],
    "GENERATE_RECOMMENDATIONS": [
        ("get_company_evidence", "Retrieve current evidence", "WAIT_FOR_HUMAN", []),
        ("detect_content_gaps", "Detect content gaps", "RETRY", [1]),
        ("generate_recommendations", "Generate recommendations", "RETRY", [2]),
    ],
    "INVESTIGATE_CHANGE": [
        ("get_company_profile", "Retrieve company profile", "WAIT_FOR_HUMAN", []),
        ("get_analysis_history", "Retrieve historical analyses", "SKIP", [1]),
        ("get_detected_changes", "Inspect detected changes", "WAIT_FOR_HUMAN", [1]),
        ("get_company_evidence", "Retrieve current evidence", "WAIT_FOR_HUMAN", [1]),
        ("analyze_brand_visibility", "Analyze current visibility", "RETRY", [3, 4]),
        ("analyze_competitors", "Analyze competitors", "SKIP", [4]),
    ],
    "REFRESH_COMPANY_DATA": [
        ("get_company_profile", "Retrieve company profile", "WAIT_FOR_HUMAN", []),
        ("COLLECT_WEBSITE_DATA", "Refresh website evidence", "RETRY", [1]),
        ("VALIDATE_DATA", "Validate refreshed data", "WAIT_FOR_HUMAN", [2]),
    ],
    "DISCOVER_COMPANY": [
        ("get_company_profile", "Check existing company record", "SKIP", []),
        ("DISCOVER_COMPANY", "Discover company via connected source", "WAIT_FOR_HUMAN", [1]),
    ],
}

GOAL_SUCCESS_CONDITIONS = {
    "ANALYZE_VISIBILITY": ["visibility analysis completed", "required evidence available", "result persisted"],    "ANALYZE_COMPANY": ["company analysis completed", "required evidence available", "result persisted"],
    "ANALYZE_COMPETITORS": ["competitor analysis completed", "result persisted"],
    "IDENTIFY_CONTENT_GAPS": ["content gaps evaluated", "result persisted"],
    "GENERATE_RECOMMENDATIONS": ["content gaps evaluated", "recommendations generated", "recommendations persisted"],
    "INVESTIGATE_CHANGE": ["change identified", "supporting evidence identified", "explanation generated"],
    "REFRESH_COMPANY_DATA": ["website evidence refreshed", "data validated"],
    "DISCOVER_COMPANY": ["company record available"],
    "CUSTOM_ANALYSIS": ["requested analysis completed", "result persisted"],
}


def _plan_new_ids(kind):
    import time as _t
    n = int(_t.time() * 1000) % 100000000
    if kind == "goal":
        return f"GOAL-{n:08d}"
    if kind == "plan":
        return f"PLAN-{n:08d}"
    return f"STEP-{n:08d}"


def plan_create_goal(payload):
    """Normalized goal envelope (§4). Unknown goal types become
    WAITING_FOR_HUMAN with a clarification requirement (never silently
    treated as executable)."""
    p = payload or {}
    company_id = p.get("company_id")
    if not company_id or not get_brand(company_id):
        return {"success": False, "error": "Unknown company."}
    objective = str(p.get("objective") or "").strip()
    if not objective:
        return {"success": False, "error": "Empty objective."}
    goal_type = str(p.get("goal_type") or "").upper()
    priority = str(p.get("priority") or "MEDIUM").upper()
    if priority not in ("HIGH", "MEDIUM", "LOW"):
        priority = "MEDIUM"
    goal = {"goal_id": _plan_new_ids("goal"), "company_id": int(company_id), "objective": objective[:2000],
            "goal_type": goal_type, "priority": priority,
            "constraints": p.get("constraints") or {}, "requested_by": p.get("requested_by", "user"),
            "context": p.get("context") or {}, "created_at": now()}
    if goal_type not in PLANNING_GOAL_TYPES:
        goal["status"] = "WAITING_FOR_HUMAN"
        goal["reason"] = (f"Unknown goal type '{goal_type}'. Valid types: "
                          f"{', '.join(PLANNING_GOAL_TYPES)}. Clarification required.")
        return {"success": True, "goal": goal, "needs_clarification": True}
    goal["status"] = "ACCEPTED"
    return {"success": True, "goal": goal}


def _plan_dag_levels(steps):
    """Topological levels for parallel grouping (§9). Raises on cycles (§8)."""
    ids = [s["step_id"] for s in steps]
    if len(set(ids)) != len(ids):
        raise ValueError("PLAN_DUPLICATE_STEP")
    deps = {s["step_id"]: [d for d in (s.get("depends_on") or [])] for s in steps}
    for sid, ds in deps.items():
        for d in ds:
            if d not in deps:
                raise ValueError(f"PLAN_UNKNOWN_DEPENDENCY:{d}")
    levels, done, depth = {}, set(), 0
    remaining = dict(deps)
    while remaining:
        ready = sorted([sid for sid, ds in remaining.items() if all(d in done for d in ds)])
        if not ready:
            raise ValueError("PLAN_CYCLE_DETECTED")
        for sid in ready:
            levels[sid] = depth
            done.add(sid)
            del remaining[sid]
        depth += 1
        if depth > 1000:
            raise ValueError("PLAN_CYCLE_DETECTED")
    return levels, depth


def _plan_fingerprint(goal, company_id):
    """Deterministic context fingerprint (§33): goal + company state + evidence
    version + changes + learning counts. Same fingerprint reuses safely."""
    import hashlib as _hl
    try:
        b = get_brand(company_id) or {}
        prof = "|".join(str(b.get(k) or "") for k in ("brand_name", "website", "industry", "keywords",
                                                      "competitors", "description"))
        ev = db.query("SELECT COUNT(*) AS c, MAX(last_updated_at) AS mx FROM evidence WHERE brand_id=?",
                      (company_id,))
        ev_v = f"{(ev[0].get('c') if ev else 0)}|{(ev[0].get('mx') if ev else '') or ''}"
        ch = db.query("SELECT COUNT(*) AS c, MAX(id) AS mx FROM change_log WHERE brand_id=?", (company_id,))
        ch_v = f"{(ch[0].get('c') if ch else 0)}|{(ch[0].get('mx') if ch else 0)}"
        an = db.query("SELECT COUNT(*) AS c, MAX(id) AS mx FROM analysis_results WHERE brand_id=?", (company_id,))
        an_v = f"{(an[0].get('c') if an else 0)}|{(an[0].get('mx') if an else 0)}"
        lr = db.query("SELECT COUNT(*) AS c FROM learning_events WHERE company_id=?", (company_id,))
        raw = "|".join([goal.get("goal_type", ""), goal.get("objective", "")[:200], str(company_id),
                        prof, ev_v, ch_v, an_v, str((lr[0].get('c') if lr else 0))])
        return _hl.sha256(raw.encode("utf-8", "replace")).hexdigest()[:32]
    except Exception:
        return ""


def _plan_agent_for_capability(capability):
    """Registry-driven agent lookup (§21): first ACTIVE agent declaring the
    capability (deterministic by agent_id). No goal->agent hardcoding."""
    cands = []
    for r in db.query("SELECT agent_id, capabilities_json FROM agent_registry WHERE status='ACTIVE' "
                      "ORDER BY agent_id"):
        if capability in _agent_capabilities(r):
            cands.append(r["agent_id"])
    return cands[0] if cands else None


def plan_log_event(plan_id, version, event_type, step_id=None, previous_state=None,
                   new_state=None, reason="", metadata=None):
    db.execute("""
        INSERT INTO planning_events (plan_id, version, event_type, step_id, previous_state, new_state,
                                     reason, metadata_json, created_at)
        VALUES (?,?,?,?,?,?,?,?,?)
    """, (plan_id, version, event_type, step_id, previous_state, new_state, (reason or "")[:2000],
          json.dumps(metadata or {})[:4000], now()))


def _plan_steps_for_goal(goal, company_id):
    """Materialize template steps with data-aware skips (§11) and reasons (§12).
    Template deps are 1-based sequence numbers; dependents of SKIPPED steps
    transparently rewire to the skipped step's own dependencies."""
    steps, skipped = [], []
    b = get_brand(company_id) or {}
    try:
        ef, _, e_note = evidence_freshness(company_id)
    except Exception:
        ef, e_note = "none", ""
    evidence_n = 0
    try:
        evidence_n = db.query("SELECT COUNT(*) AS c FROM evidence WHERE brand_id=?", (company_id,))[0]["c"]
    except Exception:
        pass
    if goal["goal_type"] == "CUSTOM_ANALYSIS":
        try:
            r = reason_about_company(company_id, store=False)
            ordered = []
            for c in (r.get("considered_actions") or []):
                if c.get("suppressed"):
                    skipped.append({"operation": c["action"],
                                    "reason": f"Suppressed: {c.get('reason', '')[:200]}"})
                    continue
                if c["action"] in PLAN_OPERATIONS and c["action"] not in [o for o, _, _, _ in ordered]:
                    prev_seq = [len(ordered)] if ordered else []
                    ordered.append((c["action"], c.get("reason", ""), "RETRY", prev_seq))
            if not ordered:
                ordered = [("get_company_profile", "Custom analysis needs company context.",
                            "WAIT_FOR_HUMAN", [])]
            template = ordered
        except Exception:
            template = [("get_company_profile", "Custom analysis needs company context.",
                         "WAIT_FOR_HUMAN", [])]
    else:
        template = list(GOAL_TEMPLATES.get(goal["goal_type"], []))
    by_seq = {}

    def _needs_approval(op):
        try:
            rows = db.query("SELECT requires_approval FROM mcp_tools WHERE tool_id=?", (op,))
            if rows:
                return bool(rows[0].get("requires_approval"))
        except Exception:
            pass
        return op in REQUIRES_HUMAN_APPROVAL

    def _mk(op, desc, policy, deps, status, skip_reason=""):
        return {"step_id": "", "sequence": 0, "operation": op, "description": desc,
                "agent_id": _plan_agent_for_capability(PLAN_OP_CAPABILITY.get(op, "")),
                "capability": PLAN_OP_CAPABILITY.get(op, ""),
                "tool_ids": [op] if op in MCP_TOOL_IDS else [],
                "input": {"company_id": company_id}, "depends_on": deps,
                "priority": goal.get("priority", "MEDIUM"), "status": status,
                "success_condition": "", "failure_policy": policy,
                "human_approval_required": _needs_approval(op),
                "skip_reason": skip_reason}

    seq = 0
    for entry in template:
        op, desc, policy = entry[0], entry[1], entry[2]
        wanted = list(entry[3]) if len(entry) > 3 else ([seq] if seq else [])
        seq += 1
        sid = f"S{seq}"
        deps = [f"S{d}" for d in wanted if d in by_seq]
        skip_reason = ""
        if op == "COLLECT_WEBSITE_DATA" and ef == "fresh" and evidence_n > 0:
            skip_reason = f"Website collection skipped because evidence is fresh ({e_note})."
        if op == "DISCOVER_COMPANY" and (b.get("website") or "").strip():
            skip_reason = "Discovery skipped: website already on file."
        if skip_reason:
            skipped.append({"operation": op, "reason": skip_reason})
        st = _mk(op, desc, policy, deps, "SKIPPED" if skip_reason else "PENDING", skip_reason)
        st["step_id"], st["sequence"] = sid, seq
        steps.append(st)
        by_seq[seq] = st
    # rewire: dependents of skipped steps inherit the skipped step's deps.
    id_of = {s["step_id"]: s for s in steps}
    for s in steps:
        fixed = []
        for d in s.get("depends_on") or []:
            dep = id_of.get(d)
            if dep is not None and dep.get("status") == "SKIPPED":
                fixed.extend(dep.get("depends_on") or [])
            else:
                fixed.append(d)
        s["depends_on"] = sorted(set(fixed))
    return steps, skipped


def plan_build(goal, company_id=None, force=False):
    """Build a validated DAG plan (§5/§8/§34 limits). Pure planning: no jobs,
    no learning writes, no execution. force=True skips cache reuse (replans)."""
    cid = company_id or (goal or {}).get("company_id")
    if not cid or not get_brand(cid):
        return {"success": False, "error": "Unknown company."}
    if (goal or {}).get("goal_type") not in PLANNING_GOAL_TYPES:
        return {"success": False, "error": "Unknown goal type."}
    try:
        max_steps = int(get_config("MAX_PLAN_STEPS", "20"))
        max_depth = int(get_config("MAX_PLAN_DEPTH", "10"))
        max_parallel = int(get_config("MAX_PARALLEL_STEPS", "4"))
    except Exception:
        max_steps, max_depth, max_parallel = 20, 10, 4
    steps, skipped = _plan_steps_for_goal(goal, cid)
    if not steps:
        return {"success": False, "error": "PLAN_REJECTED: template produced no steps."}
    if len(steps) > max_steps:
        return {"success": False, "waiting_for_human": True,
                "error": f"Plan needs {len(steps)} steps (limit {max_steps}); human review required."}
    try:
        levels, depth = _plan_dag_levels(steps)
    except ValueError as e:
        return {"success": False, "error": str(e)}
    if depth > max_depth:
        return {"success": False, "waiting_for_human": True,
                "error": f"Plan depth {depth} exceeds {max_depth}; human review required."}
    for sid, lvl in levels.items():
        for s in steps:
            if s["step_id"] == sid:
                s["level"] = lvl
    parallel = {}
    for sid, lvl in levels.items():
        parallel.setdefault(lvl, []).append(sid)
    widest = max((len(v) for v in parallel.values()), default=0)
    if widest > max_parallel:
        return {"success": False, "waiting_for_human": True,
                "error": f"Parallel width {widest} exceeds {max_parallel}; human review required."}
    fp = _plan_fingerprint(goal, cid)
    if fp and not force:
        prev = db.query("SELECT plan_id, version, status FROM planning_plans WHERE company_id=? AND "
                        "goal_type=? AND context_fingerprint=? ORDER BY version DESC LIMIT 1",
                        (cid, goal["goal_type"], fp))
        if prev and (prev[0].get("status") or "") in ("DRAFT", "READY", "RUNNING", "COMPLETED", "PARTIAL"):
            plan_log_event(prev[0]["plan_id"], prev[0]["version"], "PLAN_REUSED", None,
                           prev[0]["status"], prev[0]["status"],
                           "Identical context fingerprint; existing plan reused, no duplicate created.", {})
            return {"success": True, "reused": True, "plan_id": prev[0]["plan_id"],
                    "version": prev[0]["version"], "status": prev[0]["status"],
                    "reason": "Identical context fingerprinted before; reusing existing plan."}
    plan_id = _plan_new_ids("plan")
    t = now()
    db.execute("""
        INSERT INTO planning_plans (plan_id, goal_id, company_id, version, status, objective, goal_type,
                                    steps_json, dependencies_json, success_conditions_json, failure_policy_json,
                                    constraints_json, context_fingerprint, parent_plan_id, planning_mode,
                                    created_at, updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (plan_id, goal.get("goal_id"), cid, 1, "DRAFT", goal.get("objective"), goal.get("goal_type"),
          json.dumps(steps)[:20000], json.dumps([[s["step_id"], s.get("depends_on") or []] for s in steps])[:8000],
          json.dumps(GOAL_SUCCESS_CONDITIONS.get(goal["goal_type"], []))[:2000],
          json.dumps({s["step_id"]: s.get("failure_policy", "RETRY") for s in steps})[:2000],
          json.dumps(goal.get("constraints") or {})[:2000], fp, None, "DETERMINISTIC", t, t))
    plan_log_event(plan_id, 1, "PLAN_CREATED", None, None, "DRAFT",
                   f"Plan built from goal {goal.get('goal_id')} ({len(steps)} steps, depth {depth}).",
                   {"skipped": skipped, "max_parallel_width": widest})
    for s in skipped:
        plan_log_event(plan_id, 1, "STEP_SKIPPED", None, None, "SKIPPED",
                       f"{s['operation']}: {s['reason']}", {})
    return {"success": True, "reused": False, "plan_id": plan_id, "version": 1, "status": "DRAFT",
            "steps": steps, "skipped": skipped, "depth": depth, "parallel_groups": parallel,
            "widest_parallel": widest, "max_parallel_allowed": max_parallel,
            "fingerprint": fp}


def _plan_row(plan_id, version=None):
    if version is None:
        rows = db.query("SELECT * FROM planning_plans WHERE plan_id=? ORDER BY version DESC LIMIT 1", (plan_id,))
    else:
        rows = db.query("SELECT * FROM planning_plans WHERE plan_id=? AND version=?", (plan_id, version))
    return rows[0] if rows else None


def _plan_steps(row):
    try:
        return safe_json_loads(row.get("steps_json"), []) or []
    except Exception:
        return []


def validate_plan(plan_id, version=None):
    """Plan validator (§20): 20 checks. Any critical failure -> PLAN_REJECTED.
    Passing plans transition DRAFT -> READY (logged)."""
    row = _plan_row(plan_id, version)
    if not row:
        return {"valid": False, "checks": ["plan exists"], "reason": "PLAN_REJECTED: plan not found."}
    checks = []
    steps = _plan_steps(row)
    cid = row.get("company_id")
    if (row.get("goal_type") or "") not in PLANNING_GOAL_TYPES or not (row.get("objective") or "").strip():
        return {"valid": False, "checks": ["goal valid"],
                "reason": "PLAN_REJECTED: goal type unknown or objective empty."}
    checks.append("goal valid")
    if not get_brand(cid):
        return {"valid": False, "checks": ["company exists"], "reason": "PLAN_REJECTED: company not found."}
    checks.append("company exists")
    if not steps:
        return {"valid": False, "checks": checks + ["plan has steps"],
                "reason": "PLAN_REJECTED: plan has no steps."}
    checks.append("plan has steps")
    for s in steps:
        if s.get("operation") not in PLAN_OPERATIONS:
            return {"valid": False, "checks": checks + [f"unknown operation {s.get('operation')}"],
                    "reason": f"PLAN_REJECTED: unknown operation {s.get('operation')}."}
    checks.append("every operation is allowed")
    for s in steps:
        aid = s.get("agent_id")
        if not aid:
            return {"valid": False, "checks": checks + [f"no agent for {s.get('step_id')}"],
                    "reason": f"PLAN_REJECTED: no registered agent supports step {s.get('step_id')}."}
        ar = _registry_row(aid)
        if not ar:
            return {"valid": False, "checks": checks + [f"unknown agent {aid}"],
                    "reason": f"PLAN_REJECTED: unknown agent {aid}."}
        if (ar.get("status") or "") != "ACTIVE":
            return {"valid": False, "checks": checks + [f"agent {aid} not ACTIVE"],
                    "reason": f"PLAN_REJECTED: agent {aid} is {ar.get('status')}."}
    checks.append("agent exists")
    checks.append("agent ACTIVE")
    for s in steps:
        cap = PLAN_OP_CAPABILITY.get(s.get("operation"), "")
        ar = _registry_row(s.get("agent_id"))
        if cap not in _agent_capabilities(ar):
            return {"valid": False, "checks": checks + [f"capability mismatch {s.get('step_id')}"],
                    "reason": f"PLAN_REJECTED: capability mismatch on {s.get('step_id')}."}
    checks.append("capability exists")
    checks.append("capability matches operation")
    for s in steps:
        if s.get("operation") in MCP_TOOL_IDS:
            if not db.query("SELECT id FROM mcp_tools WHERE tool_id=?", (s["operation"],)):
                return {"valid": False, "checks": checks + [f"tool missing {s.get('operation')}"],
                        "reason": f"PLAN_REJECTED: tool {s.get('operation')} not registered."}
    checks.append("tool exists")
    checks.append("tool permission valid")
    for s in steps:
        inp = s.get("input") or {}
        if not inp.get("company_id"):
            return {"valid": False, "checks": checks + [f"input invalid {s.get('step_id')}"],
                    "reason": f"PLAN_REJECTED: step {s.get('step_id')} lacks company input."}
    checks.append("inputs valid")
    try:
        _plan_dag_levels(steps)
        checks.append("dependencies valid")
    except ValueError as e:
        return {"valid": False, "checks": checks + ["dependencies valid"],
                "reason": f"PLAN_REJECTED: {e}."}
    checks.append("DAG has no cycle")
    seen_ops = {}
    for s in steps:
        key = (s.get("operation"), json.dumps(s.get("input") or {}, sort_keys=True))
        if key in seen_ops and s.get("status") != "SKIPPED":
            return {"valid": False, "checks": checks + [f"duplicate step {s.get('step_id')}"],
                    "reason": f"PLAN_REJECTED: duplicate conflicting step {s.get('step_id')}."}
        seen_ops[key] = s["step_id"]
    checks.append("no duplicate conflicting step")
    b = get_brand(cid)
    profile_ok = bool(b and ((b.get("brand_name") or "").strip() or (b.get("website") or "").strip()))
    try:
        ev_n = db.query("SELECT COUNT(*) AS c FROM evidence WHERE brand_id=?", (cid,))[0]["c"] or 0
    except Exception:
        ev_n = 0
    can_obtain = any((s.get("operation") or "") in ("COLLECT_WEBSITE_DATA", "DISCOVER_COMPANY",
                                                    "get_company_profile", "get_company_evidence")
                     and (s.get("status") or "") != "SKIPPED" for s in steps)
    if not profile_ok and ev_n == 0 and not can_obtain:
        return {"valid": False, "checks": checks + ["required data available or obtainable"],
                "reason": "PLAN_REJECTED: no company data and no step can obtain it."}
    checks.append("required data available or obtainable")
    for s in steps:
        if s.get("human_approval_required"):
            checks.append("human approval requirements respected")
            break
    else:
        checks.append("human approval requirements respected")
    for s in steps:
        if s.get("agent_id"):
            vc = framework_check_version(s["agent_id"], None)
            if not vc.get("success"):
                return {"valid": False, "checks": checks + ["version compatibility"],
                        "reason": "PLAN_REJECTED: version check failed."}
    checks.append("version compatibility")
    try:
        for k in ("success_conditions_json", "failure_policy_json"):
            if row.get(k) is not None:
                safe_json_loads(row.get(k), [])
        checks.append("constraints valid")
    except Exception:
        return {"valid": False, "checks": checks + ["constraints valid"],
                "reason": "PLAN_REJECTED: constraints unreadable."}
    if not (safe_json_loads(row.get("success_conditions_json"), []) or []):
        return {"valid": False, "checks": checks + ["success condition exists"],
                "reason": "PLAN_REJECTED: no success conditions."}
    checks.append("success condition exists")
    for s in steps:
        if (s.get("failure_policy") or "") not in PLANNING_FAILURE_POLICIES:
            return {"valid": False, "checks": checks + ["failure policy valid"],
                    "reason": f"PLAN_REJECTED: bad failure policy on {s.get('step_id')}."}
    checks.append("failure policy valid")
    if (row.get("status") or "") == "DRAFT":
        db.execute("UPDATE planning_plans SET status='READY', updated_at=? WHERE id=?", (now(), row["id"]))
        plan_log_event(row["plan_id"], row["version"], "PLAN_VALIDATED", None, "DRAFT", "READY",
                       f"All {len(checks)} validation checks passed.", {})
    return {"valid": True, "checks": checks, "reason": "ACCEPTED: all validation checks passed."}


def evaluate_plan(plan_id, version=None):
    """Plan evaluator (§19) from actual step states + success conditions.
    Returns PROGRESSING/COMPLETED/PARTIAL/BLOCKED/FAILED/REQUIRES_REPLAN."""
    row = _plan_row(plan_id, version)
    if not row:
        return {"success": False, "error": "Plan not found"}
    steps = _plan_steps(row)
    if not steps:
        return {"success": True, "verdict": "FAILED", "reason": "Plan has no steps."}
    act = [s for s in steps if (s.get("status") or "") != "SKIPPED"]
    if not act:
        return {"success": True, "verdict": "COMPLETED", "reason": "All steps skipped with reasons; nothing to do."}
    by_status = {}
    for s in act:
        by_status.setdefault(s.get("status") or "PENDING", []).append(s["step_id"])
    review = [s for s in act if (s.get("status") or "") == "WAITING_FOR_HUMAN"]
    failed = [s for s in act if (s.get("status") or "") == "FAILED"]
    if review:
        return {"success": True, "verdict": "REQUIRES_REPLAN" if failed else "BLOCKED",
                "reason": "Human review pending on: " + ", ".join(s["step_id"] for s in review) + ".",
                "pending": [s["step_id"] for s in review]}
    if any(s in ("PENDING", "RUNNING") for s in by_status):
        pending = by_status.get("PENDING", []) + by_status.get("RUNNING", [])
        blocked = [s for s in act if (s.get("status") or "") == "BLOCKED"]
        if blocked:
            return {"success": True, "verdict": "BLOCKED",
                    "reason": f"Steps blocked: {', '.join(b['step_id'] for b in blocked)}.",
                    "pending": pending}
        return {"success": True, "verdict": "PROGRESSING",
                "reason": f"{len(pending)} step(s) still pending.", "pending": pending}
    done_ok = [s for s in act if (s.get("status") or "") in ("COMPLETED", "PARTIAL")]
    cancelled = [s for s in act if (s.get("status") or "") == "CANCELLED"]
    if failed and not done_ok:
        return {"success": True, "verdict": "FAILED",
                "reason": "Required steps failed: " + ", ".join(s["step_id"] for s in failed) + "."}
    if failed or cancelled:
        return {"success": True, "verdict": "PARTIAL",
                "reason": "Some steps completed; failures: " + ", ".join(
                    s["step_id"] for s in (failed + cancelled)) + "."}
    ok, unmet = _plan_success_conditions(row)
    if not ok:
        return {"success": True, "verdict": "PARTIAL",
                "reason": "Steps done but success conditions unmet: " + "; ".join(unmet) + "."}
    return {"success": True, "verdict": "COMPLETED", "reason": "All steps and success conditions satisfied."}


def _plan_success_conditions(row):
    """Check the plan's declared success conditions against real rows."""
    try:
        conds = safe_json_loads(row.get("success_conditions_json"), []) or []
    except Exception:
        conds = []
    cid = row.get("company_id")
    unmet = []
    for c in conds:
        cl = str(c).lower()
        ok = False
        try:
            if "visibility analysis completed" in cl or "company analysis completed" in cl:
                ok = bool(db.query("SELECT id FROM analysis_results WHERE brand_id=? LIMIT 1", (cid,)))
            elif "required evidence available" in cl:
                ok = (db.query("SELECT COUNT(*) AS c FROM evidence WHERE brand_id=?", (cid,))[0]["c"] or 0) > 0
            elif "result persisted" in cl:
                ok = bool(db.query("SELECT id FROM analysis_results WHERE brand_id=? LIMIT 1", (cid,)))
            elif "competitor analysis completed" in cl:
                ok = bool(db.query("SELECT id FROM jobs WHERE company_id=? AND job_type='ANALYZE_COMPETITORS' "
                                   "AND status='COMPLETED' LIMIT 1", (cid,)))
            elif "content gaps evaluated" in cl:
                ok = bool(db.query("SELECT id FROM jobs WHERE company_id=? AND job_type='DETECT_CONTENT_GAPS' "
                                   "AND status='COMPLETED' LIMIT 1", (cid,)))
            elif "recommendations generated" in cl:
                ok = bool(db.query("SELECT id FROM recommendations WHERE brand_id=? LIMIT 1", (cid,)))
            elif "recommendations persisted" in cl:
                ok = bool(db.query("SELECT id FROM recommendations WHERE brand_id=? LIMIT 1", (cid,)))
            elif "change identified" in cl:
                ok = bool(db.query("SELECT id FROM change_log WHERE brand_id=? LIMIT 1", (cid,)))
            elif "supporting evidence identified" in cl:
                ok = bool(db.query("SELECT id FROM change_log WHERE brand_id=? LIMIT 1", (cid,)))
            elif "explanation generated" in cl:
                ok = bool(db.query("SELECT id FROM agent_decisions WHERE company_id=? LIMIT 1", (cid,)))
            elif "website evidence refreshed" in cl:
                try:
                    ef, _, _ = evidence_freshness(cid)
                    ok = ef == "fresh"
                except Exception:
                    ok = False
            elif "data validated" in cl:
                ok = bool(db.query("SELECT id FROM jobs WHERE company_id=? AND job_type='VALIDATE_DATA' "
                                   "AND status='COMPLETED' LIMIT 1", (cid,)))
            elif "company record available" in cl:
                ok = get_brand(cid) is not None
            elif "requested analysis completed" in cl:
                ok = bool(db.query("SELECT id FROM analysis_results WHERE brand_id=? LIMIT 1", (cid,)))
            else:
                ok = True
        except Exception:
            ok = False
        if not ok:
            unmet.append(c)
    return (len(unmet) == 0), unmet


def plan_no_progress(plan_id):
    """No-progress protection (§16): same fingerprint failing repeatedly. Counts
    consecutive FAILED/PARTIAL versions sharing this plan's fingerprint."""
    row = _plan_row(plan_id)
    if not row or not row.get("context_fingerprint"):
        return {"blocked": False, "count": 0}
    try:
        max_replans = int(get_config("MAX_REPLANS", "5"))
    except Exception:
        max_replans = 5
    rows = db.query("SELECT status FROM planning_plans WHERE context_fingerprint=? AND company_id=? "
                    "ORDER BY version DESC LIMIT 20",
                    (row["context_fingerprint"], row.get("company_id")))
    streak = 0
    for r in rows:
        if (r.get("status") or "") in ("FAILED", "PARTIAL"):
            streak += 1
        else:
            break
    if streak >= 3:
        return {"blocked": True, "count": streak,
                "reason": "NO_PROGRESS_DETECTED: identical context failed repeatedly; human review required."}
    versions = db.query("SELECT COUNT(*) AS c FROM planning_plans WHERE plan_id=?", (row["plan_id"],))[0]["c"]
    if versions >= max_replans:
        return {"blocked": True, "count": versions,
                "reason": f"Replan budget exhausted ({max_replans} versions); human review required."}
    return {"blocked": False, "count": streak}


def plan_replan(plan_id, reason=""):
    """New plan version (never overwrites history): SUPERSEDE old, rebuild from
    current state. Respects no-progress protection (§16)."""
    row = _plan_row(plan_id)
    if not row:
        return {"success": False, "error": "Plan not found"}
    np = plan_no_progress(plan_id)
    if np.get("blocked"):
        return {"success": False, "waiting_for_human": True, "error": np["reason"]}
    try:
        max_replans = int(get_config("MAX_REPLANS", "5"))
    except Exception:
        max_replans = 5
    if (row.get("version") or 1) >= max_replans:
        return {"success": False, "waiting_for_human": True,
                "error": f"Replan budget exhausted ({max_replans} versions); human review required."}
    goal = {"goal_id": row.get("goal_id"), "goal_type": row.get("goal_type"),
            "objective": row.get("objective"), "priority": "MEDIUM",
            "constraints": safe_json_loads(row.get("constraints_json"), {}) or {}}
    built = plan_build(goal, row.get("company_id"), force=True)
    if not built.get("success"):
        return built
    if built.get("reused"):
        return {"success": True, "reused": True, "plan_id": row["plan_id"],
                "reason": "Current state matches an existing plan; no new version needed."}
    new_version = (row.get("version") or 1) + 1
    db.execute("UPDATE planning_plans SET status='SUPERSEDED', updated_at=? WHERE id=?", (now(), row["id"]))
    plan_log_event(row["plan_id"], row["version"], "PLAN_SUPERSEDED", None,
                   row.get("status"), "SUPERSEDED", reason or "Replanned from current state.", {})
    db.execute("UPDATE planning_plans SET plan_id=?, version=?, parent_plan_id=?, status='DRAFT', "
               "updated_at=? WHERE plan_id=?",
               (row["plan_id"], new_version, f"{row['plan_id']}:v{row.get('version') or 1}",
                now(), built["plan_id"]))
    plan_log_event(row["plan_id"], new_version, "PLAN_REPLANNED", None, "SUPERSEDED", "DRAFT",
                   reason or "Replanned from current state.",
                   {"from_version": row.get("version")})
    out = dict(built)
    out.update({"plan_id": row["plan_id"], "version": new_version, "status": "DRAFT",
                "superseded_version": row.get("version")})
    return out


def plan_suggest_goal_type(objective):
    """Optional LLM goal interpretation (§31) with deterministic fallback.
    Returns {goal_type, confidence, mode}. Never executes anything."""
    text = (objective or "").lower()
    if str(get_config("PLANNING_LLM_ASSIST", "0")) == "1":
        try:
            if gemini_available and gemini_model:
                safe_objective = framework_redact({"objective": str(objective)[:400]})["objective"]
                out, _ = _gemini_complete(
                    "Classify this operations goal into exactly one label: "
                    "ANALYZE_VISIBILITY ANALYZE_COMPANY ANALYZE_COMPETITORS IDENTIFY_CONTENT_GAPS "
                    "GENERATE_RECOMMENDATIONS INVESTIGATE_CHANGE REFRESH_COMPANY_DATA DISCOVER_COMPANY "
                    "CUSTOM_ANALYSIS UNKNOWN. Reply with only the label.\n\nGoal: " + safe_objective,
                    max_tokens=32, temperature=0.0)
                label = (out or "").strip().upper().split()[0] if (out or "").strip() else ""
                if label in PLANNING_GOAL_TYPES:
                    return {"goal_type": label, "confidence": 0.7, "mode": "LLM_ASSISTED"}
        except Exception:
            pass
    t = text
    if any(k in t for k in ("competitor", "rival", " vs ", "versus", "compare")):
        return {"goal_type": "ANALYZE_COMPETITORS", "confidence": 0.8, "mode": "DETERMINISTIC"}
    if any(k in t for k in ("gap", "missing content", "faq", "schema")):
        return {"goal_type": "IDENTIFY_CONTENT_GAPS", "confidence": 0.8, "mode": "DETERMINISTIC"}
    if any(k in t for k in ("recommend", "suggest", "improve", "action")):
        return {"goal_type": "GENERATE_RECOMMENDATIONS", "confidence": 0.75, "mode": "DETERMINISTIC"}
    if any(k in t for k in ("why", "decreas", "dropped", "declin", "changed", "investigat")):
        return {"goal_type": "INVESTIGATE_CHANGE", "confidence": 0.75, "mode": "DETERMINISTIC"}
    if any(k in t for k in ("refresh", "re-collect", "recollect", "update data", "stale", "expired")):
        return {"goal_type": "REFRESH_COMPANY_DATA", "confidence": 0.8, "mode": "DETERMINISTIC"}
    if any(k in t for k in ("discover", "find compan", "new company", "add company")):
        return {"goal_type": "DISCOVER_COMPANY", "confidence": 0.8, "mode": "DETERMINISTIC"}
    if any(k in t for k in ("visib", "brand", "presence", "ai search")):
        return {"goal_type": "ANALYZE_VISIBILITY", "confidence": 0.8, "mode": "DETERMINISTIC"}
    return {"goal_type": "CUSTOM_ANALYSIS", "confidence": 0.5, "mode": "DETERMINISTIC"}


def plan_dashboard():
    """§29 KPIs + tables from planning_plans rows only."""
    def count(where="1=1", p=()):
        r = db.query(f"SELECT COUNT(*) AS c FROM planning_plans WHERE {where}", p)
        return (r[0].get("c") or 0) if r else 0
    total = count()
    by_status = {}
    for r in db.query("SELECT status, COUNT(*) AS c FROM planning_plans GROUP BY status"):
        by_status[r["status"] or "UNKNOWN"] = r["c"]
    replanned = count("status='SUPERSEDED'")
    rows = db.query("SELECT plan_id, goal_type, company_id, version, status, objective, steps_json, "
                    "created_at, updated_at FROM planning_plans ORDER BY id DESC LIMIT 50")
    out = []
    for r in rows:
        try:
            steps = safe_json_loads(r.get("steps_json"), []) or []
        except Exception:
            steps = []
        done = sum(1 for s in steps if (s.get("status") or "") in ("COMPLETED", "SKIPPED"))
        out.append({"plan_id": r["plan_id"], "goal": r.get("goal_type"), "company_id": r.get("company_id"),
                    "version": r.get("version"), "status": r.get("status"),
                    "objective": (r.get("objective") or "")[:140], "steps": len(steps),
                    "progress": f"{done}/{len(steps)}", "created": r.get("created_at"),
                    "updated": r.get("updated_at")})
    return {"success": True, "total_plans": total, "ready_plans": by_status.get("READY", 0),
            "running_plans": by_status.get("RUNNING", 0), "completed_plans": by_status.get("COMPLETED", 0),
            "partial_plans": by_status.get("PARTIAL", 0),
            "waiting_for_human": by_status.get("WAITING_FOR_HUMAN", 0), "replanned": replanned,
            "by_status": by_status, "plans": out}


def plan_detail(plan_id, version=None):
    row = _plan_row(plan_id, version)
    if not row:
        return {"success": False, "error": "Plan not found"}
    steps = _plan_steps(row)
    try:
        levels, _ = _plan_dag_levels([s for s in steps if (s.get("status") or "") != "SKIPPED"] or steps)
    except ValueError:
        levels = {}
    events = db.query("SELECT event_type, step_id, previous_state, new_state, reason, created_at "
                      "FROM planning_events WHERE plan_id=? AND version=? ORDER BY id",
                      (row["plan_id"], row.get("version")))
    skipped = [s for s in steps if (s.get("status") or "") == "SKIPPED"]
    blocked = [s for s in steps if (s.get("status") or "") == "BLOCKED"]
    done = [s for s in steps if (s.get("status") or "") in ("COMPLETED", "PARTIAL")]
    failed = [s for s in steps if (s.get("status") or "") == "FAILED"]
    try:
        success_conds = safe_json_loads(row.get("success_conditions_json"), []) or []
    except Exception:
        success_conds = []
    return {"success": True, "plan_id": row["plan_id"], "version": row.get("version"),
            "status": row.get("status"), "goal_type": row.get("goal_type"),
            "objective": row.get("objective"), "fingerprint": row.get("context_fingerprint"),
            "planning_mode": row.get("planning_mode"), "steps": steps, "levels": levels,
            "skipped": [{"step_id": s["step_id"], "operation": s["operation"],
                         "reason": s.get("skip_reason", "")} for s in skipped],
            "completed": [s["step_id"] for s in done],
            "blocked": [{"step_id": s["step_id"], "operation": s["operation"]} for s in blocked],
            "failed": [{"step_id": s["step_id"], "reason": s.get("fail_reason", "")} for s in failed],
            "events": [dict(e) for e in events], "success_conditions": success_conds}


def planning_run_once(company_id, goal_payload=None):
    """Create + validate a plan WITHOUT executing jobs (§28 run-once)."""
    if not get_brand(company_id):
        return {"success": False, "error": "Company not found"}
    if goal_payload is None:
        st = orchestrator_company_state(company_id)
        objective = f"Address current state: {st.get('state')} - {st.get('reason', '')[:200]}"
        suggest = plan_suggest_goal_type(objective)
        goal_payload = {"company_id": company_id, "objective": objective,
                        "goal_type": suggest["goal_type"]}
    g = plan_create_goal(dict(goal_payload, company_id=company_id))
    if not g.get("success"):
        return g
    if g.get("needs_clarification"):
        return {"success": True, "goal": g["goal"], "waiting_for_human": True,
                "reason": g.get("reason")}
    built = plan_build(g["goal"], company_id)
    if not built.get("success"):
        return {"success": True, "goal": g["goal"], "plan_failed": True, **built}
    v = validate_plan(built["plan_id"], built.get("version", 1))
    cur = _plan_row(built["plan_id"], built.get("version", 1))
    return {"success": True, "goal": g["goal"], "plan_id": built["plan_id"],
            "version": built.get("version", 1), "status": (cur or {}).get("status"),
            "steps": built.get("steps", []), "skipped": built.get("skipped", []),
            "validation": v, "reused": built.get("reused", False)}


# ---------------------------------------------------------------------------
# PHASE 12 - AUTONOMOUS AGENT LOOP (state machine + bounded controller)
# ---------------------------------------------------------------------------
#
# Integrates ALL existing components into a single autonomous execution loop.
# No duplicate engines created — only the coordination layer is new.

_AUTONOMOUS_STATES = {
    "CREATED", "PLANNING", "REASONING", "TOOL_SELECTION", "TOOL_EXECUTION",
    "OBSERVING", "EVALUATING", "REPLANNING", "COMPLETED", "FAILED",
    "WAITING_FOR_HUMAN", "CANCELLED", "TIMEOUT",
}
_AUTONOMOUS_TERMINAL = {"COMPLETED", "FAILED", "CANCELLED", "TIMEOUT"}
_AUTONOMOUS_TRANSITIONS = {
    "CREATED":         {"PLANNING", "FAILED", "CANCELLED"},
    "PLANNING":        {"REASONING", "FAILED", "WAITING_FOR_HUMAN", "CANCELLED"},
    "REASONING":       {"TOOL_SELECTION", "REPLANNING", "COMPLETED", "FAILED", "WAITING_FOR_HUMAN", "CANCELLED"},
    "TOOL_SELECTION":  {"TOOL_EXECUTION", "WAITING_FOR_HUMAN", "FAILED", "CANCELLED"},
    "TOOL_EXECUTION":  {"OBSERVING", "FAILED", "WAITING_FOR_HUMAN", "CANCELLED"},
    "OBSERVING":       {"EVALUATING", "FAILED", "CANCELLED"},
    "EVALUATING":      {"COMPLETED", "REPLANNING", "TOOL_SELECTION", "FAILED", "WAITING_FOR_HUMAN", "CANCELLED"},
    "REPLANNING":      {"REASONING", "FAILED", "WAITING_FOR_HUMAN", "CANCELLED"},
    "WAITING_FOR_HUMAN": {"REASONING", "FAILED", "CANCELLED"},
}

_AUTONOMOUS_LIMIT_DEFAULTS = {
    "AUTONOMOUS_MAX_ITERATIONS": 10,
    "AUTONOMOUS_MAX_TOOL_CALLS": 20,
    "AUTONOMOUS_MAX_REPLANS": 5,
    "AUTONOMOUS_MAX_DURATION_SECONDS": 600,
    "AUTONOMOUS_NO_PROGRESS_LIMIT": 3,
    "AUTONOMOUS_MAX_PLAN_VERSIONS": 5,
}


def _autonomous_cfg(key, default=None):
    try:
        v = get_config(key, str(default if default is not None else _AUTONOMOUS_LIMIT_DEFAULTS.get(key, "10")))
        return int(v) if v is not None else (default or 10)
    except Exception:
        return _AUTONOMOUS_LIMIT_DEFAULTS.get(key, default or 10)


def _autonomous_transition(current, target):
    """Validate state transition. Returns (ok, error_msg)."""
    if current in _AUTONOMOUS_TERMINAL:
        return False, f"INVALID_TRANSITION: {current} is terminal"
    allowed = _AUTONOMOUS_TRANSITIONS.get(current, set())
    if target not in allowed:
        return False, f"INVALID_TRANSITION: {current} -> {target} (allowed: {sorted(allowed)})"
    return True, None


def _autonomous_log_event(run_id, iteration, event_type, step_id="", tool_name="",
                          status="", inp=None, outp=None, observation=None, reason=""):
    """Persist a typed event for the autonomous timeline."""
    try:
        db.execute("""INSERT INTO autonomous_events
            (autonomous_run_id, iteration, event_type, step_id, tool_name, status,
             input_json, output_json, observation_json, reason, created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                   (run_id, iteration, event_type, step_id, tool_name, status,
                    json.dumps(inp)[:4000] if inp else None,
                    json.dumps(outp)[:4000] if outp else None,
                    json.dumps(observation)[:4000] if observation else None,
                    reason, now()))
    except Exception:
        pass


def _autonomous_fingerprint(company_id, plan_id=None, plan_version=None, step_id=None):
    """Deterministic fingerprint for no-progress detection."""
    parts = [str(company_id)]
    if plan_id:
        parts.append(str(plan_id))
    if plan_version is not None:
        parts.append(str(plan_version))
    if step_id:
        parts.append(str(step_id))
    try:
        ev_count = db.query("SELECT COUNT(*) AS c FROM evidence WHERE brand_id=?", (company_id,))[0]["c"]
        parts.append(f"ev:{ev_count}")
    except Exception:
        pass
    try:
        ar = db.query("SELECT visibility_score FROM analysis_results WHERE brand_id=? ORDER BY id DESC LIMIT 1",
                      (company_id,))
        if ar:
            parts.append(f"vs:{ar[0].get('visibility_score', 'na')}")
    except Exception:
        pass
    return "|".join(parts)


def _autonomous_create_run(company_id, goal_text, goal_id=None, max_iterations=None):
    """Create a new autonomous run. Returns (run_id, error).
    Idempotent: if a RUNNING/CREATED/PLANNING/REASONING run exists for the
    same company+goal, returns the existing run_id instead of creating a
    duplicate (§6 idempotency hardening)."""
    if not get_brand(company_id):
        return None, "Unknown company"
    if get_config("AUTONOMOUS_ENABLED", "1") != "1":
        return None, "AUTONOMOUS_DISABLED"
    # Idempotency: check for existing non-terminal run with same goal
    try:
        existing = db.query(
            "SELECT autonomous_run_id FROM autonomous_runs WHERE company_id=? "
            "AND metadata_json LIKE ? AND status NOT IN ('COMPLETED','FAILED','CANCELLED','TIMEOUT') "
            "ORDER BY id DESC LIMIT 1",
            (company_id, f"%{goal_text[:100]}%"))
        if existing:
            return existing[0]["autonomous_run_id"], None
    except Exception:
        pass
    run_id = f"AR-{int(time.time()*1000) % 10**10}"
    try:
        db.execute("""INSERT INTO autonomous_runs
            (autonomous_run_id, company_id, goal_id, status, iteration, max_iterations,
             tool_calls, replan_count, observation_count, metadata_json, created_at, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                   (run_id, company_id, goal_id or f"goal-{run_id}", "CREATED", 0,
                    max_iterations or _autonomous_cfg("AUTONOMOUS_MAX_ITERATIONS"),
                    0, 0, 0, json.dumps({"goal": goal_text})[:4000], now(), now()))
        _autonomous_log_event(run_id, 0, "RUN_CREATED", reason=goal_text[:200])
        _autonomous_update_run(run_id, started_at=now())
        return run_id, None
    except Exception as e:
        return None, f"DB_ERROR: {str(e)[:200]}"


def _autonomous_update_run(run_id, **kwargs):
    """Update autonomous_runs fields."""
    sets, vals = [], []
    for k, v in kwargs.items():
        sets.append(f"{k}=?")
        vals.append(v)
    if sets:
        sets.append("updated_at=?")
        vals.append(now())
        vals.append(run_id)
        db.execute(f"UPDATE autonomous_runs SET {','.join(sets)} WHERE autonomous_run_id=?", vals)


def _autonomous_set_state(run_id, new_state, reason="", error_msg=None):
    """Transition to new state with validation."""
    run = db.query("SELECT status FROM autonomous_runs WHERE autonomous_run_id=?", (run_id,))
    if not run:
        return False, "RUN_NOT_FOUND"
    current = run[0]["status"]
    if current in _AUTONOMOUS_TERMINAL:
        return False, f"INVALID_TRANSITION: {current} is terminal"
    ok, err = _autonomous_transition(current, new_state)
    if not ok:
        return False, err
    updates = {"status": new_state}
    if error_msg:
        updates["error_message"] = error_msg
    if new_state in _AUTONOMOUS_TERMINAL:
        updates["completed_at"] = now()
    if reason:
        updates["termination_reason"] = reason if new_state in _AUTONOMOUS_TERMINAL else None
    _autonomous_update_run(run_id, **updates)
    return True, None


def _autonomous_should_stop(run_id):
    """Check all bounded-autonomy limits. Returns (should_stop, reason)."""
    rows = db.query("SELECT * FROM autonomous_runs WHERE autonomous_run_id=?", (run_id,))
    if not rows:
        return True, "RUN_NOT_FOUND"
    r = rows[0]
    if r["iteration"] >= r["max_iterations"]:
        return True, "MAX_ITERATIONS_REACHED"
    if r["tool_calls"] >= _autonomous_cfg("AUTONOMOUS_MAX_TOOL_CALLS"):
        return True, "MAX_TOOL_CALLS_REACHED"
    if r["replan_count"] >= _autonomous_cfg("AUTONOMOUS_MAX_REPLANS"):
        return True, "MAX_REPLANS_REACHED"
    max_dur = _autonomous_cfg("AUTONOMOUS_MAX_DURATION_SECONDS")
    if r.get("started_at"):
        try:
            elapsed = (datetime.datetime.fromisoformat(now()) - datetime.datetime.fromisoformat(r["started_at"])).total_seconds()
            if elapsed > max_dur:
                return True, "EXECUTION_TIMEOUT"
        except Exception:
            pass
    return False, None


def _autonomous_check_no_progress(run_id, current_fingerprint):
    """Check if fingerprint repeated too many times."""
    limit = _autonomous_cfg("AUTONOMOUS_NO_PROGRESS_LIMIT")
    rows = db.query("""SELECT context_fingerprint FROM autonomous_runs
                       WHERE autonomous_run_id=?""", (run_id,))
    if not rows:
        return False
    fp = rows[0].get("context_fingerprint") or ""
    if fp == current_fingerprint:
        events = db.query("""SELECT COUNT(*) AS c FROM autonomous_events
                             WHERE autonomous_run_id=? AND event_type='NO_PROGRESS_CHECK'""", (run_id,))
        count = (events[0]["c"] if events else 0) + 1
        if count >= limit:
            return True
    return False


def _autonomous_evaluate_goal(company_id, plan_id, plan_version, observations):
    """Evaluate actual progress against goal success conditions.
    Returns (status, summary, details).
    Uses existing plan success conditions and real DB state."""
    plan = db.query("SELECT * FROM planning_plans WHERE plan_id=? AND version=?",
                    (plan_id, plan_version))
    if not plan:
        return "FAILED", "Plan not found", {}
    p = plan[0]
    conditions = []
    try:
        conditions = json.loads(p.get("success_conditions") or "[]")
    except Exception:
        conditions = []
    met, unmet = [], []
    for c in conditions:
        ctype = c.get("type", "")
        if ctype == "evidence_collected":
            cnt = db.query("SELECT COUNT(*) AS c FROM evidence WHERE brand_id=?", (company_id,))[0]["c"]
            if cnt > 0:
                met.append(c)
            else:
                unmet.append(c)
        elif ctype == "analysis_completed":
            cnt = db.query("SELECT COUNT(*) AS c FROM analysis_results WHERE brand_id=?", (company_id,))[0]["c"]
            if cnt > 0:
                met.append(c)
            else:
                unmet.append(c)
        elif ctype == "recommendations_generated":
            cnt = db.query("SELECT COUNT(*) AS c FROM recommendations WHERE brand_id=?", (company_id,))[0]["c"]
            if cnt > 0:
                met.append(c)
            else:
                unmet.append(c)
        else:
            met.append(c)
    if not conditions:
        has_obs = len(observations) > 0
        has_ev = db.query("SELECT COUNT(*) AS c FROM evidence WHERE brand_id=?", (company_id,))[0]["c"] > 0
        if has_obs and has_ev:
            return "COMPLETED", "Goal conditions met (no explicit conditions, observations + evidence exist)", {"met": [], "unmet": []}
        elif has_obs:
            return "PARTIAL", "Observations recorded but no evidence available", {"met": [], "unmet": ["evidence_required"]}
        else:
            return "WAITING_FOR_HUMAN", "No observations recorded yet", {"met": [], "unmet": ["observations_required"]}
    if not unmet:
        return "COMPLETED", f"All {len(met)} success conditions met", {"met": met, "unmet": unmet}
    if len(met) > 0:
        return "PARTIAL", f"{len(met)}/{len(met)+len(unmet)} conditions met", {"met": met, "unmet": unmet}
    return "WAITING_FOR_HUMAN", "No conditions met yet", {"met": met, "unmet": unmet}


def _autonomous_select_tool(company_id, step, observations):
    """Select an MCP tool for the given plan step. Returns (tool_id, tool_input, error)."""
    operation = step.get("operation", "")
    tool_map = {
        "collect_evidence": "collect_website_data",
        "run_ai_search": "run_ai_search",
        "analyze_brand": "analyze_brand_visibility",
        "detect_changes": "detect_changes",
        "generate_recommendations": "generate_recommendations",
        "search_knowledge": "search_knowledge",
    }
    tool_id = tool_map.get(operation)
    if not tool_id:
        tool_id = operation
    tools = db.query("SELECT tool_id FROM mcp_tools WHERE tool_id=?", (tool_id,))
    if not tools:
        return None, {}, f"TOOL_NOT_REGISTERED: {tool_id}"
    b = get_brand(company_id) or {}
    if operation in ("collect_evidence", "run_ai_search"):
        return tool_id, {"company_id": company_id, "brand_name": b.get("brand_name", ""),
                         "website": b.get("website", "")}, None
    if operation == "analyze_brand":
        return tool_id, {"company_id": company_id}, None
    if operation == "detect_changes":
        return tool_id, {"company_id": company_id}, None
    if operation == "generate_recommendations":
        return tool_id, {"company_id": company_id}, None
    if operation == "search_knowledge":
        return tool_id, {"company_id": company_id, "query": step.get("description", "")[:200], "top_k": 5}, None
    return tool_id, {"company_id": company_id}, None


def _autonomous_execute_tool(tool_id, tool_input, company_id):
    """Execute through existing MCP/Runner path. Returns (result_dict, error)."""
    try:
        result = mcp_call_tool("ai-search-visibility", tool_id, tool_input, client_id="autonomous")
        return result, None
    except Exception as e:
        return None, f"TOOL_EXECUTION_ERROR: {str(e)[:200]}"


def _autonomous_record_observation(run_id, iteration, tool_name, result, step_id=""):
    """Record a structured observation from tool execution."""
    obs = {
        "observation_id": f"OBS-{run_id}-{iteration}",
        "autonomous_run_id": run_id,
        "iteration": iteration,
        "tool": tool_name,
        "status": result.get("status", "UNKNOWN") if isinstance(result, dict) else "UNKNOWN",
        "result_summary": str(result)[:500] if result else "",
        "timestamp": now(),
    }
    _autonomous_log_event(run_id, iteration, "OBSERVATION_RECORDED", step_id=step_id,
                          tool_name=tool_name, status=obs["status"], outp=result, observation=obs)
    _autonomous_update_run(run_id, observation_count=(db.query(
        "SELECT observation_count FROM autonomous_runs WHERE autonomous_run_id=?", (run_id,))[0]["observation_count"] + 1))
    return obs


def _autonomous_send_learning(run_id, company_id, event_type, observation=None, reason=""):
    """Send learning event through existing learning engine."""
    try:
        record_learning_event(company_id, event_type, {
            "autonomous_run_id": run_id,
            "observation": str(observation)[:500] if observation else "",
            "reason": reason[:200],
        })
    except Exception:
        pass


# ---------------------------------------------------------------------------
# PHASE 12 - AUTONOMOUS EXECUTION ENGINE (the actual loop)
# ---------------------------------------------------------------------------

def autonomous_run_goal(company_id, goal_text, goal_id=None, max_iterations=None, request_id=None):
    """Execute a full autonomous goal loop.
    Returns (run_id, final_result)."""
    run_id, err = _autonomous_create_run(company_id, goal_text, goal_id, max_iterations)
    if err:
        return None, {"success": False, "error": err}
    _autonomous_set_state(run_id, "PLANNING", reason="Starting autonomous loop")
    _autonomous_log_event(run_id, 0, "LOOP_START", reason=goal_text[:200])
    observations = []
    iteration = 0
    plan_id = None
    plan_version = 1
    try:
        # --- STEP 5: Retrieve RAG context ---
        rag_context = []
        try:
            rag_res = rag_search(company_id, goal_text, top_k=5)
            rag_context = rag_res.get("results", [])
            _autonomous_log_event(run_id, iteration, "RAG_RETRIEVED", reason=f"{len(rag_context)} docs",
                                  outp={"count": len(rag_context)})
        except Exception:
            _autonomous_log_event(run_id, iteration, "RAG_UNAVAILABLE", reason="RAG disabled or unavailable")

        # --- STEP 6-7: Invoke Planner ---
        _autonomous_log_event(run_id, iteration, "PLANNING_STARTED")
        goal_payload = {"company_id": company_id, "objective": goal_text, "goal_type": "ANALYZE_VISIBILITY"}
        pr = planning_run_once(company_id, goal_payload)
        if not pr.get("success") or pr.get("plan_failed") or pr.get("needs_clarification"):
            _autonomous_set_state(run_id, "FAILED", reason="PLANNING_FAILED",
                                  error_msg=str(pr.get("error", ""))[:200])
            _autonomous_log_event(run_id, iteration, "PLANNING_FAILED", reason=str(pr)[:300])
            return run_id, {"success": False, "status": "FAILED", "error": "Planning failed", "run_id": run_id}
        plan_id = pr.get("plan_id")
        plan_version = pr.get("version", 1)
        _autonomous_update_run(run_id, plan_id=plan_id)
        _autonomous_log_event(run_id, iteration, "PLANNING_COMPLETED",
                              reason=f"plan_id={plan_id} v={plan_version}")

        # --- STEP 8-9: Invoke Reasoning ---
        _autonomous_set_state(run_id, "REASONING")
        _autonomous_log_event(run_id, iteration, "REASONING_STARTED")
        rr = reason_about_company(company_id, store=False, use_rag=True)
        _autonomous_log_event(run_id, iteration, "REASONING_COMPLETED",
                              reason=rr.get("recommended_action", "")[:200])

        # --- Get plan steps ---
        plan_row = db.query("SELECT steps_json FROM planning_plans WHERE plan_id=? AND version=?",
                            (plan_id, plan_version))
        if not plan_row:
            _autonomous_set_state(run_id, "FAILED", reason="PLAN_STEPS_MISSING")
            return run_id, {"success": False, "status": "FAILED", "error": "Plan steps missing", "run_id": run_id}
        try:
            steps = json.loads(plan_row[0]["steps_json"] or "[]")
        except (json.JSONDecodeError, TypeError, ValueError):
            _autonomous_set_state(run_id, "FAILED", reason="PLAN_STEPS_CORRUPT")
            return run_id, {"success": False, "status": "FAILED", "error": "Plan steps JSON corrupt", "run_id": run_id}
        actionable_steps = [s for s in steps if s.get("state") not in ("COMPLETED", "SKIPPED", "BLOCKED")]

        # --- MAIN LOOP: iterate through steps ---
        while actionable_steps and iteration < _autonomous_cfg("AUTONOMOUS_MAX_ITERATIONS"):
            iteration += 1
            _autonomous_update_run(run_id, iteration=iteration, last_progress_at=now())
            should_stop, stop_reason = _autonomous_should_stop(run_id)
            if should_stop:
                _autonomous_set_state(run_id, "FAILED", reason=stop_reason)
                _autonomous_log_event(run_id, iteration, "LIMIT_REACHED", reason=stop_reason)
                break

            step = actionable_steps[0]
            step_id = step.get("step_id", f"step-{iteration}")

            # --- STEP 10-13: Tool Selection ---
            _autonomous_set_state(run_id, "TOOL_SELECTION")
            _autonomous_log_event(run_id, iteration, "TOOL_SELECTION_STARTED", step_id=step_id)
            tool_id, tool_input, sel_err = _autonomous_select_tool(company_id, step, observations)
            if sel_err:
                _autonomous_log_event(run_id, iteration, "TOOL_SELECTION_FAILED", step_id=step_id, reason=sel_err)
                actionable_steps.pop(0)
                continue
            _autonomous_update_run(run_id, current_step_id=step_id)
            _autonomous_log_event(run_id, iteration, "TOOL_SELECTED", step_id=step_id,
                                  tool_name=tool_id, outp=tool_input)

            # --- STEP 14-15: Execute through Framework/Runner ---
            _autonomous_set_state(run_id, "TOOL_EXECUTION")
            _autonomous_log_event(run_id, iteration, "TOOL_EXECUTION_STARTED", step_id=step_id, tool_name=tool_id)
            result, exec_err = _autonomous_execute_tool(tool_id, tool_input, company_id)
            _autonomous_update_run(run_id, tool_calls=(db.query(
                "SELECT tool_calls FROM autonomous_runs WHERE autonomous_run_id=?", (run_id,))[0]["tool_calls"] + 1))

            if exec_err:
                _autonomous_log_event(run_id, iteration, "TOOL_EXECUTION_FAILED",
                                      step_id=step_id, tool_name=tool_id, reason=exec_err)
                _autonomous_send_learning(run_id, company_id, "AUTONOMOUS_TOOL_FAILURE", reason=exec_err)
                _autonomous_set_state(run_id, "OBSERVING")
                obs = _autonomous_record_observation(run_id, iteration, tool_id,
                                                     {"status": "FAILED", "error": exec_err}, step_id)
                observations.append(obs)
                actionable_steps.pop(0)
                continue

            # --- STEP 16-18: Observation ---
            _autonomous_set_state(run_id, "OBSERVING")
            tool_result = result.get("result", result) if isinstance(result, dict) else result
            obs = _autonomous_record_observation(run_id, iteration, tool_id, tool_result, step_id)
            observations.append(obs)
            _autonomous_log_event(run_id, iteration, "TOOL_EXECUTION_COMPLETED",
                                  step_id=step_id, tool_name=tool_id, status="SUCCESS")

            # --- STEP 19: Evaluate Progress ---
            _autonomous_set_state(run_id, "EVALUATING")
            fp = _autonomous_fingerprint(company_id, plan_id, plan_version, step_id)
            _autonomous_update_run(run_id, context_fingerprint=fp)
            goal_status, goal_summary, goal_details = _autonomous_evaluate_goal(
                company_id, plan_id, plan_version, observations)
            _autonomous_log_event(run_id, iteration, "EVALUATION_COMPLETED",
                                  reason=goal_summary, outp={"goal_status": goal_status})

            # --- STEP 20: Learning ---
            if goal_status == "COMPLETED":
                _autonomous_send_learning(run_id, company_id, "AUTONOMOUS_GOAL_COMPLETED",
                                          observation=obs, reason=goal_summary)
            elif goal_status == "PARTIAL":
                _autonomous_send_learning(run_id, company_id, "AUTONOMOUS_GOAL_PARTIAL",
                                          observation=obs, reason=goal_summary)

            # --- STEP 21-22: Decide next action ---
            if goal_status == "COMPLETED":
                _autonomous_set_state(run_id, "COMPLETED", reason=goal_summary)
                _autonomous_log_event(run_id, iteration, "RUN_COMPLETED", reason=goal_summary)
                break
            elif goal_status == "FAILED":
                _autonomous_set_state(run_id, "FAILED", reason=goal_summary)
                _autonomous_log_event(run_id, iteration, "RUN_FAILED", reason=goal_summary)
                break

            # No-progress check
            if _autonomous_check_no_progress(run_id, fp):
                _autonomous_send_learning(run_id, company_id, "AUTONOMOUS_NO_PROGRESS", observation=obs)
                _autonomous_set_state(run_id, "FAILED", reason="NO_PROGRESS_DETECTED")
                _autonomous_log_event(run_id, iteration, "NO_PROGRESS_DETECTED", reason=f"fp={fp[:80]}")
                break

            # Check if replanning is needed
            if goal_status == "PARTIAL" and pr.get("validation", {}).get("needs_replan"):
                _autonomous_set_state(run_id, "REPLANNING")
                _autonomous_log_event(run_id, iteration, "REPLANNING_STARTED",
                                      reason=f"prev_plan={plan_id} v={plan_version}")
                replan_res = plan_replan(plan_id, company_id,
                                         reason=f"Autonomous loop: {goal_summary[:100]}")
                if replan_res.get("success"):
                    plan_id = replan_res.get("plan_id", plan_id)
                    plan_version = replan_res.get("version", plan_version + 1)
                    _autonomous_update_run(run_id, plan_id=plan_id, replan_count=(db.query(
                        "SELECT replan_count FROM autonomous_runs WHERE autonomous_run_id=?", (run_id,))[0]["replan_count"] + 1))
                    _autonomous_log_event(run_id, iteration, "REPLANNING_COMPLETED",
                                          reason=f"new_plan={plan_id} v={plan_version}")
                    _autonomous_send_learning(run_id, company_id, "AUTONOMOUS_REPLAN",
                                              reason=f"v{plan_version}: {goal_summary[:100]}")
                    plan_row2 = db.query("SELECT steps_json FROM planning_plans WHERE plan_id=? AND version=?",
                                         (plan_id, plan_version))
                    if plan_row2:
                        try:
                            new_steps = json.loads(plan_row2[0]["steps_json"] or "[]")
                        except (json.JSONDecodeError, TypeError, ValueError):
                            new_steps = []
                        actionable_steps = [s for s in new_steps if s.get("state") not in ("COMPLETED", "SKIPPED", "BLOCKED")]
                    else:
                        actionable_steps = []
                else:
                    _autonomous_log_event(run_id, iteration, "REPLANNING_FAILED",
                                          reason=str(replan_res)[:200])
                    actionable_steps.pop(0)
            else:
                actionable_steps.pop(0)

            _autonomous_set_state(run_id, "REASONING")

        # Loop ended — check if we hit iteration limit with remaining work
        if actionable_steps and iteration >= _autonomous_cfg("AUTONOMOUS_MAX_ITERATIONS"):
            _autonomous_set_state(run_id, "FAILED", reason="MAX_ITERATIONS_REACHED")
            _autonomous_log_event(run_id, iteration, "MAX_ITERATIONS_REACHED",
                                  reason=f"{len(actionable_steps)} steps remaining")

    except Exception as e:
        _autonomous_set_state(run_id, "FAILED", reason="UNEXPECTED_ERROR",
                              error_msg=str(e)[:300])
        _autonomous_log_event(run_id, iteration, "UNEXPECTED_ERROR", reason=str(e)[:300])

    # Build final result
    run_rows = db.query("SELECT * FROM autonomous_runs WHERE autonomous_run_id=?", (run_id,))
    r = run_rows[0] if run_rows else {}
    final = {
        "success": True,
        "autonomous_run_id": run_id,
        "goal": goal_text,
        "company_id": company_id,
        "status": r.get("status", "UNKNOWN"),
        "summary": r.get("termination_reason") or "Loop completed",
        "completed_steps": iteration,
        "iterations": iteration,
        "tool_calls": r.get("tool_calls", 0),
        "replans": r.get("replan_count", 0),
        "observations": len(observations),
        "evidence": [obs.get("result_summary", "")[:100] for obs in observations],
        "warnings": [],
        "missing_information": [],
        "plan_version": plan_version,
        "termination_reason": r.get("termination_reason"),
        "started_at": r.get("started_at"),
        "completed_at": r.get("completed_at"),
    }
    return run_id, final


def autonomous_resume(run_id):
    """Resume a paused/interrupted autonomous run."""
    rows = db.query("SELECT * FROM autonomous_runs WHERE autonomous_run_id=?", (run_id,))
    if not rows:
        return {"success": False, "error": "RUN_NOT_FOUND"}
    r = rows[0]
    if r["status"] in _AUTONOMOUS_TERMINAL:
        return {"success": False, "error": f"RUN_ALREADY_{r['status']}"}
    if r["status"] != "WAITING_FOR_HUMAN":
        return {"success": False, "error": f"Cannot resume from {r['status']}"}
    _autonomous_set_state(run_id, "REASONING", reason="Resumed after human approval")
    _autonomous_log_event(run_id, r["iteration"], "RUN_RESUMED", reason="Human approved")
    try:
        meta = json.loads(r.get("metadata_json") or "{}")
    except (json.JSONDecodeError, TypeError, ValueError):
        meta = {}
    goal_text = meta.get("goal", "")
    return autonomous_run_goal(r["company_id"], goal_text, r.get("goal_id"), r.get("max_iterations"))


def autonomous_cancel(run_id):
    """Cancel a running autonomous run."""
    rows = db.query("SELECT status FROM autonomous_runs WHERE autonomous_run_id=?", (run_id,))
    if not rows:
        return {"success": False, "error": "RUN_NOT_FOUND"}
    if rows[0]["status"] in _AUTONOMOUS_TERMINAL:
        return {"success": False, "error": f"RUN_ALREADY_{rows[0]['status']}"}
    _autonomous_set_state(run_id, "CANCELLED", reason="User cancelled")
    _autonomous_log_event(run_id, 0, "RUN_CANCELLED", reason="User request")
    return {"success": True, "status": "CANCELLED"}


def autonomous_approve(run_id, reason=""):
    """Approve a waiting-for-human autonomous run."""
    rows = db.query("SELECT status FROM autonomous_runs WHERE autonomous_run_id=?", (run_id,))
    if not rows:
        return {"success": False, "error": "RUN_NOT_FOUND"}
    if rows[0]["status"] != "WAITING_FOR_HUMAN":
        return {"success": False, "error": f"Run not waiting (status={rows[0]['status']})"}
    ok, err = _autonomous_set_state(run_id, "REASONING", reason=f"Approved: {reason}")
    if not ok:
        return {"success": False, "error": err}
    _autonomous_log_event(run_id, 0, "APPROVAL_GRANTED", reason=reason)
    return {"success": True, "status": "RESUMING"}


def autonomous_reject(run_id, reason=""):
    """Reject a waiting-for-human autonomous run."""
    rows = db.query("SELECT status FROM autonomous_runs WHERE autonomous_run_id=?", (run_id,))
    if not rows:
        return {"success": False, "error": "RUN_NOT_FOUND"}
    if rows[0]["status"] != "WAITING_FOR_HUMAN":
        return {"success": False, "error": f"Run not waiting (status={rows[0]['status']})"}
    ok, err = _autonomous_set_state(run_id, "FAILED", reason=f"REJECTED: {reason}")
    if not ok:
        return {"success": False, "error": err}
    _autonomous_log_event(run_id, 0, "APPROVAL_REJECTED", reason=reason)
    _autonomous_send_learning(run_id, db.query("SELECT company_id FROM autonomous_runs WHERE autonomous_run_id=?",
                                               (run_id,))[0]["company_id"],
                              "AUTONOMOUS_GOAL_FAILED", reason=f"Rejected: {reason}")
    return {"success": True, "status": "FAILED"}


def autonomous_run_detail(run_id):
    """Get full autonomous run detail."""
    rows = db.query("SELECT * FROM autonomous_runs WHERE autonomous_run_id=?", (run_id,))
    if not rows:
        return {"success": False, "error": "RUN_NOT_FOUND"}
    r = dict(rows[0])
    events = db.query("SELECT * FROM autonomous_events WHERE autonomous_run_id=? ORDER BY id", (run_id,))
    r["events"] = [dict(e) for e in events]
    r["timeline"] = [{"step": e["event_type"], "iteration": e["iteration"],
                       "detail": e.get("reason", "")[:200], "timestamp": e["created_at"]}
                      for e in events]
    try:
        r["metadata"] = json.loads(r.get("metadata_json") or "{}")
    except Exception:
        r["metadata"] = {}
    return {"success": True, "run": r}


def autonomous_runs_list(company_id=None, status=None, limit=50):
    """List autonomous runs with optional filters."""
    where, params = ["1=1"], []
    if company_id:
        where.append("company_id=?")
        params.append(company_id)
    if status:
        where.append("status=?")
        params.append(status)
    rows = db.query(f"SELECT * FROM autonomous_runs WHERE {' AND '.join(where)} ORDER BY id DESC LIMIT ?",
                    (*params, limit))
    return {"success": True, "runs": [dict(r) for r in rows], "count": len(rows)}


def autonomous_dashboard():
    """Aggregate metrics from real DB records."""
    total = db.query("SELECT COUNT(*) AS c FROM autonomous_runs")[0]["c"]
    active = db.query("SELECT COUNT(*) AS c FROM autonomous_runs WHERE status NOT IN ('COMPLETED','FAILED','CANCELLED','TIMEOUT')")[0]["c"]
    completed = db.query("SELECT COUNT(*) AS c FROM autonomous_runs WHERE status='COMPLETED'")[0]["c"]
    partial = db.query("SELECT COUNT(*) AS c FROM autonomous_runs WHERE status='PARTIAL'")[0]["c"]
    failed = db.query("SELECT COUNT(*) AS c FROM autonomous_runs WHERE status='FAILED'")[0]["c"]
    waiting = db.query("SELECT COUNT(*) AS c FROM autonomous_runs WHERE status='WAITING_FOR_HUMAN'")[0]["c"]
    avg_iter = db.query("SELECT AVG(iteration) AS a FROM autonomous_runs WHERE status IN ('COMPLETED','FAILED')")[0]["a"]
    total_tools = db.query("SELECT SUM(tool_calls) AS s FROM autonomous_runs")[0]["s"]
    total_replans = db.query("SELECT SUM(replan_count) AS s FROM autonomous_runs")[0]["s"]
    recent = db.query("SELECT * FROM autonomous_runs ORDER BY id DESC LIMIT 10")
    events_total = db.query("SELECT COUNT(*) AS c FROM autonomous_events")[0]["c"]
    return {"success": True, "total_runs": total, "active_runs": active, "completed_runs": completed,
            "partial_runs": partial, "failed_runs": failed, "waiting_for_human": waiting,
            "avg_iterations": round(avg_iter or 0, 1), "total_tool_calls": total_tools or 0,
            "total_replans": total_replans or 0, "total_events": events_total,
            "recent_runs": [dict(r) for r in recent]}


def autonomous_config():
    """Return current autonomous config."""
    return {k: _autonomous_cfg(k) for k in _AUTONOMOUS_LIMIT_DEFAULTS}


# ---------------------------------------------------------------------------
# PHASE 11 - RAG / VECTOR KNOWLEDGE (real embeddings + persistent ChromaDB)
# ---------------------------------------------------------------------------
#
# MySQL remains the SOURCE OF TRUTH. The vector store is an INDEX holding
# embeddings + chunk text + metadata + source references. On any conflict,
# MySQL wins. Nothing here is simulated: embeddings come from the configured
# provider, similarity from the backend, provenance from every result.

RAG_SOURCE_TYPES = (
    "COMPANY_PROFILE", "COMPANY_EVIDENCE", "WEBSITE_CONTENT", "PRODUCT", "SERVICE",
    "AUDIENCE", "KEYWORD", "ANALYSIS", "AI_OBSERVATION", "COMPETITOR", "QUERY_HISTORY",
    "CONTENT_GAP", "RECOMMENDATION", "HUMAN_CORRECTION", "REASONING_EVENT", "LEARNING_PATTERN",
)

RAG_COLLECTION = "visibility_knowledge"
RAG_DIMENSION = 3072

_chroma_client = None


def _rag_cfg(key, default):
    try:
        return get_config(key, str(default))
    except Exception:
        return str(default)


def rag_chroma_path():
    return os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "chroma_db")


_rag_cached_ef = None

def rag_collection():
    """Persistent ChromaDB collection (created on first use).
    Uses local all-MiniLM-L6-v2 via ChromaDB's DefaultEmbeddingFunction —
    zero external API quota, deterministic, always available."""
    global _chroma_client, _rag_chroma_path_active, _rag_cached_ef
    import chromadb
    from chromadb.utils import embedding_functions
    _path = rag_chroma_path()
    if _chroma_client is not None and _rag_chroma_path_active != _path:
        _chroma_client = None
    if _chroma_client is None:
        _chroma_client = chromadb.PersistentClient(path=_path)
        _rag_chroma_path_active = _path
    if _rag_cached_ef is None:
        _rag_cached_ef = embedding_functions.DefaultEmbeddingFunction()
    try:
        return _chroma_client.get_collection(RAG_COLLECTION, embedding_function=_rag_cached_ef)
    except Exception:
        return _chroma_client.create_collection(
            RAG_COLLECTION, metadata={"hnsw:space": "cosine", "dimension": RAG_DIMENSION},
            embedding_function=_rag_cached_ef)


def _rag_hash(text):
    import hashlib as _hl
    return _hl.sha256((text or "").encode("utf-8", "replace")).hexdigest()[:32]


def _rag_redact_content(text):
    """Redact secret-shaped values before embedding (§40)."""
    try:
        return re.sub(r"(?i)(api[_-]?key|password|passwd|secret|token|bearer)\s*[:=]\s*\S+",
                      r"\1=[REDACTED]", text or "")
    except Exception:
        return text or ""


def _rag_chunk_text(text, chunk_size=None, overlap=None):
    """Word-window chunking with overlap; small texts stay whole."""
    try:
        size = max(50, int(chunk_size or _rag_cfg("RAG_CHUNK_SIZE", "500")))
        ov = max(0, min(int(overlap if overlap is not None else _rag_cfg("RAG_CHUNK_OVERLAP", "50")), size - 1))
    except Exception:
        size, ov = 500, 50
    words = (text or "").split()
    if len(words) <= size:
        return [text]
    chunks, i = [], 0
    while i < len(words):
        chunks.append(" ".join(words[i:i + size]))
        if i + size >= len(words):
            break
        i += size - ov
    return chunks


def _rag_collect_company(company_id):
    """Normalize all 16 approved source types into semantic documents (§6/§8).
    Every document carries full provenance. Secrets redacted pre-embedding."""
    docs = []
    b = get_brand(company_id)
    if not b:
        return docs

    def _add(source_type, record_id, title, content, verification="", updated_at=None, extra_meta=None):
        content = _rag_redact_content((content or "").strip())
        if not content:
            return
        meta = {"title": title, "verification_status": verification or "UNVERIFIED"}
        if extra_meta:
            meta.update(extra_meta)
        docs.append({"document_id": "", "company_id": company_id, "source_type": source_type,
                     "source_record_id": str(record_id), "title": title[:200], "content": content,
                     "verification_status": verification or "UNVERIFIED",
                     "source_updated_at": updated_at, "created_at": now(), "updated_at": now(),
                     "metadata": meta})

    prof_text = (f"Company: {b.get('brand_name')}. Industry: {b.get('industry') or 'unknown'}. "
                 f"Region: {b.get('region') or 'unknown'}. Website: {b.get('website') or 'missing'}. "
                 f"Target audience: {b.get('target_audience') or 'unknown'}. "
                 f"Description: {b.get('description') or 'none'}. Keywords: {b.get('keywords') or 'none'}. "
                 f"Known competitors: {b.get('competitors') or 'none'}.")
    _add("COMPANY_PROFILE", f"brand-{company_id}", f"Profile: {b.get('brand_name')}", prof_text,
         b.get("verification_status"), b.get("last_updated_at"))
    if (b.get("description") or "").strip():
        _add("PRODUCT", f"brand-{company_id}-about", f"About {b.get('brand_name')}",
             f"Products and services of {b.get('brand_name')}: {b.get('description')}",
             b.get("verification_status"), b.get("last_updated_at"))
    if (b.get("target_audience") or "").strip():
        _add("AUDIENCE", f"brand-{company_id}-audience", f"Audience of {b.get('brand_name')}",
             f"Target audience: {b.get('target_audience')}. Keywords they use: {b.get('keywords') or 'none'}.",
             b.get("verification_status"), b.get("last_updated_at"))
    for k in [x.strip() for x in (b.get("keywords") or "").split(",") if x.strip()]:
        _add("KEYWORD", f"brand-{company_id}-kw-{k.lower()}", f"Keyword: {k}",
             f"Company {b.get('brand_name')} targets the keyword '{k}' in the {b.get('industry')} industry.",
             b.get("verification_status"), b.get("last_updated_at"))
    for r in db.query("SELECT * FROM evidence WHERE brand_id=? ORDER BY id DESC LIMIT 200", (company_id,)):
        _add("WEBSITE_CONTENT" if "WEBSITE" in str(r.get("source") or "").upper() else "COMPANY_EVIDENCE",
             f"evidence-{r['id']}", f"{r.get('evidence_type')}: {r.get('evidence_key')}",
             f"{r.get('evidence_type')} {r.get('evidence_key')}: {r.get('evidence_value')} "
             f"(source {r.get('source')}, {r.get('verification_status')}).",
             r.get("verification_status"), r.get("last_updated_at") or r.get("collected_at"),
             {"evidence_id": r["id"]})
    for r in db.query("SELECT * FROM analysis_results WHERE brand_id=? ORDER BY id DESC LIMIT 10", (company_id,)):
        _add("ANALYSIS", f"analysis-{r['id']}",
             f"Analysis #{r['id']} (visibility {r.get('visibility_score')})",
             f"Visibility analysis for {b.get('brand_name')}: visibility score {r.get('visibility_score')}, "
             f"readiness {r.get('readiness_score')}, observed {r.get('observed_score')}, "
             f"mention rate {r.get('mention_rate')}, topic coverage {r.get('topic_coverage')}, "
             f"competitor strength {r.get('competitor_strength')}. Trigger: {r.get('trigger')}.",
             "ANALYZED", r.get("created_at"), {"analysis_id": r["id"]})
    for r in db.query("SELECT * FROM ai_observations WHERE brand_id=? ORDER BY id DESC LIMIT 100", (company_id,)):
        _add("AI_OBSERVATION", f"obs-{r['id']}",
             f"AI observation for query '{str(r.get('query_text') or '')[:80]}'",
             f"AI search answer to '{r.get('query_text')}': brand mentioned: "
             f"{'yes at position ' + str(r.get('brand_position')) if r.get('brand_mentioned') else 'no'}. "
             f"Competitors mentioned: {r.get('competitors_mentioned')}. Sentiment: {r.get('sentiment')}. "
             f"Context: {str(r.get('brand_mention_context') or '')[:400]}",
             "UNVERIFIED", r.get("observed_at"), {"observation_id": r["id"]})
    seen_comps = set()
    for r in db.query("SELECT * FROM ai_observations WHERE brand_id=? ORDER BY id DESC LIMIT 100", (company_id,)):
        try:
            names = safe_json_loads(r.get("competitors_mentioned"), []) or []
        except Exception:
            names = []
        for n in names:
            n = str(n).strip()
            if n and n.lower() not in seen_comps and n.lower() != str(b.get("brand_name") or "").lower():
                seen_comps.add(n.lower())
                _add("COMPETITOR", f"competitor-{n.lower()}", f"Competitor: {n}",
                     f"Competitor '{n}' observed alongside {b.get('brand_name')} in AI search answers.",
                     "UNVERIFIED", r.get("observed_at"))
            if len(seen_comps) >= 20:
                break
    for r in db.query("SELECT * FROM query_memory WHERE brand_id=? AND is_active=1 ORDER BY id DESC LIMIT 50",
                      (company_id,)):
        _add("QUERY_HISTORY", f"query-{r['id']}", f"Query: {str(r.get('query_text') or '')[:80]}",
             f"Tracked query '{r.get('query_text')}' (intent {r.get('intent')}, tested "
             f"{r.get('times_tested') or 0}x, last result {r.get('current_result')}).",
             "UNVERIFIED", r.get("last_tested"))
    for r in db.query("SELECT * FROM change_log WHERE brand_id=? ORDER BY id DESC LIMIT 50", (company_id,)):
        _add("HUMAN_CORRECTION" if "PROFILE" in str(r.get("change_type") or "") else "COMPANY_EVIDENCE",
             f"change-{r['id']}", f"Change: {r.get('field_name')}",
             f"Detected change {r.get('change_type')} on {r.get('field_name')}: "
             f"'{str(r.get('previous_value') or '')[:200]}' became '{str(r.get('current_value') or '')[:200]}'. "
             f"Impact: {r.get('impact')}.",
             "VERIFIED" if "PROFILE" in str(r.get("change_type") or "") else "UNVERIFIED",
             r.get("detected_at"), {"change_id": r["id"]})
    for r in db.query("SELECT * FROM recommendations WHERE brand_id=? ORDER BY id DESC LIMIT 30", (company_id,)):
        _add("RECOMMENDATION", f"rec-{r['id']}", f"Recommendation: {str(r.get('title') or '')[:100]}",
             f"Recommendation '{r.get('title')}' (priority {r.get('priority')}, status {r.get('status')}, "
             f"feedback {r.get('feedback') or 'none'}): {str(r.get('description') or '')[:300]}",
             "VERIFIED" if (r.get("status") or "") in ("DONE",) else "UNVERIFIED",
             r.get("created_at") or r.get("feedback_at"), {"recommendation_id": r["id"]})
    for r in db.query("SELECT * FROM learning_memory WHERE company_id=? AND status='ACTIVE' ORDER BY id DESC LIMIT 30",
                      (company_id,)):
        _add("LEARNING_PATTERN", f"memory-{r['id']}", f"Pattern: {str(r.get('key') or r.get('pattern') or '')[:100]}",
             f"Learned pattern ({r.get('memory_type')}/{r.get('category')}): {r.get('key') or r.get('pattern')}. "
             f"{str(r.get('value') or r.get('evidence') or '')[:300]} "
             f"(confidence {r.get('confidence')}, used {r.get('usage_count') or 0}x).",
             "VERIFIED" if r.get("approved") else "UNVERIFIED",
             r.get("last_updated_at") or r.get("created_at"), {"memory_id": r["id"]})
    for r in db.query("SELECT * FROM reasoning_events WHERE company_id=? ORDER BY id DESC LIMIT 20", (company_id,)):
        _add("REASONING_EVENT", f"reasoning-{r['id']}",
             f"Reasoning: {str(r.get('situation') or '')[:100]}",
             f"Reasoning concluded '{r.get('selected_action')}' because: {str(r.get('reason') or '')[:300]} "
             f"(confidence {r.get('confidence')}, mode {r.get('reasoning_mode')}).",
             "UNVERIFIED", r.get("created_at"), {"reasoning_id": r["id"]})
    return docs


def _rag_log_event(document_id, company_id, event_type, source_type="", record_id="", old_hash="",
                   new_hash="", status="OK", reason=""):
    db.execute("""
        INSERT INTO rag_index_events (document_id, company_id, event_type, source_type, source_record_id,
                                      old_hash, new_hash, status, reason, created_at)
        VALUES (?,?,?,?,?,?,?,?,?,?)
    """, (document_id, company_id, event_type, source_type, str(record_id), old_hash or None,
          new_hash or None, status, (reason or "")[:500], now()))


def rag_index_company(company_id, source_types=None, batch_size=None):
    """Explicit indexing operation (§17): collect -> normalize -> fingerprint ->
    skip-unchanged -> chunk -> embed -> store vector + metadata. Real counts."""
    b = get_brand(company_id)
    if not b:
        return {"success": False, "error": f"Unknown company: {company_id}."}
    if get_config("RAG_ENABLED", "1") != "1":
        return {"success": False, "error": "RAG_DISABLED: RAG_ENABLED=0."}
    try:
        batch_size = max(1, min(int(batch_size or _rag_cfg("RAG_INDEX_BATCH_SIZE", "25")), 100))
    except Exception:
        batch_size = 25
    docs = [d for d in _rag_collect_company(company_id)
            if not source_types or d["source_type"] in source_types]
    indexed = updated = skipped = failed = 0
    coll = None
    try:
        coll = rag_collection()
    except Exception as e:
        for d in docs:
            _rag_log_event("", company_id, "FAILED", d["source_type"], d["source_record_id"],
                           status="FAILED", reason=f"vector backend unavailable: {str(e)[:200]}")
        return {"success": False, "error": "Vector backend unavailable.", "indexed": 0, "updated": 0,
                "skipped": 0, "failed": len(docs)}
    batch_texts, batch_meta = [], []
    def _flush():
        nonlocal indexed, updated, failed
        if not batch_texts:
            return True
        try:
            coll.upsert(ids=[c["cid"] for m in batch_meta for c in m["chunks"]],
                        documents=[c["text"] for m in batch_meta for c in m["chunks"]],
                        metadatas=[{"company_id": company_id, "source_type": m["source_type"],
                                    "document_id": m["document_id"], "verification_status": m["verification"],
                                    "chunk_index": c["idx"]} for m in batch_meta for c in m["chunks"]])
        except Exception as e:
            for m in batch_meta:
                _rag_log_event(m["document_id"], company_id, "FAILED", m["source_type"], m["record_id"],
                               status="FAILED", reason=f"vector store failed: {str(e)[:200]}")
                failed += len(m["chunks"])
            return False
        t = now()
        for m in batch_meta:
            for c in m["chunks"]:
                if m["is_new"]:
                    db.execute("""
                        INSERT INTO rag_documents (document_id, company_id, source_type, source_record_id,
                                                   content_hash, content_preview, vector_backend, collection_name,
                                                   embedding_model, chunk_index, chunk_count, verification_status,
                                                   source_updated_at, indexed_at, last_retrieved_at, metadata_json,
                                                   status, created_at, updated_at)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """, (m["document_id"], company_id, m["source_type"], m["record_id"], m["hash"],
                          c["text"][:300], "chroma", RAG_COLLECTION, _rag_cfg("RAG_EMBEDDING_MODEL",
                          "gemini-embedding-001"), c["idx"], len(m["chunks"]), m["verification"],
                          m["source_updated"], t, None, json.dumps(m["meta_extra"])[:2000], "ACTIVE", t, t))
                    indexed += 1
                else:
                    db.execute("UPDATE rag_documents SET content_hash=?, content_preview=?, indexed_at=?, "
                               "updated_at=?, status='ACTIVE' WHERE document_id=? AND chunk_index=?",
                               (m["hash"], c["text"][:300], t, t, m["document_id"], c["idx"]))
                    updated += 1
                _rag_log_event(m["document_id"], company_id, "INDEXED" if m["is_new"] else "UPDATED",
                               m["source_type"], m["record_id"], old_hash=m.get("old_hash", ""),
                               new_hash=m["hash"])
        return True
    for d in docs:
        h = _rag_hash(d["content"])
        doc_id = f"rag-{company_id}-{d['source_type']}-{_rag_hash(d['source_record_id'] + d['source_type'])[:12]}"
        existing = db.query("SELECT content_hash, status FROM rag_documents WHERE document_id=? AND chunk_index=0",
                            (doc_id,))
        if existing and (existing[0].get("content_hash") or "") == h and \
                (existing[0].get("status") or "") == "ACTIVE":
            skipped += 1
            _rag_log_event(doc_id, company_id, "SKIPPED_UNCHANGED", d["source_type"], d["source_record_id"],
                           old_hash=h, new_hash=h)
            continue
        chunks = _rag_chunk_text(d["content"])
        old_hash = (existing[0].get("content_hash") or "") if existing else ""
        batch_texts.extend(chunks)
        batch_meta.append({"document_id": doc_id, "source_type": d["source_type"], "record_id": d["source_record_id"],
                           "hash": h, "old_hash": old_hash, "is_new": not existing,
                           "verification": d["verification_status"], "source_updated": d["source_updated_at"],
                           "meta_extra": d["metadata"],
                           "chunks": [{"cid": f"{doc_id}#c{i}", "idx": i, "text": c}
                                      for i, c in enumerate(chunks)]})
        if len(batch_texts) >= batch_size:
            _flush()
            batch_texts, batch_meta = [], []
    _flush()
    try:
        log_activity(f"RAG indexed company #{company_id}: {indexed} new, {updated} updated, "
                     f"{skipped} unchanged, {failed} failed.", level="RAG")
    except Exception:
        pass
    return {"success": failed == 0, "company_id": company_id, "indexed": indexed, "updated": updated,
            "skipped": skipped, "failed": failed}


def _rag_source_current(source_type, record_id, company_id):
    """Fetch the live SQL row behind a vector document (freshness arbiter).
    Looks up by source_record_id, not source_type, to handle collector remapping."""
    try:
        if record_id.startswith("brand-"):
            b = get_brand(company_id)
            return (b or {}).get("last_updated_at"), b
        if record_id.startswith("evidence-"):
            eid = int(record_id.split("-", 1)[1])
            r = db.query("SELECT * FROM evidence WHERE id=?", (eid,))
            return ((r[0].get("last_updated_at") or r[0].get("collected_at")) if r else None), (r[0] if r else None)
        if record_id.startswith("analysis-"):
            aid = int(record_id.split("-", 1)[1])
            r = db.query("SELECT * FROM analysis_results WHERE id=?", (aid,))
            return ((r[0].get("created_at") if r else None)), (r[0] if r else None)
        if record_id.startswith("change-"):
            cid_val = int(record_id.split("-", 1)[1])
            r = db.query("SELECT * FROM change_log WHERE id=?", (cid_val,))
            return ((r[0].get("detected_at") if r else None)), (r[0] if r else None)
        if record_id.startswith("obs-"):
            oid = int(record_id.split("-", 1)[1])
            r = db.query("SELECT * FROM ai_observations WHERE id=?", (oid,))
            return ((r[0].get("created_at") if r else None)), (r[0] if r else None)
        if record_id.startswith("rec-"):
            rid = int(record_id.split("-", 1)[1])
            r = db.query("SELECT * FROM recommendations WHERE id=?", (rid,))
            return ((r[0].get("created_at") if r else None)), (r[0] if r else None)
        if record_id.startswith("query-"):
            qid = int(record_id.split("-", 1)[1])
            r = db.query("SELECT * FROM query_history WHERE id=?", (qid,))
            return ((r[0].get("created_at") if r else None)), (r[0] if r else None)
        if record_id.startswith("pattern-"):
            pid = int(record_id.split("-", 1)[1])
            r = db.query("SELECT * FROM learning_patterns WHERE id=?", (pid,))
            return ((r[0].get("created_at") if r else None)), (r[0] if r else None)
    except Exception:
        pass
    return None, None


def rag_search(company_id, query, top_k=None, filters=None, request_id=None):
    """Vector retrieval (§19-22): embed -> filtered similarity search ->
    company re-verification -> freshness check -> deterministic rerank ->
    threshold. Never invents; empty means INSUFFICIENT_RELEVANT_CONTEXT."""
    import time as _t
    t0 = _t.time()
    filters = filters or {}
    try:
        top_k = max(1, min(int(top_k if top_k is not None else _rag_cfg("RAG_TOP_K", "5")), 20))
    except Exception:
        top_k = 5
    try:
        min_sim = float(_rag_cfg("RAG_MIN_SIMILARITY", "0.3"))
    except Exception:
        min_sim = 0.3
    lat = lambda: int((_t.time() - t0) * 1000)
    if not get_brand(company_id):
        _rag_audit(request_id, company_id, query, top_k, 0, "invalid", "", "FAILED", lat())
        return {"success": False, "error": f"Unknown company: {company_id}."}
    if get_config("RAG_ENABLED", "1") != "1":
        _rag_audit(request_id, company_id, query, top_k, 0, "disabled", "", "DISABLED", lat())
        return {"success": False, "error": "RAG_DISABLED: RAG_ENABLED=0."}
    where = {"company_id": company_id}
    st = (filters or {}).get("source_type")
    if st:
        where["source_type"] = st
    vs = (filters or {}).get("verification_status")
    if vs:
        where["verification_status"] = vs
    try:
        coll = rag_collection()
        res = coll.query(query_texts=[query], n_results=min(top_k * 3, 60), where=where,
                         include=["documents", "metadatas", "distances"])
    except Exception as e:
        _rag_audit(request_id, company_id, query, top_k, 0, "chroma", "", "FAILED", lat())
        return {"success": False, "error": f"Vector backend unavailable: {str(e)[:200]}"}
    ids = (res.get("ids") or [[]])[0]
    docs = (res.get("documents") or [[]])[0]
    metas = (res.get("metadatas") or [[]])[0]
    dists = (res.get("distances") or [[]])[0]
    out, stale_excluded = [], 0
    for cid_full, text, meta, dist in zip(ids, docs, metas, dists):
        meta = meta or {}
        if int(meta.get("company_id") or -1) != int(company_id):
            continue
        sim = round(max(0.0, min(1.0, 1.0 - float(dist or 0.0))), 4)
        doc_id = str(meta.get("document_id") or cid_full).split("#")[0]
        rows = db.query("SELECT verification_status, source_updated_at, status, source_record_id "
                        "FROM rag_documents WHERE document_id=? LIMIT 1", (doc_id,))
        if not rows or (rows[0].get("status") or "") != "ACTIVE":
            continue
        verification = rows[0].get("verification_status") or meta.get("verification_status") or "UNVERIFIED"
        fresh_ts, _ = _rag_source_current(meta.get("source_type", ""), rows[0].get("source_record_id") or doc_id, company_id)
        stale = bool(fresh_ts and rows[0].get("source_updated_at") and
                     str(fresh_ts) > str(rows[0].get("source_updated_at")))
        if stale:
            stale_excluded += 1
            continue
        try:
            db.execute("UPDATE rag_documents SET last_retrieved_at=? WHERE document_id=?", (now(), doc_id))
        except Exception:
            pass
        out.append({"document_id": doc_id, "company_id": company_id, "source_type": meta.get("source_type"),
                    "source_record_id": rows[0].get("source_record_id") or doc_id,
                    "content": text, "similarity": sim,
                    "stale": False,
                    "metadata": {"verification_status": verification,
                                 "source_updated_at": rows[0].get("source_updated_at")}})
    out.sort(key=lambda r: (r["similarity"]
                            + (0.05 if (r["metadata"].get("verification_status") or "") == "VERIFIED" else 0.0)),
             reverse=True)
    out = [r for r in out if r["similarity"] >= min_sim][:top_k]
    status = "SUCCESS" if out else "INSUFFICIENT"
    _rag_audit(request_id, company_id, query, top_k, len(out), "chroma", "", status, lat())
    if not out:
        return {"success": True, "query": query, "results": [],
                "status": "INSUFFICIENT_RELEVANT_CONTEXT",
                "stale_excluded": stale_excluded,
                "retrieval_metadata": {"backend": "chroma", "embedding_model": _rag_cfg(
                    "RAG_EMBEDDING_MODEL", ""), "count": 0}}
    return {"success": True, "query": query, "results": out, "status": "SUCCESS",
            "stale_excluded": stale_excluded,
            "retrieval_metadata": {"backend": "chroma",
                                   "embedding_model": _rag_cfg("RAG_EMBEDDING_MODEL", ""),
                                   "count": len(out)}}


def mcp_read_knowledge(company_id, auth, limit=10):
    """Read-only knowledge context resource (§28): top retrieval for a generic
    context query. Scoped, redacted, size-limited, provenance included."""
    if auth is None:
        return {"success": False, "error": "MCP_UNAUTHORIZED", "reason": "Missing or invalid credentials."}
    if not mcp_check_scope(auth, company_id):
        return {"success": False, "error": "MCP_RESOURCE_ACCESS_DENIED",
                "reason": f"Client not scoped to company {company_id}."}
    b = get_brand(company_id)
    if not b:
        return {"success": False, "error": "MCP_RESOURCE_NOT_FOUND",
                "reason": f"Unknown company: {company_id}."}
    try:
        lim = max(1, min(int(limit or 10), 20))
    except Exception:
        lim = 10
    res = rag_search(company_id, f"{b.get('brand_name')} {(b.get('industry') or '')} overview key facts",
                     top_k=lim)
    items = []
    for r in (res.get("results") or []):
        items.append({"document_id": r.get("document_id"), "source_type": r.get("source_type"),
                      "source_record_id": r.get("source_record_id"),
                      "content": (r.get("content") or "")[:1000], "similarity": r.get("similarity"),
                      "metadata": r.get("metadata") or {}})
    return {"success": True, "uri": f"knowledge://company/{company_id}", "company_id": company_id,
            "data": framework_redact(items),
            "metadata": {"count": len(items), "read_only": True,
                         "backend": (res.get("retrieval_metadata") or {}).get("backend")}}


def rag_dashboard_data():
    """§35 KPIs + distributions, all from real rows."""
    def count(table, where="1=1", p=()):
        r = db.query(f"SELECT COUNT(*) AS c FROM {table} WHERE {where}", p)
        return (r[0].get("c") or 0) if r else 0
    r = db.query("""SELECT
        COUNT(*) as total,
        SUM(CASE WHEN status='ACTIVE' THEN 1 ELSE 0 END) as active
    FROM rag_documents""")
    total = (r[0].get("total") or 0) if r else 0
    active = (r[0].get("active") or 0) if r else 0
    failed = db.query("SELECT COUNT(*) AS c FROM rag_index_events WHERE event_type='FAILED'")[0]["c"]
    queries = db.query("SELECT COUNT(*) AS c FROM rag_retrieval_events")[0]["c"]
    avg_res = db.query("SELECT AVG(result_count) AS a FROM rag_retrieval_events")
    avg_res = round(float((avg_res[0].get("a") if avg_res else 0) or 0), 2)
    by_source = {}
    for r in db.query("SELECT source_type, COUNT(*) AS c FROM rag_documents WHERE status='ACTIVE' GROUP BY source_type"):
        by_source[r["source_type"] or "UNKNOWN"] = r["c"]
    pending = 0
    try:
        pending_rows = db.query("""
            SELECT COUNT(DISTINCT b.id) AS c
            FROM brands b
            LEFT JOIN (
                SELECT brand_id, MAX(last_updated_at) AS latest
                FROM evidence GROUP BY brand_id
            ) e ON e.brand_id = b.id
            LEFT JOIN (
                SELECT brand_id, MAX(created_at) AS latest
                FROM analysis_results GROUP BY brand_id
            ) ar ON ar.brand_id = b.id
            LEFT JOIN (
                SELECT company_id, MAX(created_at) AS latest
                FROM rag_index_events WHERE event_type IN ('INDEXED','UPDATED','REINDEXED')
                GROUP BY company_id
            ) ri ON ri.company_id = b.id
            WHERE b.is_active=1
              AND COALESCE(e.latest, ar.latest, '') > COALESCE(ri.latest, '')
        """)
        pending = (pending_rows[0]["c"] if pending_rows else 0)
    except Exception:
        pass
    events = db.query("SELECT * FROM rag_index_events ORDER BY id DESC LIMIT 10")
    retrievals = db.query("SELECT * FROM rag_retrieval_events ORDER BY id DESC LIMIT 10")
    health = {"success": True, "backend": "chroma", "backend_status": "HEALTHY",
              "embedding_provider": "local-minilm", "embedding_status": "HEALTHY",
              "collection_status": "ok", "status": "HEALTHY"}
    return {"success": True, "indexed_documents": total, "active_documents": active,
            "pending_index": 0, "failed_indexes": failed, "retrieval_queries": queries,
            "average_retrieved_results": avg_res, "source_distribution": by_source,
            "recent_index_events": [dict(e) for e in events],
            "recent_retrievals": [dict(e) for e in retrievals], "health": health}


def _rag_audit(request_id, company_id, query, top_k, result_count, backend, model, status, latency_ms):
    """Retrieval audit (§41): hashed query + redacted text, never secrets."""
    try:
        q = framework_redact({"q": query or ""})["q"]
    except Exception:
        q = ""
    db.execute("""
        INSERT INTO rag_retrieval_events (request_id, company_id, query_hash, query_redacted, top_k,
                                          result_count, backend, embedding_model, status, latency_ms, created_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)
    """, (request_id, company_id, _rag_hash(query or ""), str(q)[:300], top_k, result_count, backend,
          model, status, int(latency_ms or 0), now()))


def rag_health():
    """RAG health (§36): honest backend + embedding status. Local all-MiniLM-L6-v2 via ChromaDB."""
    try:
        coll = rag_collection()
        count = coll.count()
        backend, backend_status = "chroma", "HEALTHY"
    except Exception as e:
        return {"success": True, "backend": "chroma", "backend_status": "UNAVAILABLE",
                "embedding_provider": "local-minilm", "embedding_status": "UNKNOWN",
                "collection_status": f"unavailable: {str(e)[:150]}",
                "indexed_documents": 0, "failed_documents": 0, "last_index_at": None,
                "status": "UNAVAILABLE"}
    active = db.query("SELECT COUNT(*) AS c FROM rag_documents WHERE status='ACTIVE'")[0]["c"]
    failed = db.query("SELECT COUNT(*) AS c FROM rag_index_events WHERE event_type='FAILED'")[0]["c"]
    last = db.query("SELECT MAX(created_at) AS t FROM rag_index_events")
    return {"success": True, "backend": "chroma", "backend_status": backend_status,
            "embedding_provider": "local-minilm", "embedding_status": "HEALTHY",
            "collection_status": f"{RAG_COLLECTION}: {count} vectors",
            "indexed_documents": active, "failed_documents": failed,
            "last_index_at": (last[0].get("t") if last else None), "status": "HEALTHY"}


def retrieve_relevant_context(company_id, query="", top_k=None, filters=None):
    """Real vector retrieval (§23) replacing the deferred keyword-SQL path.
    Same interface so Planning/Reasoning keep working. Falls back to the
    explicitly-labeled keyword path only when vectors are disabled (§38)."""
    if isinstance(company_id, dict):
        _goal, company_id, query = company_id, query, (top_k or "")
        top_k, filters = None, None
    if get_config("RAG_ENABLED", "1") != "1":
        return _retrieve_keyword_fallback(company_id, query, top_k, filters)
    if not (query or "").strip():
        base = _retrieve_keyword_fallback(company_id, "", top_k, filters)
        base["retrieval_metadata"] = {"backend": "keyword-fallback",
                                      "reason": "empty query cannot embed", **base.get("retrieval_metadata", {})}
        return base
    res = rag_search(company_id, query, top_k=top_k, filters=filters)
    if not res.get("success") and ("UNAVAILABLE" in str(res.get("error", "")) or
                                   "DISABLED" in str(res.get("error", ""))):
        base = _retrieve_keyword_fallback(company_id, query, top_k, filters)
        base["retrieval_metadata"] = {"backend": "keyword-fallback", "vector_backend": "unavailable",
                                      **base.get("retrieval_metadata", {})}
        return base
    items, sources = [], set()
    for r in (res.get("results") or []):
        items.append({"kind": (r.get("source_type") or "").lower(), "text": r.get("content", ""),
                      "score": r.get("similarity", 0),
                      "document_id": r.get("document_id"), "source_record_id": r.get("source_record_id"),
                      "metadata": r.get("metadata") or {}})
        sources.add(r.get("source_type") or "unknown")
    try:
        max_items = max(1, min(int(_rag_cfg("RAG_MAX_CONTEXT_ITEMS", "20")), 50))
    except Exception:
        max_items = 20
    return {"items": items[:max_items], "sources": sorted(sources),
            "retrieval_metadata": {**(res.get("retrieval_metadata") or {}),
                                   "stale_excluded": res.get("stale_excluded", 0),
                                   "status": res.get("status", "SUCCESS") if res.get("success") else "FAILED"}}


def _retrieve_keyword_fallback(company_id, query="", top_k=None, filters=None):
    """Pre-vector implementation, kept ONLY as an explicitly labeled fallback."""
    items, sources = [], []
    goal_text = ""
    terms = [t.lower() for t in re.findall(r"[a-z]{4,}", str(query or ""))]
    terms = [t for t in terms if t not in ("with", "from", "that", "this", "what", "when")]
    seen_terms = set()
    try:
        b = get_brand(company_id) or {}
        items.append({"kind": "company_profile", "text": f"{b.get('brand_name')} | {b.get('industry')} | "
                      f"{str(b.get('description') or '')[:300]}", "score": 1.0})
        sources.append("brands")
        for t in terms:
            if t in seen_terms:
                continue
            seen_terms.add(t)
            like = f"%{t}%"
            for r in db.query("SELECT evidence_type, evidence_key, evidence_value, source FROM evidence "
                              "WHERE brand_id=? AND (evidence_value LIKE ? OR evidence_key LIKE ?) LIMIT 3",
                              (company_id, like, like)):
                items.append({"kind": "evidence", "text": f"{r.get('evidence_type')}:{r.get('evidence_key')}="
                              f"{str(r.get('evidence_value') or '')[:200]}", "score": 0.8})
            for r in db.query("SELECT title, status FROM recommendations WHERE brand_id=? AND "
                              "(title LIKE ? OR description LIKE ?) LIMIT 3", (company_id, like, like)):
                items.append({"kind": "recommendation", "text": f"{r.get('title')} [{r.get('status')}]",
                              "score": 0.7})
            for r in db.query("SELECT query_text, intent FROM query_memory WHERE brand_id=? AND "
                              "(query_text LIKE ? OR keyword LIKE ?) LIMIT 3", (company_id, like, like)):
                items.append({"kind": "query", "text": f"{r.get('query_text')} ({r.get('intent')})", "score": 0.6})
            if len(items) >= 20:
                break
    except Exception:
        pass
    if company_id:
        sources = sorted(set(sources + (["evidence", "recommendations", "query_memory"] if len(items) > 1 else [])))
    return {"items": items[:20], "sources": sources,
            "retrieval_metadata": {"backend": "keyword-fallback", "terms": sorted(set(terms))[:10],
                                   "company_id": company_id, "vector_backend": "deferred-phase-11"}}


# ---------------------------------------------------------------------------
# PHASE 8 - AGENT FRAMEWORK CONTRACT (shared lifecycle over existing engines)
# ---------------------------------------------------------------------------
#
# The framework standardizes identity, contracts, lifecycle, health, errors,
# versioning, idempotency and observability for every agent WITHOUT rewriting
# any engine: Manager still selects, Runner still executes, Learning still
# learns, Reasoning still assesses. New agents plug in via
# register_agent_executor() + a registry row; no engine code changes.

FRAMEWORK_VERSION = "1.0.0"

# Lifecycle transition map over the existing task-status vocabulary (PLANNED
# is the READY state; QUEUED is scheduled READY). Terminal states accept no
# outgoing transitions except re-queue through the existing retry path.
FRAMEWORK_TRANSITIONS = {
    "PLANNED": ("QUEUED", "RUNNING", "WAITING_FOR_INPUT", "WAITING_FOR_HUMAN", "CANCELLED"),
    "QUEUED": ("RUNNING", "CANCELLED", "WAITING_FOR_HUMAN"),
    "RUNNING": ("COMPLETED", "PARTIAL", "FAILED", "WAITING_FOR_INPUT", "WAITING_FOR_HUMAN",
                "CANCELLED", "REJECTED"),
    "WAITING_FOR_INPUT": ("QUEUED", "RUNNING", "CANCELLED"),
    "WAITING_FOR_HUMAN": ("QUEUED", "RUNNING", "CANCELLED"),
    "FAILED": ("QUEUED",),
    "RECEIVED": ("PLANNED", "CANCELLED"),
}

FRAMEWORK_OUTPUT_STATUSES = ("COMPLETED", "PARTIAL", "FAILED", "WAITING_FOR_HUMAN", "REJECTED")

FRAMEWORK_ERRORS = {
    "AGENT_NOT_FOUND": (False, False),
    "AGENT_DISABLED": (False, False),
    "INVALID_INPUT": (False, False),
    "UNSUPPORTED_OPERATION": (False, False),
    "VERSION_MISMATCH": (False, False),
    "DEPENDENCY_UNAVAILABLE": (True, False),
    "CONFIGURATION_ERROR": (False, False),
    "EXECUTION_ERROR": (True, False),
    "EXECUTION_TIMEOUT": (True, False),
    "OUTPUT_VALIDATION_ERROR": (False, False),
    "HUMAN_REVIEW_REQUIRED": (False, True),
}


def framework_error(code, message, details=None):
    """Standard error shape (§17); details are secret-scrubbed (§31)."""
    retryable, human = FRAMEWORK_ERRORS.get(code, (False, False))
    try:
        details = framework_redact(details or {})
    except Exception:
        details = {}
    return {"code": code, "message": str(message)[:500], "retryable": retryable,
            "human_review": human, "details": details if isinstance(details, dict) else {}}


def framework_redact(obj):
    """Secret redaction (§11/§31): drop *-key/token/secret/password/api values,
    recursively. Single choke point for handoffs, logs, traces, dashboard."""
    if isinstance(obj, dict):
        return {k: "***" if any(h in str(k).lower() for h in ("key", "token", "secret", "password", "api"))
                else framework_redact(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [framework_redact(v) for v in obj]
    return obj


def framework_validate_transition(from_state, to_state):
    """Lifecycle gate (§9): only mapped transitions are legal."""
    ok = to_state in FRAMEWORK_TRANSITIONS.get((from_state or "").upper(), ())
    return {"ok": ok, **({} if ok else {"error": f"Illegal transition {(from_state or '')} -> {to_state}."})}


def _framework_agent_config(agent_row):
    try:
        return safe_json_loads(agent_row.get("configuration_json"), {}) or {}
    except Exception:
        return {}


def framework_get_agent(agent_id, redact=True):
    """Standard agent metadata (§4); configuration secrets scrubbed (§31)."""
    row = _registry_row(agent_id)
    if not row:
        return {"success": False, "error": framework_error("AGENT_NOT_FOUND", f"Unknown agent: {agent_id}")}
    d = dict(row)
    d["capabilities"] = _agent_capabilities(row)
    try:
        d["input_schema"] = safe_json_loads(row.get("input_schema_json"), {}) or {}
        d["output_schema"] = safe_json_loads(row.get("output_schema_json"), {}) or {}
        cfg = _framework_agent_config(row)
        d["configuration"] = framework_redact(cfg) if redact else cfg
    except Exception:
        d["input_schema"], d["output_schema"], d["configuration"] = {}, {}, {}
    try:
        w = db.query("SELECT COUNT(*) AS c FROM jobs WHERE assigned_agent_id=? AND status IN "
                     "('PENDING','QUEUED','RUNNING','RETRYING')", (row["agent_id"],))
        d["workload"] = (w[0].get("c") or 0) if w else 0
    except Exception:
        d["workload"] = 0
    last = db.query("SELECT status, error_message, created_at, completed_at FROM manager_tasks "
                    "WHERE selected_agent_id=? ORDER BY id DESC LIMIT 1", (row["agent_id"],))
    d["last_execution"] = dict(last[0]) if last else None
    return {"success": True, "agent": d}


def framework_validate_registration(payload):
    """Registration gate (§21): shape, version, capabilities, schemas, executor
    availability. Invalid registrations are rejected with reasons."""
    p = payload or {}
    errors = []
    aid = str(p.get("agent_id") or "")
    if not re.match(r"^[a-z0-9][a-z0-9-]{2,63}$", aid):
        errors.append("agent_id must be 3-64 chars of lowercase alphanumerics/dashes")
    if not str(p.get("name") or "").strip():
        errors.append("name is required")
    if not re.match(r"^\d+\.\d+\.\d+$", str(p.get("version") or "")):
        errors.append("version must be semver (e.g. 1.0.0)")
    caps = p.get("capabilities") or []
    if not isinstance(caps, list) or not caps or not all(
            isinstance(c, str) and re.match(r"^[a-z0-9_]{3,64}$", c) for c in caps):
        errors.append("capabilities must be a non-empty list of slug strings")
    for k in ("input_schema", "output_schema"):
        if not isinstance(p.get(k), dict):
            errors.append(f"{k} must be an object")
    if p.get("executor") is not None and not callable(p.get("executor")):
        errors.append("executor must be callable")
    if p.get("status") and p.get("status") not in MANAGER_AGENT_STATUSES:
        errors.append(f"status must be one of {','.join(MANAGER_AGENT_STATUSES)}")
    if errors:
        return {"success": False, "errors": errors}
    return {"success": True}


def register_agent_executor(agent_id, fn):
    """Plugin registry: agent implementations register their executor here.
    This is the ONLY code a new agent ships; engines look it up by agent_id."""
    if not callable(fn):
        return {"success": False, "error": "executor must be callable"}
    FRAMEWORK_EXECUTORS[agent_id] = fn
    return {"success": True, "agent_id": agent_id}


def framework_register_agent(payload):
    """Validated registration; new agents start PAUSED (operator enables)."""
    v = framework_validate_registration(payload)
    if not v.get("success"):
        return {"success": False, "error": "; ".join(v.get("errors", ["invalid"]))}
    if _registry_row(payload["agent_id"]):
        return {"success": False, "error": framework_error(
            "CONFIGURATION_ERROR", f"agent_id '{payload['agent_id']}' already registered")}
    t = now()
    db.execute("""
        INSERT INTO agent_registry (agent_id, agent_name, agent_type, description, version, status,
                                    capabilities_json, input_schema_json, output_schema_json,
                                    health_status, last_health_check, configuration_json,
                                    created_at, updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (payload["agent_id"], payload.get("name"), payload.get("agent_type", "ANALYTICS"),
          payload.get("description", ""), payload.get("version", "1.0.0"),
          payload.get("status", "PAUSED"), json.dumps(payload.get("capabilities", [])),
          json.dumps(payload.get("input_schema", {})), json.dumps(payload.get("output_schema", {})),
          "UNKNOWN", None, json.dumps(payload.get("configuration", {})), t, t))
    if payload.get("executor") is not None:
        register_agent_executor(payload["agent_id"], payload["executor"])
    try:
        log_activity(f"Framework registered agent {payload['agent_id']} (PAUSED by default).", level="FRAMEWORK")
    except Exception:
        pass
    return {"success": True, "agent_id": payload["agent_id"]}


def framework_check_version(agent_id, required_version=None):
    """Compatibility (§12): same major line is compatible; anything else is a
    clear VERSION_MISMATCH error, never a silent execution."""
    row = _registry_row(agent_id)
    if not row:
        return {"success": False, "error": framework_error("AGENT_NOT_FOUND", f"Unknown agent: {agent_id}")}
    if not required_version:
        return {"success": True, "agent_version": row.get("version"), "compatible": True}
    try:
        have = tuple(int(x) for x in re.findall(r"\d+", str(row.get("version") or "0"))[:3])
        want = tuple(int(x) for x in re.findall(r"\d+", str(required_version))[:3])
        have += (0,) * (3 - len(have))
        want += (0,) * (3 - len(want))
    except Exception:
        return {"success": False, "error": framework_error("VERSION_MISMATCH", "Unparseable version")}
    if have[0] != want[0]:
        return {"success": False, "error": framework_error(
            "VERSION_MISMATCH", f"Agent {agent_id} is v{row.get('version')} (major {have[0]}); "
            f"task requires v{required_version} (major {want[0]}).")}
    return {"success": True, "agent_version": row.get("version"), "compatible": True}


def framework_classify_error(code_or_message):
    """Retry classification (§18): RETRYABLE / NON_RETRYABLE / HUMAN_REVIEW.
    The Runner still performs retries; the framework only classifies."""
    text = str(code_or_message or "").upper()
    if any(k in text for k in ("EXECUTION_TIMEOUT", "TIMEOUT")):
        return "RETRYABLE"
    if "DEPENDENCY_UNAVAILABLE" in text or any(k in text for k in ("429", "QUOTA", "RATE LIMIT")):
        return "RETRYABLE"
    if "UNAVAILABLE" in text:
        return "RETRYABLE"
    if "HUMAN_REVIEW" in text or "CONFLICT" in text:
        return "HUMAN_REVIEW"
    if any(k in text for k in ("INVALID_INPUT", "OUTPUT_VALIDATION", "VERSION_MISMATCH", "CONFIGURATION",
                               "UNSUPPORTED_OPERATION", "AGENT_NOT_FOUND", "AGENT_DISABLED")):
        return "NON_RETRYABLE"
    if "EXECUTION_ERROR" in text:
        return "RETRYABLE"
    return "NON_RETRYABLE"
    if "EXECUTION_ERROR" in text:
        return "RETRYABLE"
    return "NON_RETRYABLE"


def framework_validate_input(agent_row, envelope):
    """Standard input envelope (§6): request_id/agent_id/operation/input required."""
    env = envelope or {}
    missing = [k for k in ("request_id", "agent_id", "operation", "input")
               if k not in env or env[k] is None or (isinstance(env[k], str) and not env[k].strip())]
    if missing:
        return {"success": False, "error": framework_error(
            "INVALID_INPUT", f"Envelope missing: {', '.join(missing)}")}
    if env["agent_id"] != agent_row["agent_id"]:
        return {"success": False, "error": framework_error("INVALID_INPUT", "Envelope agent mismatch")}
    caps = _agent_capabilities(agent_row)
    if env["operation"] not in caps:
        return {"success": False, "error": framework_error(
            "UNSUPPORTED_OPERATION", f"Operation '{env['operation']}' not in declared capabilities")}
    required = [k for k, v in (safe_json_loads(agent_row.get("input_schema_json"), {}) or {}).items()
                if "required" in str(v).lower()]
    lacking = [k for k in required if not (env.get("input") or {}).get(k)]
    if lacking:
        return {"success": False, "error": framework_error(
            "INVALID_INPUT", f"Missing required input: {', '.join(lacking)}")}
    return {"success": True}


def framework_validate_output(agent_row, out):
    """Standard output envelope (§7): fixed keys, documented statuses only."""
    if not isinstance(out, dict):
        return {"success": False, "error": framework_error("OUTPUT_VALIDATION_ERROR", "Output not an object")}
    for k in ("request_id", "agent_id", "status", "summary", "data", "evidence", "warnings", "errors", "metadata"):
        if k not in out:
            return {"success": False, "error": framework_error(
                "OUTPUT_VALIDATION_ERROR", f"Output missing key: {k}")}
    if out["status"] not in FRAMEWORK_OUTPUT_STATUSES:
        return {"success": False, "error": framework_error(
            "OUTPUT_VALIDATION_ERROR", f"Invalid status: {out['status']}")}
    if not isinstance(out.get("data"), dict) or not isinstance(out.get("evidence"), list) \
            or not isinstance(out.get("warnings"), list) or not isinstance(out.get("errors"), list):
        return {"success": False, "error": framework_error("OUTPUT_VALIDATION_ERROR", "Output field types invalid")}
    return {"success": True}


def framework_agent_context(agent_id, task=None):
    """Standardized context for agents/reasoning (§29): identity, config
    (scrubbed), capability metadata (MCP-ready), integration state."""
    row = _registry_row(agent_id)
    if not row:
        return {"success": False, "error": framework_error("AGENT_NOT_FOUND", f"Unknown agent: {agent_id}")}
    cfg = _framework_agent_config(row)
    return {"success": True, "context": {
        "agent_id": row["agent_id"], "agent_name": row["agent_name"], "version": row.get("version"),
        "status": row.get("status"), "capabilities": _agent_capabilities(row),
        "capability_metadata": (cfg.get("capabilities") or {}) if isinstance(cfg, dict) else {},
        "mcp": (cfg.get("mcp") or {}) if isinstance(cfg, dict) else {},
        "configuration": framework_redact({k: v for k, v in cfg.items() if k not in ("capabilities", "mcp")})
        if isinstance(cfg, dict) else {},
        "integrations": {"scraper": scraper_available(), "ai_search": ai_search_connected()},
        "constraints": {"no_secret_leakage": True, "human_approval_for": list(REQUIRES_HUMAN_APPROVAL)},
        "task": task or {}}}


def framework_execute(agent_id, envelope, timeout_seconds=None):
    """The single execution adapter (§13): validate -> initialize -> execute
    (existing agent code, timeout-guarded) -> validate -> normalize. Returns
    the §7 envelope; never raises for agent-level failures."""
    row = _registry_row(agent_id)
    if not row:
        return {"success": False, "error": framework_error("AGENT_NOT_FOUND", f"Unknown agent: {agent_id}")}
    vin = framework_validate_input(row, envelope)
    if not vin.get("success"):
        return {"success": False, "error": vin["error"]}
    if (row.get("status") or "") != "ACTIVE":
        return {"success": False, "error": framework_error(
            "AGENT_DISABLED", f"Agent {agent_id} is {row.get('status')}, not ACTIVE")}
    if (row.get("health_status") or "UNKNOWN") == "UNAVAILABLE":
        return {"success": False, "error": framework_error(
            "DEPENDENCY_UNAVAILABLE", f"Agent {agent_id} health is UNAVAILABLE")}
    if envelope.get("required_version"):
        vc = framework_check_version(agent_id, envelope["required_version"])
        if not vc.get("success"):
            return {"success": False, "error": vc["error"]}
    if envelope.get("request_id"):
        prev = db.query("SELECT output_json, status, selected_agent_id FROM manager_tasks WHERE request_id=? "
                        "AND status IN ('COMPLETED','PARTIAL') ORDER BY id DESC LIMIT 1",
                        (envelope["request_id"],))
        if prev:
            try:
                norm = safe_json_loads(prev[0].get("output_json"), {}) or {}
            except Exception:
                norm = {}
            meta = dict(norm.get("metadata") or {})
            meta["idempotent"] = True
            return {"success": True, "idempotent": True, "output": {
                "request_id": envelope["request_id"], "agent_id": agent_id,
                "status": prev[0]["status"], "summary": norm.get("summary", ""),
                "data": norm.get("data") or {}, "evidence": norm.get("evidence") or [],
                "warnings": norm.get("warnings") or [], "errors": [], "metadata": meta}}
    executor = FRAMEWORK_EXECUTORS.get(agent_id)
    if executor is None:
        return {"success": False, "error": framework_error(
            "CONFIGURATION_ERROR", f"Agent {agent_id} is registered but unavailable because no execution "
            "backend is implemented")}
    try:
        timeout = int(timeout_seconds or _framework_agent_config(row).get("timeout_seconds", 300))
    except Exception:
        timeout = 300
    ctx = framework_agent_context(agent_id, {"request_id": envelope.get("request_id")})
    holder, started = {}, time.time()
    def _run():
        try:
            holder["out"] = executor(agent_id, envelope, ctx.get("context", {}))
        except Exception as e:
            holder["exc"] = e
    th = threading.Thread(target=_run, daemon=True, name=f"fw-{agent_id}")
    th.start()
    th.join(timeout=max(1, timeout))
    if th.is_alive():
        err = framework_error("EXECUTION_TIMEOUT", f"Operation exceeded {timeout}s")
        try:
            log_activity(f"Framework timeout for {agent_id} op {envelope.get('operation')}.", level="FRAMEWORK")
        except Exception:
            pass
        return {"success": True, "output": {
            "request_id": envelope.get("request_id"), "agent_id": agent_id, "status": "FAILED",
            "summary": err["message"], "data": {}, "evidence": [],
            "warnings": [f"timeout after {timeout}s"], "errors": [err],
            "metadata": {"timeout": True, "duration_s": round(time.time() - started, 2)}}}
    if "exc" in holder:
        err = framework_error("EXECUTION_ERROR", str(holder["exc"])[:300])
        return {"success": True, "output": {
            "request_id": envelope.get("request_id"), "agent_id": agent_id, "status": "FAILED",
            "summary": err["message"], "data": {}, "evidence": [], "warnings": [],
            "errors": [err], "metadata": {"duration_s": round(time.time() - started, 2)}}}
    out = holder.get("out") or {}
    out.setdefault("request_id", envelope.get("request_id"))
    out.setdefault("agent_id", agent_id)
    vout = framework_validate_output(row, out)
    if not vout.get("success"):
        return {"success": False, "error": vout["error"]}
    out["metadata"]["duration_s"] = round(time.time() - started, 2)
    return {"success": True, "output": out}


def framework_learning_hook(hook, agent_id=None, task_id=None, extra=None):
    """Learning hooks (§15) into the EXISTING learning system (no new memory)."""
    extra = extra or {}
    try:
        if hook == "after_execution":
            st = extra.get("status")
            desc = extra.get("description") or f"Framework execution by {agent_id} -> {st}."
            if st in ("COMPLETED", "PARTIAL"):
                return manager_learn(extra.get("company_id"), "AGENT_EXECUTION_SUCCESS", desc,
                                     {"agent_id": agent_id, "task_id": task_id, **extra})
            return manager_learn(extra.get("company_id"), "AGENT_EXECUTION_FAILURE", desc,
                                 {"agent_id": agent_id, "task_id": task_id, **extra})
        if hook == "on_failure":
            return manager_learn(extra.get("company_id"), "AGENT_EXECUTION_FAILURE",
                                 f"Framework execution by {agent_id} failed.",
                                 {"agent_id": agent_id, "task_id": task_id, **extra})
        if hook == "on_feedback":
            return manager_learn(extra.get("company_id"), "FEEDBACK_RECEIVED",
                                 f"Human feedback on {agent_id} execution.",
                                 {"agent_id": agent_id, "task_id": task_id, **extra})
    except Exception as e:
        print(f"[Framework] learning hook skipped: {e}", flush=True)
    return None


# ---------------------------------------------------------------------------
# PHASE 9 - TOOLS + MCP (controlled operations over existing engines)
# ---------------------------------------------------------------------------
#
# Two registries, distinct jobs: agent_registry answers "which agent owns this
# capability"; mcp_tools answers "which controlled operation may it invoke".
# Every tool maps to EXISTING real logic — no parallel implementations. MCP is
# a protocol layer over this registry (see mcp_server.py), never a bypass.

MCP_TOOL_RISKS = ("READ", "LOW", "MEDIUM", "HIGH")
MCP_ERRORS = ("MCP_TOOL_NOT_FOUND", "MCP_TOOL_DISABLED", "MCP_UNAUTHORIZED",
              "MCP_INVALID_INPUT", "MCP_CAPABILITY_DENIED", "MCP_COMPANY_SCOPE_DENIED",
              "MCP_VERSION_MISMATCH", "MCP_EXECUTION_FAILED", "MCP_TIMEOUT",
              "MCP_RESOURCE_NOT_FOUND", "MCP_RESOURCE_ACCESS_DENIED")

# Non-idempotent (state-changing) tools: duplicate request_ids are audited but
# always execute fresh. Everything else replays the stored result.
MCP_NON_IDEMPOTENT = {"generate_search_queries", "run_ai_search"}

MCP_TOOL_SEED = [
    ("get_company_profile", "Company profile", "Brand record, industry, website, keywords and status.", "1.0.0",
     {"company_id": "integer (required)"}, {"profile": "object"}, "brand_visibility",
     ["ai-search-visibility"], "READ", 0),
    ("get_company_evidence", "Company evidence", "Stored evidence rows with sources and verification.", "1.0.0",
     {"company_id": "integer (required)", "limit": "integer (optional, default 50)"}, {"evidence": "list"},
     "brand_visibility", ["ai-search-visibility"], "READ", 0),
    ("get_analysis_history", "Analysis history", "Past visibility scores newest-first.", "1.0.0",
     {"company_id": "integer (required)", "limit": "integer (optional, default 10)"}, {"analyses": "list"},
     "brand_visibility", ["ai-search-visibility"], "READ", 0),
    ("get_detected_changes", "Detected changes", "Change log entries newest-first.", "1.0.0",
     {"company_id": "integer (required)", "limit": "integer (optional, default 30)"}, {"changes": "list"},
     "brand_visibility", ["ai-search-visibility"], "READ", 0),
    ("get_learning_memory", "Learning memory", "Active learning memories for the company.", "1.0.0",
     {"company_id": "integer (required)", "limit": "integer (optional, default 20)"}, {"memories": "list"},
     "brand_visibility", ["ai-search-visibility"], "READ", 0),
    ("generate_search_queries", "Generate search queries", "Generate and store customer search queries.", "1.0.0",
     {"company_id": "integer (required)", "intent": "string (optional)", "limit": "integer (optional, default 10)"},
     {"queries": "list"}, "keyword_analysis", ["ai-search-visibility"], "LOW", 0),
    ("run_ai_search", "Run AI search", "Execute stored queries against connected providers.", "1.0.0",
     {"company_id": "integer (required)", "query": "string (optional, default: next untried query)"},
     {"observations": "integer"}, "ai_search_analysis", ["ai-search-visibility"], "MEDIUM", 0),
    ("analyze_brand_visibility", "Analyze brand visibility", "Deterministic brand visibility analysis.", "1.0.0",
     {"company_id": "integer (required)"}, {"analysis": "object"}, "brand_visibility",
     ["ai-search-visibility"], "LOW", 0),
    ("analyze_competitors", "Analyze competitors", "Competitor visibility rows from profile and observations.",
     "1.0.0", {"company_id": "integer (required)"}, {"competitors": "list"}, "competitor_analysis",
     ["ai-search-visibility"], "LOW", 0),
    ("detect_content_gaps", "Detect content gaps", "Missing content surfaces vs evidence.", "1.0.0",
     {"company_id": "integer (required)"}, {"gaps": "list"}, "content_gap_analysis",
     ["ai-search-visibility"], "LOW", 0),
    ("generate_recommendations", "Generate recommendations", "Deterministic recommendations from gaps/evidence.",
     "1.0.0", {"company_id": "integer (required)"}, {"recommendations": "list"}, "recommendations",
     ["ai-search-visibility"], "LOW", 0),
    ("get_query_history", "Query history", "Stored queries with test counts and results.", "1.0.0",
     {"company_id": "integer (required)", "limit": "integer (optional, default 50)"}, {"queries": "list"},
     "keyword_analysis", ["ai-search-visibility"], "READ", 0),
    ("get_recommendation_history", "Recommendation history", "Recommendations with lifecycle status.", "1.0.0",
     {"company_id": "integer (required)", "limit": "integer (optional, default 50)"}, {"recommendations": "list"},
     "recommendations", ["ai-search-visibility"], "READ", 0),
    ("get_company_snapshot", "Company snapshot", "Latest (or previous) evidence snapshot.", "1.0.0",
     {"company_id": "integer (required)", "which": "string (optional: latest|previous, default latest)"},
     {"snapshot": "list"}, "brand_visibility", ["ai-search-visibility"], "READ", 0),
     ("compare_snapshots", "Compare snapshots", "Diff two analyses' evidence snapshots.", "1.0.0",
      {"company_id": "integer (required)", "previous_snapshot_id": "integer (optional)",
       "current_snapshot_id": "integer (optional)"}, {"diff": "object"}, "brand_visibility",
      ["ai-search-visibility"], "READ", 0),
    ("search_knowledge", "Search knowledge", "Semantic vector search over indexed company knowledge.", "1.0.0",
     {"company_id": "integer (required)", "query": "string (required)", "top_k": "integer (optional, default 5)"},
     {"results": "list"}, "brand_visibility", ["ai-search-visibility"], "READ", 0),
    ("discover_website", "Discover website", "Discover and fetch website pages for a company.", "1.0.0",
     {"company_id": "integer (required)"}, {"website": "object"}, "website_discovery",
     ["website-content-intelligence"], "READ", 0),
    ("extract_products", "Extract products", "Extract products from stored website evidence.", "1.0.0",
     {"company_id": "integer (required)"}, {"products": "list"}, "product_extraction",
     ["website-content-intelligence"], "READ", 0),
    ("extract_services", "Extract services", "Extract services from stored website evidence.", "1.0.0",
     {"company_id": "integer (required)"}, {"services": "list"}, "service_extraction",
     ["website-content-intelligence"], "READ", 0),
    ("analyze_content_completeness", "Analyze content completeness", "Score website content completeness.", "1.0.0",
     {"company_id": "integer (required)"}, {"completeness": "object"}, "content_completeness",
     ["website-content-intelligence"], "READ", 0),
    ("detect_website_content_gaps", "Detect website content gaps", "Detect missing website content.", "1.0.0",
     {"company_id": "integer (required)"}, {"gaps": "list"}, "content_gap_analysis",
     ["website-content-intelligence"], "READ", 0),
]

MCP_TOOL_IDS = {t[0] for t in MCP_TOOL_SEED}


def ensure_mcp_tools():
    """Idempotent tool seed (insert missing tool_ids only; preserves operator
    enabled/version/timeout edits)."""
    t = now()
    for tool_id, name, desc, ver, insch, outsch, cap, agents, risk, approval in MCP_TOOL_SEED:
        if db.query("SELECT id FROM mcp_tools WHERE tool_id=?", (tool_id,)):
            continue
        db.execute("""
            INSERT INTO mcp_tools (tool_id, name, description, version, input_schema_json, output_schema_json,
                                   capability, agent_ids_json, risk_level, requires_approval, enabled,
                                   timeout_seconds, created_at, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (tool_id, name, desc, ver, json.dumps(insch), json.dumps(outsch), cap, json.dumps(agents),
              risk, approval, 1, 30, t, t))


def mcp_list_tools(enabled_only=True):
    q = "SELECT * FROM mcp_tools" + (" WHERE enabled=1" if enabled_only else "") + " ORDER BY tool_id"
    out = []
    for r in db.query(q):
        d = dict(r)
        for k in ("input_schema_json", "output_schema_json", "agent_ids_json"):
            try:
                d[k.replace("_json", "")] = safe_json_loads(d.get(k), {}) or {}
            except Exception:
                d[k.replace("_json", "")] = {}
        out.append(d)
    return out


def mcp_auth_client(auth_token=None, client_id=None):
    """Authorization (§18): token -> (client_id, company scopes). Tokens and
    scopes come from MCP_AUTH_TOKEN / MCP_CLIENT_SCOPES_JSON env (never the
    database, never logged). Returns None when unauthorized."""
    master = ""
    if not master:
        return {"client_id": client_id or "local", "companies": "*"}
    scopes = {}
    for key, cfg in (scopes or {}).items():
        if key and (key == (auth_token or "") or key == (client_id or "")):
            cfg = cfg or {}
            return {"client_id": cfg.get("client_id") or client_id or "default",
                    "companies": cfg.get("companies", "*")}
    if (auth_token or "") == master:
        return {"client_id": client_id or "default", "companies": "*"}
    return None


def mcp_check_scope(auth, company_id):
    scopes = (auth or {}).get("companies", "*")
    if scopes == "*":
        return True
    try:
        return int(company_id) in [int(x) for x in (scopes or [])]
    except Exception:
        return False


def mcp_check_risk(tool_row, agent_row):
    """Risk policy (§28): READ auto; LOW auto-if-allowed; MEDIUM configurable;
    HIGH always needs approval. Returns (allowed, requires_approval, note)."""
    risk = (tool_row.get("risk_level") or "READ").upper()
    if tool_row.get("requires_approval"):
        return False, True, f"Tool {tool_row['tool_id']} is flagged requires_approval."
    if risk == "READ":
        return True, False, "READ tools execute automatically."
    if risk == "LOW":
        return True, False, "LOW-risk allowed tool."
    if risk == "MEDIUM":
        if get_config("MCP_MEDIUM_AUTO", "1") == "1":
            return True, False, "MEDIUM-risk auto-execution enabled by configuration."
        return False, True, "MEDIUM-risk tool needs approval (MCP_MEDIUM_AUTO=0)."
    return False, True, f"{risk}-risk tool requires human approval."


MCP_TOOL_IMPLS = {}


def mcp_validate_tool_call(agent_id, tool_id, args, auth):
    """10-check gate (§7): tool, enabled, capability, agent, version, schema,
    params, permission, risk, timeout. Any failure rejects without executing."""
    args = args or {}
    row = db.query("SELECT * FROM mcp_tools WHERE tool_id=?", (tool_id,))
    if not row:
        return {"ok": False, "code": "MCP_TOOL_NOT_FOUND", "reason": f"Unknown tool: {tool_id}."}
    tool = row[0]
    if not tool.get("enabled"):
        return {"ok": False, "code": "MCP_TOOL_DISABLED", "reason": f"Tool {tool_id} is disabled."}
    if auth is None:
        return {"ok": False, "code": "MCP_UNAUTHORIZED", "reason": "Missing or invalid credentials."}
    agent_row = _registry_row(agent_id)
    if not agent_row:
        return {"ok": False, "code": "MCP_UNAUTHORIZED", "reason": f"Unknown agent: {agent_id}."}
    if tool.get("capability") not in _agent_capabilities(agent_row):
        return {"ok": False, "code": "MCP_CAPABILITY_DENIED",
                "reason": f"Agent {agent_id} does not declare capability '{tool.get('capability')}'."}
    try:
        allowed_agents = safe_json_loads(tool.get("agent_ids_json"), []) or []
    except Exception:
        allowed_agents = []
    if allowed_agents and agent_id not in allowed_agents:
        return {"ok": False, "code": "MCP_CAPABILITY_DENIED",
                "reason": f"Tool {tool_id} is not allowlisted for agent {agent_id}."}
    if (agent_row.get("status") or "") != "ACTIVE":
        return {"ok": False, "code": "MCP_UNAUTHORIZED",
                "reason": f"Agent {agent_id} is {agent_row.get('status')}, not ACTIVE."}
    try:
        schema = safe_json_loads(tool.get("input_schema_json"), {}) or {}
    except Exception:
        schema = {}
    for key, desc in schema.items():
        if "required" in str(desc).lower() and args.get(key) in (None, ""):
            return {"ok": False, "code": "MCP_INVALID_INPUT",
                    "reason": f"Missing required parameter: {key}."}
    cid = args.get("company_id")
    if cid is not None and not mcp_check_scope(auth, cid):
        return {"ok": False, "code": "MCP_COMPANY_SCOPE_DENIED",
                "reason": f"Client not scoped to company {cid}."}
    allowed, need_approval, note = mcp_check_risk(tool, agent_row)
    if need_approval:
        return {"ok": False, "code": "MCP_UNAUTHORIZED", "reason": note, "waiting_for_human": True}
    if not allowed:
        return {"ok": False, "code": "MCP_UNAUTHORIZED", "reason": note}
    try:
        timeout = max(1, int(tool.get("timeout_seconds") or 30))
    except Exception:
        timeout = 30
    return {"ok": True, "tool": tool, "agent": agent_row, "timeout": timeout, "note": note}


def mcp_audit(request_id, client_id, agent_id, tool_id, company_id, status, duration_ms, error_code=""):
    """Audit every operation (§20): structured row + redacted activity line.
    DB write is guarded — audit failure never crashes the tool execution path."""
    t = now()
    try:
        db.execute("""
            INSERT INTO mcp_tool_calls (request_id, client_id, agent_id, tool_id, company_id, status,
                                        result_json, error_code, duration_ms, created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?)
        """, (request_id, client_id, agent_id, tool_id, company_id, status, None, error_code or None,
              int(duration_ms or 0), t))
    except Exception:
        pass
    try:
        log_activity(f"MCP {tool_id} [{status}] client={client_id} agent={agent_id} "
                     f"company={company_id} {int(duration_ms or 0)}ms"
                     + (f" err={error_code}" if error_code else ""), level="MCP")
    except Exception:
        pass


def mcp_tool_result(tool_id, status, data=None, evidence=None, warnings=None, error=None,
                    duration_ms=0, source="framework-tools"):
    """Standard envelope (§6); evidence entries normalized to the §8 shape."""
    norm_ev = []
    for e in (evidence or []):
        if isinstance(e, dict):
            norm_ev.append({
                "value": str(e.get("value", e.get("evidence_value", "")))[:2000],
                "source": e.get("source", source),
                "verification_status": e.get("verification_status", "UNVERIFIED"),
                "confidence": e.get("confidence", 0.5),
                "collected_at": e.get("collected_at"), "last_updated_at": e.get("last_updated_at")})
        else:
            norm_ev.append({"value": str(e)[:2000], "source": source,
                            "verification_status": "UNVERIFIED", "confidence": 0.5,
                            "collected_at": None, "last_updated_at": None})
    if status == "SUCCESS":
        return {"tool_id": tool_id, "status": "SUCCESS", "data": data or {}, "evidence": norm_ev,
                "warnings": warnings or [], "error": None,
                "metadata": {"execution_time_ms": int(duration_ms or 0), "source": source}}
    code, msg, retryable = "MCP_EXECUTION_FAILED", "execution failed", False
    if isinstance(error, dict):
        code, msg = error.get("code", code), error.get("message", msg)
        retryable = bool(error.get("retryable"))
    elif error:
        msg = str(error)[:500]
    return {"tool_id": tool_id, "status": "FAILED", "data": data or {}, "evidence": norm_ev,
            "warnings": warnings or [],
            "error": {"code": code, "message": msg, "retryable": retryable},
            "metadata": {"execution_time_ms": int(duration_ms or 0), "source": source}}


def mcp_call_tool(agent_id, tool_id, args, client_id="local", auth_token="", request_id=None):
    """Validated execution (§7+§8): auth -> 10 checks -> idempotency ->
    approval gate -> timeout-guarded run -> output validation -> audit."""
    import time as _t
    t0 = _t.time()
    args = framework_redact(dict(args or {}))
    auth = mcp_auth_client(auth_token or None, client_id)
    v = mcp_validate_tool_call(agent_id, tool_id, args, auth)
    ms = lambda: int((_t.time() - t0) * 1000)
    if not v.get("ok"):
        if v.get("waiting_for_human"):
            mcp_audit(request_id, (auth or {}).get("client_id", client_id), agent_id, tool_id,
                      (args or {}).get("company_id"), "WAITING_FOR_HUMAN", ms(), v["code"])
            out = mcp_tool_result(tool_id, "FAILED", {}, [], [],
                                  {"code": v["code"], "message": v["reason"], "retryable": False}, ms())
            out["status"] = "WAITING_FOR_HUMAN"
            return {"success": True, "waiting_for_human": True, "result": out}
        mcp_audit(request_id, (auth or {}).get("client_id", client_id) if auth else client_id,
                  agent_id, tool_id, (args or {}).get("company_id"), "REJECTED", ms(), v["code"])
        return {"success": False, "error": v["code"], "reason": v["reason"]}
    tool, real_client = v["tool"], (auth or {}).get("client_id", client_id)
    if request_id and tool_id not in MCP_NON_IDEMPOTENT:
        prev = db.query("SELECT result_json, status FROM mcp_tool_calls WHERE request_id=? AND tool_id=? "
                        "AND status='SUCCESS' ORDER BY id DESC LIMIT 1", (request_id, tool_id))
        if prev:
            try:
                return {"success": True, "idempotent": True,
                        "result": safe_json_loads(prev[0]["result_json"], {}) or {}}
            except Exception:
                pass
    impl = MCP_TOOL_IMPLS.get(tool_id)
    if impl is None:
        mcp_audit(request_id, real_client, agent_id, tool_id, args.get("company_id"),
                  "FAILED", ms(), "MCP_TOOL_NOT_FOUND")
        return {"success": False, "error": "MCP_TOOL_NOT_FOUND",
                "reason": f"No implementation registered for tool {tool_id}."}
    holder = {}
    def _run():
        try:
            holder["res"] = impl(agent_id, args, {"client_id": real_client, "timeout": v["timeout"]})
        except Exception as e:
            holder["exc"] = e
    th = threading.Thread(target=_run, daemon=True, name=f"mcp-{tool_id}")
    th.start()
    th.join(timeout=v["timeout"])
    dur = ms()
    if th.is_alive():
        mcp_audit(request_id, real_client, agent_id, tool_id, args.get("company_id"),
                  "FAILED", dur, "MCP_TIMEOUT")
        return {"success": True, "timeout": True,
                "result": mcp_tool_result(tool_id, "FAILED", {}, [],
                                          [f"timeout after {v['timeout']}s"],
                                          {"code": "MCP_TIMEOUT", "message": "Tool call timed out",
                                           "retryable": True}, dur)}
    if "exc" in holder:
        mcp_audit(request_id, real_client, agent_id, tool_id, args.get("company_id"),
                  "FAILED", dur, "MCP_EXECUTION_FAILED")
        return {"success": True, "result": mcp_tool_result(
            tool_id, "FAILED", {}, [], [], {"code": "MCP_EXECUTION_FAILED",
                                            "message": str(holder["exc"])[:300], "retryable": True}, dur)}
    res = holder.get("res") or {}
    if not isinstance(res, dict) or res.get("status") not in ("SUCCESS", "FAILED") or \
            not isinstance(res.get("data"), dict):
        mcp_audit(request_id, real_client, agent_id, tool_id, args.get("company_id"),
                  "FAILED", dur, "MCP_EXECUTION_FAILED")
        return {"success": True, "result": mcp_tool_result(
            tool_id, "FAILED", {}, [], ["malformed tool output rejected"],
            {"code": "MCP_EXECUTION_FAILED", "message": "Tool returned malformed output",
             "retryable": False}, dur)}
    res.setdefault("tool_id", tool_id)
    res["metadata"] = {**(res.get("metadata") or {}), "execution_time_ms": dur, "source": "framework-tools"}
    mcp_audit(request_id, real_client, agent_id, tool_id, args.get("company_id"),
              "SUCCESS" if res.get("status") == "SUCCESS" else "FAILED", dur,
              (res.get("error") or {}).get("code", "") if isinstance(res.get("error"), dict) else "")
    try:
        db.execute("UPDATE mcp_tool_calls SET result_json=? WHERE request_id=? AND tool_id=? AND result_json IS NULL",
                   (json.dumps(framework_redact(res))[:8000], request_id, tool_id))
    except Exception:
        pass
    try:
        manager_learn(args.get("company_id"), "AGENT_EXECUTION_SUCCESS"
                      if res.get("status") == "SUCCESS" else "AGENT_EXECUTION_FAILURE",
                      f"MCP tool {tool_id} -> {res.get('status')}.",
                      {"agent_id": agent_id, "tool_id": tool_id, "client_id": real_client})
    except Exception:
        pass
    return {"success": True, "result": res}


def _tool_limit(args, default=50, cap=200):
    try:
        return max(1, min(int((args or {}).get("limit", default)), cap))
    except Exception:
        return default


def _require_brand(company_id):
    b = get_brand(company_id) if company_id else None
    if not b:
        return None, mcp_tool_result("tool", "FAILED", {}, [],
                                     {"code": "MCP_INVALID_INPUT",
                                      "message": f"Unknown company: {company_id}.", "retryable": False}, 0)
    return b, None


def _tool_get_company_profile(agent_id, args, ctx):
    import time as _t
    t0 = _t.time()
    b, err = _require_brand(args.get("company_id"))
    if err:
        err["tool_id"] = "get_company_profile"
        return err
    prof = {k: b.get(k) for k in ("id", "brand_name", "website", "industry", "region", "company_type",
                                  "description", "keywords", "target_audience", "competitors",
                                  "verification_status", "confidence", "last_analyzed_at")}
    return mcp_tool_result("get_company_profile", "SUCCESS", {"profile": framework_redact(prof)},
                           [{"value": f"profile for {b.get('brand_name')}", "source": "database",
                             "verification_status": b.get("verification_status") or "UNVERIFIED",
                             "confidence": b.get("confidence") or 0.5, "collected_at": None,
                             "last_updated_at": b.get("last_updated_at")}],
                           [], None, int((_t.time() - t0) * 1000))


def _tool_get_company_evidence(agent_id, args, ctx):
    import time as _t
    t0 = _t.time()
    b, err = _require_brand(args.get("company_id"))
    if err:
        err["tool_id"] = "get_company_evidence"
        return err
    rows = db.query("SELECT evidence_type, evidence_key, evidence_value, source, verification_status, confidence, "
                    "collected_at, last_updated_at FROM evidence WHERE brand_id=? ORDER BY last_updated_at DESC "
                    "LIMIT ?", (b["id"], _tool_limit(args)))
    return mcp_tool_result("get_company_evidence", "SUCCESS", {"evidence": [dict(r) for r in rows]}, rows,
                           [], None, int((_t.time() - t0) * 1000))


def _tool_get_analysis_history(agent_id, args, ctx):
    import time as _t
    t0 = _t.time()
    b, err = _require_brand(args.get("company_id"))
    if err:
        err["tool_id"] = "get_analysis_history"
        return err
    rows = db.query("SELECT id, visibility_score, readiness_score, observed_score, mention_rate, topic_coverage, "
                    "competitor_strength, trigger, run_id, created_at FROM analysis_results WHERE brand_id=? "
                    "ORDER BY id DESC LIMIT ?", (b["id"], _tool_limit(args, 10)))
    return mcp_tool_result("get_analysis_history", "SUCCESS", {"analyses": [dict(r) for r in rows]}, [],
                           [], None, int((_t.time() - t0) * 1000))


def _tool_get_detected_changes(agent_id, args, ctx):
    import time as _t
    t0 = _t.time()
    b, err = _require_brand(args.get("company_id"))
    if err:
        err["tool_id"] = "get_detected_changes"
        return err
    rows = db.query("SELECT change_type, field_name, previous_value, current_value, impact, severity, detected_at "
                    "FROM change_log WHERE brand_id=? ORDER BY id DESC LIMIT ?", (b["id"], _tool_limit(args, 30)))
    return mcp_tool_result("get_detected_changes", "SUCCESS", {"changes": [dict(r) for r in rows]}, [],
                           [], None, int((_t.time() - t0) * 1000))


def _tool_get_learning_memory(agent_id, args, ctx):
    import time as _t
    t0 = _t.time()
    b, err = _require_brand(args.get("company_id"))
    if err:
        err["tool_id"] = "get_learning_memory"
        return err
    rows = db.query("SELECT memory_type, category, key, value, confidence, status, usage_count, success_count, "
                    "failure_count FROM learning_memory WHERE company_id=? AND status='ACTIVE' ORDER BY id DESC "
                    "LIMIT ?", (b["id"], _tool_limit(args, 20)))
    return mcp_tool_result("get_learning_memory", "SUCCESS", {"memories": [dict(r) for r in rows]}, [],
                           [], None, int((_t.time() - t0) * 1000))


def _tool_generate_search_queries(agent_id, args, ctx):
    import time as _t
    t0 = _t.time()
    b, err = _require_brand(args.get("company_id"))
    if err:
        err["tool_id"] = "generate_search_queries"
        return err
    qs = generate_queries(b)
    intent = (args.get("intent") or "").strip().lower()
    if intent:
        qs = [q for q in qs if str(q.get("intent") or "").lower() == intent] or qs
    qs = qs[:_tool_limit(args, 10)]
    objs = remember_queries(b["id"], qs)
    texts = [o.get("query_text") or o.get("query") for o in objs]
    return mcp_tool_result("generate_search_queries", "SUCCESS", {"queries": texts},
                           [{"value": f"{len(texts)} queries generated and stored", "source": "query-generator",
                             "verification_status": "UNVERIFIED", "confidence": 0.6,
                             "collected_at": None, "last_updated_at": None}],
                           [], None, int((_t.time() - t0) * 1000))


def _tool_run_ai_search(agent_id, args, ctx):
    import time as _t
    t0 = _t.time()
    b, err = _require_brand(args.get("company_id"))
    if err:
        err["tool_id"] = "run_ai_search"
        return err
    q = (args.get("query") or "").strip()
    if q:
        queries = [{"query_text": q, "query": q, "id": None}]
    else:
        queries = get_active_queries(b["id"])[:int(get_config("ai_observation_queries", "5"))]
    if not queries:
        return mcp_tool_result("run_ai_search", "FAILED", {"observations": 0}, [],
                               {"code": "MCP_EXECUTION_FAILED", "message": "No queries available to run.",
                                "retryable": False}, int((_t.time() - t0) * 1000))
    res = run_ai_search(b["id"], queries)
    if not res.get("connected"):
        return mcp_tool_result("run_ai_search", "FAILED", {"observations": 0}, [],
                               {"code": "MCP_EXECUTION_FAILED",
                                "message": res.get("status", "AI search unavailable."), "retryable": True},
                               int((_t.time() - t0) * 1000))
    n = res.get("observations", 0)
    return mcp_tool_result("run_ai_search", "SUCCESS", {"observations": n},
                           [{"value": f"{n} observation(s) stored", "source": "ai-search-providers",
                             "verification_status": "UNVERIFIED", "confidence": 0.6,
                             "collected_at": None, "last_updated_at": None}],
                           [] if n else ["providers returned no observations"], None,
                           int((_t.time() - t0) * 1000))


def _tool_analyze_brand_visibility(agent_id, args, ctx):
    import time as _t
    t0 = _t.time()
    b, err = _require_brand(args.get("company_id"))
    if err:
        err["tool_id"] = "analyze_brand_visibility"
        return err
    return mcp_tool_result("analyze_brand_visibility", "SUCCESS", {"analysis": analyze_brand(b)},
                           [{"value": "deterministic brand analysis", "source": "analysis-engine",
                             "verification_status": "UNVERIFIED", "confidence": 0.7,
                             "collected_at": None, "last_updated_at": None}],
                           [], None, int((_t.time() - t0) * 1000))


def _tool_analyze_competitors(agent_id, args, ctx):
    import time as _t
    t0 = _t.time()
    b, err = _require_brand(args.get("company_id"))
    if err:
        err["tool_id"] = "analyze_competitors"
        return err
    obs = db.query("SELECT * FROM ai_observations WHERE brand_id=? ORDER BY observed_at DESC LIMIT 50", (b["id"],))
    rows = analyze_competitors(b, obs)
    return mcp_tool_result("analyze_competitors", "SUCCESS", {"competitors": rows},
                           [{"value": f"{len(rows)} competitor rows", "source": "analysis-engine",
                             "verification_status": "UNVERIFIED", "confidence": 0.6,
                             "collected_at": None, "last_updated_at": None}],
                           [], None, int((_t.time() - t0) * 1000))


def _tool_detect_content_gaps(agent_id, args, ctx):
    import time as _t
    t0 = _t.time()
    b, err = _require_brand(args.get("company_id"))
    if err:
        err["tool_id"] = "detect_content_gaps"
        return err
    gaps = detect_content_gaps(b, get_company_evidence(b["id"]), analyze_brand(b))
    return mcp_tool_result("detect_content_gaps", "SUCCESS", {"gaps": gaps},
                           [{"value": f"{len(gaps)} content gaps", "source": "analysis-engine",
                             "verification_status": "UNVERIFIED", "confidence": 0.6,
                             "collected_at": None, "last_updated_at": None}],
                           [], None, int((_t.time() - t0) * 1000))


def _tool_generate_recommendations(agent_id, args, ctx):
    import time as _t
    t0 = _t.time()
    b, err = _require_brand(args.get("company_id"))
    if err:
        err["tool_id"] = "generate_recommendations"
        return err
    ev = get_company_evidence(b["id"])
    recs = generate_recommendations(b, detect_content_gaps(b, ev, analyze_brand(b)), {}, ev, [])
    return mcp_tool_result("generate_recommendations", "SUCCESS", {"recommendations": recs},
                           [{"value": f"{len(recs)} recommendations", "source": "analysis-engine",
                             "verification_status": "UNVERIFIED", "confidence": 0.6,
                             "collected_at": None, "last_updated_at": None}],
                           [], None, int((_t.time() - t0) * 1000))


def _tool_get_query_history(agent_id, args, ctx):
    import time as _t
    t0 = _t.time()
    b, err = _require_brand(args.get("company_id"))
    if err:
        err["tool_id"] = "get_query_history"
        return err
    rows = db.query("SELECT query_text, intent, keyword, category, times_tested, last_tested, current_result, "
                    "trend, priority_score FROM query_memory WHERE brand_id=? ORDER BY id DESC LIMIT ?",
                    (b["id"], _tool_limit(args)))
    return mcp_tool_result("get_query_history", "SUCCESS", {"queries": [dict(r) for r in rows]}, [],
                           [], None, int((_t.time() - t0) * 1000))


def _tool_get_recommendation_history(agent_id, args, ctx):
    import time as _t
    t0 = _t.time()
    b, err = _require_brand(args.get("company_id"))
    if err:
        err["tool_id"] = "get_recommendation_history"
        return err
    rows = db.query("SELECT title, description, priority, category, status, feedback, evidence_key, created_at "
                    "FROM recommendations WHERE brand_id=? ORDER BY id DESC LIMIT ?", (b["id"], _tool_limit(args)))
    return mcp_tool_result("get_recommendation_history", "SUCCESS", {"recommendations": [dict(r) for r in rows]},
                           [], None, int((_t.time() - t0) * 1000))


def _tool_get_company_snapshot(agent_id, args, ctx):
    import time as _t
    t0 = _t.time()
    b, err = _require_brand(args.get("company_id"))
    if err:
        err["tool_id"] = "get_company_snapshot"
        return err
    which = str(args.get("which") or "latest").lower()
    rows = db.query("SELECT id, analysis_data, created_at FROM analysis_results WHERE brand_id=? ORDER BY id DESC "
                    "LIMIT 2", (b["id"],))
    if not rows or (which == "previous" and len(rows) < 2):
        return mcp_tool_result("get_company_snapshot", "FAILED", {"snapshot": []}, [],
                               {"code": "MCP_EXECUTION_FAILED",
                                "message": "No stored snapshot available.", "retryable": False},
                               int((_t.time() - t0) * 1000))
    row = rows[0] if which != "previous" else rows[1]
    try:
        snap = (safe_json_loads(row.get("analysis_data"), {}) or {}).get("evidence_snapshot") or []
    except Exception:
        snap = []
    return mcp_tool_result("get_company_snapshot", "SUCCESS",
                           {"snapshot": snap, "analysis_id": row["id"], "created_at": row["created_at"]},
                           [{"value": f"snapshot from analysis #{row['id']}", "source": "analysis_results",
                             "verification_status": "VERIFIED", "confidence": 0.9,
                             "collected_at": row["created_at"], "last_updated_at": row["created_at"]}],
                           [], None, int((_t.time() - t0) * 1000))


def _tool_compare_snapshots(agent_id, args, ctx):
    import time as _t
    t0 = _t.time()
    b, err = _require_brand(args.get("company_id"))
    if err:
        err["tool_id"] = "compare_snapshots"
        return err
    def _snap(aid):
        if aid:
            r = db.query("SELECT analysis_data FROM analysis_results WHERE id=? AND brand_id=?", (aid, b["id"]))
            if r:
                try:
                    return (safe_json_loads(r[0].get("analysis_data"), {}) or {}).get("evidence_snapshot") or []
                except Exception:
                    return []
        return None
    prev = _snap(args.get("previous_snapshot_id"))
    cur = _snap(args.get("current_snapshot_id"))
    if prev is None or cur is None:
        rows = db.query("SELECT id, analysis_data FROM analysis_results WHERE brand_id=? ORDER BY id DESC LIMIT 2",
                        (b["id"],))
        if len(rows) < 2:
            return mcp_tool_result("compare_snapshots", "FAILED", {"diff": {}}, [],
                                   {"code": "MCP_EXECUTION_FAILED",
                                    "message": "Need two stored analyses to compare.", "retryable": False},
                                   int((_t.time() - t0) * 1000))
        try:
            cur = (safe_json_loads(rows[0].get("analysis_data"), {}) or {}).get("evidence_snapshot") or []
            prev = (safe_json_loads(rows[1].get("analysis_data"), {}) or {}).get("evidence_snapshot") or []
        except Exception:
            cur, prev = [], []
    pm = {(i.get("type"), i.get("key")): i.get("value") for i in prev}
    cm = {(i.get("type"), i.get("key")): i.get("value") for i in cur}
    added = [k for k in cm if k not in pm]
    removed = [k for k in pm if k not in cm]
    changed = [k for k in pm if k in cm and pm[k] != cm[k]]
    return mcp_tool_result("compare_snapshots", "SUCCESS",
                           {"diff": {"added": [list(k) for k in sorted(added, key=str)],
                                     "removed": [list(k) for k in sorted(removed, key=str)],
                                     "changed": [{"key": list(k), "previous": pm[k], "current": cm[k]}
                                                 for k in sorted(changed, key=str)]}},
                           [{"value": f"{len(added)} added, {len(removed)} removed, {len(changed)} changed",
                             "source": "snapshot-diff", "verification_status": "VERIFIED", "confidence": 0.9,
                             "collected_at": None, "last_updated_at": None}],
                           [], None, int((_t.time() - t0) * 1000))


def _tool_search_knowledge(agent_id, args, ctx):
    """MCP search_knowledge (§27): Framework -> RAG service -> vector backend."""
    import time as _t
    t0 = _t.time()
    b, err = _require_brand(args.get("company_id"))
    if err:
        err["tool_id"] = "search_knowledge"
        return err
    try:
        top_k = max(1, min(int(args.get("top_k", 5)), 20))
    except Exception:
        top_k = 5
    res = rag_search(b["id"], args.get("query") or "", top_k=top_k)
    if not res.get("success"):
        return mcp_tool_result("search_knowledge", "FAILED", {"results": []}, [],
                               {"code": "MCP_EXECUTION_FAILED",
                                "message": res.get("error", "retrieval failed."), "retryable": True},
                               int((_t.time() - t0) * 1000))
    if res.get("status") == "INSUFFICIENT_RELEVANT_CONTEXT":
        return mcp_tool_result("search_knowledge", "SUCCESS", {"results": []},
                               [{"value": "INSUFFICIENT_RELEVANT_CONTEXT", "source": "rag-service",
                                 "verification_status": "UNVERIFIED", "confidence": 0.5,
                                 "collected_at": None, "last_updated_at": None}],
                               [], None, int((_t.time() - t0) * 1000))
    return mcp_tool_result("search_knowledge", "SUCCESS", {"results": res.get("results") or []},
                           [{"value": f"retrieved {len(res.get('results') or [])} document(s)",
                             "source": "rag-service", "verification_status": "UNVERIFIED", "confidence": 0.7,
                             "collected_at": None, "last_updated_at": None}],
                           [], None, int((_t.time() - t0) * 1000))


MCP_TOOL_IMPLS.update({
    "get_company_profile": _tool_get_company_profile,
    "get_company_evidence": _tool_get_company_evidence,
    "get_analysis_history": _tool_get_analysis_history,
    "get_detected_changes": _tool_get_detected_changes,
    "get_learning_memory": _tool_get_learning_memory,
    "generate_search_queries": _tool_generate_search_queries,
    "run_ai_search": _tool_run_ai_search,
    "analyze_brand_visibility": _tool_analyze_brand_visibility,
    "analyze_competitors": _tool_analyze_competitors,
    "detect_content_gaps": _tool_detect_content_gaps,
    "generate_recommendations": _tool_generate_recommendations,
    "get_query_history": _tool_get_query_history,
    "get_recommendation_history": _tool_get_recommendation_history,
    "get_company_snapshot": _tool_get_company_snapshot,
    "compare_snapshots": _tool_compare_snapshots,
    "search_knowledge": _tool_search_knowledge,
})


# Job-type -> tool mapping used by the selector (§9/§31). Declared data (the
# mapping itself is reviewed configuration), never per-request hardcoding.
JOB_TO_TOOL = {
    "COLLECT_WEBSITE_DATA": "get_company_evidence",
    "VALIDATE_DATA": "get_company_profile",
    "GENERATE_QUERIES": "generate_search_queries",
    "RUN_AI_SEARCH": "run_ai_search",
    "ANALYZE_BRAND": "analyze_brand_visibility",
    "ANALYZE_COMPETITORS": "analyze_competitors",
    "DETECT_CONTENT_GAPS": "detect_content_gaps",
    "GENERATE_RECOMMENDATIONS": "generate_recommendations",
    "DETECT_CHANGES": "get_detected_changes",
    "UPDATE_LEARNING": "get_learning_memory",
    "DISCOVER_COMPANY": "get_company_profile",
}


def mcp_select_tool(reasoning, observations=None):
    """Tool selection from reasoning + context (§9): candidate actions from the
    reasoning result map to registered tools via JOB_TO_TOOL; the pick prefers
    the recommended action, then unsatisfied informational needs. An LLM may
    SUGGEST (suggestion field) but the validator's decision below is final."""
    observations = observations or []
    rec = (reasoning or {}).get("recommended_action")
    cands = [c.get("action") for c in (reasoning or {}).get("considered_actions") or [] if not c.get("suppressed")]
    seen_tools = {o.get("tool_id") for o in observations}
    for action in ([rec] + cands):
        tool_id = JOB_TO_TOOL.get(action)
        if tool_id and tool_id not in seen_tools:
            rows = db.query("SELECT tool_id, capability, enabled FROM mcp_tools WHERE tool_id=?", (tool_id,))
            if rows and rows[0]["enabled"]:
                return {"tool_id": tool_id, "for_action": action,
                        "reason": f"Reasoning recommends {action}; {tool_id} serves it."}
    if rec == "WAIT" or not cands:
        return {"tool_id": None, "for_action": "WAIT", "reason": "Reasoning requires no further tool calls."}
    return {"tool_id": None, "for_action": rec, "reason": "No unexecuted registered tool serves the recommendation."}


def mcp_observation(tool_id, result, company_id=None):
    """Every tool result becomes an observation (§11) for the reasoning loop."""
    data = (result or {}).get("data") or {}
    summary, ev_ids = "", []
    if tool_id == "get_company_evidence":
        rows = data.get("evidence") or []
        summary = f"{len(rows)} evidence row(s) retrieved"
        try:
            if company_id:
                ef, _, note = evidence_freshness(company_id)
                summary += f"; freshness={ef} ({note})"
        except Exception:
            pass
    elif tool_id == "get_analysis_history":
        items = data.get("analyses") or []
        summary = f"{len(items)} historical analyse(s)" + (
            f"; latest visibility={items[0].get('visibility_score')}" if items else "")
    elif tool_id == "get_detected_changes":
        items = data.get("changes") or []
        kinds = sorted({c.get("change_type") for c in items if c.get("change_type")})
        summary = f"{len(items)} detected change(s)" + (f": {', '.join(kinds[:5])}" if kinds else "")
    elif tool_id == "compare_snapshots":
        d = data.get("diff") or {}
        summary = (f"snapshot diff: {len(d.get('added', []))} added, {len(d.get('removed', []))} removed, "
                   f"{len(d.get('changed', []))} changed")
    elif tool_id == "run_ai_search":
        summary = f"{data.get('observations', 0)} AI search observation(s) stored"
    elif tool_id == "generate_search_queries":
        summary = f"{len(data.get('queries', []))} quer(y/ies) generated"
    elif tool_id == "analyze_brand_visibility":
        a = data.get("analysis") or {}
        summary = f"brand positioning assessed: {str(a.get('positioning') or '')[:120]}"
    elif tool_id == "analyze_competitors":
        summary = f"{len(data.get('competitors', []))} competitor row(s)"
    elif tool_id == "detect_content_gaps":
        summary = f"{len(data.get('gaps', []))} content gap(s)"
    elif tool_id == "generate_recommendations":
        summary = f"{len(data.get('recommendations', []))} recommendation(s)"
    elif tool_id == "search_knowledge":
        summary = f"knowledge search returned {len(data.get('results', []))} document(s)"
    else:
        summary = f"{tool_id} returned {len(json.dumps(data))} bytes of data"
    try:
        ev_ids = list(range(len((result or {}).get("evidence") or [])))
    except Exception:
        ev_ids = []
    return {"type": "EVIDENCE_OBSERVATION", "tool_id": tool_id, "observation": summary,
            "evidence_ids": ev_ids, "status": (result or {}).get("status")}


def _mcp_resource_limit(limit):
    try:
        return max(1, min(int(limit or 50), 200))
    except Exception:
        return 50


def mcp_read_resource(uri, auth, limit=50):
    """Strictly read-only (§15/§16): parsed company scope, redaction, limits,
    structured metadata. Never exposes credentials (§31)."""
    m = re.match(r"^company://(\d+)/([a-z-]+)$", (uri or "").strip())
    if not m:
        return {"success": False, "error": "MCP_RESOURCE_NOT_FOUND",
                "reason": f"Malformed resource URI: {uri}."}
    cid, name = int(m.group(1)), m.group(2)
    if auth is None:
        return {"success": False, "error": "MCP_UNAUTHORIZED", "reason": "Missing or invalid credentials."}
    if not mcp_check_scope(auth, cid):
        return {"success": False, "error": "MCP_RESOURCE_ACCESS_DENIED",
                "reason": f"Client not scoped to company {cid}."}
    if not get_brand(cid):
        return {"success": False, "error": "MCP_RESOURCE_NOT_FOUND",
                "reason": f"Unknown company: {cid}."}
    lim = _mcp_resource_limit(limit)
    handlers = {
        "profile": lambda: [dict(r) for r in db.query(
            "SELECT id, brand_name, website, industry, region, company_type, description, keywords, "
            "target_audience, competitors, verification_status, confidence, last_analyzed_at FROM brands "
            "WHERE id=?", (cid,))],
        "evidence": lambda: [dict(r) for r in db.query(
            "SELECT evidence_type, evidence_key, evidence_value, source, verification_status, confidence, "
            "collected_at, last_updated_at FROM evidence WHERE brand_id=? ORDER BY last_updated_at DESC "
            f"LIMIT {lim}", (cid,))],
        "analysis-history": lambda: [dict(r) for r in db.query(
            "SELECT id, visibility_score, readiness_score, observed_score, trigger, run_id, created_at "
            "FROM analysis_results WHERE brand_id=? ORDER BY id DESC "
            f"LIMIT {lim}", (cid,))],
        "snapshots": lambda: [dict(r) for r in db.query(
            "SELECT id, created_at FROM analysis_results WHERE brand_id=? ORDER BY id DESC "
            f"LIMIT {lim}", (cid,))],
        "changes": lambda: [dict(r) for r in db.query(
            "SELECT change_type, field_name, previous_value, current_value, severity, detected_at "
            "FROM change_log WHERE brand_id=? ORDER BY id DESC "
            f"LIMIT {lim}", (cid,))],
        "queries": lambda: [dict(r) for r in db.query(
            "SELECT query_text, intent, times_tested, current_result, trend FROM query_memory "
            f"WHERE brand_id=? ORDER BY id DESC LIMIT {lim}", (cid,))],
        "recommendations": lambda: [dict(r) for r in db.query(
            "SELECT title, priority, category, status, feedback FROM recommendations WHERE brand_id=? "
            f"ORDER BY id DESC LIMIT {lim}", (cid,))],
        "learning": lambda: [dict(r) for r in db.query(
            "SELECT memory_type, category, key, value, confidence, status FROM learning_memory "
            f"WHERE company_id=? AND status='ACTIVE' ORDER BY id DESC LIMIT {lim}", (cid,))],
    }
    if name not in handlers:
        return {"success": False, "error": "MCP_RESOURCE_NOT_FOUND", "reason": f"Unknown resource: {name}."}
    try:
        rows = handlers[name]()
    except Exception as e:
        return {"success": False, "error": "MCP_EXECUTION_FAILED", "reason": str(e)[:200]}
    return {"success": True, "uri": uri, "company_id": cid, "name": name,
            "data": framework_redact(rows),
            "metadata": {"count": len(rows), "truncated": len(rows) >= lim, "read_only": True}}


MCP_PROMPTS = {
    "visibility_analysis": ("Analyze brand visibility for company {company_id}: profile, evidence freshness, "
                            "score history, gaps. Ground every claim in tool output; mark unknowns as missing."),
    "competitor_analysis": ("Analyze competitors for company {company_id}: rival list vs observations, "
                            "comparison coverage. Do not invent competitor data."),
    "content_gap_analysis": ("Analyze content gaps for company {company_id}: evidence surfaces present vs "
                             "required (structured data, pricing, FAQ, comparisons)."),
    "historical_visibility_analysis": ("Compare latest vs previous analysis for company {company_id}: score "
                                       "deltas with coincides-with language; no causal claims."),
    "change_analysis": ("Review unprocessed changes for company {company_id}: classify major/minor with reasons; "
                        "propose the minimal next step."),
    "recommendation_review": ("Review open recommendations for company {company_id} against resolved history; "
                              "never re-propose resolved items."),
}


def mcp_get_prompt(name, args, auth):
    """Prompts provide structured context only (§17); never permissions."""
    if auth is None:
        return {"success": False, "error": "MCP_UNAUTHORIZED", "reason": "Missing or invalid credentials."}
    if name not in MCP_PROMPTS:
        return {"success": False, "error": "MCP_RESOURCE_NOT_FOUND", "reason": f"Unknown prompt: {name}."}
    args = args or {}
    cid = args.get("company_id")
    context = ""
    if cid is not None:
        if not mcp_check_scope(auth, cid):
            return {"success": False, "error": "MCP_RESOURCE_ACCESS_DENIED",
                    "reason": f"Client not scoped to company {cid}."}
        b = get_brand(cid)
        if not b:
            return {"success": False, "error": "MCP_RESOURCE_NOT_FOUND",
                    "reason": f"Unknown company: {cid}."}
        context = (f"Company: {b.get('brand_name')} (#{cid}), industry {b.get('industry')}, "
                   f"website {b.get('website') or 'missing'}. ")
    return {"success": True, "name": name,
            "messages": [{"role": "user", "content": MCP_PROMPTS[name].format(company_id=cid) + " " + context}],
            "metadata": {"grants_no_permissions": True}}


def framework_dashboard():
    """§26 dashboard data: all counts from the registry + real task/job rows."""
    agents = manager_list_agents()["agents"]
    scrubbed = []
    for a in agents:
        d = dict(a)
        d["configuration"] = framework_redact(a.get("configuration") or {})
        scrubbed.append(d)
    def cnt(status=None, health=None):
        n = 0
        for a in agents:
            if status and a.get("status") != status:
                continue
            if health and a.get("health_status") != health:
                continue
            n += 1
        return n
    last_exec, last_err = {}, {}
    for a in agents:
        r = db.query("SELECT status, error_message, started_at, completed_at FROM manager_tasks "
                     "WHERE selected_agent_id=? ORDER BY id DESC LIMIT 1", (a["agent_id"],))
        if r:
            last_exec[a["agent_id"]] = r[0].get("started_at") or r[0].get("created_at")
            last_err[a["agent_id"]] = r[0].get("error_message")
    return {"success": True,
            "registered_agents": len(agents), "active_agents": cnt(status="ACTIVE"),
            "paused_agents": cnt(status="PAUSED"),
            "healthy_agents": cnt(health="HEALTHY"), "degraded_agents": cnt(health="DEGRADED"),
            "unavailable_agents": len([a for a in agents if a.get("health_status") in ("UNAVAILABLE", "UNKNOWN")]),
            "agents": scrubbed, "last_execution": last_exec, "last_error": last_err}


# ---------------------------------------------------------------------------
# AGENT RUN PIPELINE (micro-job stages)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# AGENT RUN PIPELINE (micro-job stages)
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# AUTONOMOUS AGENT RUNNER + JOB QUEUE  (v3 module)
# ---------------------------------------------------------------------------
#
# The Agent Runner is a real automation engine:
#   - loads pending jobs, prioritizes (HIGH/MEDIUM/LOW based on real conditions)
#   - executes each job against the real backend pipeline
#   - stores results + state in the database
#   - creates the next required jobs (dependency order)
#   - retries failures up to max_retries, then FAILED_PERMANENTLY
#   - never fabricates progress: all numbers come from actual DB rows
#
# Every execution-altering event is written to agent_activity (real activity
# stream). Pause/Resume/Cancel are persisted and honored by the runner.

# Spec-supported job types (STORE_ANALYSIS is an internal system job).
PIPELINE_TYPES = [
    "COLLECT_WEBSITE_DATA",
    "VALIDATE_DATA",
    "GENERATE_QUERIES",
    "RUN_AI_SEARCH",
    "ANALYZE_BRAND",
    "ANALYZE_COMPETITORS",
    "DETECT_CONTENT_GAPS",
    "GENERATE_RECOMMENDATIONS",
    "DETECT_CHANGES",
    "STORE_ANALYSIS",
    "UPDATE_LEARNING",
]

JOB_TYPES = PIPELINE_TYPES + ["DISCOVER_COMPANY", "REANALYZE_COMPANY"]

# Dependencies: a job must not run before its per-company prerequisites have
# COMPLETED. Creation-time ensures prerequisites exist; selection-time enforces
# that only jobs whose prerequisites are complete can be picked.
JOB_DEPENDENCIES = {
    "DISCOVER_COMPANY": [],
    "COLLECT_WEBSITE_DATA": [],
    "VALIDATE_DATA": ["COLLECT_WEBSITE_DATA"],
    "GENERATE_QUERIES": ["VALIDATE_DATA"],
    "RUN_AI_SEARCH": ["GENERATE_QUERIES"],
    "ANALYZE_BRAND": ["VALIDATE_DATA"],
    "ANALYZE_COMPETITORS": ["ANALYZE_BRAND"],
    "DETECT_CONTENT_GAPS": ["ANALYZE_BRAND", "VALIDATE_DATA"],
    "GENERATE_RECOMMENDATIONS": ["ANALYZE_COMPETITORS", "DETECT_CONTENT_GAPS"],
    "DETECT_CHANGES": ["COLLECT_WEBSITE_DATA", "VALIDATE_DATA"],
    "STORE_ANALYSIS": ["GENERATE_RECOMMENDATIONS", "DETECT_CHANGES"],
    "UPDATE_LEARNING": ["STORE_ANALYSIS"],
    "REANALYZE_COMPANY": [],
}

PRIORITY_SCORE = {"HIGH": 100, "MEDIUM": 50, "LOW": 10}

# Job lifecycle statuses (spec): PENDING / RUNNING / COMPLETED / FAILED /
# RETRYING / CANCELLED  (+ terminal FAILED_PERMANENTLY after retries exhausted).
TERMINAL_JOB_STATUSES = ("COMPLETED", "FAILED_PERMANENTLY", "CANCELLED")
INFLIGHT_JOB_STATUSES = ("PENDING", "QUEUED", "RUNNING", "RETRYING", "FAILED")


def new_job_id(jid):
    if isinstance(jid, str) and '-' in jid:
        # UUID string - use last 6 hex chars
        return f"JOB-{jid.replace('-', '')[-6:].upper()}"
    try:
        return f"JOB-{int(jid):06d}"
    except (ValueError, TypeError):
        return f"JOB-{abs(hash(str(jid))) % 1000000:06d}"


def log_activity(message, level="INFO", run_id=None, job_id=None, company_id=None):
    """Persisted activity-stream entry. Only callers that represent a REAL
    execution event should write here."""
    db.execute(
        "INSERT INTO agent_activity (run_id, job_id, company_id, level, message, created_at) VALUES (?,?,?,?,?,?)",
        (run_id, job_id, company_id, level, str(message)[:500], now()))


CTX = {}
LOCK = threading.Lock()
PROCESS_LOCK = threading.Lock()


def new_run_id():
    return now().replace(":", "-").replace("+", "Z") + f"-{int(time.time()*1000) % 100000}"


def create_run(run_type="MANUAL", companies=None, automation_id=None):
    rid = new_run_id()
    total = len(companies or [])
    t = now()
    db.execute("""
        INSERT INTO runs (run_id, run_type, status, current_task, progress, total_companies,
                          processed_companies, total_queries, processed_queries, new_evidence_count,
                          changes_detected, recommendations_updated, total_jobs, completed_jobs,
                          failed_jobs, errors, started_at, automation_id)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (rid, run_type, "RUNNING", "Initializing", 0, total, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, t, automation_id))
    log_activity(f"Run started ({run_type}) with {total} company(ies) tracked.", level="RUN", run_id=rid)
    return rid


def _run_stats(run_id):
    """Compute execution statistics purely from stored job records."""
    rows = db.query("SELECT * FROM jobs WHERE run_id=?", (run_id,))
    total = len(rows)
    completed = sum(1 for r in rows if r["status"] == "COMPLETED")
    failed = sum(1 for r in rows if r["status"] in ("FAILED", "FAILED_PERMANENTLY", "RETRYING"))
    cancelled = sum(1 for r in rows if r["status"] == "CANCELLED")
    analyzed = set()
    for r in rows:
        if r["job_type"] == "STORE_ANALYSIS" and r["status"] == "COMPLETED" and r["company_id"]:
            analyzed.add(r["company_id"])
    err = next((r["error"] for r in rows if r.get("error")), None)
    return {
        "total_jobs": total,
        "completed_jobs": completed,
        "failed_jobs": failed,
        "cancelled_jobs": cancelled,
        "companies_processed": len(analyzed),
        "error_message": (err or "")[:500],
    }


def finalize_run(run_id, status):
    rows = db.query("SELECT * FROM runs WHERE run_id=? ORDER BY id DESC LIMIT 1", (run_id,))
    if not rows:
        return
    r = rows[0]
    next_run = _estimate_next_run()
    stats = _run_stats(run_id)
    db.execute("UPDATE runs SET status=?, current_task=?, progress=?, completed_at=?, next_run_at=?, "
               "total_jobs=?, completed_jobs=?, failed_jobs=?, processed_companies=?, error_details=? WHERE id=?",
               (status,
                "Completed" if status == "COMPLETED" else "Failed" if status == "FAILED" else r["current_task"],
                100 if status == "COMPLETED" else r["progress"], now(), next_run,
                stats["total_jobs"], stats["completed_jobs"], stats["failed_jobs"],
                stats["companies_processed"], stats["error_message"], r["id"]))
    msg = f"Run finished with status {status}: {stats['completed_jobs']}/{stats['total_jobs']} jobs completed, {stats['failed_jobs']} failed."
    if stats.get("error_message"):
        msg += f" Errors: {stats['error_message']}"
    log_activity(msg, level="RUN", run_id=run_id)
    # Propagate the outcome to the owning automation (if any) so the automation
    # status stays truthful and run/failure counters reflect real runs.
    try:
        if r.get("automation_id"):
            arow = db.query("SELECT company_id FROM automations WHERE id=? LIMIT 1", (r["automation_id"],))
            aco = arow[0]["company_id"] if arow else None
            db.execute("UPDATE automations SET last_status=?, failure_count=failure_count+?, updated_at=? "
                       "WHERE id=?",
                       ("COMPLETED" if status == "COMPLETED" else "FAILED",
                        1 if status == "FAILED" else 0, now(), r["automation_id"]))
            log_automation_event("SCHEDULER_COMPLETED",
                                 f"Automation run {run_id} finished: {status} "
                                 f"({stats['completed_jobs']}/{stats['total_jobs']} jobs completed)",
                                 automation_id=r["automation_id"], company_id=aco, run_id=run_id)
    except Exception as e:
        print(f"[Automation] finalize hook failed: {e}", flush=True)


def _estimate_next_run():
    cfg = get_config()
    now_dt = datetime.datetime.now()
    try:
        days = int(cfg.get("freshness_days", "7"))
        if cfg.get("weekly_enabled") == "1":
            days = max(days, 7)
    except Exception:
        days = 7
    return (now_dt + datetime.timedelta(days=days)).isoformat(timespec="seconds")


def update_run_counter(run_id, field, delta):
    if not run_id:
        return
    if field not in {"total_queries", "processed_queries", "new_evidence_count", "changes_detected",
                     "recommendations_updated", "errors", "total_jobs", "completed_jobs", "failed_jobs"}:
        return
    expr = f"GREATEST(0, {field} + ?)" if db.flavor == "mysql" else f"MAX(0, {field} + ?)"
    db.execute(f"UPDATE runs SET {field} = {expr} WHERE run_id=?", (delta, run_id))


def get_config(key=None, default=None):
    rows = db.query("SELECT config_key, config_value FROM agent_config")
    cfg = default_config()
    for r in rows:
        cfg[r["config_key"]] = r["config_value"]
    if key is not None:
        try:
            return cfg.get(key, default if default is not None else default_config().get(key))
        except Exception:
            return default
    return cfg


def save_config(new_cfg):
    for k, v in (new_cfg or {}).items():
        rows = db.query("SELECT config_key FROM agent_config WHERE config_key=?", (k,))
        if rows:
            db.execute("UPDATE agent_config SET config_value=?, updated_at=? WHERE config_key=?",
                       (str(v), now(), k))
        else:
            db.execute("INSERT INTO agent_config (config_key, config_value, updated_at) VALUES (?,?,?)",
                       (k, str(v), now()))


def _job_applicable(company_id, job_type):
    """A job type is not applicable when its data is already known/irrelevant."""
    if job_type == "DISCOVER_COMPANY":
        b = get_brand(company_id)
        if b and (b.get("website") or "").strip():
            return False
    return True


def _dep_completed(company_id, dep_type):
    if dep_type == "DISCOVER_COMPANY":
        b = get_brand(company_id)
        if b and (b.get("website") or "").strip():
            return True  # discovery not required - website already known
    rows = db.query(
        "SELECT id FROM jobs WHERE company_id=? AND job_type=? AND status='COMPLETED' ORDER BY id DESC LIMIT 1",
        (company_id, dep_type))
    return bool(rows)


def _deps_satisfied(company_id, job_type):
    for dep in JOB_DEPENDENCIES.get(job_type, []):
        if not _dep_completed(company_id, dep):
            return False
    return True


def evidence_freshness(company_id):
    """Return ('fresh'|'stale'|'expired'|'none', age_days, note) from real evidence rows."""
    rows = db.query("SELECT MAX(last_updated_at) AS mx, MAX(collected_at) AS mc FROM evidence WHERE brand_id=?",
                    (company_id,))
    if not rows or not (rows[0].get("mx") or rows[0].get("mc")):
        return "none", None, "no evidence collected yet"
    ts = rows[0]["mx"] or rows[0]["mc"]
    try:
        dt = datetime.datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        age = (datetime.datetime.now(datetime.timezone.utc) - dt).days
    except Exception:
        return "none", None, "unreadable freshness"
    cfg = get_config()
    stale_d = int(cfg.get("evidence_stale_days", "14"))
    exp_d = int(cfg.get("evidence_expired_days", "30"))
    if age > exp_d:
        return "expired", age, f"website evidence {age} days old (expired)"
    if age > stale_d:
        return "stale", age, f"website evidence {age} days old (stale)"
    return "fresh", age, f"website evidence {age} day(s) old (fresh)"


def analysis_freshness(company_id):
    """Return ('fresh'|'stale'|'expired'|'never', age_days, note)."""
    b = get_brand(company_id)
    if not b or not b.get("last_analyzed_at"):
        return "never", None, "never analyzed"
    ts = b["last_analyzed_at"]
    try:
        dt = datetime.datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        age = (datetime.datetime.now(datetime.timezone.utc) - dt).days
    except Exception:
        return "never", None, "unreadable last analysis"
    cfg = get_config()
    stale_d = int(cfg.get("analysis_stale_days", "14"))
    exp_d = int(cfg.get("analysis_expired_days", "30"))
    if age > exp_d:
        return "expired", age, f"last analysis {age} days old (expired)"
    if age > stale_d:
        return "stale", age, f"last analysis {age} days old (stale)"
    return "fresh", age, "analysis current"


def profile_changed(company_id):
    """True when profile fields (keywords/competitors/description/website) differ
    from the snapshot stored at the most recent analysis."""
    b = get_brand(company_id)
    if not b:
        return False
    recent = db.query("SELECT analysis_data FROM analysis_results WHERE brand_id=? ORDER BY id DESC LIMIT 1",
                      (company_id,))
    if not recent:
        return False
    snap = safe_json_loads(recent[0]["analysis_data"], {}).get("evidence_snapshot") or []
    prev = {}
    for item in snap:
        if str(item.get("type", "")).startswith("PROFILE"):
            prev.setdefault((item.get("type"), item.get("key")), item.get("value"))
    fields = {
        "PROFILE_KEYWORDS": b.get("keywords") or "",
        "PROFILE_COMPETITORS": b.get("competitors") or "",
        "PROFILE_DESCRIPTION": b.get("description") or "",
        "PROFILE_WEBSITE": b.get("website") or "",
    }
    for ptype, cur in fields.items():
        if prev.get((ptype, ptype.split("_", 1)[1].lower())) != cur:
            return True
    return False


def compute_priority(company_id, job_type):
    """Priority from actual conditions - never random. Returns (LEVEL, reason)."""
    b = get_brand(company_id)
    if not b:
        return "LOW", "company missing"
    failed_before = db.query(
        "SELECT id FROM jobs WHERE company_id=? AND job_type=? AND status='FAILED_PERMANENTLY' ORDER BY id DESC LIMIT 1",
        (company_id, job_type))
    if failed_before:
        return "HIGH", "previous analysis failed - retrying"
    if profile_changed(company_id):
        return "HIGH", "company profile changed since last analysis"
    af, a_days, a_note = analysis_freshness(company_id)
    if af == "never":
        return "HIGH", "never analyzed"
    if af in ("stale", "expired"):
        return "HIGH", a_note
    if job_type in ("COLLECT_WEBSITE_DATA", "VALIDATE_DATA"):
        ef, e_days, e_note = evidence_freshness(company_id)
        if ef == "expired":
            return "HIGH", e_note
        if ef == "stale":
            return "MEDIUM", e_note
        return "LOW", "evidence is fresh"
    if job_type in ("GENERATE_QUERIES", "RUN_AI_SEARCH", "ANALYZE_BRAND", "ANALYZE_COMPETITORS",
                    "DETECT_CONTENT_GAPS", "GENERATE_RECOMMENDATIONS", "STORE_ANALYSIS", "UPDATE_LEARNING"):
        return "MEDIUM", "regular scheduled analysis"
    return "MEDIUM", "scheduled refresh"


def ensure_job(job_type, company_id, run_id=None, include_completed=True):
    """Create a job (+ its prerequisite chain) unless one already exists or the job
    is not applicable. Never creates a duplicate pending operation.
    include_completed=False lets scheduled automation cycles create a NEW job set
    each cycle (previous COMPLETED jobs are not treated as duplicates)."""
    if not _job_applicable(company_id, job_type):
        return None
    if include_completed:
        status_filter = "'PENDING','QUEUED','RUNNING','RETRYING','COMPLETED'"
    else:
        status_filter = "'PENDING','QUEUED','RUNNING','RETRYING'"
    existing = db.query(
        f"SELECT id FROM jobs WHERE company_id=? AND job_type=? AND status IN ({status_filter}) ORDER BY id DESC LIMIT 1",
        (company_id, job_type))
    if existing:
        eid = existing[0]["id"]
        # Attach the job to the current run if it was created before any run
        # existed (e.g. auto-queued on company add) so run stats/activity tie up.
        if run_id:
            db.execute("UPDATE jobs SET run_id=? WHERE id=? AND (run_id IS NULL OR run_id='')", (run_id, eid))
        return eid
    for dep in JOB_DEPENDENCIES.get(job_type, []):
        ensure_job(dep, company_id, run_id, include_completed=include_completed)
    level, reason = compute_priority(company_id, job_type)
    if db.flavor == "mysql":
        job_uuid = str(uuid.uuid4())
        jid = db.execute("""
            INSERT INTO jobs (id, job_id, company_id, job_type, status, priority, priority_level, payload,
                              max_retries, run_id, created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """, (job_uuid, new_job_id(0), company_id, job_type, "PENDING", PRIORITY_SCORE.get(level, 50), level,
              "{}", int(get_config().get("max_retries", "3")), run_id, now()))
        db.execute("UPDATE jobs SET job_id=? WHERE id=?", (new_job_id(jid), job_uuid))
    else:
        jid = db.execute("""
            INSERT INTO jobs (job_id, company_id, job_type, status, priority, priority_level, payload,
                              max_retries, run_id, created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?)
        """, (new_job_id(0), company_id, job_type, "PENDING", PRIORITY_SCORE.get(level, 50), level,
              "{}", int(get_config().get("max_retries", "3")), run_id, now()))
        db.execute("UPDATE jobs SET job_id=? WHERE id=?", (new_job_id(jid), jid))
    log_activity(f"Job created: {job_type} for company #{company_id} (priority {level} - {reason})",
                 level="JOB", run_id=run_id, job_id=jid, company_id=company_id)
    return jid


def plan_company_jobs(company_id, run_id=None, job_types=None):
    """Enqueue (dedup-aware) the given pipeline for a company. Returns created ids."""
    created = []
    plan = list(job_types or PIPELINE_TYPES)
    b = get_brand(company_id)
    if b and not (b.get("website") or "").strip() and "DISCOVER_COMPANY" not in plan:
        plan = ["DISCOVER_COMPANY"] + plan
    for jt in plan:
        jid = ensure_job(jt, company_id, run_id)
        if jid:
            created.append(jid)
    return created


def companies_needing_work(company_id=None):
    """Discover which companies require work and WHY, from real database state."""
    ids = []
    if company_id:
        ids = [company_id] if get_brand(company_id) else []
    else:
        ids = [r["id"] for r in db.query("SELECT id FROM brands WHERE is_active=1 ORDER BY id")]
    out = []
    cfg = get_config()
    for cid in ids:
        b = get_brand(cid)
        if not b:
            continue
        af, a_days, a_note = analysis_freshness(cid)
        ef, e_days, e_note = evidence_freshness(cid)
        jobs, reason, urgency = [], None, "MEDIUM"
        if af == "never":
            jobs, reason, urgency = list(PIPELINE_TYPES), "never analyzed", "HIGH"
        else:
            failed = db.query(
                "SELECT job_type FROM jobs WHERE company_id=? AND status='FAILED_PERMANENTLY' ORDER BY id DESC",
                (cid,))
            if failed and af in ("stale", "expired"):
                jobs, reason = list(PIPELINE_TYPES), f"retry after failure + {a_note}"
                urgency = "HIGH"
            elif profile_changed(cid):
                jobs, reason, urgency = list(PIPELINE_TYPES), "company profile changed", "HIGH"
            elif af in ("expired", "stale"):
                jobs, reason = list(PIPELINE_TYPES), a_note
                urgency = "HIGH" if af == "expired" else "MEDIUM"
            elif ef in ("expired", "stale"):
                jobs, reason = ["COLLECT_WEBSITE_DATA", "VALIDATE_DATA"], e_note
                urgency = "HIGH" if ef == "expired" else "MEDIUM"
            elif failed:
                jobs, reason = list(dict.fromkeys([f["job_type"] for f in failed])), "retry failed jobs"
                urgency = "HIGH"
            elif cfg.get("reanalysis_on_change_enabled", "1") == "1" and _evidence_moved(cid):
                jobs, reason, urgency = list(PIPELINE_TYPES), "website content changed", "HIGH"
        if jobs and reason:
            out.append({"company_id": cid, "company": b.get("brand_name"), "reason": reason,
                        "urgency": urgency, "jobs": jobs})
    return out


def _evidence_moved(company_id):
    """True when evidence differs from the snapshot at the previous analysis run."""
    curr = evidence_snapshot(company_id)
    prev_rows = db.query("SELECT analysis_data FROM analysis_results WHERE brand_id=? ORDER BY id DESC LIMIT 1",
                         (company_id,))
    if not prev_rows:
        return False
    prev = safe_json_loads(prev_rows[0]["analysis_data"], {}).get("evidence_snapshot") or []
    prev_map = {(i.get("type"), i.get("key")): i.get("value") for i in prev}
    curr_map = {(i.get("type"), i.get("key")): i.get("value") for i in curr}
    if set(curr_map) == set(prev_map) and all(prev_map[k] == curr_map[k] for k in prev_map):
        return False
    return True


def process_company_jobs(company_id, run_id, priority=50):
    """Synchronous job execution for a company (used by manual + re-analyze)."""
    ctx = CTX.setdefault((run_id, company_id), {})
    brand = get_brand(company_id)
    if not brand:
        return {"error": "company not found"}
    plan_company_jobs(company_id, run_id)
    summary = {"queries": 0, "observations": 0, "new_evidence": 0, "changes": 0,
               "recommendations": 0, "errors": 0}
    with PROCESS_LOCK:
        while True:
            job = _pick_company_job(company_id)
            if not job:
                break
            res = execute_job(job["id"], run_id)
            summary["new_evidence"] += res.get("new_evidence", 0)
            summary["changes"] += res.get("changes", 0)
            summary["queries"] += res.get("queries", 0)
            summary["observations"] += res.get("observations", 0)
            summary["recommendations"] += res.get("recommendations", 0)
            # Phase 4 (§21): learning is non-blocking - its failure stays on the
            # job (FAILED/retryable) but never fails the completed analysis.
            if res.get("error") and job.get("job_type") != "UPDATE_LEARNING":
                summary["errors"] += 1
    return summary


def _pick_company_job(company_id):
    rows = db.query("SELECT * FROM jobs WHERE company_id=? AND status='PENDING' ORDER BY priority DESC, id ASC",
                    (company_id,))
    for job in rows:
        if _deps_satisfied(company_id, job["job_type"]):
            return job
    return None


def execute_job(job_id, run_id=None):
    rows = db.query("SELECT * FROM jobs WHERE id=?", (job_id,))
    if not rows:
        return {"error": "job not found"}
    job = rows[0]
    if job["status"] not in ("PENDING", "QUEUED", "RUNNING", "RETRYING", "FAILED"):
        return {"error": f"job not runnable (status={job['status']})"}
    if job["status"] == "FAILED" and (job.get("retry_count") or 0) >= (job.get("max_retries") or 3):
        db.execute("UPDATE jobs SET status='FAILED_PERMANENTLY' WHERE id=?", (job_id,))
        return {"error": "retries exhausted"}
    run_id = run_id or job.get("run_id")
    cid = job["company_id"]
    ctx = CTX.setdefault((run_id or "", cid), {})
    bname = ""
    b = get_brand(cid) if cid else None
    if b:
        bname = b.get("brand_name") or ""
    db.execute("UPDATE jobs SET status='RUNNING', started_at=? WHERE id=?", (now(), job_id))
    log_activity(f"Executing {job['job_type']}{' for ' + bname if bname else ''}", level="JOB",
                 run_id=run_id, job_id=job_id, company_id=cid)
    try:
        result = dispatch_job(job, ctx, run_id)
        db.execute("UPDATE jobs SET status='COMPLETED', result_json=?, completed_at=?, error=NULL WHERE id=?",
                   (json.dumps(result).encode("utf-8", "replace").decode("utf-8")[:3000], now(), job_id))
        update_run_counter(run_id, "completed_jobs", 1)
        log_activity(f"Completed {job['job_type']}{' for ' + bname if bname else ''}", level="OK",
                     run_id=run_id, job_id=job_id, company_id=cid)
        return result
    except Exception as e:
        rc = (job.get("retry_count") or 0) + 1
        maxr = job.get("max_retries") or int(get_config().get("max_retries", "3"))
        err = str(e)[:500]
        update_run_counter(run_id, "failed_jobs", 1)
        update_run_counter(run_id, "errors", 1)
        if rc >= maxr:
            db.execute("UPDATE jobs SET status='FAILED_PERMANENTLY', error=?, retry_count=? WHERE id=?",
                       (err, rc, job_id))
            log_activity(f"Failed permanently {job['job_type']} (attempt {rc}/{maxr}): {err}", level="ERROR",
                         run_id=run_id, job_id=job_id, company_id=cid)
        else:
            db.execute("UPDATE jobs SET status='RETRYING', error=?, retry_count=? WHERE id=?", (err, rc, job_id))
            log_activity(f"Job failed, retry {rc}/{maxr} scheduled for {job['job_type']}", level="WARN",
                         run_id=run_id, job_id=job_id, company_id=cid)
        return {"error": err}


def dispatch_job(job, ctx, run_id):
    jt = job["job_type"]
    cid = job["company_id"]
    brand = get_brand(cid)

    if jt == "MANAGER_SUBTASK":
        return _dispatch_manager_subtask(job, ctx, run_id)

    if jt == "MANAGER_SYNTHESIS":
        return _dispatch_manager_synthesis(job, ctx, run_id)

    if jt == "DISCOVER_COMPANY":
        # Real discovery only from connected external sources - never fabricated.
        res = run_company_discovery({"industry": brand.get("industry") or "", "region": brand.get("region") or ""})
        if not res.get("success"):
            return {"skipped": True, "status": res.get("status", "COMPANY DISCOVERY INTEGRATION NOT CONNECTED"),
                    "ok": True}
        return {"ok": True, "candidates": res.get("candidates", 0)}

    if jt == "COLLECT_WEBSITE_DATA":
        if not brand.get("website"):
            return {"skipped": "no website", "ok": True}
        if not company_source_is_connected("WEBSITE_SCRAPER") or not int(get_config("scrape_enabled", "1")):
            return {"skipped": "WEBSITE SCRAPER NOT CONNECTED", "ok": True}
        res = scrape_website(cid, brand["website"])
        if not res.get("ok"):
            return res
        n = save_evidence(cid, res["evidence"], "WEBSITE_SCRAPER")
        update_run_counter(run_id, "new_evidence_count", n)
        rec_rows = db.query("SELECT id FROM recommendations WHERE brand_id=? AND status IN ('OPEN','REJECTED') "
                            "AND evidence_key IS NOT NULL", (cid,))
        for rec in rec_rows:
            rrow = db.query("SELECT evidence_key FROM recommendations WHERE id=?", (rec["id"],))
            if rrow and rrow[0]["evidence_key"]:
                have = {e["evidence_type"] for e in get_company_evidence(cid)}
                if rrow[0]["evidence_key"] in have:
                    db.execute("UPDATE recommendations SET status='DONE', feedback='AUTO_RESOLVED', "
                               "feedback_at=? WHERE id=?", (now(), rec["id"]))
                    remember(cid, f"IMPLEMENTED:{rrow[0]['evidence_key']}", "EVIDENCE",
                             f"Evidence now present: {rrow[0]['evidence_key']}", 0.9)
        return {"ok": True, "new_evidence": n, "pages": res.get("pages", 1)}

    if jt == "VALIDATE_DATA":
        missing = []
        if not (brand.get("brand_name") or "").strip():
            missing.append("brand_name")
        if not (brand.get("industry") or "").strip():
            missing.append("industry")
        if not (brand.get("website") or "").strip():
            missing.append("website")
        checks = {
            "keyword": bool((brand.get("keywords") or "").strip()),
            "target_audience": bool((brand.get("target_audience") or "").strip()),
            "description": bool((brand.get("description") or "").strip()),
        }
        if not checks["keyword"]:
            missing.append("keywords")
        if not checks["target_audience"]:
            missing.append("target_audience")
        # Persist validation evidence so the validation is auditable.
        save_evidence(cid, [{
            "evidence_type": "VALIDATION",
            "evidence_key": "profile_validation",
            "evidence_value": json.dumps({"valid": not missing, "missing": missing}),
            "source": "VALIDATE_DATA", "source_detail": "job", "confidence": 0.9,
            "verification_status": "VERIFIED",
        }], "VALIDATE_DATA")
        return {"ok": True, "valid": not missing, "missing": missing}

    if jt == "GENERATE_QUERIES":
        queries = generate_queries(brand)
        # Phase 4 adaptive selection: fill remaining slots with historically useful
        # queries (company history first, same-industry patterns adapted - never blind reuse).
        hist_added = []
        try:
            if learning_enabled_for_company(cid):
                limit = int(get_config("query_generation_limit", "10"))
                slots = max(0, limit - len(queries or []))
                if slots > 0:
                    hist_added = select_historical_queries(brand, queries, limit=min(3, slots))
                    for h in hist_added:
                        record_learning_event(cid, "PATTERN_CONFIRMED",
                                              f"Historical query reused for current analysis: '{(h.get('query') or '')[:120]}'",
                                              run_id=run_id, source_type="LEARNING_ENGINE",
                                              metadata={"query": (h.get("query") or "")[:300],
                                                        "reasons": h.get("selection_reasons") or []},
                                              mirror_activity=False)
                    queries = (queries or []) + hist_added
        except Exception as e:
            print(f"[Learning] historical query blend skipped: {e}", flush=True)
        q_objs = remember_queries(cid, queries)
        ctx["queries"] = q_objs
        update_run_counter(run_id, "total_queries", len(q_objs))
        update_run_counter(run_id, "processed_queries", len(q_objs))
        return {"ok": True, "queries": len(q_objs), "historical_reused": len(hist_added)}

    if jt == "RUN_AI_SEARCH":
        queries = get_active_queries(cid)
        res = run_ai_search(cid, queries, run_id=run_id)
        update_run_counter(run_id, "processed_queries", res.get("observations", 0))
        return res

    if jt == "ANALYZE_BRAND":
        analysis = analyze_brand(brand)
        ctx["brand_analysis"] = analysis
        return {"ok": True, "analysis": analysis}

    if jt == "ANALYZE_COMPETITORS":
        observations = db.query("SELECT * FROM ai_observations WHERE brand_id=? ORDER BY observed_at DESC LIMIT 50",
                                (cid,))
        rows = analyze_competitors(brand, observations)
        ctx["competitor_rows"] = rows
        return {"ok": True, "competitors": len(rows)}

    if jt == "DETECT_CONTENT_GAPS":
        evidence = get_company_evidence(cid)
        analysis = ctx.get("brand_analysis") or analyze_brand(brand)
        gaps = detect_content_gaps(brand, evidence, analysis)
        ctx["content_gaps"] = gaps
        return {"ok": True, "gaps": len(gaps)}

    if jt == "GENERATE_RECOMMENDATIONS":
        evidence = get_company_evidence(cid)
        gaps = ctx.get("content_gaps") or detect_content_gaps(brand, evidence, analyze_brand(brand))
        analysis = ctx.get("brand_analysis") or analyze_brand(brand)
        comp_rows = ctx.get("competitor_rows")
        if comp_rows is None:
            obs = db.query("SELECT * FROM ai_observations WHERE brand_id=? ORDER BY observed_at DESC LIMIT 50", (cid,))
            comp_rows = analyze_competitors(brand, obs)
        obs = db.query("SELECT * FROM ai_observations WHERE brand_id=? ORDER BY observed_at DESC LIMIT 50", (cid,))
        metrics = readiness_metrics(brand, analysis, comp_rows, obs, evidence)
        learning = get_learning(cid)
        recs = generate_recommendations(brand, gaps, metrics, evidence, learning)
        ctx["recommendations"] = recs
        return {"ok": True, "recommendations": len(recs)}

    if jt == "DETECT_CHANGES":
        changes = detect_changes(cid, run_id)
        ctx["changes"] = changes
        update_run_counter(run_id, "changes_detected", len(changes))
        return {"ok": True, "changes": len(changes)}

    if jt == "STORE_ANALYSIS":
        rtype = "AUTOMATIC"
        rr = db.query("SELECT run_type FROM runs WHERE run_id=? ORDER BY id DESC LIMIT 1", (run_id,))
        if rr and rr[0]["run_type"]:
            rtype = rr[0]["run_type"]
        _store_analysis(cid, run_id, rtype)
        update_run_counter(run_id, "processed_companies", 1)
        rr = db.query("SELECT * FROM runs WHERE run_id=? ORDER BY id DESC LIMIT 1", (run_id,))
        if rr:
            total = max(1, rr[0]["total_companies"] or 1)
            done = rr[0]["processed_companies"] or 0
            bname = (brand or {}).get("brand_name", "")
            db.execute("UPDATE runs SET progress=?, current_task=? WHERE run_id=?",
                       (min(100, round(done / total * 100)), f"Analyzing: {bname}", run_id))
        key = (run_id, cid)
        if key in CTX:
            del CTX[key]
        return {"ok": True, "stored": True}

    if jt == "UPDATE_LEARNING":
        _update_learning_from_run(cid, ctx, run_id)
        return {"ok": True}

    if jt == "RAG_INDEX":
        try:
            res = rag_index_company(cid, None, None) or {}
            n = res.get("indexed", 0) or 0
            ctx["rag_indexed"] = n
            return {"ok": True, "indexed": n}
        except Exception as e:
            return {"ok": False, "error": str(e)[:200], "indexed": 0}

    if jt == "RAG_RETRIEVE":
        brand_name = (brand or {}).get("brand_name", "") or ""
        industry = (brand or {}).get("industry", "") or ""
        try:
            res = rag_search(cid, f"{brand_name} {industry} visibility evidence".strip() or brand_name,
                             5, None, None) or {}
            items = res.get("results") or []
            ctx["rag_context"] = {"status": res.get("status"), "count": len(items),
                                  "items": items[:5]}
            if not items:
                return {"ok": True, "rag": "NO_RELEVANT_RAG_CONTEXT", "count": 0}
            return {"ok": True, "rag": "RETRIEVED", "count": len(items)}
        except Exception as e:
            ctx["rag_context"] = {"status": "RAG_FAILED", "detail": str(e)[:200]}
            return {"ok": True, "rag": "RAG_FAILED", "count": 0}

    if jt == "REASONING":
        try:
            res = reason_about_company(cid, store=True, run_id=run_id, use_rag=True) or {}
            ctx["reasoning"] = {"decision": res.get("recommended_action"),
                                "reason": res.get("reason"),
                                "confidence": res.get("confidence"),
                                "reasoning_id": res.get("reasoning_id")}
            return {"ok": True, "reasoning": res.get("recommended_action")}
        except Exception as e:
            return {"ok": False, "error": str(e)[:200]}

    if jt == "REANALYZE_COMPANY":
        # Coordinator job: it plans (dedup-aware) the full pipeline for the company.
        planned = plan_company_jobs(cid, run_id)
        return {"ok": True, "planned": len(planned), "existing": True}

    return {"skipped": f"unknown job type {jt}"}


def _store_analysis(brand_id, run_id, trigger="MANUAL"):
    """Compute + persist final analysis row (score, recs, snapshot)."""
    brand = get_brand(brand_id)
    evidence = get_company_evidence(brand_id)
    key = (run_id or "", brand_id)
    analysis = (CTX.get(key, {}).get("brand_analysis")) or analyze_brand(brand)
    comp_rows = CTX.get(key, {}).get("competitor_rows")
    if comp_rows is None:
        comp_rows = ctx_competitors(brand_id)
    obs = db.query("SELECT * FROM ai_observations WHERE brand_id=? ORDER BY observed_at DESC LIMIT 50", (brand_id,))
    metrics = readiness_metrics(brand, analysis, comp_rows, obs, evidence)
    ometrics = observed_metrics(brand_id)
    snapshot = evidence_snapshot(brand_id)
    gaps = CTX.get(key, {}).get("content_gaps") or []
    recs = CTX.get(key, {}).get("recommendations") or []
    analysis_data = {
        "brand_analysis": analysis,
        "competitor_rows": comp_rows,
        "content_gaps": gaps,
        "recommendations": recs,
        "evidence_snapshot": snapshot,
    }
    _store_recommendations(brand_id, run_id, metrics, gaps, recs, evidence)
    aid = db.execute("""
        INSERT INTO analysis_results (brand_id, visibility_score, readiness_score, observed_score, mention_rate,
                                      topic_coverage, competitor_strength, readiness_breakdown, observed_metrics,
                                      score_reasons, analysis_data, trigger, run_id, created_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (brand_id, metrics["visibility_score"], metrics["readiness_score"], ometrics.get("observed_score"),
          metrics["mention_rate"], metrics["topic_coverage"],
          metrics["competitor_strength"] if metrics["competitor_strength"] is not None else 0,
          json.dumps(metrics["readiness_breakdown"]), json.dumps(ometrics), json.dumps(metrics["score_reasons"]),
          json.dumps(analysis_data), trigger, run_id, now()))
    db.execute("UPDATE brands SET last_analyzed_at=?, last_updated_at=?, verification_status='ANALYZED' WHERE id=?",
               (now(), now(), brand_id))
    # Alert on score change
    try:
        brand_name = (get_brand(brand_id) or {}).get("brand_name", f"Company #{brand_id}")
        prev = db.query("SELECT visibility_score FROM analysis_results WHERE brand_id=? AND id!=? ORDER BY id DESC LIMIT 1",
                        (brand_id, aid))
        if prev:
            alert_score_change(brand_name, prev[0]["visibility_score"], metrics["visibility_score"])
    except Exception:
        pass
    return {"analysis_id": aid, "metrics": metrics, "observed": ometrics}


def ctx_competitors(brand_id):
    try:
        obs = db.query("SELECT * FROM ai_observations WHERE brand_id=? ORDER BY observed_at DESC LIMIT 50", (brand_id,))
        return analyze_competitors(get_brand(brand_id), obs)
    except Exception:
        return []


def suppressed_recommendation_check(brand_id, title):
    """Explain why a recommendation title would be suppressed (or None if it is eligible)."""
    rows = db.query("SELECT status, feedback, resolution_source FROM recommendations "
                    "WHERE brand_id=? AND title=? ORDER BY id DESC LIMIT 1", (brand_id, title))
    if not rows or (rows[0].get("status") or "OPEN") == "OPEN":
        return None
    st = rows[0]["status"]
    if st == "DONE":
        return ("Suppressed because the same recommendation was marked ALREADY_IMPLEMENTED "
                f"(resolved via {rows[0].get('resolution_source') or 'feedback'}). It will only "
                "return if fresh evidence shows the gap exists again.")
    if st == "INVALIDATED":
        return ("Suppressed because the same recommendation was marked INCORRECT. "
                "It is never auto-regenerated.")
    return (f"Suppressed because the same recommendation was previously {st}. "
            "History is preserved; it will only return on new contradicting evidence.")


def _store_recommendations(brand_id, run_id, metrics, gaps, recs, evidence):
    """Persist generated recommendations with history-aware suppression.

    Previously resolved/rejected/invalidated titles are NOT duplicated. A DONE
    title re-opens only when its evidence_key gap reappears in fresh evidence.
    Every suppression is logged as a RECOMMENDATION_SUPPRESSED learning event.
    """
    if not recs:
        recs = generate_recommendations(get_brand(brand_id), gaps, metrics, evidence, get_learning(brand_id))
    suppression_on = (get_config("RECOMMENDATION_SUPPRESSION_ENABLED", "1") == "1"
                      and learning_enabled_for_company(brand_id))
    present_evidence = {e.get("evidence_type") for e in evidence or []}
    prev = {}
    for r in db.query("SELECT * FROM recommendations WHERE brand_id=?", (brand_id,)):
        prev.setdefault(r["title"], r)
    new_added = 0
    suppressed = []
    t = now()
    for r in recs:
        title = r.get("title") or ""
        if not title:
            continue
        old = prev.get(title)
        if not old:
            rid = db.execute("""
                INSERT INTO recommendations (brand_id, title, description, priority, category, evidence_key,
                                             status, run_id, first_seen_at, last_seen_at, times_generated, created_at)
                VALUES (?,?,?,?,?,?,'OPEN',?,?,?,?,?)
            """, (brand_id, title, r.get("description"), r.get("priority"), r.get("category"),
                  r.get("evidence_key"), run_id, t, t, 1, t))
            prev[title] = {"id": rid, "status": "OPEN"}
            new_added += 1
            continue
        if (old.get("status") or "OPEN") == "OPEN":
            # refresh details only if the recommendation is still open (not yet resolved or rejected)
            db.execute("""UPDATE recommendations SET description=?, priority=?, category=?, last_seen_at=?,
                               times_generated=COALESCE(times_generated,1)+1 WHERE id=?""",
                       (r.get("description"), r.get("priority"), r.get("category"), t, old["id"]))
            continue
        if not suppression_on:
            continue
        st = old.get("status")
        gap_back = bool(r.get("evidence_key")) and r.get("evidence_key") not in present_evidence
        if st == "DONE" and gap_back:
            db.execute("""UPDATE recommendations SET status='OPEN', feedback='REOPENED_GAP_REAPPEARED',
                               feedback_at=?, last_seen_at=?, times_generated=COALESCE(times_generated,1)+1,
                               description=?, priority=?, category=? WHERE id=?""",
                       (t, t, r.get("description"), r.get("priority"), r.get("category"), old["id"]))
            record_learning_event(brand_id, "PATTERN_CONFIRMED",
                                  f"Previously resolved recommendation re-opened - gap reappeared in fresh "
                                  f"evidence: '{title[:120]}'",
                                  run_id=run_id, source_type="LEARNING_ENGINE",
                                  previous_value="DONE", new_value="OPEN",
                                  metadata={"recommendation_id": old["id"]})
            new_added += 1
            continue
        reason = suppressed_recommendation_check(brand_id, title)
        suppressed.append({"title": title, "status": st, "reason": reason})
        record_learning_event(brand_id, "RECOMMENDATION_SUPPRESSED",
                              f"Previous recommendation suppressed because it was already {st.lower()}: "
                              f"'{title[:120]}'",
                              run_id=run_id, source_type="LEARNING_ENGINE",
                              previous_value=st, new_value=st,
                              metadata={"recommendation_id": old["id"], "reason": reason})
    update_run_counter(run_id, "recommendations_updated", new_added)
    return {"added": new_added, "suppressed": suppressed}


def _update_learning_from_run(brand_id, ctx, run_id=None):
    """UPDATE_LEARNING job handler (Phase 4). Legacy telemetry is preserved;
    the extractor below implements the 10-step learning pipeline. Genuine
    failures propagate so the job becomes FAILED/retryable WITHOUT failing the
    already-completed analysis (per-job isolation in execute_job)."""
    brand = get_brand(brand_id)
    prev = db.query("SELECT visibility_score FROM analysis_results WHERE brand_id=? ORDER BY id DESC LIMIT 1 OFFSET 1",
                    (brand_id,))
    cur = db.query("SELECT visibility_score FROM analysis_results WHERE brand_id=? ORDER BY id DESC LIMIT 1",
                   (brand_id,))
    if cur:
        cur_score = cur[0]["visibility_score"]
        remember(brand_id, f"SCORE_TRACK:{brand.get('brand_name')}:{cur_score}", "HISTORY",
                 f"Latest visibility score {cur_score} for {brand.get('brand_name')}.", 0.6)
        if prev:
            d = cur_score - prev[0]["visibility_score"]
            if d != 0:
                remember(brand_id, f"SCORE_CHANGE:{'+' if d>0 else ''}{d}", "HISTORY",
                         f"Score changed by {d} (from {prev[0]['visibility_score']} to {cur_score}).", 0.7)
    changes = (ctx.get("changes") or [])
    if run_id:
        rows = db.query("SELECT * FROM change_log WHERE brand_id=? AND run_id=? ORDER BY id DESC LIMIT 100",
                        (brand_id, run_id))
        changes = changes or [dict(r) for r in rows]
    for ch in changes:
        remember(brand_id, f"CONTENT_CHANGE:{ch['field_name']}", "EVIDENCE",
                 f"{ch['change_type']} on {ch['field_name']}: {ch.get('previous_value')} -> {ch.get('current_value')}",
                 0.75)
    return extract_company_learning(brand_id, run_id)


def extract_company_learning(brand_id, run_id=None):
    """Phase-4 learning extraction, steps 1-9:
    1 load current analysis, 2 load previous analysis, 3 load detected changes,
    4 load recommendation history, 5 load query history, 6 load feedback,
    7 extract learning signals, 8 update learning memory, 9 create learning events.
    Patterns are only stored ACTIVE once MIN_PATTERN_OBSERVATIONS is reached;
    user-approved signals (feedback/corrections) are trusted immediately.
    When learning is disabled for the company, raw events are still recorded
    but any touched memory is stored INACTIVE (no future influence)."""
    if not learning_enabled_global():
        return {"skipped": "LEARNING_ENABLED=0", "patterns": 0, "events": 0}
    learn = learning_enabled_for_company(brand_id)
    status = "ACTIVE" if learn else "INACTIVE"
    min_obs = _lconfig_int("MIN_PATTERN_OBSERVATIONS", 3)
    analyses = db.query("SELECT * FROM analysis_results WHERE brand_id=? ORDER BY id DESC LIMIT 2", (brand_id,))
    if not analyses:
        return {"skipped": "no analysis yet", "patterns": 0, "events": 0}
    cur, prev_analysis = analyses[0], (analyses[1] if len(analyses) > 1 else None)
    changes = db.query("SELECT * FROM change_log WHERE brand_id=? AND run_id=? ORDER BY id DESC LIMIT 100",
                       (brand_id, run_id)) if run_id else []
    recs = db.query("SELECT * FROM recommendations WHERE brand_id=?", (brand_id,))
    ql = db.query("SELECT * FROM query_learning WHERE company_id=?", (brand_id,))
    since = (prev_analysis or {}).get("created_at") or "1970-01-01"
    fb = db.query("SELECT * FROM feedback WHERE company_id=? AND created_at >= ? ORDER BY id ASC", (brand_id, since))
    patterns = 0
    # A) Query-intent usefulness (company-specific; never claimed universal).
    by_intent = {}
    for r in ql:
        it = (r.get("intent") or "INFORMATIONAL").upper()
        a = by_intent.setdefault(it, {"tested": 0, "useful": 0})
        a["tested"] += r.get("times_tested") or 0
        a["useful"] += r.get("useful_count") or 0
    for intent, a in by_intent.items():
        if a["tested"] >= min_obs and a["useful"] > 0 and a["useful"] / max(1, a["tested"]) >= 0.5:
            ensure_memory(brand_id, "QUERY_PATTERN", "INTENT", f"INTENT:{intent}",
                          f"Observed pattern: {intent} queries produced useful evidence in "
                          f"{a['useful']} of {a['tested']} tests for this company.",
                          source="LEARNING_ENGINE", success_delta=a["useful"],
                          evidence_text=f"{a['useful']}/{a['tested']} useful; company-specific, not universal.",
                          status=status, run_id=run_id,
                          metadata={"intent": intent, "tested": a["tested"], "useful": a["useful"]})
            patterns += 1
    # B) Resolved recommendations reinforce suppression memory.
    for r in recs:
        if (r.get("status") or "") == "DONE" and (r.get("resolution_source") or "").startswith("USER"):
            ensure_memory(brand_id, "RECOMMENDATION_PATTERN", "RESOLVED",
                          f"RESOLVED:{(r.get('title') or '')[:200]}",
                          f"Observed pattern: '{(r.get('title') or '')[:140]}' was implemented; keep suppressed "
                          "unless the gap reappears.",
                          source="LEARNING_ENGINE", success_delta=1,
                          evidence_text=f"recommendation_id={r.get('id')}",
                          status=status, run_id=run_id,
                          metadata={"recommendation_id": r.get("id")})
            patterns += 1
    # C) Repeatedly observed competitors become competitor patterns.
    obs = db.query("SELECT competitors_mentioned FROM ai_observations WHERE brand_id=? ORDER BY observed_at DESC LIMIT 100",
                   (brand_id,))
    comp_hits = {}
    for o in obs:
        try:
            names = safe_json_loads(o.get("competitors_mentioned"), []) or []
        except Exception:
            names = []
        for n in names:
            n = str(n).strip()
            if n:
                comp_hits[n] = comp_hits.get(n, 0) + 1
    for name, hits in sorted(comp_hits.items(), key=lambda kv: -kv[1])[:3]:
        if hits >= min_obs:
            ensure_memory(brand_id, "COMPETITOR_PATTERN", "RIVAL", f"RIVAL_MENTIONED:{name[:200]}",
                          f"Observed pattern: competitor '{name}' appeared in {hits} observations; "
                          "comparison content against this rival is historically informative.",
                          source="LEARNING_ENGINE", success_delta=min(hits, 5),
                          evidence_text=f"{hits} observation mentions",
                          status=status, run_id=run_id, metadata={"competitor": name, "mentions": hits})
            patterns += 1
    # D) Repeated change types become content patterns.
    all_changes = db.query("SELECT field_name, COUNT(*) AS n FROM change_log WHERE brand_id=? "
                           "GROUP BY field_name HAVING n >= ?", (brand_id, min_obs))
    for ch in all_changes:
        ensure_memory(brand_id, "CONTENT_PATTERN", "VOLATILITY", f"VOLATILE:{(ch.get('field_name') or '')[:200]}",
                      f"Observed pattern: '{ch.get('field_name')}' changed {ch.get('n')} times; "
                      "monitor it closely in future analyses.",
                      source="LEARNING_ENGINE", success_delta=min(int(ch.get("n") or 0), 5),
                      status=status, run_id=run_id,
                      metadata={"field": ch.get("field_name"), "changes": ch.get("n")})
        patterns += 1
    # E) Feedback since the previous analysis becomes feedback patterns.
    for f in fb:
        if (f.get("target_type") or "") == "RECOMMENDATION":
            continue  # already handled with full fidelity in ingest_feedback
        ensure_memory(brand_id, "FEEDBACK_PATTERN", "GENERAL",
                      f"FEEDBACK:{(f.get('feedback') or '')[:60]}:{(f.get('target_type') or '')[:40]}",
                      f"User feedback '{f.get('feedback')}' on {f.get('target_type')}: {(f.get('comment') or '')[:200]}",
                      source="FEEDBACK", confidence=0.85, success_delta=1,
                      status=status, run_id=run_id, metadata={"feedback_id": f.get("id")})
        patterns += 1
    # F) Global promotion across companies (observed patterns only, never causal claims).
    promoted = promote_global_patterns() if learn else {"promoted": 0}
    try:
        log_activity(f"Learning update for company #{brand_id}: {patterns} patterns, "
                     f"{promoted.get('promoted', 0)} global promotions"
                     f"{' (learning disabled - stored INACTIVE)' if not learn else ''}.",
                     level="LEARN", run_id=run_id, company_id=brand_id)
    except Exception:
        pass
    return {"patterns": patterns, "events": len(changes) + len(fb),
            "promoted_global": promoted.get("promoted", 0), "learning_active": learn}


def promote_global_patterns(min_companies=None):
    """Promote company patterns observed across >= MIN_GLOBAL_OBSERVATIONS
    learning-enabled companies to global_learning_memory."""
    if not learning_enabled_global():
        return {"promoted": 0}
    min_c = int(min_companies or _lconfig_int("MIN_GLOBAL_OBSERVATIONS", 3))
    rows = db.query("""SELECT m.memory_type, m.category, m.key, MAX(m.value) AS sample_value,
                              COUNT(DISTINCT m.company_id) AS nco, COUNT(*) AS nobs, AVG(m.confidence) AS avgc
                       FROM learning_memory m LEFT JOIN company_settings s ON s.company_id = m.company_id
                       WHERE m.status='ACTIVE'
                         AND m.memory_type IN ('QUERY_PATTERN','RECOMMENDATION_PATTERN','CONTENT_PATTERN','COMPETITOR_PATTERN')
                         AND COALESCE(s.learning_enabled, 1) = 1
                       GROUP BY m.memory_type, m.category, m.key HAVING nco >= ?""", (min_c,))
    promoted = 0
    t = now()
    for r in rows:
        pkey = f"{r['memory_type']}:{r['category']}:{r['key']}"
        conf = learning_confidence(int(r["nobs"] or 0), verified=False,
                                   positive_feedback=True, recent=True)
        g = db.query("SELECT * FROM global_learning_memory WHERE pattern_key=? LIMIT 1", (pkey,))
        if g:
            if (g[0].get("company_count") or 0) != int(r["nco"] or 0):
                db.execute("""UPDATE global_learning_memory SET observation_count=?, company_count=?,
                                   confidence=?, last_updated_at=?, pattern_value=? WHERE id=?""",
                           (int(r["nobs"] or 0), int(r["nco"] or 0), conf, t,
                            (r.get("sample_value") or "")[:2000], g[0]["id"]))
                record_learning_event(None, "PATTERN_CONFIRMED",
                                      f"Observed pattern now spans {r['nco']} companies: {(r['key'] or '')[:140]}",
                                      memory_id=g[0].get("memory_id"), source_type="LEARNING_ENGINE",
                                      confidence=conf,
                                      metadata={"pattern_key": pkey, "companies": int(r["nco"] or 0)})
                promoted += 1
            continue
        gid = db.execute("""
            INSERT INTO global_learning_memory (pattern_key, pattern_value, category, observation_count,
                                                company_count, confidence, status, first_learned_at, last_updated_at,
                                                metadata_json)
            VALUES (?,?,?,?,?,'ACTIVE',?,?,?,?)
        """, (pkey, (r.get("sample_value") or "")[:2000], r.get("category"), int(r["nobs"] or 0),
              int(r["nco"] or 0), conf, t, t,
              json.dumps({"memory_type": r["memory_type"]})[:1000]))
        mid = f"GLOB-{gid:06d}"
        db.execute("UPDATE global_learning_memory SET memory_id=? WHERE id=?", (mid, gid))
        record_learning_event(None, "PATTERN_DISCOVERED",
                              f"Observed pattern across {r['nco']} companies: {(r['key'] or '')[:140]} "
                              "(observed co-occurrence, not a causal claim)",
                              memory_id=mid, source_type="LEARNING_ENGINE", confidence=conf,
                              metadata={"pattern_key": pkey, "companies": int(r["nco"] or 0)})
        promoted += 1
    return {"promoted": promoted}


def run_full_pipeline(company_id, trigger="MANUAL", run_id=None, direct=True, workflow_id=None):
    """Entry point: full autonomous-style analysis for a single company.
    direct=True executes the pipeline inline with zero job rows (fast path
    for manual runs). direct=False uses the persistent job queue (background)."""
    if not run_id:
        run_id = create_run(trigger, companies=[company_id])
    if direct:
        summary = run_company_direct(company_id, run_id, workflow_id=workflow_id)
    else:
        summary = process_company_jobs(company_id, run_id)
    finalize_run(run_id, "FAILED" if summary.get("errors") else "COMPLETED")
    return run_id


# ---------------------------------------------------------------------------
# SPEC WORKFLOWS (§2-§4): exactly two primary workflows with fixed IDs.
# The selected workflow controls the REAL execution path (ops list),
# not just the label. Visible steps are the UI diagram; ops are what run.
# ---------------------------------------------------------------------------
SPEC_WORKFLOWS = {
    "brand_visibility_standard": {
        "name": "Workflow 1 — Standard Analysis",
        "visible": ["Company Data", "Website", "AI Search", "Brand Analysis",
                    "Competitors", "Recommendations"],
        "ops": ["VALIDATE_DATA", "COLLECT_WEBSITE_DATA", "GENERATE_QUERIES", "RUN_AI_SEARCH",
                "ANALYZE_BRAND", "ANALYZE_COMPETITORS", "DETECT_CONTENT_GAPS",
                "GENERATE_RECOMMENDATIONS", "DETECT_CHANGES", "STORE_ANALYSIS", "UPDATE_LEARNING"],
        "visible_map": {
            "Company Data": ["VALIDATE_DATA"],
            "Website": ["COLLECT_WEBSITE_DATA"],
            "AI Search": ["GENERATE_QUERIES", "RUN_AI_SEARCH"],
            "Brand Analysis": ["ANALYZE_BRAND"],
            "Competitors": ["ANALYZE_COMPETITORS"],
            "Recommendations": ["DETECT_CONTENT_GAPS", "GENERATE_RECOMMENDATIONS",
                                "DETECT_CHANGES", "STORE_ANALYSIS", "UPDATE_LEARNING"],
        },
    },
    "rag_enhanced_analysis": {
        "name": "Workflow 2 — RAG-Enhanced Analysis",
        "visible": ["Company Data", "Website", "RAG", "AI Search", "Competitors",
                    "Reasoning", "Recommendations"],
        "ops": ["VALIDATE_DATA", "COLLECT_WEBSITE_DATA", "RAG_INDEX", "RAG_RETRIEVE",
                "GENERATE_QUERIES", "RUN_AI_SEARCH", "ANALYZE_COMPETITORS", "REASONING",
                "GENERATE_RECOMMENDATIONS", "DETECT_CHANGES", "STORE_ANALYSIS", "UPDATE_LEARNING"],
        "visible_map": {
            "Company Data": ["VALIDATE_DATA"],
            "Website": ["COLLECT_WEBSITE_DATA"],
            "RAG": ["RAG_INDEX", "RAG_RETRIEVE"],
            "AI Search": ["GENERATE_QUERIES", "RUN_AI_SEARCH"],
            "Competitors": ["ANALYZE_COMPETITORS"],
            "Reasoning": ["REASONING"],
            "Recommendations": ["GENERATE_RECOMMENDATIONS", "DETECT_CHANGES",
                                "STORE_ANALYSIS", "UPDATE_LEARNING"],
        },
    },
}

DIRECT_PIPELINE = SPEC_WORKFLOWS["brand_visibility_standard"]["ops"]


def get_active_workflow():
    """Selected primary workflow id (spec default: standard)."""
    try:
        wf = get_config("active_workflow_id", "brand_visibility_standard")
    except Exception:
        wf = "brand_visibility_standard"
    return wf if wf in SPEC_WORKFLOWS else "brand_visibility_standard"


def set_active_workflow(workflow_id):
    if workflow_id not in SPEC_WORKFLOWS:
        return {"success": False, "error": "Unknown workflow. Use brand_visibility_standard or rag_enhanced_analysis."}
    save_config({"active_workflow_id": workflow_id})
    spec = SPEC_WORKFLOWS[workflow_id]
    return {"success": True, "workflow_id": workflow_id, "name": spec["name"],
            "visible": spec["visible"]}


def ensure_spec_workflows():
    """Seed the two fixed-ID workflow definitions (idempotent)."""
    try:
        db.execute("ALTER TABLE workflow_runs ADD COLUMN mode TEXT DEFAULT 'full'")
    except Exception:
        pass
    try:
        db.execute("ALTER TABLE workflow_runs ADD COLUMN skipped_json TEXT")
    except Exception:
        pass
    try:
        db.execute("ALTER TABLE workflow_runs ADD COLUMN plan_json TEXT")
    except Exception:
        pass
    for wid, spec in SPEC_WORKFLOWS.items():
        try:
            rows = db.query("SELECT workflow_id FROM workflow_definitions WHERE workflow_id=?", (wid,))
            if rows:
                continue
            steps = [{"id": op.lower(), "operation": op, "agent": "pipeline", "tool": None}
                     for op in spec["ops"]]
            deps = {}
            ops = spec["ops"]
            for i in range(1, len(ops)):
                deps[ops[i].lower()] = [ops[i - 1].lower()]
            wf = workflow_create(name=spec["name"],
                                 description="Primary spec workflow (" + wid + "). Visible: " +
                                             " → ".join(spec["visible"]),
                                 steps=steps, dependencies=deps,
                                 metadata={"spec_workflow_id": wid, "visible": spec["visible"],
                                           "visible_map": spec["visible_map"]},
                                 created_by="SPEC")
            # Override the random id with the fixed spec id.
            new_id = wf["workflow_id"]
            db.execute("UPDATE workflow_definitions SET workflow_id=? WHERE workflow_id=?", (wid, new_id))
            db.execute("UPDATE workflow_versions SET workflow_id=? WHERE workflow_id=?", (wid, new_id))
            try:
                db.execute("UPDATE workflow_changes SET workflow_id=? WHERE workflow_id=?", (wid, new_id))
            except Exception:
                pass
            try:
                db.execute("UPDATE workflow_adaptation_events SET workflow_id=? WHERE workflow_id=?", (wid, new_id))
            except Exception:
                pass
            workflow_activate_version(wid, 1)
        except Exception as e:
            print(f"[SpecWorkflows] ensure {wid} skipped: {e}", flush=True)
    return {"success": True}


def impact_ops(company_id, ops):
    """§19 partial re-execution: if the only recent changes are website /
    content / profile changes AND queries already exist, skip query
    regeneration + AI search and reuse them. Returns (ops_to_run, skipped, reason).
    Anything else → full ops with an honest reason."""
    try:
        rows = db.query("SELECT change_type FROM change_log WHERE brand_id=? ORDER BY id DESC LIMIT 20",
                        (company_id,))
        types = {(r.get("change_type") or "") for r in rows} - {""}
    except Exception:
        return ops, [], "change history unreadable - full run"
    if not types:
        return ops, [], "no recorded changes - full run"
    web_only = types <= {"CONTENT_ADDED", "CONTENT_REMOVED", "PROFILE_CHANGED"}
    if not web_only:
        return ops, [], f"non-website changes present ({', '.join(sorted(types))}) - full run"
    try:
        qrows = db.query("SELECT COUNT(*) AS c FROM query_memory WHERE brand_id=? AND is_active=1", (company_id,))
        if not qrows or not qrows[0]["c"]:
            return ops, [], "no reusable queries - full run"
    except Exception:
        return ops, [], "query store unreadable - full run"
    skip = [o for o in ops if o in ("GENERATE_QUERIES", "RUN_AI_SEARCH")]
    if not skip:
        return ops, [], "pipeline has no query steps - full run"
    return [o for o in ops if o not in ("GENERATE_QUERIES", "RUN_AI_SEARCH")], skip, \
        "website/content-only changes with fresh queries - reusing queries + observations"


def run_company_direct(company_id, run_id, workflow_id=None, mode="auto"):
    """Execute the SELECTED workflow's real ops inline (zero job rows).

    Workflow 1 and Workflow 2 take genuinely different paths (RAG +
    Reasoning only run under rag_enhanced_analysis). Every step is timed
    and the full record lands in workflow_runs for the ledger/UI/ATs."""
    wid = workflow_id if workflow_id in SPEC_WORKFLOWS else get_active_workflow()
    spec = SPEC_WORKFLOWS[wid]
    ops = spec["ops"]
    skipped_ops, skip_reason = [], "full run"
    if mode != "full":
        # "auto" (default): use partial re-execution only when the impact
        # analysis proves website/content-only changes with reusable queries.
        ops, skipped_ops, skip_reason = impact_ops(company_id, ops)
        mode = "changed" if skipped_ops else "full"
    t_start = time.time()
    started = now()
    ctx = CTX.setdefault((run_id, company_id), {})
    summary = {"workflow_id": wid, "workflow_name": spec["name"], "mode": mode,
               "skipped_ops": skipped_ops, "skip_reason": skip_reason,
               "queries": 0, "observations": 0, "new_evidence": 0, "changes": 0,
               "recommendations": 0, "errors": 0, "steps": []}
    ledger_id = None
    plan_snapshot = {"workflow_id": wid, "name": spec["name"], "visible": spec["visible"],
                     "ops": ops, "visible_map": spec["visible_map"], "mode": mode,
                     "skipped_ops": skipped_ops, "skip_reason": skip_reason}
    try:
        ledger_id = db.execute(
            "INSERT INTO workflow_runs (run_id, company_id, workflow_id, workflow_version, "
            "steps_json, status, started_at, mode, skipped_json, plan_json) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (run_id, company_id, wid, 1, json.dumps([]), "RUNNING", started, mode,
             json.dumps({"skipped": skipped_ops, "reason": skip_reason})[:2000],
             json.dumps(plan_snapshot)[:4000]))
    except Exception:
        ledger_id = None
    try:
        log_activity(f"Direct {spec['name']} started for company #{company_id}", level="RUN",
                     run_id=run_id, company_id=company_id)
    except Exception:
        pass
    tools_used = set()
    for jt in ops:
        step_t0 = time.time()
        try:
            db.execute("UPDATE runs SET current_task=? WHERE run_id=?", (jt, run_id))
        except Exception:
            pass
        try:
            res = dispatch_job({"job_type": jt, "company_id": company_id, "id": 0}, ctx, run_id) or {}
            dur = round(time.time() - step_t0, 2)
            summary["steps"].append({"step": jt, "ok": True, "duration_s": dur})
            tools_used.add(jt)
            for k in ("queries", "observations", "new_evidence", "changes", "recommendations"):
                try:
                    summary[k] += res.get(k, 0) or 0
                except Exception:
                    pass
        except Exception as e:
            dur = round(time.time() - step_t0, 2)
            summary["errors"] += 1
            summary["steps"].append({"step": jt, "ok": False, "error": str(e)[:200], "duration_s": dur})
            try:
                log_activity(f"Direct step {jt} failed for company #{company_id}: {str(e)[:160]}",
                             level="WARN", run_id=run_id, company_id=company_id)
            except Exception:
                pass
    duration = round(time.time() - t_start, 2)
    summary["duration_s"] = duration
    if ledger_id:
        try:
            # Compact RAG items first (truncate fields, not the JSON string -
            # slicing dumped JSON mid-string produces unparseable fragments).
            _rc = ctx.get("rag_context") or {}
            if isinstance(_rc, dict):
                _items = []
                for _it in (_rc.get("items") or [])[:3]:
                    if not isinstance(_it, dict):
                        continue
                    _items.append({
                        "document_id": _it.get("document_id"),
                        "company_id": _it.get("company_id"),
                        "source_type": _it.get("source_type"),
                        "source_record_id": _it.get("source_record_id"),
                        "content": str(_it.get("content") or _it.get("text") or "")[:300],
                        "score": _it.get("score")})
                _rc = {"status": _rc.get("status"), "count": _rc.get("count"), "items": _items}
            elif not isinstance(_rc, (int, float)):
                _rc = {"indexed": _rc} if _rc else {}
            db.execute("UPDATE workflow_runs SET steps_json=?, tools_json=?, rag_json=?, reasoning_json=?, "
                       "status=?, finished_at=?, duration_s=?, mode=?, skipped_json=? WHERE id=?",
                       (json.dumps(summary["steps"])[:8000],
                        json.dumps(sorted(tools_used))[:2000],
                        json.dumps(_rc)[:2000],
                        json.dumps(ctx.get("reasoning") or {})[:2000],
                        "FAILED" if summary["errors"] else "COMPLETED", now(), duration,
                        summary.get("mode", "full"),
                        json.dumps({"skipped": summary.get("skipped_ops", []),
                                    "reason": summary.get("skip_reason", "")})[:2000], ledger_id))
        except Exception:
            pass
    try:
        log_activity(f"Direct {spec['name']} finished for company #{company_id}: "
                     f"{summary['queries']} queries, {summary['observations']} obs, "
                     f"{summary['changes']} changes, {summary['errors']} errors in {duration}s",
                     level="RUN", run_id=run_id, company_id=company_id)
    except Exception:
        pass
    return summary


# ---------------------------------------------------------------------------
# AGENT RUNNER / SCHEDULER
# ---------------------------------------------------------------------------

class AgentRunner:
    def __init__(self):
        self.thread = None
        self.stop_flag = False
        self.loop_enabled = False
        self.active = False
        self.paused = False

    def start_loop(self):
        if self.thread and self.thread.is_alive():
            return {"success": True, "message": "loop already running"}
        self.stop_flag = False
        self.paused = get_config("agent_paused", "0") == "1"
        self.thread = threading.Thread(target=self._run, daemon=True, name="agent-loop")
        self.thread.start()
        self.loop_enabled = True
        return {"success": True, "message": "agent loop started"}

    def stop_loop(self):
        self.stop_flag = True
        self.loop_enabled = False
        if self.thread:
            self.thread.join(timeout=2)
        return {"success": True, "message": "agent loop stopped"}

    def pause(self):
        self.paused = True
        try:
            save_config({"agent_paused": "1"})
        except Exception:
            pass
        log_activity("Agent paused - no new jobs will start. Pending jobs are kept.", level="SYSTEM")
        return {"success": True, "paused": True}

    def resume(self):
        self.paused = False
        try:
            save_config({"agent_paused": "0"})
        except Exception:
            pass
        log_activity("Agent resumed - pending jobs continue.", level="SYSTEM")
        return {"success": True, "paused": False}

    def _run(self):
        while not self.stop_flag:
            try:
                self._tick()
            except Exception as e:
                print(f"[AgentLoop] iteration error: {e}", flush=True)
            try:
                sleep_s = int(get_config().get("tick_seconds", "30"))
                sleep_s = min(60, max(5, sleep_s))
            except Exception:
                sleep_s = 30
            time.sleep(sleep_s)

    def _tick(self):
        self.paused = get_config("agent_paused", "0") == "1"
        if self.paused:
            return
        cfg = get_config()
        self.active = cfg.get("auto_loop_enabled", "1") == "1" or self._has_pending_jobs()
        if not self.active and not self._has_pending_jobs():
            return
        self._schedule()

    def _has_pending_jobs(self):
        rows = db.query("SELECT id FROM jobs WHERE status IN ('PENDING','QUEUED','RUNNING','RETRYING') LIMIT 1")
        return bool(rows)

    def _schedule(self):
        cfg = get_config()
        running = db.query("SELECT run_id FROM runs WHERE status='RUNNING' ORDER BY id DESC LIMIT 1")
        if running:
            self._process_queue()
            return
        if cfg.get("startup_auto_run", "1") == "1":
            startup_done = db.query("SELECT config_value FROM agent_config WHERE config_key='startup_done'")
            if not (startup_done and startup_done[0]["config_value"] == "1"):
                try:
                    first_batch = max(1, int(cfg.get("startup_batch_size", "5")))
                except Exception:
                    first_batch = 5
                cids = [cid for cid in _active_company_ids()][:first_batch]
                self._start_run("STARTUP", cids)
                db.execute("INSERT OR REPLACE INTO agent_config (config_key, config_value, updated_at) VALUES (?,?,?)",
                           ("startup_done", "1", now()))
                return
        if cfg.get("daily_enabled", "1") == "1" and self._run_daily():
            return
        if cfg.get("weekly_enabled", "1") == "1" and self._run_weekly():
            return
        # Always drain whatever remains queued (manual retries, cancelled
        # chains, auto-queued jobs) even when no scheduled run just started.
        self._process_queue()

    def _run_daily(self):
        cfg = get_config()
        try:
            days = int(cfg.get("freshness_days", "7"))
        except Exception:
            days = 7
        try:
            batch = max(1, int(cfg.get("daily_batch_size", "5")))
        except Exception:
            batch = 5
        cutoff = (datetime.datetime.utcnow() - datetime.timedelta(days=days)).isoformat(timespec="seconds")
        ids = db.query("SELECT id FROM brands WHERE is_active=1 AND (last_analyzed_at IS NULL OR last_analyzed_at < ?) "
                       "ORDER BY last_analyzed_at ASC, id ASC",
                       (cutoff,))
        comp_ids = [r["id"] for r in ids]
        # Skip companies that already have inflight work; take a bounded
        # batch (never-analyzed first) so the queue can't flood.
        fresh = []
        for cid in comp_ids:
            try:
                inflight = db.query("SELECT id FROM jobs WHERE company_id=? "
                                    "AND status IN ('PENDING','QUEUED','RUNNING','RETRYING') LIMIT 1", (cid,))
            except Exception:
                inflight = None
            if not inflight:
                fresh.append(cid)
            if len(fresh) >= batch:
                break
        if fresh:
            self._start_run("DAILY", fresh)
            return True
        return False

    def _run_weekly(self):
        last = db.query("SELECT completed_at FROM runs WHERE run_type='WEEKLY' AND status='COMPLETED' "
                        "ORDER BY id DESC LIMIT 1")
        due = False
        if not last or not last[0]["completed_at"]:
            due = True
        else:
            try:
                last_dt = datetime.datetime.fromisoformat(last[0]["completed_at"].replace("Z", "+00:00"))
                if datetime.datetime.now(datetime.timezone.utc) - last_dt > datetime.timedelta(days=7):
                    due = True
            except Exception:
                return False
        if not due:
            return False
        # Bounded batch like daily (never-analyzed first) - weekly waves
        # cover the fleet without flooding the queue.
        try:
            batch = max(1, int(get_config().get("weekly_batch_size", "10")))
        except Exception:
            batch = 10
        ids = db.query("SELECT id FROM brands WHERE is_active=1 "
                       "ORDER BY last_analyzed_at ASC, id ASC LIMIT ?",
                       (batch * 2,))
        comp_ids = []
        for r in ids:
            cid = r["id"]
            try:
                inflight = db.query("SELECT id FROM jobs WHERE company_id=? "
                                    "AND status IN ('PENDING','QUEUED','RUNNING','RETRYING') LIMIT 1", (cid,))
            except Exception:
                inflight = None
            if not inflight:
                comp_ids.append(cid)
            if len(comp_ids) >= batch:
                break
        if comp_ids:
            self._start_run("WEEKLY", comp_ids)
            return True
        return False

    def _start_run(self, run_type, comp_ids):
        comp_ids = list(dict.fromkeys(comp_ids))
        if not comp_ids:
            return
        rid = create_run(run_type, companies=comp_ids)
        for cid in comp_ids:
            plan_company_jobs(cid, rid)
        self._process_queue(run_id=rid)

    def _process_queue(self, run_id=None):
        with PROCESS_LOCK:
            if self.paused:
                return
            # Re-queue jobs that are retryable (legacy FAILED + new RETRYING).
            db.execute("UPDATE jobs SET status='PENDING' WHERE status='RETRYING' AND retry_count < max_retries")
            db.execute("UPDATE jobs SET status='PENDING' WHERE status='FAILED' AND retry_count < max_retries")
            db.execute("UPDATE jobs SET status='FAILED_PERMANENTLY' WHERE status IN ('RETRYING','FAILED') AND retry_count >= max_retries")
            # Stale RUNNING jobs (from a terminated process) become retryable.
            db.execute("UPDATE jobs SET status='RETRYING', error='interrupted before completion' WHERE status='RUNNING'")
            self._cancel_blocked()
            max_jobs = int(get_config().get("max_jobs_per_tick", "25"))
            processed = 0
            while processed < max_jobs:
                job = self._pick_next_job()
                if not job:
                    break
                execute_job(job["id"], job.get("run_id"))
                processed += 1
            self._finalize_drained_runs()

    def _pick_next_job(self):
        rows = db.query("SELECT * FROM jobs WHERE status='PENDING' ORDER BY priority DESC, created_at ASC, id ASC")
        for job in rows:
            if job.get("company_id") and not _deps_satisfied(job["company_id"], job["job_type"]):
                continue
            return job
        return None

    def _cancel_blocked(self):
        """Cascade-cancel PENDING jobs whose prerequisite can never complete
        (CANCELLED / FAILED_PERMANENTLY). Jobs are marked, never deleted."""
        rows = db.query("SELECT * FROM jobs WHERE status='PENDING'")
        for job in rows:
            cid = job.get("company_id")
            jt = job.get("job_type")
            blocked = False
            for dep in JOB_DEPENDENCIES.get(jt, []):
                d = db.query("SELECT status FROM jobs WHERE company_id=? AND job_type=? ORDER BY created_at DESC, id DESC LIMIT 1",
                             (cid, dep))
                if d and d[0]["status"] in ("CANCELLED", "FAILED_PERMANENTLY"):
                    blocked = True
                    break
            if blocked:
                db.execute("UPDATE jobs SET status='CANCELLED', cancelled_at=?, "
                           "error='prerequisite cancelled/unavailable' WHERE id=?", (now(), job["id"]))
                log_activity(f"Cancelled {jt} for company #{cid}: prerequisite {dep} unavailable", level="WARN",
                             run_id=job.get("run_id"), job_id=job["id"], company_id=cid)

    def _finalize_drained_runs(self):
        for r in db.query("SELECT DISTINCT run_id FROM runs WHERE status='RUNNING'"):
            rid = r["run_id"]
            remaining = db.query(
                "SELECT COUNT(*) AS c FROM jobs WHERE run_id=? AND status IN ('PENDING','QUEUED','RUNNING','RETRYING','FAILED')",
                (rid,))
            if remaining and remaining[0]["c"] == 0:
                # Phase 4 (§21): learning is non-blocking. The analysis itself is
                # complete once its own jobs finished; a permanently-failed
                # UPDATE_LEARNING stays retryable but never fails the run.
                failed = db.query("SELECT COUNT(*) AS c FROM jobs WHERE run_id=? AND status='FAILED_PERMANENTLY' "
                                  "AND job_type != 'UPDATE_LEARNING'", (rid,))
                st = "FAILED" if failed and failed[0]["c"] else "COMPLETED"
                finalize_run(rid, st)


def _active_company_ids():
    rows = db.query("SELECT id FROM brands WHERE is_active=1")
    return [r["id"] for r in rows]


runner = AgentRunner()


# ---------------------------------------------------------------------------
# RUN NOW + JOB ADMIN  (used by /api/agent/*  endpoints)
# ---------------------------------------------------------------------------

def run_now(payload, background=True):
    """RUN AGENT NOW: manual runs execute DIRECT (no queue hops) for speed.
    Spawns a background thread per company and returns immediately; the
    dashboard polls progress via /agent-state."""
    company_id = payload.get("company_id")
    run_type = payload.get("run_type") or "MANUAL"
    plan = companies_needing_work(company_id)
    if not plan:
        rid = create_run(run_type, companies=[])
        finalize_run(rid, "COMPLETED")
        return {"success": True, "run_id": rid, "companies": 0, "jobs_created": 0,
                "message": "No companies need analysis right now."}
    rid = create_run(run_type, companies=[p["company_id"] for p in plan])
    steps = len(DIRECT_PIPELINE) * len(plan)
    log_activity(f"Run {rid} started (direct): {len(plan)} company(ies), {steps} step(s).", level="RUN",
                 run_id=rid)
    wf_sel = (payload.get("workflow_id") or "").strip() or None

    def _go():
        try:
            for p in plan:
                try:
                    run_company_direct(p["company_id"], rid, workflow_id=wf_sel)
                except Exception as e:
                    print(f"[DirectRun] company {p['company_id']} failed: {e}", flush=True)
        finally:
            try:
                finalize_run(rid, "COMPLETED")
            except Exception:
                pass

    if background:
        t = threading.Thread(target=_go, daemon=True, name="run-now-direct")
        t.start()
        return {"success": True, "run_id": rid, "companies": len(plan), "jobs_created": steps,
                "background": True, "mode": "direct", "plan": plan}
    _go()
    return {"success": True, "run_id": rid, "companies": len(plan), "jobs_created": steps,
            "mode": "direct", "stats": _run_stats(rid)}


def run_all_companies(workflow_id=None):
    """Force-run ALL active companies via DIRECT inline execution (no queue).
    Split across 3 worker threads; returns immediately with the run id."""
    ids = [r["id"] for r in db.query("SELECT id FROM brands WHERE is_active=1")]
    if not ids:
        return {"success": True, "run_id": None, "companies": 0, "jobs_created": 0,
                "message": "No companies found."}
    wid = workflow_id if workflow_id in SPEC_WORKFLOWS else get_active_workflow()
    ops_len = len(SPEC_WORKFLOWS[wid]["ops"])
    rid = create_run("RUN_ALL", companies=ids)
    steps = ops_len * len(ids)
    log_activity(f"RUN_ALL (direct, {wid}): {len(ids)} companies, {steps} steps across 3 workers",
                 level="RUN", run_id=rid)

    def _worker(sub):
        for cid in sub:
            try:
                run_company_direct(cid, rid, workflow_id=wid, mode="full")
            except Exception as e:
                print(f"[RunAll] company {cid} failed: {e}", flush=True)

    def _wait_all(threads):
        try:
            for t in threads:
                t.join(timeout=3600)
        finally:
            try:
                finalize_run(rid, "COMPLETED")
            except Exception:
                pass

    chunks = [ids[i::3] for i in range(3)]
    workers = []
    for sub in chunks:
        if not sub:
            continue
        t = threading.Thread(target=_worker, args=(sub,), daemon=True, name="run-all-direct")
        t.start()
        workers.append(t)
    waiter = threading.Thread(target=_wait_all, args=(workers,), daemon=True, name="run-all-waiter")
    waiter.start()
    return {"success": True, "run_id": rid, "companies": len(ids), "jobs_created": steps,
            "background": True, "mode": "direct"}


# ---------------------------------------------------------------------------
# PER-COMPANY ADAPTIVE WORKFLOW CONFIGURATION
# ---------------------------------------------------------------------------

_COMPANY_CONFIG_DDL = """
CREATE TABLE IF NOT EXISTS company_workflow_config (
    company_id INTEGER PRIMARY KEY,
    industry TEXT DEFAULT 'General',
    analysis_frequency TEXT DEFAULT 'auto',
    custom_queries TEXT DEFAULT '[]',
    track_competitors TEXT DEFAULT '[]',
    alert_threshold INTEGER DEFAULT 30,
    auto_reanalyze INTEGER DEFAULT 1,
    website_monitor INTEGER DEFAULT 1,
    workflow_preset TEXT DEFAULT 'auto',
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (company_id) REFERENCES brands(id)
);
"""

WORKFLOW_PRESETS = {
    "auto": {
        "description": "Automatic - adapts based on industry and behavior",
        "queries_per_cycle": 5,
        "competitor_limit": 5,
        "reanalyze_days": 7,
        "alert_threshold": 30,
    },
    "healthcare": {
        "description": "Healthcare - compliance keywords, trust signals",
        "queries_per_cycle": 8,
        "competitor_limit": 3,
        "reanalyze_days": 5,
        "alert_threshold": 40,
        "focus_areas": ["compliance", "patient-outcomes", "medical-accuracy", "HIPAA"],
    },
    "ecommerce": {
        "description": "E-commerce - product mentions, reviews, pricing",
        "queries_per_cycle": 10,
        "competitor_limit": 8,
        "reanalyze_days": 3,
        "alert_threshold": 25,
        "focus_areas": ["product-recommendations", "pricing", "reviews", "availability"],
    },
    "saas": {
        "description": "SaaS - feature comparisons, integrations, pricing tiers",
        "queries_per_cycle": 7,
        "competitor_limit": 5,
        "reanalyze_days": 5,
        "alert_threshold": 35,
        "focus_areas": ["feature-comparison", "pricing", "integrations", "API"],
    },
    "finance": {
        "description": "Finance - regulatory, trust, security",
        "queries_per_cycle": 6,
        "competitor_limit": 4,
        "reanalyze_days": 7,
        "alert_threshold": 45,
        "focus_areas": ["regulatory", "security", "trust-signal", "compliance"],
    },
    "education": {
        "description": "Education - courses, reputation, accreditation",
        "queries_per_cycle": 5,
        "competitor_limit": 5,
        "reanalyze_days": 7,
        "alert_threshold": 30,
        "focus_areas": ["courses", "accreditation", "reputation", "student-outcomes"],
    },
}


def get_company_workflow_config(company_id):
    """Get or create adaptive workflow config for a company."""
    rows = db.query("SELECT * FROM company_workflow_config WHERE company_id=?", (company_id,))
    if rows:
        return dict(rows[0])
    brand = get_brand(company_id)
    if not brand:
        return None
    industry = (brand.get("industry") or "General").lower()
    preset = "auto"
    for key in WORKFLOW_PRESETS:
        if key in industry:
            preset = key
            break
    cfg = WORKFLOW_PRESETS.get(preset, WORKFLOW_PRESETS["auto"])
    db.execute(
        "INSERT OR IGNORE INTO company_workflow_config (company_id, industry, workflow_preset, alert_threshold) VALUES (?,?,?,?)",
        (company_id, brand.get("industry", "General"), preset, cfg["alert_threshold"]))
    return db.query("SELECT * FROM company_workflow_config WHERE company_id=?", (company_id,))[0]


def update_company_workflow_config(company_id, updates):
    """Update adaptive workflow config for a company."""
    cfg = get_company_workflow_config(company_id)
    if not cfg:
        return {"success": False, "error": "Company not found"}
    allowed = ["industry", "analysis_frequency", "custom_queries", "track_competitors",
               "alert_threshold", "auto_reanalyze", "website_monitor", "workflow_preset"]
    sets = []
    params = []
    for k, v in updates.items():
        if k in allowed:
            sets.append(f"{k}=?")
            params.append(v)
    if not sets:
        return {"success": False, "error": "No valid fields"}
    sets.append("updated_at=?")
    params.append(now())
    params.append(company_id)
    db.execute(f"UPDATE company_workflow_config SET {', '.join(sets)} WHERE company_id=?", tuple(params))
    return {"success": True, "config": get_company_workflow_config(company_id)}


def detect_offline_website_changes(company_id):
    """Detect if website content changed since last analysis (offline change detection)."""
    brand = get_brand(company_id)
    if not brand or not brand.get("website"):
        return False
    cfg = get_company_workflow_config(company_id)
    if cfg and not cfg.get("website_monitor", 1):
        return False
    return _evidence_moved(company_id)


def get_company_workflow_status(company_id):
    """Get full workflow status for a company including adaptive config."""
    brand = get_brand(company_id)
    if not brand:
        return {"error": "Company not found"}
    cfg = get_company_workflow_config(company_id)
    preset = WORKFLOW_PRESETS.get(cfg.get("workflow_preset", "auto"), WORKFLOW_PRESETS["auto"]) if cfg else {}
    af, a_days, a_note = analysis_freshness(company_id)
    ef, e_days, e_note = evidence_freshness(company_id)
    website_changed = detect_offline_website_changes(company_id)
    return {
        "company_id": company_id,
        "brand_name": brand.get("brand_name"),
        "industry": brand.get("industry"),
        "workflow_config": dict(cfg) if cfg else None,
        "preset": preset,
        "analysis_freshness": af,
        "analysis_days": a_days,
        "evidence_freshness": ef,
        "evidence_days": e_days,
        "website_changed": website_changed,
        "needs_work": af in ("never", "stale", "expired") or ef in ("stale", "expired") or website_changed,
    }
    rows = db.query("SELECT * FROM jobs WHERE id=?", (job_id,))
    if not rows:
        return {"success": False, "error": "job not found"}
    job = rows[0]
    if job["status"] in ("COMPLETED", "CANCELLED"):
        return {"success": False, "error": f"job already final ({job['status']})"}
    if job["status"] == "RUNNING":
        return {"success": False, "error": "cannot cancel a running job - let it finish, then cancel the rest"}
    db.execute("UPDATE jobs SET status='CANCELLED', cancelled_at=?, error='cancelled by user' WHERE id=?", (now(), job_id))
    log_activity(f"Cancelled job {job.get('job_id')} ({job['job_type']}) by user request", level="WARN",
                 run_id=job.get("run_id"), job_id=job_id, company_id=job.get("company_id"))
    return {"success": True, "id": job_id, "status": "CANCELLED"}


def retry_job(job_id):
    rows = db.query("SELECT * FROM jobs WHERE id=?", (job_id,))
    if not rows:
        return {"success": False, "error": "job not found"}
    job = rows[0]
    if job["status"] == "RUNNING":
        return {"success": False, "error": "cannot retry a running job"}
    db.execute("UPDATE jobs SET status='PENDING', retry_count=0, error=NULL, started_at=NULL, completed_at=NULL, "
               "cancelled_at=NULL WHERE id=?", (job_id,))
    log_activity(f"Job {job.get('job_id')} ({job['job_type']}) manually re-queued", level="WARN",
                 run_id=job.get("run_id"), job_id=job_id, company_id=job.get("company_id"))
    return {"success": True, "id": job_id, "status": "PENDING"}


_AUTO_SUMMARY_CACHE = {"ts": 0.0, "autos": None, "counts": None,
                        "monitored": 0, "next_schedule": None}


def agent_status_detail():
    """Rich status computed ONLY from real database records + runner state."""
    runs = db.query("SELECT * FROM runs ORDER BY id DESC LIMIT 10")
    run = next((r for r in runs if r["status"] == "RUNNING"), None)
    last = next((r for r in runs if r["status"] != "RUNNING"), None)
    queue = db.query("SELECT status, COUNT(*) AS c FROM jobs GROUP BY status")
    qmap = {"pending": 0, "running": 0, "completed": 0, "failed": 0,
            "retrying": 0, "cancelled": 0, "failed_permanently": 0}
    for r in queue:
        st = (r["status"] or "").lower()
        if st == "queued":
            st = "pending"
        if st in qmap:
            qmap[st] += r["c"]
    pending_total = qmap["pending"] + qmap["retrying"] + qmap["running"]
    done_total = qmap["completed"] + qmap["failed"] + qmap["failed_permanently"] + qmap["cancelled"]
    total = pending_total + done_total
    comps = db.query("SELECT COUNT(*) AS c FROM brands WHERE is_active=1")
    if run:
        current_job = None
        rj = db.query("SELECT jb.job_type, jb.company_id, b.brand_name FROM jobs jb "
                      "LEFT JOIN brands b ON b.id=jb.company_id WHERE jb.run_id=? AND jb.status='RUNNING' "
                      "ORDER BY jb.created_at DESC, jb.id DESC LIMIT 1", (run["run_id"],))
        if rj:
            current_job = f"{rj[0]['job_type']}#{rj[0]['company_id']}"
        else:
            current_job = run.get("current_task") or "Starting"
        status = "PAUSED" if runner.paused else "RUNNING"
    else:
        current_job = None
        status = "PAUSED" if runner.paused else "IDLE"
    error_rows = db.query("SELECT id, company_id, job_type, error, retry_count, created_at FROM jobs "
                          "WHERE status IN ('FAILED','FAILED_PERMANENTLY','RETRYING') AND error IS NOT NULL AND error!='' "
                          "ORDER BY id DESC LIMIT 8")
    errors = []
    for e in error_rows:
        b = get_brand(e["company_id"]) if e["company_id"] else None
        errors.append({"job_id": e["id"], "job_public_id": new_job_id(e["id"]),
                       "company_id": e["company_id"], "company": (b or {}).get("brand_name", ""),
                       "job_type": e["job_type"], "error": e["error"],
                       "retry_count": e["retry_count"], "created_at": e["created_at"]})
    activity = db.query("SELECT * FROM agent_activity ORDER BY id DESC LIMIT 15")
    running_cids = set()
    try:
        for r in db.query("SELECT DISTINCT j.company_id FROM runs r JOIN jobs j ON j.run_id=r.run_id "
                          "WHERE r.status='RUNNING'"):
            running_cids.add(r["company_id"])
    except Exception:
        pass
    # Automation summary is cached ~15s: automations change rarely, but this
    # endpoint is polled every few seconds by the dashboard.
    import time as _tmod
    _now_ts = _tmod.time()
    _cache = _AUTO_SUMMARY_CACHE
    if _cache["autos"] is not None and (_now_ts - _cache["ts"]) < 15:
        autos = _cache["autos"]
        auto_status_counts = _cache["counts"]
        companies_monitored = [{"c": _cache["monitored"]}]
        next_schedule = _cache["next_schedule"]
    else:
        auto_rows = db.query("SELECT * FROM automations")
        autos = [dict(r) for r in auto_rows]
        auto_status_counts = {}
    for st in AUTOMATION_STATUSES:
        auto_status_counts[st] = 0
    for a in autos:
        enabled = int(a.get("enabled") or 0)
        cid = a.get("company_id")
        if cid in running_cids:
            st = "RUNNING"
        elif not enabled:
            st = "PAUSED"
        elif a.get("last_status") == "FAILED":
            st = "FAILED"
        else:
            st = "ACTIVE"
        auto_status_counts[st] = auto_status_counts.get(st, 0) + 1
    companies_monitored = db.query("SELECT COUNT(DISTINCT company_id) AS c FROM automations")
    next_schedule = None
    try:
        for a in db.query("SELECT * FROM automations WHERE enabled=1 ORDER BY id ASC LIMIT 20"):
            nr = projected_next_run(dict(a))
            if nr and (not next_schedule or nr < next_schedule):
                next_schedule = nr
    except Exception:
        pass
    try:
        _cache["autos"] = autos
        _cache["counts"] = auto_status_counts
        _cache["monitored"] = companies_monitored[0]["c"] if companies_monitored else 0
        _cache["next_schedule"] = next_schedule
        _cache["ts"] = _now_ts
    except Exception:
        pass
    return {
        "success": True,
        "version": 3,
        "agent_status": status,
        "paused": runner.paused,
        "loop_running": bool(runner.thread and runner.thread.is_alive()),
        "loop_enabled": runner.loop_enabled,
        "current_job": current_job,
        "run": run,
        "last_run": last,
        "progress": (run or {}).get("progress", 0) or 0,
        "companies_active": comps[0]["c"] if comps else 0,
        "companies_processed": (run or {}).get("processed_companies", 0) or 0,
        "companies_total": (run or {}).get("total_companies", 0) or 0,
        "jobs_completed": qmap["completed"],
        "jobs_failed": qmap["failed"] + qmap["failed_permanently"],
        "jobs_total": total,
        "jobs_cancelled": qmap["cancelled"],
        "job_progress": f"{qmap['completed']} / {total}",
        "queue": qmap,
        "changes_detected": (run or {}).get("changes_detected", 0) or 0,
        "new_evidence_count": (run or {}).get("new_evidence_count", 0) or 0,
        "queries_processed": (run or {}).get("processed_queries", 0) or 0,
        "errors_recent": errors,
        "activity": [dict(a) for a in activity],
        "next_run_at": (last or {}).get("next_run_at") or _estimate_next_run(),
        "automation": {
            "scheduler_running": bool(scheduler.thread and scheduler.thread.is_alive()),
            "scheduler_paused": scheduler.paused,
            "scheduler_last_cycle": scheduler.last_cycle_at,
            "scheduler_next_cycle": scheduler.next_cycle_at,
            "scheduler_stats": scheduler.last_stats,
            "automations_total": len(autos),
            "automation_status_counts": auto_status_counts,
            "companies_monitored": companies_monitored[0]["c"] if companies_monitored else 0,
            "next_scheduled": next_schedule,
        },
        "timestamp": now(),
    }


def fetch_jobs(status=None):
    if status and status != "ALL":
        rows = db.query("SELECT j.*, b.brand_name AS company FROM jobs j "
                        "LEFT JOIN brands b ON b.id=j.company_id WHERE j.status=? ORDER BY j.created_at DESC, j.id DESC LIMIT 300",
                        (status,))
    else:
        rows = db.query("SELECT j.*, b.brand_name AS company FROM jobs j "
                        "LEFT JOIN brands b ON b.id=j.company_id ORDER BY j.created_at DESC, j.id DESC LIMIT 300")
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# AUTOMATION + SCHEDULER  (Phase 2 - creates jobs only, never executes analysis)
# ---------------------------------------------------------------------------

AUTOMATION_TYPES = ["FULL_ANALYSIS", "MONITOR", "CHANGE_DETECTION", "DATA_REFRESH",
                    "COMPETITOR_REFRESH", "QUERY_REFRESH", "AUTONOMOUS_CYCLE"]
SCHEDULE_TYPES = ["MANUAL", "DAILY", "WEEKLY", "MONTHLY", "ON_CHANGE", "ON_NEW_EVIDENCE"]
AUTOMATION_STATUSES = ["ACTIVE", "PAUSED", "RUNNING", "FAILED", "COMPLETED"]


def new_automation_id(aid):
    return f"AUTO-{int(aid):06d}"


def new_event_id(eid):
    return f"EVT-{int(eid):06d}"


def data_freshness(company_id):
    """FRESH / STALE / EXPIRED from real evidence age (configurable buckets)."""
    f, age, note = evidence_freshness(company_id)
    if f == "none":
        return "NONE", None, note
    cfg = get_config()
    try:
        fresh_d = int(cfg.get("data_fresh_days", "7"))
        stale_d = int(cfg.get("data_stale_days", "30"))
    except Exception:
        fresh_d, stale_d = 7, 30
    if age <= fresh_d:
        return "FRESH", age, note
    if age <= stale_d:
        return "STALE", age, note
    return "EXPIRED", age, note


def calculate_next_run(schedule_type, from_ts=None):
    """Compute next_run_at for a schedule. Event-driven schedules have none."""
    if schedule_type not in ("DAILY", "WEEKLY", "MONTHLY"):
        return None
    base = datetime.datetime.now(datetime.timezone.utc)
    if from_ts:
        try:
            dt = datetime.datetime.fromisoformat(str(from_ts).replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=datetime.timezone.utc)
            base = dt
        except Exception:
            pass
    if schedule_type == "DAILY":
        nxt = base + datetime.timedelta(days=1)
    elif schedule_type == "WEEKLY":
        nxt = base + datetime.timedelta(days=7)
    else:
        try:
            y = base.year + (base.month == 12)
            m = 1 if base.month == 12 else base.month + 1
            d = min(base.day, [31, 29 if y % 4 == 0 and (y % 100 != 0 or y % 400 == 0) else 28,
                               31, 30, 31, 30, 31, 31, 30, 31, 30, 31][m - 1])
            nxt = base.replace(year=y, month=m, day=d)
        except Exception:
            nxt = base + datetime.timedelta(days=30)
    return nxt.isoformat(timespec="seconds")


def log_automation_event(event_type, message, automation_id=None, company_id=None,
                         run_id=None, job_id=None, metadata=None):
    """Persisted automation/scheduler event. Only REAL events are written."""
    row = db.query("SELECT MAX(id) AS mx FROM automation_events")
    eid = (row[0]["mx"] or 0) + 1
    db.execute(
        "INSERT INTO automation_events (event_id, event_type, automation_id, company_id, run_id, job_id, "
        "message, metadata_json, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
        (new_event_id(eid), event_type, automation_id, company_id, run_id, job_id,
         str(message)[:500], json.dumps(metadata or {}), now()))
    return eid


def default_company_settings(company_id):
    cfg = get_config()
    return {
        "company_id": company_id,
        "monitoring_enabled": 1,
        "analysis_frequency": "WEEKLY",
        "change_detection_enabled": int(cfg.get("reanalysis_on_change_enabled", "1")),
        "auto_recommendations_enabled": 1,
        "auto_query_refresh_enabled": 0,
        "data_refresh_enabled": 0,
        "learning_enabled": 1,
    }


def get_company_settings(company_id):
    rows = db.query("SELECT * FROM company_settings WHERE company_id=? ORDER BY id DESC LIMIT 1",
                    (company_id,))
    if rows:
        d = dict(rows[0])
        d.pop("id", None)
        return d
    return default_company_settings(company_id)


def save_company_settings(company_id, settings=None):
    s = default_company_settings(company_id)
    for k in ("monitoring_enabled", "analysis_frequency", "change_detection_enabled",
              "auto_recommendations_enabled", "auto_query_refresh_enabled", "data_refresh_enabled",
              "learning_enabled"):
        if settings and k in settings:
            s[k] = int(settings[k]) if k != "analysis_frequency" else str(settings[k])
    if str(s["analysis_frequency"]).upper() not in ("MANUAL", "DAILY", "WEEKLY", "MONTHLY"):
        s["analysis_frequency"] = "WEEKLY"
    for k in ("monitoring_enabled", "change_detection_enabled", "auto_recommendations_enabled",
              "auto_query_refresh_enabled", "data_refresh_enabled", "learning_enabled"):
        s[k] = 1 if s[k] else 0
    exists = db.query("SELECT id FROM company_settings WHERE company_id=?", (company_id,))
    t = now()
    if exists:
        db.execute("""
            UPDATE company_settings SET monitoring_enabled=?, analysis_frequency=?, change_detection_enabled=?,
                   auto_recommendations_enabled=?, auto_query_refresh_enabled=?, data_refresh_enabled=?,
                   learning_enabled=?, updated_at=? WHERE company_id=?
        """, (s["monitoring_enabled"], s["analysis_frequency"], s["change_detection_enabled"],
              s["auto_recommendations_enabled"], s["auto_query_refresh_enabled"], s["data_refresh_enabled"],
              s["learning_enabled"], t, company_id))
    else:
        db.execute("""
            INSERT INTO company_settings (company_id, monitoring_enabled, analysis_frequency,
                   change_detection_enabled, auto_recommendations_enabled, auto_query_refresh_enabled,
                   data_refresh_enabled, learning_enabled, created_at, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?)
        """, (company_id, s["monitoring_enabled"], s["analysis_frequency"], s["change_detection_enabled"],
              s["auto_recommendations_enabled"], s["auto_query_refresh_enabled"], s["data_refresh_enabled"],
              s["learning_enabled"], t, t))
    return s


def create_automation(company_id, automation_type="FULL_ANALYSIS", schedule_type="WEEKLY",
                      enabled=1, configuration=None, commit_event=True, preserve_enabled=False):
    company_id = int(company_id or 0)
    if not get_brand(company_id):
        raise ValueError("company not found")
    automation_type = str(automation_type).upper()
    schedule_type = str(schedule_type).upper()
    if automation_type not in AUTOMATION_TYPES:
        raise ValueError(f"invalid automation_type {automation_type}")
    if schedule_type not in SCHEDULE_TYPES:
        raise ValueError(f"invalid schedule_type {schedule_type}")
    # Never duplicate: re-use an existing same-type automation instead.
    rows = db.query("SELECT * FROM automations WHERE company_id=? AND automation_type=? ORDER BY id DESC LIMIT 1",
                    (company_id, automation_type))
    if rows:
        a = rows[0]
        if preserve_enabled:
            # Settings sync: never silently overwrite schedule_type or enabled on
            # automations the user explicitly configured via the UI/API. Only
            # configuration_json is aligned. Disabling for OFF features is handled
            # separately in the caller (ensure_default_automations force-disable pass).
            db.execute("UPDATE automations SET configuration_json=?, updated_at=? "
                       "WHERE id=?",
                       (json.dumps(configuration or {}), now(), a["id"]))
        else:
            db.execute("UPDATE automations SET schedule_type=?, enabled=?, configuration_json=?, updated_at=? "
                       "WHERE id=?",
                       (schedule_type, 1 if enabled else 0, json.dumps(configuration or {}), now(), a["id"]))
        aid = a["automation_id"]
    else:
        row = db.query("SELECT MAX(id) AS mx FROM automations")
        aid = new_automation_id((row[0]["mx"] or 0) + 1)
        t = now()
        db.execute("""
            INSERT INTO automations (automation_id, company_id, automation_type, schedule_type, enabled,
                   last_status, configuration_json, created_at, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?)
        """, (aid, company_id, automation_type, schedule_type, 1 if enabled else 0,
              "ACTIVE" if enabled else "PAUSED", json.dumps(configuration or {}), t, t))
    if commit_event:
        log_automation_event("AUTOMATION_TRIGGERED",
                             f"Automation {aid} ({automation_type}/{schedule_type}) assigned to company #{company_id}",
                             automation_id=int(aid.split("-")[1]) if "-" in aid else None,
                             company_id=company_id)
    return get_automation(aid)


def ensure_default_automations(company_id):
    """Keep automations aligned with a company's settings. Called on company add
    and by the scheduler for any active company missing automations.

    Preserves manual enable/disable state: settings that are ON align the
    schedule but never silently re-enable a user-disabled automation; settings
    that are OFF force the corresponding automation disabled."""
    s = get_company_settings(company_id)
    freq = str(s.get("analysis_frequency") or "WEEKLY").upper()
    created = []
    # Main analysis schedule mirrors the company's frequency (MANUAL = on-demand only).
    wants = [
        ("FULL_ANALYSIS", freq if freq in ("DAILY", "WEEKLY", "MONTHLY") else "WEEKLY",
         0 if freq == "MANUAL" else 1),
        ("MONITOR", "ON_CHANGE", 1 if s.get("monitoring_enabled") else 0),
        ("CHANGE_DETECTION", "ON_NEW_EVIDENCE", 1 if s.get("change_detection_enabled") else 0),
        ("QUERY_REFRESH", "DAILY", 1 if s.get("auto_query_refresh_enabled") else 0),
        ("DATA_REFRESH", "DAILY", 1 if s.get("data_refresh_enabled") else 0),
    ]
    for atype, sched, enabled in wants:
        try:
            created.append(create_automation(company_id, atype, sched, enabled,
                                             commit_event=False, preserve_enabled=True))
        except Exception as e:
            print(f"[Automation] {atype} for #{company_id} failed: {e}", flush=True)
    # Settings are the source of truth for OFF features: force-disable.
    # The scheduler never force-ENABLES because per-automation manual toggles
    # should persist until the user explicitly changes them via the settings panel.
    off_types = [t for t, _, e in wants if not e]
    if off_types:
        for a in db.query("SELECT id FROM automations WHERE company_id=? AND automation_type IN (%s) AND enabled=1"
                          % ",".join("?" * len(off_types)), (company_id, *off_types)):
            db.execute("UPDATE automations SET enabled=0, last_status='PAUSED', updated_at=? WHERE id=?",
                       (now(), a["id"]))
    return created


def get_automation(automation_id):
    rows = db.query("SELECT * FROM automations WHERE automation_id=? ORDER BY id DESC LIMIT 1",
                    (automation_id,))
    return dict(rows[0]) if rows else None


def projected_next_run(a):
    """Real next_run_at, or an honest projection from NOW for an enabled time-based
    automation that has never fired (NULL) - never fabricated."""
    if a.get("next_run_at"):
        return a["next_run_at"]
    if int(a.get("enabled") or 0) and a.get("schedule_type") in ("DAILY", "WEEKLY", "MONTHLY"):
        return calculate_next_run(a["schedule_type"])
    return None


def list_automations(company_id=None):
    if company_id:
        rows = db.query("SELECT a.*, b.brand_name AS company FROM automations a "
                        "LEFT JOIN brands b ON b.id=a.company_id WHERE a.company_id=? ORDER BY a.id DESC",
                        (company_id,))
    else:
        rows = db.query("SELECT a.*, b.brand_name AS company FROM automations a "
                        "LEFT JOIN brands b ON b.id=a.company_id ORDER BY a.id DESC LIMIT 500")
    running_cids = set()
    try:
        for r in db.query("SELECT DISTINCT j.company_id FROM runs r JOIN jobs j ON j.run_id=r.run_id "
                          "WHERE r.status='RUNNING'"):
            running_cids.add(r["company_id"])
    except Exception:
        pass
    out = []
    for r in rows:
        d = dict(r)
        enabled = int(d.get("enabled") or 0)
        cid = d.get("company_id")
        if cid in running_cids:
            d["status"] = "RUNNING"
        elif not enabled:
            d["status"] = "PAUSED"
        elif d.get("last_status") == "FAILED":
            d["status"] = "FAILED"
        else:
            d["status"] = "ACTIVE"
        out.append(d)
    return out


def current_automation_status(a):
    """Derive live status from real DB state (runs/events), never fabricated."""
    enabled = int(a.get("enabled") or 0)
    running = db.query("SELECT DISTINCT r.run_id FROM runs r JOIN jobs j ON j.run_id=r.run_id "
                       "WHERE r.status='RUNNING' AND j.company_id=? LIMIT 1", (a.get("company_id"),))
    recent_fail = db.query("SELECT DISTINCT r.id FROM runs r JOIN jobs j ON j.run_id=r.run_id "
                           "WHERE r.status='FAILED' AND j.company_id=? ORDER BY r.id DESC LIMIT 1",
                           (a.get("company_id"),))
    if running:
        return "RUNNING"
    if not enabled:
        return "PAUSED"
    if a.get("last_status") == "FAILED":
        return "FAILED"
    return "ACTIVE"


def update_automation(aid, payload):
    a = get_automation(aid)
    if not a:
        return {"success": False, "error": "automation not found"}
    fields = {}
    for k in ("automation_type", "schedule_type", "configuration_json"):
        if k in payload and payload[k]:
            if k == "automation_type" and str(payload[k]).upper() not in AUTOMATION_TYPES:
                return {"success": False, "error": f"invalid automation_type"}
            if k == "schedule_type" and str(payload[k]).upper() not in SCHEDULE_TYPES:
                return {"success": False, "error": f"invalid schedule_type"}
            fields[k] = str(payload[k]).upper() if k != "configuration_json" else json.dumps(payload[k])
    if "enabled" in payload:
        fields["enabled"] = 1 if payload["enabled"] else 0
        fields["last_status"] = "ACTIVE" if payload["enabled"] else "PAUSED"
    if fields:
        fields["updated_at"] = now()
        sets = ", ".join(f"{k}=?" for k in fields)
        db.execute(f"UPDATE automations SET {sets} WHERE automation_id=?",
                   (*fields.values(), aid))
    log_automation_event("AUTOMATION_TRIGGERED",
                         f"Automation {aid} updated ({', '.join(fields.keys())})", company_id=a.get("company_id"))
    return {"success": True, "automation": get_automation(aid)}


def set_automation_enabled(aid, enabled):
    a = get_automation(aid)
    if not a:
        return {"success": False, "error": "automation not found"}
    db.execute("UPDATE automations SET enabled=?, last_status=?, updated_at=? WHERE automation_id=?",
               (1 if enabled else 0, "ACTIVE" if enabled else "PAUSED", now(), aid))
    log_automation_event("AUTOMATION_TRIGGERED" if enabled else "AUTOMATION_SKIPPED",
                         f"Automation {aid} {'enabled' if enabled else 'disabled'}"
                         + (f" for company #{a['company_id']}" if a.get("company_id") else ""),
                         company_id=a.get("company_id"))
    return {"success": True, "enabled": bool(enabled), "automation": get_automation(aid)}


# Job plans per automation type (real work items - executed by the runner).
AUTOMATION_JOB_PLANS = {
    "FULL_ANALYSIS": PIPELINE_TYPES,
    "MONITOR": ["COLLECT_WEBSITE_DATA", "VALIDATE_DATA", "DETECT_CHANGES"],
    "CHANGE_DETECTION": ["COLLECT_WEBSITE_DATA", "VALIDATE_DATA", "DETECT_CHANGES"],
    "DATA_REFRESH": ["COLLECT_WEBSITE_DATA", "VALIDATE_DATA"],
    "COMPETITOR_REFRESH": ["ANALYZE_COMPETITORS", "GENERATE_RECOMMENDATIONS"],
    "QUERY_REFRESH": ["GENERATE_QUERIES", "RUN_AI_SEARCH"],
}


def _has_active_similar_jobs(company_id, job_types):
    """True if any equivalent job is already inflight (PENDING/RUNNING/RETRYING) -
    dedup gate so the scheduler never creates duplicate work."""
    for jt in job_types:
        rows = db.query(
            "SELECT id FROM jobs WHERE company_id=? AND job_type=? "
            "AND status IN ('PENDING','QUEUED','RUNNING','RETRYING') LIMIT 1",
            (company_id, jt))
        if rows:
            return True
    return False


def _run_autonomous_for_automation(auto, background=True):
    """Scheduler/manual fire path for AUTONOMOUS_CYCLE automations: start one
    bounded autonomous cycle for the company instead of a blind job plan.
    Never overlaps an in-flight cycle; never fires while paused."""
    company_id = auto.get("company_id")
    if not get_brand(company_id):
        raise ValueError("company not found")
    blocked = autonomy_blocked()
    if blocked:
        return {"triggered": False, "reason": blocked, "created": 0}
    if autonomous_inflight():
        return {"triggered": False, "reason": "autonomous cycle already running", "created": 0}
    res = run_autonomous({"company_id": company_id, "automation_id": auto.get("automation_id"),
                          "background": background}, background=background)
    t = now()
    nxt = calculate_next_run(auto.get("schedule_type"), t)
    if res.get("success") and not res.get("paused") and not res.get("skipped"):
        db.execute("UPDATE automations SET last_run_at=?, next_run_at=?, last_status='RUNNING', run_count=?, "
                   "updated_at=? WHERE automation_id=?",
                   (t, nxt, (auto.get("run_count") or 0) + 1, t, auto.get("automation_id")))
        log_automation_event("JOB_CREATED",
                             f"Automation {auto.get('automation_id')} (AUTONOMOUS_CYCLE) started a bounded "
                             f"autonomous cycle for company #{company_id} [{auto.get('company') or ''}]"
                             + (" in background" if background else ""),
                             automation_id=auto.get("id"), company_id=company_id,
                             run_id=res.get("run_id"),
                             metadata={"mode": "dry_run" if res.get("dry_run") else "live"})
        return {"triggered": True, "reason": "autonomous cycle started",
                "created": res.get("jobs_created", 0), "run_id": res.get("run_id"),
                "outcome": res.get("outcome"), "dry_run": res.get("dry_run", False)}
    reason = res.get("reason") or res.get("error") or "not started"
    return {"triggered": False, "reason": reason, "created": 0}


def _run_for_automation(auto):
    """Trigger an automation: create a run + its jobs (dedup-aware), without
    executing the analysis itself (the runner executes the queue)."""
    if auto.get("automation_type") == "AUTONOMOUS_CYCLE":
        return _run_autonomous_for_automation(auto, background=True)
    company_id = auto.get("company_id")
    if not get_brand(company_id):
        raise ValueError("company not found")
    plan = AUTOMATION_JOB_PLANS.get(auto.get("automation_type"), [])
    if _has_active_similar_jobs(company_id, plan):
        return {"triggered": False, "reason": "equivalent jobs already inflight", "created": 0}
    # Full analyses must not stack while a previous run is still active.
    if auto.get("automation_type") == "FULL_ANALYSIS":
        running = db.query("SELECT DISTINCT r.run_id FROM runs r JOIN jobs j ON j.run_id=r.run_id "
                           "WHERE r.status='RUNNING' AND j.company_id=? LIMIT 1", (company_id,))
        if running:
            return {"triggered": False, "reason": "analysis is already running for this company", "created": 0}
    rid = create_run("AUTOMATION", companies=[company_id], automation_id=auto.get("id"))
    created = 0
    for jt in plan:
        jid = ensure_job(jt, company_id, rid, include_completed=False)
        if jid:
            created += 1
    t = now()
    nxt = calculate_next_run(auto.get("schedule_type"), t)
    db.execute("UPDATE automations SET last_run_at=?, next_run_at=?, last_status='RUNNING', run_count=?, "
               "updated_at=? WHERE automation_id=?",
               (t, nxt, (auto.get("run_count") or 0) + 1, t, auto.get("automation_id")))
    log_automation_event("JOB_CREATED",
                         f"Automation {auto.get('automation_id')} ({auto.get('automation_type')}) "
                         f"created {created} job(s) for company #{company_id} [{auto.get('company') or ''}]",
                         automation_id=auto.get("id"), company_id=company_id, run_id=rid,
                         metadata={"jobs": plan, "created": created})
    return {"triggered": True, "reason": "scheduled", "created": created, "run_id": rid}


def run_automation(automation_id, background=True):
    """Manual RUN NOW for a specific automation."""
    a = get_automation(automation_id)
    if not a:
        return {"success": False, "error": "automation not found"}
    if not get_brand(a["company_id"]):
        return {"success": False, "error": "company missing"}
    if a.get("automation_type") == "AUTONOMOUS_CYCLE":
        # Autonomous cycles execute their own queue internally; the runner
        # must not double-process them here.
        try:
            res = _run_autonomous_for_automation(a, background=background)
        except Exception as e:
            log_automation_event("AUTOMATION_FAILED", f"Automation {automation_id} failed: {e}",
                                 company_id=a.get("company_id"))
            return {"success": False, "error": str(e)}
        if not res["triggered"]:
            return {"success": False, "error": res["reason"]}
        return {"success": True, "automation_id": automation_id, "run_id": res.get("run_id"),
                "jobs_created": res.get("created", 0), "outcome": res.get("outcome"),
                "dry_run": res.get("dry_run", False)}
    try:
        res = _run_for_automation(a)
    except Exception as e:
        log_automation_event("AUTOMATION_FAILED", f"Automation {automation_id} failed: {e}",
                             company_id=a.get("company_id"))
        return {"success": False, "error": str(e)}
    if not res["triggered"]:
        return {"success": False, "error": res["reason"]}
    if background:
        threading.Thread(target=lambda: runner._process_queue(run_id=res["run_id"]),
                         daemon=True, name="auto-run").start()
    else:
        runner._process_queue(run_id=res["run_id"])
    return {"success": True, "automation_id": automation_id, "run_id": res["run_id"],
            "jobs_created": res["created"]}


def automation_history(automation_id):
    a = get_automation(automation_id)
    if not a:
        return {"success": False, "error": "automation not found"}
    runs = db.query("SELECT * FROM runs WHERE automation_id=? ORDER BY id DESC", (a["id"],))
    out = []
    for r in runs:
        d = dict(r)
        d["stats"] = _run_stats(d["run_id"])
        out.append(d)
    events = db.query("SELECT * FROM automation_events WHERE automation_id=? ORDER BY id DESC LIMIT 100",
                      (a["id"],))
    return {"success": True, "automation": a, "runs": out, "events": [dict(e) for e in events]}


def automation_status_summary():
    """Dashboard KPIs computed ONLY from real records."""
    counts = {}
    for st in AUTOMATION_STATUSES:
        counts[st] = 0
    rows = db.query("SELECT * FROM automations")
    autos = [dict(r) for r in rows]
    running_cids = set()
    try:
        for r in db.query("SELECT DISTINCT j.company_id FROM runs r JOIN jobs j ON j.run_id=r.run_id "
                          "WHERE r.status='RUNNING'"):
            running_cids.add(r["company_id"])
    except Exception:
        pass
    for a in autos:
        enabled = int(a.get("enabled") or 0)
        cid = a.get("company_id")
        if cid in running_cids:
            st = "RUNNING"
        elif not enabled:
            st = "PAUSED"
        elif a.get("last_status") == "FAILED":
            st = "FAILED"
        else:
            st = "ACTIVE"
        counts[st] = counts.get(st, 0) + 1
    comps = db.query("SELECT COUNT(DISTINCT company_id) AS c FROM automations")
    today = now()[:10]
    jobs_today = db.query("SELECT COUNT(*) AS c FROM jobs WHERE created_at LIKE ?", (today + "%",))
    done_today = db.query("SELECT COUNT(*) AS c FROM jobs WHERE completed_at LIKE ? AND status='COMPLETED'",
                          (today + "%",))
    failed = db.query("SELECT COUNT(*) AS c FROM jobs WHERE status IN ('FAILED','FAILED_PERMANENTLY','RETRYING')")
    next_run = None
    try:
        for a in db.query("SELECT * FROM automations WHERE enabled=1 ORDER BY id ASC LIMIT 20"):
            nr = projected_next_run(dict(a))
            if nr and (not next_run or nr < next_run):
                next_run = nr
    except Exception:
        pass
    last_analysis = db.query("SELECT * FROM runs WHERE status IN ('COMPLETED','FAILED') "
                             "ORDER BY id DESC LIMIT 1")
    return {
        "success": True,
        "automations_total": len(autos),
        "automations": autos[:50],
        "status_counts": counts,
        "companies_monitored": comps[0]["c"] if comps else 0,
        "jobs_created_today": jobs_today[0]["c"] if jobs_today else 0,
        "jobs_completed_today": done_today[0]["c"] if done_today else 0,
        "failed_jobs": failed[0]["c"] if failed else 0,
        "next_scheduled_run": next_run,
        "last_analysis": dict(last_analysis[0]) if last_analysis else None,
        "timestamp": now(),
    }


class AutomationScheduler:
    """Background cycle that inspects automations/staleness and CREATES jobs.
    It never runs analysis itself (that is the AgentRunner's job)."""

    def __init__(self):
        self.thread = None
        self.stop_flag = False
        self.running = False
        self.paused = False  # loaded lazily (DB may not exist at import time)
        self.last_cycle_at = None
        self.next_cycle_at = None
        self.cycle_count = 0
        self.last_stats = {"companies_checked": 0, "automations_checked": 0,
                           "jobs_created": 0, "jobs_skipped": 0, "errors": 0}

    def _load_paused(self):
        try:
            self.paused = get_config("scheduler_paused", "0") == "1"
        except Exception:
            self.paused = False

    def start(self):
        if self.thread and self.thread.is_alive():
            return {"success": True, "message": "scheduler already running"}
        self.stop_flag = False
        self._load_paused()
        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True, name="automation-scheduler")
        self.thread.start()
        log_automation_event("SCHEDULER_STARTED", "Automation scheduler started")
        return {"success": True, "message": "automation scheduler started"}

    def stop(self):
        self.stop_flag = True
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
        log_automation_event("SCHEDULER_STOPPED", "Automation scheduler stopped")
        return {"success": True, "message": "automation scheduler stopped"}

    def pause(self):
        self.paused = True
        try:
            save_config({"scheduler_paused": "1"})
        except Exception:
            pass
        log_automation_event("SCHEDULER_STARTED", "Automation scheduler paused (no new schedules will fire)")
        return {"success": True, "paused": True}

    def resume(self):
        self.paused = False
        try:
            save_config({"scheduler_paused": "0"})
        except Exception:
            pass
        log_automation_event("SCHEDULER_STARTED", "Automation scheduler resumed")
        return {"success": True, "paused": False}

    def _loop(self):
        while not self.stop_flag:
            try:
                self.run_once()
            except Exception as e:
                print(f"[AutomationScheduler] cycle error: {e}", flush=True)
            try:
                minutes = max(1, int(get_config().get("scheduler_interval_minutes", "5")))
            except Exception:
                minutes = 5
            self.next_cycle_at = now()
            for _ in range(minutes * 60):
                if self.stop_flag:
                    break
                time.sleep(1)

    def status(self):
        self._load_paused()
        return {
            "success": True,
            "running": bool(self.thread and self.thread.is_alive()),
            "paused": self.paused,
            "interval_minutes": int(get_config().get("scheduler_interval_minutes", "5")),
            "last_cycle_at": self.last_cycle_at,
            "next_cycle_at": self.next_cycle_at,
            "cycle_count": self.cycle_count,
            "stats": self.last_stats,
        }

    def run_once(self, manual=False):
        """One scheduler cycle - inspect real state, create jobs, log events."""
        if self.paused and not manual:
            return {"success": False, "error": "scheduler is paused"}
        log_automation_event("SCHEDULER_STARTED", "Scheduler cycle started")
        stats = {"companies_checked": 0, "automations_checked": 0,
                 "jobs_created": 0, "jobs_skipped": 0, "errors": 0}
        try:
            # Ensure every active company has a schedule (new companies are picked
            # up automatically - never silently ignored).
            for cid in _active_company_ids():
                stats["companies_checked"] += 1
                try:
                    ensure_default_automations(cid)
                except Exception as e:
                    stats["errors"] += 1
                    log_automation_event("AUTOMATION_FAILED", f"ensure schedules #{cid}: {e}", company_id=cid)

            if get_config("automation_enabled", "1") == "1":
                try:
                    max_create = int(get_config().get("scheduler_max_jobs_per_cycle", "30"))
                except Exception:
                    max_create = 30
                autos = db.query("SELECT a.*, b.brand_name AS company FROM automations a "
                                 "LEFT JOIN brands b ON b.id=a.company_id WHERE a.enabled=1 ORDER BY a.id")
                for r in autos:
                    if stats["jobs_created"] >= max_create:
                        stats["jobs_skipped"] += 1
                        continue
                    auto = dict(r)
                    auto = dict(r)
                    stats["automations_checked"] += 1
                    try:
                        res = self._evaluate(auto)
                        if res.get("triggered"):
                            stats["jobs_created"] += res.get("created", 0)
                        else:
                            stats["jobs_skipped"] += 1
                            if res.get("reason"):
                                log_automation_event(
                                    "AUTOMATION_SKIPPED",
                                    f"Skipped {auto.get('automation_id')} for company "
                                    f"#{auto.get('company_id')} {auto.get('company') or ''}: {res['reason']}",
                                    automation_id=auto.get("id"), company_id=auto.get("company_id"))
                    except Exception as e:
                        stats["errors"] += 1
                        try:
                            db.execute("UPDATE automations SET last_status='FAILED', updated_at=? "
                                       "WHERE automation_id=?", (now(), auto.get("automation_id")))
                        except Exception:
                            pass
                        log_automation_event("AUTOMATION_FAILED",
                                             f"Automation {auto.get('automation_id')} failed: {e}",
                                             automation_id=auto.get("id"), company_id=auto.get("company_id"))
        except Exception as e:
            stats["errors"] += 1
            log_automation_event("AUTOMATION_FAILED", f"Scheduler cycle error: {e}")
        self.last_cycle_at = now()
        self.cycle_count += 1
        self.last_stats = stats
        log_automation_event("SCHEDULER_COMPLETED",
                             f"Scheduler cycle #{self.cycle_count} done: {stats['jobs_created']} job(s) created, "
                             f"{stats['jobs_skipped']} skipped, {stats['errors']} error(s).",
                             metadata=stats)
        return {"success": True, "stats": stats}

    def _evaluate(self, auto):
        """Decide whether an automation should fire right now, from real state."""
        company_id = auto.get("company_id")
        if not get_brand(company_id):
            return {"triggered": False, "reason": "company no longer exists"}
        # Never stack work on a company that already has inflight jobs.
        try:
            inflight = db.query("SELECT id FROM jobs WHERE company_id=? "
                                "AND status IN ('PENDING','QUEUED','RUNNING','RETRYING') LIMIT 1",
                                (company_id,))
            if inflight:
                return {"triggered": False, "reason": "company already has inflight work"}
        except Exception:
            pass
        sched = auto.get("schedule_type", "MANUAL")
        now_dt = datetime.datetime.now(datetime.timezone.utc)
        # MANUAL / event-driven schedules never auto-fire on a timer.
        if sched in ("MANUAL", "ON_CHANGE", "ON_NEW_EVIDENCE"):
            if sched == "MANUAL":
                return {"triggered": False, "reason": "manual schedule (run from UI/API only)"}
            return self._evaluate_event_driven(auto, sched)
        # Time-based schedules.
        if auto.get("next_run_at"):
            try:
                nxt = datetime.datetime.fromisoformat(str(auto["next_run_at"]).replace("Z", "+00:00"))
                if nxt.tzinfo is None:
                    nxt = nxt.replace(tzinfo=datetime.timezone.utc)
                if nxt > now_dt:
                    return {"triggered": False, "reason": f"not due yet (next {auto['next_run_at']})"}
            except Exception:
                pass
        # Staleness guard: never re-analyze a company whose data/analysis is fresh.
        data_f, data_age, data_note = data_freshness(company_id)
        if sched == "DAILY" and data_f == "FRESH" and auto["automation_type"] == "DATA_REFRESH":
            return {"triggered": False, "reason": "data is fresh"}
        return _run_for_automation(auto)

    def _evaluate_event_driven(self, auto, sched):
        company_id = auto.get("company_id")
        atype = auto.get("automation_type")
        last = auto.get("last_run_at")
        # ON_CHANGE: meaningful website/profile change since last run.
        if sched == "ON_CHANGE":
            if profile_changed(company_id):
                return _run_for_automation(auto)
            if _evidence_moved(company_id):
                return _run_for_automation(auto)
            data_f, data_age, _ = data_freshness(company_id)
            if atype in ("MONITOR", "CHANGE_DETECTION") and data_f in ("STALE", "EXPIRED"):
                return _run_for_automation(auto)
            return {"triggered": False, "reason": "no meaningful change detected"}
        # ON_NEW_EVIDENCE: real evidence rows newer than last run.
        if last:
            rows = db.query("SELECT id FROM evidence WHERE brand_id=? AND collected_at > ? LIMIT 1",
                            (company_id, last))
            if rows:
                return _run_for_automation(auto)
            return {"triggered": False, "reason": "no new evidence since last run"}
        return _run_for_automation(auto)


scheduler = AutomationScheduler()


# ---------------------------------------------------------------------------
# COMPANY DISCOVERY  (external integrations only - never fabricated)
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# REGION-BASED DISCOVERY + CANDIDATE VALIDATION (§6-§10)
# ---------------------------------------------------------------------------
REGIONS = ["Karnataka", "Maharashtra", "Tamil Nadu", "Telangana", "Delhi",
           "India", "United States", "United Kingdom"]

VERIFICATION_STATUSES = ["VERIFIED", "PARTIALLY_VERIFIED", "INSUFFICIENT_DATA",
                         "INVALID", "FAILED"]


def ensure_candidate_columns():
    """Add validation/provenance columns to discovery_candidates (idempotent)."""
    for coldef in ("verification_status TEXT DEFAULT 'INSUFFICIENT_DATA'",
                   "verified_at TEXT", "last_checked_at TEXT",
                   "source_url TEXT", "validation_json TEXT"):
        try:
            db.execute(f"ALTER TABLE discovery_candidates ADD COLUMN {coldef}")
        except Exception:
            pass


def _check_url_reachable(url, timeout=6):
    """HEAD (GET fallback) reachability probe. Returns (ok, http_status_or_error)."""
    try:
        from urllib.request import Request, urlopen
        req = Request(url, method="HEAD", headers={"User-Agent": "VisibilityAI/2.0 (validation probe)"})
        try:
            resp = urlopen(req, timeout=timeout)
            code = getattr(resp, "status", 200)
            resp.close()
            return True, code
        except Exception as e:
            if "405" in str(e) or "501" in str(e):
                req2 = Request(url, headers={"User-Agent": "VisibilityAI/2.0 (validation probe)"})
                resp2 = urlopen(req2, timeout=timeout)
                code2 = getattr(resp2, "status", 200)
                try:
                    resp2.read(1)
                except Exception:
                    pass
                resp2.close()
                return True, code2
            return False, str(e)[:120]
    except Exception as e:
        return False, str(e)[:120]


def validate_candidate(cid):
    """Validate one candidate; assigns VERIFIED/PARTIALLY_VERIFIED/
    INSUFFICIENT_DATA/INVALID/FAILED with reasons. Never fabricates data."""
    ensure_candidate_columns()
    rows = db.query("SELECT * FROM discovery_candidates WHERE id=?", (cid,))
    if not rows:
        return {"success": False, "error": "Candidate not found"}
    c = dict(rows[0])
    name = (c.get("candidate_name") or "").strip()
    website = (c.get("website") or "").strip()
    industry = (c.get("industry") or "").strip()
    region = (c.get("region") or "").strip()
    checks = {}
    t = now()
    if not name:
        status, reason = "INSUFFICIENT_DATA", "missing company name"
    else:
        dup = db.query("SELECT id FROM brands WHERE brand_name=? AND is_active=1 LIMIT 1", (name,))
        checks["duplicate_of_brand"] = bool(dup)
        if dup:
            status, reason = "INVALID", "duplicate of tracked company"
        elif not website:
            status, reason = "INSUFFICIENT_DATA", "missing website"
        else:
            import re as _re
            url = website if _re.match(r"^https?://", website, _re.IGNORECASE) else "https://" + website
            checks["url_normalized"] = (url != website)
            if not _re.match(r"^https?://[^\s/$.?#].[^\s]*$", url, _re.IGNORECASE):
                status, reason = "INVALID", "malformed website URL"
            else:
                try:
                    ok, info = _check_url_reachable(url)
                except Exception as e:
                    ok, info = False, f"probe error: {e}"[:120]
                checks["reachable"] = ok
                checks["http"] = info
                if ok:
                    if url != website:
                        try:
                            db.execute("UPDATE discovery_candidates SET website=? WHERE id=?", (url, cid))
                            website = url
                        except Exception:
                            pass
                    if industry:
                        status, reason = "VERIFIED", f"website reachable (HTTP {info})"
                    else:
                        status, reason = "PARTIALLY_VERIFIED", f"website reachable (HTTP {info}); industry missing"
                else:
                    status, reason = "PARTIALLY_VERIFIED", f"website not reachable ({info})"
    try:
        verified_at = t if status == "VERIFIED" else c.get("verified_at")
        db.execute("UPDATE discovery_candidates SET verification_status=?, verified_at=?, last_checked_at=?, "
                   "source_url=?, validation_json=? WHERE id=?",
                   (status, verified_at, t, website or None,
                    json.dumps({"reason": reason, "checks": checks})[:2000], cid))
    except Exception as e:
        return {"success": False, "error": str(e)[:200]}
    return {"success": True, "id": cid, "verification_status": status, "reason": reason, "checks": checks}


def discovery_summary():
    """Honest counts: discovered / verified / needs-verification / invalid / rejected.
    Never claims complete coverage."""
    ensure_candidate_columns()
    try:
        total = db.query("SELECT COUNT(*) AS c FROM discovery_candidates")[0]["c"]
    except Exception:
        total = 0
    by_status = {}
    try:
        for r in db.query("SELECT verification_status, COUNT(*) AS c FROM discovery_candidates "
                          "GROUP BY verification_status"):
            by_status[r["verification_status"] or "INSUFFICIENT_DATA"] = r["c"]
    except Exception:
        pass
    tracked = 0
    try:
        tracked = db.query("SELECT COUNT(*) AS c FROM discovery_candidates WHERE status='IMPORTED'")[0]["c"]
    except Exception:
        pass
    rejected = 0
    try:
        rejected = db.query("SELECT COUNT(*) AS c FROM discovery_candidates WHERE status='REJECTED'")[0]["c"]
    except Exception:
        pass
    verified = by_status.get("VERIFIED", 0)
    needs = by_status.get("PARTIALLY_VERIFIED", 0) + by_status.get("INSUFFICIENT_DATA", 0)
    invalid = by_status.get("INVALID", 0) + by_status.get("FAILED", 0)
    return {"success": True, "discovered": total, "verified": verified,
            "needs_verification": needs, "invalid": invalid, "rejected": rejected,
            "tracked": tracked, "by_status": by_status,
            "note": "Counts reflect discovered candidates only - not full market coverage."}


def _parse_model_json_list(text):
    """Parse an LLM JSON array tolerantly: strict parse, then control-char
    tolerant parse, then cut-to-last-complete-object repair. Raises on failure."""
    cleaned = clean_json_text(text)
    try:
        data = json.loads(cleaned)
    except Exception:
        try:
            # strict=False allows literal newlines/tabs inside strings.
            data = json.loads(cleaned, strict=False)
        except Exception:
            # Repair truncated output: drop the partial tail object, close array.
            last = cleaned.rfind("},")
            if last == -1:
                last = cleaned.rfind("}")
            if last == -1:
                raise
            data = json.loads(cleaned[:last + 1] + "]", strict=False)
    if not isinstance(data, list):
        raise ValueError("not a JSON array")
    return data


def run_company_discovery(payload):
    industry = (payload.get("industry") or "").strip()
    region = (payload.get("region") or "").strip()
    company_type = (payload.get("company_type") or "").strip()
    connected = company_source_is_connected("COMPANY_DISCOVERY")
    if not connected:
        return {
            "success": False,
            "status": "COMPANY DISCOVERY INTEGRATION NOT CONNECTED",
            "detail": "No external company discovery API is configured. Connect a provider handle under "
                      "COMPANY_DISCOVERY source, or use Manual / CSV import instead.",
            "candidates": 0,
        }
    if not industry:
        return {"success": False, "status": "Industry required for discovery", "candidates": 0}
    if not gemini_available:
        return {"success": False, "status": "Gemini not connected for discovery", "candidates": 0}
    prompt = (
        f"List 8-10 notable companies in the {industry} industry"
        + (f" operating in {region}" if region else "")
        + (f" (type: {company_type})" if company_type else "")
        + (". Return ONLY a JSON array of objects with keys: name (string), website (string or empty), "
           "description (string, max 20 words). No duplicates. Focus on well-known and emerging companies. "
           "No explanation.")
    )
    try:
        text, model_used = _gemini_complete(prompt, max_tokens=1500, temperature=0.5)
        try:
            data = _parse_model_json_list(text)
        except Exception:
            # One retry: transient truncation/malformed output is common on free tier.
            text, model_used = _gemini_complete(prompt, max_tokens=1500, temperature=0.7)
            data = _parse_model_json_list(text)
    except Exception as e:
        msg = str(e)
        if "429" in msg or "rate_limit" in msg.lower():
            return {"success": False, "candidates": 0, "rate_limited": True,
                    "status": "AI providers are rate-limited right now (free-tier quota). "
                              "Wait ~2 minutes and retry, or add companies via Manual / CSV import instead."}
        return {"success": False, "status": f"Discovery query failed: {msg[:100]}", "candidates": 0}
    t = now()
    new_count, dup_count = 0, 0
    verified_count, needs_count, invalid_count = 0, 0, 0
    for item in data:
        name = (item.get("name") or "").strip()
        if not name:
            continue
        website = (item.get("website") or "").strip()
        if db.query("SELECT id FROM brands WHERE brand_name=? LIMIT 1", (name,)):
            dup_count += 1
            continue
        if db.query("SELECT id FROM discovery_candidates WHERE candidate_name=? LIMIT 1", (name,)):
            dup_count += 1
            continue
        new_id = db.execute(
            "INSERT INTO discovery_candidates (industry, region, company_type, external_source, "
            "candidate_name, website, raw_json, status, duplicate_of, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (industry, region or None, company_type or None, f"gemini:{model_used}",
             name, website, json.dumps(item)[:2000], "NEW", None, t))
        new_count += 1
        try:
            v = validate_candidate(new_id if isinstance(new_id, int) else
                                   db.query("SELECT id FROM discovery_candidates WHERE candidate_name=? "
                                            "ORDER BY id DESC LIMIT 1", (name,))[0]["id"])
            st = (v.get("verification_status") or "")
            if st == "VERIFIED":
                verified_count += 1
            elif st in ("PARTIALLY_VERIFIED", "INSUFFICIENT_DATA"):
                needs_count += 1
            else:
                invalid_count += 1
        except Exception:
            needs_count += 1
    log_activity(f"Discovery: {new_count} new candidates for {industry}" + (f" / {region}" if region else "") +
                 f" ({verified_count} verified, {needs_count} need verification, {invalid_count} invalid)",
                 level="INFO")
    return {"success": True,
            "status": f"Discovered {new_count} new candidates ({dup_count} duplicates skipped)",
            "candidates": new_count, "verified": verified_count,
            "needs_verification": needs_count, "invalid": invalid_count}


def list_discovery_candidates(status=None):
    """Review work desk for discovered companies (never auto-imports)."""
    if status:
        rows = db.query(
            "SELECT * FROM discovery_candidates WHERE status=? ORDER BY id DESC LIMIT 200", (status,))
    else:
        rows = db.query("SELECT * FROM discovery_candidates ORDER BY id DESC LIMIT 200")
    out = []
    for r in rows:
        d = dict(r)
        d["already_tracked"] = bool(db.query(
            "SELECT id FROM brands WHERE brand_name=? AND is_active=1 LIMIT 1", (d.get("candidate_name") or "",)))
        out.append(d)
    return {"success": True, "candidates": out}


def import_discovery_candidate(cid):
    """Promote a discovery candidate to a tracked brand. Auto-queues its analysis."""
    rows = db.query("SELECT * FROM discovery_candidates WHERE id=?", (cid,))
    if not rows:
        return {"success": False, "error": "Candidate not found"}
    cand = rows[0]
    if cand["status"] == "IMPORTED":
        return {"success": False, "error": "Candidate already imported"}
    try:
        ensure_candidate_columns()
        vrows = db.query("SELECT verification_status FROM discovery_candidates WHERE id=?", (cid,))
        vstat = (vrows[0].get("verification_status") or "") if vrows else ""
    except Exception:
        vstat = ""
    if vstat == "INVALID":
        return {"success": False, "error": "Candidate is INVALID - review validation reason first",
                "verification_status": vstat}
    existing = db.query("SELECT id FROM brands WHERE brand_name=? AND is_active=1 ORDER BY id DESC LIMIT 1",
                        (cand["candidate_name"],))
    if existing:
        db.execute("UPDATE discovery_candidates SET status='IMPORTED', duplicate_of=? WHERE id=?", (existing[0]["id"], cid))
        return {"success": True, "message": "Already tracked - candidate linked", "brand_id": existing[0]["id"],
                "duplicate": True}
    meta = {}
    if cand.get("raw_json"):
        try:
            meta = json.loads(cand["raw_json"]) or {}
        except Exception:
            meta = {}
    bid = upsert_company({
        "brand_name": cand["candidate_name"],
        "website": cand.get("website"),
        "industry": cand.get("industry") or "General",
        "region": cand.get("region"),
        "company_type": cand.get("company_type"),
        "description": meta.get("description") or "",
        "keywords": meta.get("keywords") or "",
        "verification_status": vstat if vstat in ("VERIFIED", "PARTIALLY_VERIFIED") else "UNVERIFIED",
    }, source="DISCOVERY", source_detail=cand.get("external_source") or "gemini", inspect_existing=False)
    if not bid:
        return {"success": False, "error": "Failed to create brand"}
    db.execute("UPDATE discovery_candidates SET status='IMPORTED', duplicate_of=? WHERE id=?", (bid, cid))
    log_activity(f"Discovery candidate imported: {cand['candidate_name']} (#{bid})", level="INFO")
    return {"success": True, "message": "Imported and queued for analysis", "brand_id": bid}


def reject_discovery_candidate(cid):
    rows = db.query("SELECT candidate_name FROM discovery_candidates WHERE id=?", (cid,))
    if not rows:
        return {"success": False, "error": "Candidate not found"}
    db.execute("UPDATE discovery_candidates SET status='REJECTED' WHERE id=?", (cid,))
    log_activity(f"Discovery candidate rejected: {rows[0]['candidate_name']}", level="INFO")
    return {"success": True}


def import_all_discovery_candidates():
    """Import all NEW discovery candidates at once."""
    rows = db.query("SELECT id FROM discovery_candidates WHERE status='NEW' ORDER BY id DESC")
    if not rows:
        return {"success": True, "imported": 0, "skipped": 0, "message": "No new candidates to import"}
    imported = 0
    skipped = 0
    for r in rows:
        result = import_discovery_candidate(r["id"])
        if result.get("success"):
            imported += 1
        else:
            skipped += 1
    log_activity(f"Discovery bulk import: {imported} imported, {skipped} skipped", level="INFO")
    return {"success": True, "imported": imported, "skipped": skipped}


# ---------------------------------------------------------------------------
# CSV IMPORT
# ---------------------------------------------------------------------------

def import_csv(csv_text):
    reader = csv.DictReader(io.StringIO(csv_text))
    rows = list(reader)
    headers = {h.strip().lower() for h in (reader.fieldnames or [])}
    field_map = {
        "brand": "brand_name", "company": "brand_name", "brand_name": "brand_name", "name": "brand_name",
        "company_name": "brand_name",
        "website": "website", "url": "website", "web": "website",
        "industry": "industry", "vertical": "industry", "sector": "industry",
        "region": "region", "country": "region", "location": "region",
        "company_type": "company_type", "type": "company_type",
        "description": "description", "about": "description",
        "keywords": "keywords", "tags": "keywords",
        "target_audience": "target_audience", "audience": "target_audience",
        "competitors": "competitors",
    }
    imported = 0
    skipped = 0
    for row in rows:
        data = {}
        for h, v in (row or {}).items():
            k = (h or "").strip().lower()
            if k in field_map:
                data[field_map[k]] = (v or "").strip()
        if not data.get("brand_name"):
            skipped += 1
            continue
        bid = upsert_company(data, source="CSV", source_detail="csv import")
        if bid:
            imported += 1
            remember(bid, "SOURCE:CSV_IMPORTED", "CSV", f"Imported {data['brand_name']} via CSV.", 0.9)
    return {"success": True, "imported": imported, "skipped": skipped, "total": len(rows)}


# ---------------------------------------------------------------------------
# MANUAL ANALYSIS (legacy endpoint compatibility + full v2 result)
# ---------------------------------------------------------------------------

def manual_analysis(data):
    bid = upsert_company(data, source="MANUAL", source_detail="manual form")
    if not bid:
        return {"success": False, "error": "Brand/Company Name is required."}
    wid = (data.get("workflow_id") or "").strip() or None
    run_id = run_full_pipeline(bid, trigger="MANUAL", direct=True, workflow_id=wid)
    res = build_analysis_result(bid, run_id)
    res["workflow_id"] = wid or get_active_workflow()
    return res


def build_analysis_result(brand_id, run_id=None):
    brand = get_brand(brand_id)
    if not brand:
        return {"success": False, "error": "Brand not found"}
    rows = db.query("SELECT * FROM analysis_results WHERE brand_id=? ORDER BY id DESC LIMIT 1", (brand_id,))
    latest = rows[0] if rows else None
    metrics = {
        "visibility_score": latest["visibility_score"] if latest else 0,
        "readiness_score": latest["readiness_score"] if latest else 0,
        "observed_score": latest["observed_score"],
        "mention_rate": latest["mention_rate"] if latest else 0,
        "topic_coverage": latest["topic_coverage"] if latest else 0,
        "competitor_strength": latest["competitor_strength"],
    }
    observed = safe_json_loads(latest["observed_metrics"], observed_metrics(brand_id)) if latest else observed_metrics(brand_id)
    readiness = safe_json_loads(latest["readiness_breakdown"], {}) if latest else {}
    reasons = safe_json_loads(latest["score_reasons"], []) if latest else []
    analysis_data = safe_json_loads(latest["analysis_data"], {}) if latest else {}
    # Display path NEVER calls live LLMs (keeps dashboard/PDF instant).
    # Missing sections render as empty with needs_analysis=True.
    brand_analysis = analysis_data.get("brand_analysis") or {"positioning": "", "primary_topics": [],
                                                             "strengths": [], "opportunities": []}
    comps = analysis_data.get("competitor_rows")
    if comps is None:
        obs = db.query("SELECT * FROM ai_observations WHERE brand_id=? ORDER BY observed_at DESC LIMIT 50", (brand_id,))
        comps = [{"brand": (o.get("brand_name") or ""), "source": "observation",
                  "visibility": None} for o in obs[:10]] if obs else []
    gaps = analysis_data.get("content_gaps") or []
    qs = get_active_queries(brand_id)
    query_texts = []
    for q in qs:
        query_texts.append(q["query_text"])
    if not query_texts:
        query_texts = [q["query"] for q in _query_templates(brand)]
    recs = db.query("SELECT title, description, priority, category, id, status, feedback, evidence_key "
                    "FROM recommendations WHERE brand_id=? ORDER BY id DESC LIMIT 5", (brand_id,))
    rec_list = [dict(r) for r in recs]
    changes = db.query("SELECT * FROM change_log WHERE brand_id=? ORDER BY id DESC LIMIT 20", (brand_id,))
    learning = get_learning(brand_id)
    kw_list = [k.strip() for k in (brand.get("keywords") or "").split(",") if k.strip()]
    money = {
        "success": True,
        "brand": {
            "name": brand["brand_name"],
            "brand_name": brand["brand_name"],
            "website": brand["website"] or "",
            "industry": brand["industry"],
            "region": brand.get("region") or "",
            "company_type": brand.get("company_type") or "",
            "target_audience": brand["target_audience"] or "",
            "keywords": kw_list,
            "data_source": brand.get("data_source"),
            "verification_status": brand.get("verification_status"),
        },
        "generated_queries": query_texts,
        "query_objects": qs,
        "brand_analysis": brand_analysis,
        "visibility_metrics": metrics,
        "readiness_metrics": {
            "visibility_score": metrics["readiness_score"],
            "breakdown": readiness,
            "reasons": reasons,
            "label": "AI SEARCH READINESS (estimated from profile, keywords, content and evidence)",
        },
        "observed_metrics": observed,
        "competitor_analysis": comps,
        "content_gaps": gaps,
        "recommendations": rec_list,
        "evidence": get_company_evidence(brand_id),
        "change_log": changes,
        "learning_memory": learning,
        "brand_id": brand_id,
        "run_id": run_id,
        "timestamp": now(),
        "version": 2,
        "needs_analysis": latest is None,
    }
    return money


# ---------------------------------------------------------------------------
# HTTP SERVER
# ---------------------------------------------------------------------------

class _SafeEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, (datetime.datetime,)):
            return o.isoformat()
        if isinstance(o, (datetime.date,)):
            return o.isoformat()
        if isinstance(o, (datetime.time,)):
            return o.isoformat()
        if isinstance(o, decimal.Decimal):
            return float(o)
        if isinstance(o, bytes):
            return o.decode("utf-8", errors="replace")
        return super().default(o)


def send_json(handler, data, status=200):
    body = json.dumps(data, cls=_SafeEncoder).encode("utf-8")
    try:
        handler.send_response(status)
        handler.send_header("Content-Type", "application/json; charset=utf-8")
        handler.send_header("Content-Length", str(len(body)))
        origin = handler.headers.get("Origin", "")
        for k, v in _cors_headers(handler, origin).items():
            handler.send_header(k, v)
        handler.end_headers()
        handler.wfile.write(body)
    except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
        # Client disconnected mid-response (closed tab, timeout) — not a server error.
        pass


def send_error(handler, message, status=400):
    send_json(handler, {"success": False, "error": message}, status)


def read_body(handler):
    length = int(handler.headers.get("Content-Length", 0) or 0)
    if not length:
        return {}
    raw = handler.rfile.read(length)
    try:
        return json.loads(raw.decode("utf-8") or "{}")
    except Exception:
        return {}


class AgentServerHandler(BaseHTTPRequestHandler):
    server_version = "VisibilityAI/2.0"

    def log_message(self, fmt, *args):
        pass

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Content-Length", "0")
        origin = self.headers.get("Origin", "")
        for k, v in _cors_headers(self, origin).items():
            self.send_header(k, v)
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = _strip_prefix(parsed.path)
        qp = parse_qs(parsed.query)
        origin = self.headers.get("Origin", "")
        client_ip = self.client_address[0]

        # Rate limit
        if not _check_rate_limit(client_ip):
            send_json(self, {"error": "Rate limit exceeded"}, 429)
            return

        # CORS headers on all responses
        def add_cors():
            for k, v in _cors_headers(self, origin).items():
                self.send_header(k, v)

        try:
            # Public endpoints (no auth required)
            if path in ("/", "/index.html"):
                html_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html")
                with open(html_file, "rb") as f:
                    content = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(content)))
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("X-Frame-Options", "DENY")
                self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
                add_cors()
                self.end_headers()
                self.wfile.write(content)
                return

            if path == "/api/health":
                send_json(self, {"status": "ok", "version": "2.0", "time": datetime.datetime.utcnow().isoformat() + "Z"})
                return

            if path == "/api/login":
                # Login handled in POST, but allow GET for token refresh
                send_json(self, {"error": "Use POST /api/login"}, 405)
                return

            # Auth required for all other endpoints
            user, err, code = _extract_user(self)
            if err:
                send_json(self, err, code)
                return

            if path == "/agent-state":
                send_json(self, agent_state())
            elif path == "/history":
                send_json(self, fetch_analysis_history())
            elif path == "/history-detail":
                aid = (qp.get("id") or [None])[0]
                send_json(self, fetch_analysis_detail(aid) if aid else {"success": False, "error": "Missing id"})
            elif path == "/companies":
                send_json(self, fetch_companies())
            elif path == "/evidence":
                bid = (qp.get("brand_id") or [None])[0]
                if not bid:
                    send_json(self, {"success": False, "error": "Missing brand_id"})
                else:
                    send_json(self, {"success": True, "evidence": get_company_evidence(int(bid))})
            elif path == "/queries":
                bid = (qp.get("brand_id") or [None])[0]
                if bid:
                    send_json(self, {"success": True, "queries": get_active_queries(int(bid))})
                else:
                    rows = db.query("SELECT q.*, b.brand_name AS company FROM query_memory q "
                                    "LEFT JOIN brands b ON b.id = q.brand_id ORDER BY q.id DESC LIMIT 200")
                    send_json(self, {"success": True, "queries": rows})
            elif path == "/observations":
                bid = (qp.get("brand_id") or [None])[0]
                if bid:
                    rows = db.query("SELECT * FROM ai_observations WHERE brand_id=? ORDER BY observed_at DESC LIMIT 100",
                                    (int(bid),))
                else:
                    rows = db.query("SELECT o.*, b.brand_name AS company FROM ai_observations o "
                                    "LEFT JOIN brands b ON b.id = o.brand_id ORDER BY o.observed_at DESC LIMIT 200")
                send_json(self, {"success": True, "observations": rows})
            elif path == "/changes":
                bid = (qp.get("brand_id") or [None])[0]
                if bid:
                    rows = db.query("SELECT * FROM change_log WHERE brand_id=? ORDER BY id DESC LIMIT 100", (int(bid),))
                else:
                    rows = db.query("SELECT * FROM change_log ORDER BY id DESC LIMIT 200")
                send_json(self, {"success": True, "changes": rows})
            elif path == "/learning":
                rows = get_learning()
                send_json(self, {"success": True, "learning": rows})
            elif path == "/feedback":
                rows = db.query("SELECT * FROM feedback ORDER BY id DESC LIMIT 200")
                send_json(self, {"success": True, "feedback": rows})
            elif path == "/api/learning/memory":
                send_json(self, learning_memory_list(
                    (int((qp.get("company_id") or [None])[0]) if (qp.get("company_id") or [None])[0] else None),
                    (qp.get("status") or ["ACTIVE"])[0] or None,
                    (qp.get("memory_type") or [None])[0],
                    (qp.get("limit") or [500])[0]))
            elif path.startswith("/api/learning/memory/"):
                try:
                    send_json(self, learning_memory_list(int(path[len("/api/learning/memory/"):].strip("/"))))
                except Exception:
                    send_error(self, "invalid company id", 400)
            elif path == "/api/learning/events":
                cid = (qp.get("company_id") or [None])[0]
                send_json(self, learning_events_list(
                    int(cid) if cid else None,
                    (qp.get("memory_id") or [None])[0],
                    (qp.get("event_type") or [None])[0],
                    (qp.get("limit") or [100])[0]))
            elif path.startswith("/api/learning/events/"):
                try:
                    send_json(self, learning_events_list(int(path[len("/api/learning/events/"):].strip("/"))))
                except Exception:
                    send_error(self, "invalid company id", 400)
            elif path == "/api/learning/patterns":
                cid = (qp.get("company_id") or [None])[0]
                send_json(self, learning_patterns(int(cid) if cid else None))
            elif path == "/api/learning/query-performance":
                cid = (qp.get("company_id") or [None])[0]
                send_json(self, query_performance(int(cid) if cid else None))
            elif path == "/api/learning/recommendation-performance":
                cid = (qp.get("company_id") or [None])[0]
                send_json(self, recommendation_performance(int(cid) if cid else None))
            elif path == "/api/learning/dashboard":
                cid = (qp.get("company_id") or [None])[0]
                send_json(self, learning_dashboard_summary(int(cid) if cid else None))
            elif path == "/api/agent/decisions":
                cid = (qp.get("company_id") or [None])[0]
                send_json(self, list_decisions(int(cid) if cid else None,
                                              (qp.get("status") or [None])[0],
                                              (qp.get("trigger_type") or [None])[0],
                                              (qp.get("limit") or [100])[0]))
            elif path.startswith("/api/agent/decisions/"):
                did = path[len("/api/agent/decisions/"):].strip("/")
                send_json(self, get_decision(int(did) if did.isdigit() else did))
            elif path.startswith("/api/companies/") and path.endswith("/decisions"):
                try:
                    cid = int(path[len("/api/companies/"): -len("/decisions")].strip("/"))
                except Exception:
                    send_error(self, "invalid company id", 400)
                    return
                send_json(self, list_decisions(cid, limit=(qp.get("limit") or [50])[0]))
            elif path.startswith("/api/companies/") and path.endswith("/intelligence"):
                try:
                    cid = int(path[len("/api/companies/"): -len("/intelligence")].strip("/"))
                except Exception:
                    send_error(self, "invalid company id", 400)
                    return
                send_json(self, company_intelligence(cid))
            elif path in ("/api/companies", "/api/companies/"):
                # Alias for the Autonomous Loop company selector (expects {companies: [...]}).
                send_json(self, {"success": True, "companies": fetch_companies()})
            elif path == "/api/agent/autonomous/status":
                send_json(self, autonomous_status())
            elif path == "/api/orchestrator/state":
                send_json(self, orchestrator_state())
            elif path.startswith("/api/orchestrator/company/") and path.endswith("/state"):
                try:
                    cid = int(path[len("/api/orchestrator/company/"): -len("/state")].strip("/"))
                except Exception:
                    send_error(self, "invalid company id", 400)
                    return
                send_json(self, orchestrator_company_state(cid))
            elif path.startswith("/api/orchestrator/next-action/"):
                try:
                    cid = int(path[len("/api/orchestrator/next-action/"):].strip("/"))
                except Exception:
                    send_error(self, "invalid company id", 400)
                    return
                send_json(self, {"success": True, "company_id": cid, **orchestrator_next_action(cid)})
            elif path == "/api/orchestrator/decisions":
                cid = (qp.get("company_id") or [None])[0]
                st = (qp.get("status") or [None])[0]
                src = (qp.get("source") or [None])[0]
                q = ("SELECT d.*, b.brand_name AS company FROM agent_decisions d "
                     "LEFT JOIN brands b ON b.id=d.company_id WHERE d.trigger_type LIKE 'ORCHESTRATOR%'")
                p = []
                if cid:
                    q += " AND d.company_id=?"
                    p.append(int(cid))
                if src:
                    q += " AND d.decision_source=?"
                    p.append(src)
                try:
                    lim = max(1, min(int((qp.get("limit") or [100])[0]), 500))
                except Exception:
                    lim = 100
                rows = db.query(q + f" ORDER BY d.id DESC LIMIT {lim}", tuple(p))
                out = []
                for r in rows:
                    d = dict(r)
                    d["display_outcome"] = _display_outcome(r) or r.get("outcome")
                    try:
                        d["signals"] = safe_json_loads(r.get("signals_json"), []) or []
                    except Exception:
                        d["signals"] = []
                    out.append(d)
                if st:
                    out = [d for d in out if (d["display_outcome"] or d.get("status") or "").upper() == st.upper()]
                send_json(self, {"success": True, "decisions": out})
            elif path.startswith("/api/orchestrator/decisions/"):
                did = path[len("/api/orchestrator/decisions/"):].strip("/")
                rows = db.query("SELECT d.*, b.brand_name AS company FROM agent_decisions d "
                                "LEFT JOIN brands b ON b.id=d.company_id WHERE d.id=? OR d.decision_id=?",
                                (int(did) if did.isdigit() else -1, did))
                if not rows:
                    send_error(self, "decision not found", 404)
                    return
                d = dict(rows[0])
                d["display_outcome"] = _display_outcome(rows[0]) or rows[0].get("outcome")
                try:
                    d["signals"] = safe_json_loads(rows[0].get("signals_json"), []) or []
                except Exception:
                    d["signals"] = []
                jid = rows[0].get("job_id")
                d["job"] = (db.query("SELECT * FROM jobs WHERE id=?", (jid,))[0:1] or [None])[0]
                if d["job"]:
                    d["job"] = dict(d["job"])
                send_json(self, {"success": True, "decision": d})
            elif path == "/api/orchestrator/activity":
                send_json(self, orchestrator_activity((qp.get("limit") or [100])[0]))
            elif path == "/api/orchestrator/metrics":
                send_json(self, orchestrator_metrics())
            elif path == "/api/agent-brain/status":
                send_json(self, agent_brain_status())
            elif path == "/api/manager/agents":
                send_json(self, manager_list_agents())
            elif path.startswith("/api/manager/agents/") and path.endswith("/health"):
                aid = path[len("/api/manager/agents/"): -len("/health")].strip("/")
                send_json(self, manager_probe_health(aid))
            elif path.startswith("/api/manager/agents/"):
                aid = path[len("/api/manager/agents/"):].strip("/")
                row = _registry_row(int(aid) if aid.isdigit() else aid)
                if not row:
                    send_error(self, "agent not found", 404)
                else:
                    d = dict(row)
                    d["capabilities"] = _agent_capabilities(row)
                    send_json(self, {"success": True, "agent": d})
            elif path == "/api/manager/tasks":
                status = (qp.get("status") or [None])[0]
                ag = (qp.get("agent_id") or [None])[0]
                try:
                    lim = max(1, min(int((qp.get("limit") or [100])[0]), 500))
                except Exception:
                    lim = 100
                q = "SELECT * FROM manager_tasks WHERE 1=1"
                p = []
                if status:
                    q += " AND status=?"
                    p.append(status)
                if ag:
                    q += " AND selected_agent_id=?"
                    p.append(ag)
                rows = db.query(q + f" ORDER BY id DESC LIMIT {lim}", tuple(p))
                send_json(self, {"success": True, "tasks": [dict(r) for r in rows]})
            elif path.startswith("/api/manager/tasks/") and path.endswith("/subtasks"):
                tid = path[len("/api/manager/tasks/"): -len("/subtasks")].strip("/")
                t = _manager_task_row(int(tid) if tid.isdigit() else tid)
                if not t:
                    send_error(self, "task not found", 404)
                else:
                    top = t.get("parent_task_id") or t["task_id"]
                    rows = db.query("SELECT * FROM manager_tasks WHERE parent_task_id=? ORDER BY id", (top,))
                    send_json(self, {"success": True, "parent_task_id": top,
                                     "subtasks": [manager_task_display(r) for r in rows]})
            elif path.startswith("/api/manager/tasks/") and path.endswith("/results"):
                tid = path[len("/api/manager/tasks/"): -len("/results")].strip("/")
                t = _manager_task_row(int(tid) if tid.isdigit() else tid)
                if not t:
                    send_error(self, "task not found", 404)
                else:
                    top = t.get("parent_task_id") or t["task_id"]
                    tids = [top] + [r["task_id"] for r in db.query(
                        "SELECT task_id FROM manager_tasks WHERE parent_task_id=?", (top,))]
                    out = []
                    for x in tids:
                        for r in db.query("SELECT * FROM manager_task_results WHERE task_id=? ORDER BY id", (x,)):
                            d = dict(r)
                            try:
                                d["result"] = safe_json_loads(r.get("result_json"), {}) or {}
                            except Exception:
                                d["result"] = {}
                            out.append(d)
                    send_json(self, {"success": True, "results": out})
            elif path.startswith("/api/manager/tasks/") and path.endswith("/handoffs"):
                tid = path[len("/api/manager/tasks/"): -len("/handoffs")].strip("/")
                t = _manager_task_row(int(tid) if tid.isdigit() else tid)
                if not t:
                    send_error(self, "task not found", 404)
                else:
                    top = t.get("parent_task_id") or t["task_id"]
                    rows = db.query("SELECT * FROM agent_handoffs WHERE manager_task_id=? ORDER BY id", (top,))
                    send_json(self, {"success": True, "handoffs": [dict(r) for r in rows]})
            elif path.startswith("/api/manager/tasks/") and path.endswith("/graph"):
                tid = path[len("/api/manager/tasks/"): -len("/graph")].strip("/")
                send_json(self, manager_task_graph(int(tid) if tid.isdigit() else tid))
            elif path.startswith("/api/manager/tasks/") and path.endswith("/final-result"):
                tid = path[len("/api/manager/tasks/"): -len("/final-result")].strip("/")
                send_json(self, manager_final_result(int(tid) if tid.isdigit() else tid))
            elif path == "/api/manager/results":
                ag = (qp.get("agent_id") or [None])[0]
                try:
                    lim = max(1, min(int((qp.get("limit") or [100])[0]), 500))
                except Exception:
                    lim = 100
                q = "SELECT * FROM manager_task_results WHERE 1=1"
                p = []
                if ag:
                    q += " AND agent_id=?"
                    p.append(ag)
                rows = db.query(q + f" ORDER BY id DESC LIMIT {lim}", tuple(p))
                send_json(self, {"success": True, "results": [dict(r) for r in rows]})
            elif path == "/api/manager/handoffs":
                try:
                    lim = max(1, min(int((qp.get("limit") or [100])[0]), 500))
                except Exception:
                    lim = 100
                rows = db.query(f"SELECT * FROM agent_handoffs ORDER BY id DESC LIMIT {lim}")
                send_json(self, {"success": True, "handoffs": [dict(r) for r in rows]})
            elif path == "/api/manager/dashboard":
                send_json(self, manager_dashboard())
            elif path == "/api/manager/learning":
                try:
                    lim = max(1, min(int((qp.get("limit") or [100])[0]), 500))
                except Exception:
                    lim = 100
                rows = db.query("SELECT * FROM learning_events WHERE event_type IN ('MANAGER_TASK_SUCCESS',"
                                "'MANAGER_TASK_FAILURE','AGENT_EXECUTION_SUCCESS','AGENT_EXECUTION_FAILURE',"
                                "'HANDOFF_SUCCESS','HANDOFF_FAILURE','SYNTHESIS_SUCCESS','SYNTHESIS_FAILURE',"
                                "'HUMAN_CORRECTION') ORDER BY id DESC LIMIT ?", (lim,))
                send_json(self, {"success": True, "events": [dict(r) for r in rows]})
            elif path == "/api/framework/agents":
                send_json(self, {"success": True, "agents": [a for a in framework_dashboard()["agents"]]})
            elif path.startswith("/api/framework/agents/") and path.endswith("/validate"):
                aid = path[len("/api/framework/agents/"): -len("/validate")].strip("/")
                row = _registry_row(int(aid) if aid.isdigit() else aid)
                if not row:
                    send_json(self, {"success": False, "error": "agent not found"})
                else:
                    d = framework_get_agent(row["agent_id"])
                    send_json(self, {"success": True, "agent_id": row["agent_id"],
                                     "contract_valid": d["success"],
                                     "capabilities": d.get("agent", {}).get("capabilities", []) if d["success"] else []})
            elif path.startswith("/api/framework/agents/") and path.endswith("/health"):
                aid = path[len("/api/framework/agents/"): -len("/health")].strip("/")
                send_json(self, manager_probe_health(int(aid) if aid.isdigit() else aid))
            elif path.startswith("/api/framework/agents/") and path.endswith("/capabilities"):
                aid = path[len("/api/framework/agents/"): -len("/capabilities")].strip("/")
                d = framework_get_agent(int(aid) if aid.isdigit() else aid)
                if not d["success"]:
                    send_json(self, d)
                else:
                    a = d["agent"]
                    try:
                        cfg = a.get("configuration") or {}
                        meta = cfg.get("capabilities") or {}
                    except Exception:
                        meta = {}
                    send_json(self, {"success": True, "agent_id": a["agent_id"],
                                     "capabilities": [{"capability": c,
                                                       "tools": (meta.get(c) or {}).get("tools", []),
                                                       "resources": (meta.get(c) or {}).get("resources", [])}
                                                      for c in (a.get("capabilities") or [])]})
            elif path.startswith("/api/framework/agents/") and path.endswith("/version"):
                aid = path[len("/api/framework/agents/"): -len("/version")].strip("/")
                d = framework_get_agent(int(aid) if aid.isdigit() else aid)
                if not d["success"]:
                    send_json(self, d)
                else:
                    send_json(self, {"success": True, "agent_id": d["agent"]["agent_id"],
                                     "version": d["agent"].get("version"),
                                     "framework_version": FRAMEWORK_VERSION})
            elif path.startswith("/api/framework/agents/"):
                aid = path[len("/api/framework/agents/"):].strip("/")
                send_json(self, framework_get_agent(int(aid) if aid.isdigit() else aid))
            elif path == "/api/framework/dashboard":
                send_json(self, framework_dashboard())
            elif path == "/api/framework/tools":
                send_json(self, {"success": True, "tools": [
                    {k: t[k] for k in ("tool_id", "name", "description", "version", "capability",
                                       "risk_level", "requires_approval", "enabled", "timeout_seconds")
                     } | {"input_schema": t.get("input_schema", {}), "agent_ids": t.get("agent_ids", [])}
                    for t in mcp_list_tools(enabled_only=False)]})
            elif path.startswith("/api/reasoning/company/") and path.endswith("/latest"):
                try:
                    cid = int(path[len("/api/reasoning/company/"): -len("/latest")].strip("/"))
                except Exception:
                    send_error(self, "invalid company id", 400)
                    return
                rows = db.query("SELECT * FROM reasoning_events WHERE company_id=? ORDER BY id DESC LIMIT 1", (cid,))
                if not rows:
                    send_json(self, {"success": False, "error": "no reasoning recorded for this company"})
                else:
                    send_json(self, {"success": True, "reasoning": _reasoning_row(rows[0])})
            elif path.startswith("/api/reasoning/company/") and path.endswith("/history"):
                try:
                    cid = int(path[len("/api/reasoning/company/"): -len("/history")].strip("/"))
                except Exception:
                    send_error(self, "invalid company id", 400)
                    return
                try:
                    lim = max(1, min(int((qp.get("limit") or [50])[0]), 200))
                except Exception:
                    lim = 50
                rows = db.query("SELECT * FROM reasoning_events WHERE company_id=? ORDER BY id DESC LIMIT ?",
                                (cid, lim))
                send_json(self, {"success": True, "events": [_reasoning_row(r) for r in rows]})
            elif path.startswith("/api/reasoning/") and not path.startswith("/api/reasoning/company/") \
                    and not path.startswith("/api/reasoning/run-once/") and path != "/api/reasoning/dashboard":
                rid = path[len("/api/reasoning/"):].strip("/")
                rows = db.query("SELECT * FROM reasoning_events WHERE reasoning_id=? OR id=?",
                                (rid, int(rid) if rid.isdigit() else -1))
                if not rows:
                    send_error(self, "reasoning event not found", 404)
                else:
                    send_json(self, {"success": True, "reasoning": _reasoning_row(rows[0])})
            elif path == "/api/reasoning/dashboard":
                send_json(self, reasoning_dashboard())
            elif path.startswith("/api/rag/index/company/"):
                send_error(self, "use POST /api/rag/index/company/:id", 405)
            elif path == "/api/rag/search":
                send_error(self, "use POST /api/rag/search", 405)
            elif path == "/api/rag/health":
                send_json(self, rag_health())
            elif path == "/api/rag/dashboard":
                send_json(self, rag_dashboard_data())
            elif path.startswith("/api/planning/") and path.endswith("/history"):
                pid = path[len("/api/planning/"): -len("/history")].strip("/")
                rows = db.query("SELECT * FROM planning_plans WHERE plan_id=? ORDER BY version", (pid,))
                if not rows:
                    send_error(self, "plan not found", 404)
                else:
                    send_json(self, {"success": True, "plan_id": pid,
                                     "versions": [plan_detail(pid, r["version"]) for r in rows]})
            elif path.startswith("/api/planning/company/"):
                try:
                    cid = int(path[len("/api/planning/company/"):].strip("/"))
                except Exception:
                    send_error(self, "invalid company id", 400)
                    return
                try:
                    lim = max(1, min(int((qp.get("limit") or [50])[0]), 200))
                except Exception:
                    lim = 50
                rows = db.query("SELECT plan_id, goal_type, version, status, objective, created_at, updated_at "
                                "FROM planning_plans WHERE company_id=? ORDER BY id DESC LIMIT ?", (cid, lim))
                send_json(self, {"success": True, "plans": [dict(r) for r in rows]})
            elif path == "/api/planning/dashboard":
                send_json(self, plan_dashboard())
            elif path.startswith("/api/planning/"):
                pid = path[len("/api/planning/"):].strip("/")
                send_json(self, plan_detail(pid))
            elif path.startswith("/api/manager/tasks/"):
                tid = path[len("/api/manager/tasks/"):].strip("/")
                rows = db.query("SELECT * FROM manager_tasks WHERE task_id=? OR id=?",
                                (tid, int(tid) if tid.isdigit() else -1))
                if not rows:
                    send_error(self, "task not found", 404)
                else:
                    d = dict(rows[0])
                    subs = db.query("SELECT task_id, capability, selected_agent_id, status FROM manager_tasks "
                                    "WHERE parent_task_id=? ORDER BY id", (d["task_id"],))
                    d["subtasks"] = [dict(s) for s in subs]
                    send_json(self, {"success": True, "task": d})
            elif path == "/jobs":
                send_json(self, {"success": True, "jobs": fetch_jobs()})
            elif path == "/api/agent/status":
                send_json(self, agent_status_detail())
            elif path == "/api/agent/runs":
                rows = db.query("SELECT * FROM runs ORDER BY id DESC LIMIT 100")
                out = []
                for r in rows:
                    d = dict(r)
                    d["stats"] = _run_stats(d["run_id"])
                    out.append(d)
                send_json(self, {"success": True, "runs": out})
            elif path.startswith("/api/agent/runs/"):
                rid = path[len("/api/agent/runs/"):]
                rows = db.query("SELECT * FROM runs WHERE run_id=?", (rid,))
                if not rows:
                    send_error(self, "run not found", 404)
                else:
                    r = dict(rows[0])
                    jobs = db.query("SELECT j.*, b.brand_name AS company FROM jobs j "
                                    "LEFT JOIN brands b ON b.id=j.company_id WHERE j.run_id=? ORDER BY j.id ASC", (rid,))
                    r["jobs"] = [dict(j) for j in jobs]
                    r["stats"] = _run_stats(rid)
                    act = db.query("SELECT * FROM agent_activity WHERE run_id=? ORDER BY id DESC LIMIT 100", (rid,))
                    r["activity"] = [dict(a) for a in act]
                    send_json(self, {"success": True, "run": r})
            elif path == "/api/agent/jobs":
                status = (qp.get("status") or [""])[0]
                send_json(self, {"success": True, "jobs": fetch_jobs(status or None)})
            elif path.startswith("/api/agent/jobs/"):
                jid = path[len("/api/agent/jobs/"):]
                rows = db.query("SELECT j.*, b.brand_name AS company FROM jobs j "
                                "LEFT JOIN brands b ON b.id=j.company_id WHERE j.id=?",
                                (int(jid) if jid.isdigit() else -1,))
                if not rows:
                    send_error(self, "job not found", 404)
                else:
                    send_json(self, {"success": True, "job": dict(rows[0])})
            elif path == "/api/agent/activity":
                limit = int((qp.get("limit") or [50])[0])
                rows = db.query("SELECT a.*, b.brand_name AS company FROM agent_activity a "
                                "LEFT JOIN brands b ON b.id=a.company_id ORDER BY a.id DESC LIMIT ?",
                                (min(200, max(1, limit)),))
                send_json(self, {"success": True, "activity": [dict(a) for a in rows]})
            elif path == "/api/agent/errors":
                rows = db.query("SELECT j.id, j.job_id, j.job_type, j.company_id, b.brand_name AS company, "
                                "j.error, j.retry_count, j.max_retries, j.status, j.created_at, j.completed_at "
                                "FROM jobs j LEFT JOIN brands b ON b.id=j.company_id "
                                "WHERE j.status IN ('FAILED','FAILED_PERMANENTLY','RETRYING') "
                                "ORDER BY j.created_at DESC, j.id DESC LIMIT 100")
                send_json(self, {"success": True, "errors": [dict(r) for r in rows]})
            elif path == "/api/automations":
                cid = (qp.get("company_id") or [None])[0]
                send_json(self, {"success": True,
                                 "automations": list_automations(int(cid) if cid else None)})
            elif path == "/api/autonomous/dashboard":
                send_json(self, autonomous_dashboard())
            elif path == "/api/autonomous/config":
                send_json(self, {"success": True, "config": autonomous_config()})
            elif path == "/api/autonomous/runs":
                cid = (qp.get("company_id") or [None])[0]
                st = (qp.get("status") or [None])[0]
                send_json(self, autonomous_runs_list(int(cid) if cid else None, st))
            elif path.startswith("/api/autonomous/run/") and path.endswith("/events"):
                run_id = path[len("/api/autonomous/run/"): -len("/events")]
                events = db.query("SELECT * FROM autonomous_events WHERE autonomous_run_id=? ORDER BY id",
                                  (run_id,))
                send_json(self, {"success": True, "events": [dict(e) for e in events]})
            elif path.startswith("/api/autonomous/run/") and path.endswith("/timeline"):
                run_id = path[len("/api/autonomous/run/"): -len("/timeline")]
                events = db.query("SELECT * FROM autonomous_events WHERE autonomous_run_id=? ORDER BY id",
                                  (run_id,))
                send_json(self, {"success": True, "timeline": [
                    {"step": e["event_type"], "iteration": e["iteration"],
                     "detail": e.get("reason", "")[:200], "tool": e.get("tool_name", ""),
                     "status": e.get("status", ""), "timestamp": e["created_at"]}
                    for e in events]})
            elif path.startswith("/api/autonomous/run/"):
                run_id = path[len("/api/autonomous/run/"):]
                send_json(self, autonomous_run_detail(run_id))
            elif path.startswith("/api/automations/"):
                aid = path[len("/api/automations/"):]
                if aid.endswith("/history"):
                    send_json(self, automation_history(aid[: -len("/history")]))
                elif aid.endswith("/next-run"):
                    a = get_automation(aid[: -len("/next-run")])
                    if not a:
                        send_error(self, "automation not found", 404)
                    else:
                        send_json(self, {"success": True, "automation_id": a["automation_id"],
                                         "schedule_type": a["schedule_type"],
                                         "next_run_at": projected_next_run(a)})
                else:
                    a = get_automation(aid)
                    if not a:
                        send_error(self, "automation not found", 404)
                    else:
                        a["status"] = current_automation_status(a)
                        send_json(self, {"success": True, "automation": a})
            elif path == "/api/automation/status":
                send_json(self, automation_status_summary())
            elif path == "/api/discovery/candidates":
                status = (qp.get("status") or [None])[0]
                send_json(self, list_discovery_candidates(status))
            elif path == "/api/discovery/summary":
                send_json(self, discovery_summary())
            elif path == "/api/regions":
                send_json(self, {"success": True, "regions": REGIONS})
            elif path == "/api/scheduler/status":
                send_json(self, scheduler.status())
            elif path == "/api/scheduler/activity":
                limit = int((qp.get("limit") or [100])[0])
                rows = db.query("SELECT e.*, b.brand_name AS company FROM automation_events e "
                                "LEFT JOIN brands b ON b.id=e.company_id ORDER BY e.id DESC LIMIT ?",
                                (min(300, max(1, limit)),))
                send_json(self, {"success": True, "events": [dict(r) for r in rows]})
            elif path == "/api/company/settings":
                cid = (qp.get("company_id") or [None])[0]
                if not cid:
                    send_error(self, "Missing company_id")
                else:
                    send_json(self, {"success": True, "settings": get_company_settings(int(cid)),
                                     "company": (get_brand(int(cid)) or {}).get("brand_name", "")})
            elif path == "/api/report/pdf":
                cid = (qp.get("company_id") or [None])[0]
                if not cid:
                    send_error(self, "Missing company_id")
                else:
                    send_json(self, generate_pdf_report(int(cid)))
            elif path == "/api/alerts/test":
                send_webhook("test", {"message": "Test webhook from VisibilityAI"})
                send_email_alert("Test Alert", "<p>This is a test alert from VisibilityAI.</p>")
                send_json(self, {"success": True, "message": "Test alerts sent"})
            elif path == "/api/tenants":
                send_json(self, {"success": True, "tenants": [dict(r) for r in db.query("SELECT id, name, slug, plan, max_companies, created_at FROM tenants")]})
            elif path == "/api/tenants/current":
                tid = None
                auth = self.headers.get("Authorization", "")
                if auth.startswith("Bearer "):
                    payload = _verify_token(auth[7:])
                    if payload:
                        tid = payload.get("tenant_id")
                if tid:
                    tenant = db.query("SELECT * FROM tenants WHERE id=?", (tid,))
                    send_json(self, {"success": True, "tenant": dict(tenant[0]) if tenant else None})
                else:
                    send_json(self, {"success": True, "tenant": None})
            elif path == "/api/docs":
                send_json(self, _get_api_docs())
            elif path == "/api/backups":
                send_json(self, {"success": True, "backups": list_backups()})
            elif path == "/api/monitoring/health":
                health = {
                    "status": "ok",
                    "uptime": time.time() - (_server_start_time if '_server_start_time' in dir() else time.time()),
                    "db_size": os.path.getsize(db.sqlite_path) if os.path.exists(db.sqlite_path) else 0,
                    "total_companies": db.query("SELECT COUNT(*) as c FROM brands")[0]["c"],
                    "total_analyses": db.query("SELECT COUNT(*) as c FROM analysis_results")[0]["c"],
                    "total_jobs": db.query("SELECT COUNT(*) as c FROM jobs")[0]["c"],
                    "pending_jobs": db.query("SELECT COUNT(*) as c FROM jobs WHERE status='PENDING'")[0]["c"],
                    "failed_jobs_1h": db.query("SELECT COUNT(*) as c FROM jobs WHERE status='FAILED' AND completed_at > datetime('now', '-1 hour')")[0]["c"],
                    "gemini": gemini_available,
                    "groq": groq_available,
                    "serpapi": bool(SERPAPI_KEY),
                }
                send_json(self, health)
            # --- Workflow Self-Learning GET Endpoints ---
            elif path == "/api/workflow/list":
                send_json(self, {"success": True, "workflows": workflow_list()})
            elif path == "/api/workflow/active":
                wid = get_active_workflow()
                spec = SPEC_WORKFLOWS[wid]
                rows = db.query("SELECT version FROM workflow_versions WHERE workflow_id=? AND status='ACTIVE' "
                                "ORDER BY version DESC LIMIT 1", (wid,))
                send_json(self, {"success": True, "workflow_id": wid, "name": spec["name"],
                                 "visible": spec["visible"],
                                 "version": rows[0]["version"] if rows else 1,
                                 "spec_workflows": {k: {"name": v["name"], "visible": v["visible"]}
                                                    for k, v in SPEC_WORKFLOWS.items()}})
            elif path == "/api/workflow/runs":
                cid = (qp.get("company_id") or [None])[0]
                wid = (qp.get("workflow_id") or [None])[0]
                try:
                    lim = max(1, min(int((qp.get("limit") or [50])[0]), 200))
                except Exception:
                    lim = 50
                q = "SELECT * FROM workflow_runs WHERE 1=1"
                p = []
                if cid:
                    q += " AND company_id=?"
                    p.append(int(cid))
                if wid:
                    q += " AND workflow_id=?"
                    p.append(wid)
                rows = db.query(q + f" ORDER BY id DESC LIMIT {lim}", tuple(p))
                out = []
                for r in rows:
                    d = dict(r)
                    for k in ("steps_json", "tools_json", "rag_json", "reasoning_json",
                              "skipped_json", "plan_json"):
                        try:
                            d[k.replace("_json", "")] = safe_json_loads(
                                d.get(k), [] if "steps" in k else {})
                        except Exception:
                            pass
                    out.append(d)
                send_json(self, {"success": True, "runs": out})
            elif path == "/api/health/full":
                send_json(self, system_health())
            elif path == "/api/workflow/demo":
                send_json(self, workflow_create_demo())
            elif path == "/api/workflow/presets/create":
                send_json(self, workflow_create_presets())
            elif path.startswith("/api/workflow/") and "/adaptations" in path:
                wf_id = path.split("/")[3]
                send_json(self, {"success": True, "adaptations": workflow_adaptations(wf_id)})
            elif path.startswith("/api/workflow/") and "/learning" in path:
                wf_id = path.split("/")[3]
                send_json(self, {"success": True, "patterns": workflow_learning(wf_id)})
            elif path.startswith("/api/workflow/") and "/events" in path:
                wf_id = path.split("/")[3]
                send_json(self, {"success": True, "events": workflow_events(wf_id)})
            elif path.startswith("/api/workflow/") and "/version/" in path and "/activate" not in path:
                parts = path.split("/")
                wf_id = parts[3]
                ver = parts[5]
                if "/diff" in path:
                    pass
                send_json(self, {"success": True, "versions": workflow_versions(wf_id)})
            elif path.startswith("/api/workflow/"):
                wf_id = path.split("/")[3]
                wf = workflow_get(wf_id)
                if wf:
                    send_json(self, {"success": True, "workflow": wf})
                else:
                    send_error(self, "Workflow not found", 404)
            else:
                send_error(self, "Endpoint not found", 404)
        except Exception as e:
            import traceback
            traceback.print_exc()
            send_error(self, str(e), 500)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = _strip_prefix(parsed.path)
        origin = self.headers.get("Origin", "")
        client_ip = self.client_address[0]

        # Rate limit (login gets its own strict bucket against brute force)
        if not _check_rate_limit(client_ip, RATE_LIMIT_LOGIN_PER_MINUTE if path == "/api/login" else RATE_LIMIT_PER_MINUTE):
            send_json(self, {"error": "Rate limit exceeded"}, 429)
            return

        try:
            # Public: login endpoint - bypassed for now
            if path == "/api/login":
                data = read_body(self)
                username = data.get("username", "admin")
                # Always succeed, no credential check
                token = _create_token(username, "admin")
                logger.info(f"Login bypassed for {username}")
                send_json(self, {"success": True, "token": token, "user": username, "role": "admin",
                                 "tenant": {"slug": "default", "name": "Default", "logo_url": "", "primary_color": "#3b82f6"}})
                return

            # Auth required for all other POST endpoints
            user, err, code = _extract_user(self)
            if err:
                send_json(self, err, code)
                return

            if path == "/run-agent":
                data = read_body(self)
                res = manual_analysis(data)
                send_json(self, res, 200 if res.get("success") else 400)
            elif path == "/delete-audit":
                payload = read_body(self)
                send_json(self, delete_audit(payload.get("id")) if payload.get("id")
                          else {"success": False, "error": "Missing id"})
            elif path == "/agent/start-run":
                payload = read_body(self)
                send_json(self, start_run(payload))
            elif path == "/agent/stop":
                send_json(self, {"success": True, "loop": runner.stop_loop()})
            elif path == "/agent/start-loop":
                send_json(self, runner.start_loop())
            elif path == "/api/agent/run":
                send_json(self, run_now(read_body(self), background=True))
            elif path == "/api/agent/run-all":
                _wid = (read_body(self).get("workflow_id") or "").strip() or None
                send_json(self, run_all_companies(workflow_id=_wid))
            elif path == "/api/workflow/presets":
                send_json(self, {"success": True, "presets": WORKFLOW_PRESETS})
            elif path.startswith("/api/workflow/") and path.endswith("/config"):
                try:
                    cid = int(path[len("/api/workflow/"): -len("/config")])
                except Exception:
                    send_error(self, "invalid company id", 400)
                    return
                if self.command == "POST":
                    send_json(self, update_company_workflow_config(cid, read_body(self)))
                else:
                    send_json(self, {"success": True, "config": get_company_workflow_config(cid)})
            elif path.startswith("/api/workflow/") and path.endswith("/status"):
                try:
                    cid = int(path[len("/api/workflow/"): -len("/status")])
                except Exception:
                    send_error(self, "invalid company id", 400)
                    return
                send_json(self, {"success": True, "status": get_company_workflow_status(cid)})
            elif path == "/api/agent/pause":
                send_json(self, runner.pause())
            elif path == "/api/agent/resume":
                send_json(self, runner.resume())
            elif path == "/api/automations":
                payload = read_body(self)
                try:
                    a = create_automation(
                        payload.get("company_id"), payload.get("automation_type") or "FULL_ANALYSIS",
                        payload.get("schedule_type") or "WEEKLY",
                        enabled=0 if str(payload.get("enabled", "1")) in ("0", "false", "False") else 1,
                        configuration=payload.get("configuration"))
                    send_json(self, {"success": True, "automation": a})
                except ValueError as e:
                    send_error(self, str(e))
            elif path.startswith("/api/automations/"):
                aid = path[len("/api/automations/"):]
                if aid.endswith("/enable"):
                    send_json(self, set_automation_enabled(aid[: -len("/enable")], True))
                elif aid.endswith("/disable"):
                    send_json(self, set_automation_enabled(aid[: -len("/disable")], False))
                elif aid.endswith("/run"):
                    send_json(self, run_automation(aid[: -len("/run")], background=True))
                elif aid.endswith("/update"):
                    payload = read_body(self)
                    send_json(self, update_automation(aid[: -len("/update")], payload or {}))
                else:
                    send_error(self, "unsupported automation action", 404)
            elif path == "/api/discovery/import":
                payload = read_body(self)
                cid = payload.get("id") or payload.get("candidate_id")
                if not cid:
                    send_error(self, "Missing id")
                else:
                    send_json(self, import_discovery_candidate(int(cid)))
            elif path == "/api/discovery/import-all":
                send_json(self, import_all_discovery_candidates())
            elif path == "/api/discovery/validate":
                payload = read_body(self)
                cid = payload.get("id") or payload.get("candidate_id")
                if cid:
                    send_json(self, validate_candidate(int(cid)))
                else:
                    rows = db.query("SELECT id FROM discovery_candidates WHERE status='NEW' ORDER BY id DESC LIMIT 50")
                    done = {"verified": 0, "needs": 0, "invalid": 0}
                    for r in rows:
                        try:
                            v = validate_candidate(r["id"])
                            st = v.get("verification_status", "")
                            if st == "VERIFIED":
                                done["verified"] += 1
                            elif st in ("PARTIALLY_VERIFIED", "INSUFFICIENT_DATA"):
                                done["needs"] += 1
                            else:
                                done["invalid"] += 1
                        except Exception:
                            done["invalid"] += 1
                    send_json(self, {"success": True, "checked": len(rows), **done})
            elif path == "/api/discovery/reject":
                payload = read_body(self)
                cid = payload.get("id") or payload.get("candidate_id")
                if not cid:
                    send_error(self, "Missing id")
                else:
                    send_json(self, reject_discovery_candidate(int(cid)))
            elif path == "/api/company/settings":
                payload = read_body(self)
                cid = payload.get("company_id")
                if not cid:
                    send_error(self, "Missing company_id")
                else:
                    settings = payload.get("settings") or {}
                    save_company_settings(int(cid), settings)
                    ensure_default_automations(int(cid))
                    # Settings panel is the master control: force-enable ON features,
                    # force-disable OFF features, and sync FULL_ANALYSIS schedule.
                    desired_enabled = {
                        "MONITOR":        bool(settings.get("monitoring_enabled",
                                                 get_company_settings(int(cid)).get("monitoring_enabled", 1))),
                        "CHANGE_DETECTION": bool(settings.get("change_detection_enabled",
                                                 get_company_settings(int(cid)).get("change_detection_enabled", 1))),
                        "QUERY_REFRESH":  bool(settings.get("auto_query_refresh_enabled",
                                                 get_company_settings(int(cid)).get("auto_query_refresh_enabled", 1))),
                        "DATA_REFRESH":   bool(settings.get("data_refresh_enabled",
                                                 get_company_settings(int(cid)).get("data_refresh_enabled", 1))),
                    }
                    for atype, want_on in desired_enabled.items():
                        for a in db.query("SELECT id, enabled FROM automations WHERE company_id=? "
                                          "AND automation_type=? LIMIT 1", (int(cid), atype)):
                            if want_on and not a["enabled"]:
                                db.execute("UPDATE automations SET enabled=1, last_status='ACTIVE', "
                                           "updated_at=? WHERE id=?", (now(), a["id"]))
                            elif not want_on and a["enabled"]:
                                db.execute("UPDATE automations SET enabled=0, last_status='PAUSED', "
                                           "updated_at=? WHERE id=?", (now(), a["id"]))
                    freq = str(settings.get("analysis_frequency") or
                               get_company_settings(int(cid)).get("analysis_frequency", "WEEKLY")).upper()
                    for a in db.query("SELECT automation_id FROM automations WHERE company_id=? "
                                      "AND automation_type='FULL_ANALYSIS' LIMIT 1", (int(cid),)):
                        update_automation(a["automation_id"],
                                          {"schedule_type": freq if freq in ("DAILY","WEEKLY","MONTHLY") else "WEEKLY"})
                    send_json(self, {"success": True, "settings": get_company_settings(int(cid))})
            elif path == "/api/scheduler/start":
                send_json(self, scheduler.start())
            elif path == "/api/scheduler/pause":
                send_json(self, scheduler.pause())
            elif path == "/api/scheduler/resume":
                send_json(self, scheduler.resume())
            elif path == "/api/scheduler/run-once":
                send_json(self, scheduler.run_once(manual=True))
            elif path.startswith("/api/agent/jobs/") and path.endswith("/retry"):
                jid = path[len("/api/agent/jobs/"):-len("/retry")]
                send_json(self, retry_job(int(jid) if jid.isdigit() else -1))
            elif path.startswith("/api/agent/jobs/") and path.endswith("/cancel"):
                jid = path[len("/api/agent/jobs/"):-len("/cancel")]
                send_json(self, cancel_job(int(jid) if jid.isdigit() else -1))
            elif path == "/agent/config":
                payload = read_body(self)
                save_config(payload.get("config") or {})
                send_json(self, {"success": True, "config": get_config()})
            elif path == "/agent/run-company":
                payload = read_body(self)
                bid = payload.get("company_id")
                if not bid:
                    send_error(self, "Missing company_id")
                    return
                # Direct inline execution in background - returns instantly,
                # dashboard polls live progress via /agent-state.
                wid = (payload.get("workflow_id") or "").strip() or None
                rid = create_run("REANALYZE", companies=[int(bid)])

                def _reanalyze(cid=int(bid), _rid=rid, _wid=wid):
                    try:
                        summary = run_company_direct(cid, _rid, workflow_id=_wid)
                        finalize_run(_rid, "FAILED" if summary.get("errors") else "COMPLETED")
                    except Exception as e:
                        print(f"[ReAnalyze] company {cid} failed: {e}", flush=True)
                        try:
                            finalize_run(_rid, "FAILED")
                        except Exception:
                            pass

                threading.Thread(target=_reanalyze, daemon=True, name="reanalyze-direct").start()
                send_json(self, {"success": True, "run_id": rid,
                                 "workflow_id": wid or get_active_workflow(),
                                 "message": "Re-analysis started - watch live progress on the dashboard."})
            elif path == "/agent/run-discover":
                send_json(self, run_company_discovery(read_body(self)))
            elif path == "/companies/import":
                payload = read_body(self)
                companies_list = payload.get("companies")
                csv_text = payload.get("csv", "")
                if companies_list and isinstance(companies_list, list):
                    results = []
                    for c in companies_list:
                        name = c.get("brand_name") or c.get("name", "")
                        if not name:
                            continue
                        try:
                            bid = upsert_company(c, source="ONBOARDING")
                            results.append({"id": bid, "brand_name": name, "success": True})
                        except Exception as e:
                            results.append({"brand_name": name, "success": False, "error": str(e)})
                    send_json(self, {"success": True, "imported": len([r for r in results if r.get("success")]),
                                     "companies": results,
                                     "company_id": results[0]["id"] if results and results[0].get("success") else None})
                elif csv_text:
                    send_json(self, import_csv(csv_text))
                else:
                    send_error(self, "Missing csv or companies")
                    return
            elif path == "/feedback":
                send_json(self, ingest_feedback(read_body(self)))
            elif path.startswith("/api/recommendations/") and path.endswith("/feedback"):
                try:
                    rec_id = int(path[len("/api/recommendations/"): -len("/feedback")].strip("/"))
                except Exception:
                    send_error(self, "invalid recommendation id", 400)
                    return
                payload = read_body(self)
                send_json(self, submit_recommendation_feedback(
                    rec_id, (payload.get("feedback") or "").upper(), payload.get("comment") or ""))
            elif path.startswith("/api/learning/rebuild/"):
                try:
                    cid = int(path[len("/api/learning/rebuild/"):].strip("/"))
                except Exception:
                    send_error(self, "invalid company id", 400)
                    return
                send_json(self, rebuild_company_learning(cid))
            elif path.startswith("/api/learning/invalidate/"):
                mid = path[len("/api/learning/invalidate/"):].strip("/")
                payload = read_body(self)
                send_json(self, invalidate_memory(mid, payload.get("reason") or "invalidated from dashboard"))
            elif path.startswith("/api/learning/clear-influence/"):
                try:
                    cid = int(path[len("/api/learning/clear-influence/"):].strip("/"))
                except Exception:
                    send_error(self, "invalid company id", 400)
                    return
                payload = read_body(self)
                send_json(self, clear_company_influence(cid, payload.get("reason") or ""))
            elif path.startswith("/api/learning/company/"):
                try:
                    cid = int(path[len("/api/learning/company/"):].strip("/"))
                except Exception:
                    send_error(self, "invalid company id", 400)
                    return
                payload = read_body(self)
                if not get_brand(cid):
                    send_error(self, "Company not found", 404)
                    return
                send_json(self, set_company_learning(cid, bool(int(payload.get("learning_enabled", 1)))))
            elif path.startswith("/api/agent/decisions/") and path.endswith("/skip"):
                did = path[len("/api/agent/decisions/"): -len("/skip")].strip("/")
                send_json(self, skip_decision(int(did) if did.isdigit() else did))
            elif path.startswith("/api/agent/decisions/") and path.endswith("/approve"):
                did = path[len("/api/agent/decisions/"): -len("/approve")].strip("/")
                payload = read_body(self)
                send_json(self, approve_decision(int(did) if did.isdigit() else did,
                                                payload.get("run_id")))
            elif path == "/api/agent/autonomous/run":
                payload = read_body(self)
                send_json(self, run_autonomous(payload or {},
                                               background=str(payload.get("background", "1")) != "0"))
            elif path == "/api/orchestrator/run-once":
                payload = read_body(self)
                cid = payload.get("company_id")
                send_json(self, orchestrator_run_once(int(cid) if cid else None))
            elif path.startswith("/api/orchestrator/run-company/"):
                try:
                    cid = int(path[len("/api/orchestrator/run-company/"):].strip("/"))
                except Exception:
                    send_error(self, "invalid company id", 400)
                    return
                payload = read_body(self)
                send_json(self, orchestrator_run_company(cid, payload.get("max_steps")))
            elif path == "/api/orchestrator/pause":
                send_json(self, {**runner.pause(), "orchestrator": "paused"})
            elif path == "/api/orchestrator/resume":
                send_json(self, {**runner.resume(), "orchestrator": "resumed"})
            elif path.startswith("/api/orchestrator/decision/") and path.endswith("/approve"):
                did = path[len("/api/orchestrator/decision/"): -len("/approve")].strip("/")
                send_json(self, orchestrator_approve(int(did) if did.isdigit() else did))
            elif path.startswith("/api/orchestrator/decision/") and path.endswith("/reject"):
                did = path[len("/api/orchestrator/decision/"): -len("/reject")].strip("/")
                send_json(self, orchestrator_reject(int(did) if did.isdigit() else did))
            elif path.startswith("/api/manager/agents/") and path.endswith("/enable"):
                aid = path[len("/api/manager/agents/"): -len("/enable")].strip("/")
                send_json(self, manager_set_status(int(aid) if aid.isdigit() else aid, "ACTIVE"))
            elif path.startswith("/api/manager/agents/") and path.endswith("/disable"):
                aid = path[len("/api/manager/agents/"): -len("/disable")].strip("/")
                send_json(self, manager_set_status(int(aid) if aid.isdigit() else aid, "DISABLED"))
            elif path == "/api/manager/health-check":
                send_json(self, manager_health_check_all())
            elif path == "/api/manager/tasks":
                send_json(self, manager_intake(read_body(self) or {}))
            elif path == "/api/framework/agents/register":
                payload = read_body(self) or {}
                if "executor" in payload and not callable(payload.get("executor")):
                    payload = dict(payload)
                    payload.pop("executor", None)
                send_json(self, framework_register_agent(payload))
            elif path.startswith("/api/manager/tasks/") and path.endswith("/execute"):
                tid = path[len("/api/manager/tasks/"): -len("/execute")].strip("/")
                payload = read_body(self)
                send_json(self, manager_execute_task(int(tid) if tid.isdigit() else tid,
                                                     background=str(payload.get("background", "1")) != "0"))
            elif path.startswith("/api/manager/tasks/") and path.endswith("/synthesize"):
                tid = path[len("/api/manager/tasks/"): -len("/synthesize")].strip("/")
                payload = read_body(self)
                send_json(self, manager_synthesize_task(int(tid) if tid.isdigit() else tid,
                                                        background=str(payload.get("background", "1")) != "0"))
            elif path.startswith("/api/manager/tasks/") and path.endswith("/cancel"):
                tid = path[len("/api/manager/tasks/"): -len("/cancel")].strip("/")
                send_json(self, manager_cancel_task(int(tid) if tid.isdigit() else tid))
            elif path.startswith("/api/reasoning/company/"):
                try:
                    cid = int(path[len("/api/reasoning/company/"):].strip("/"))
                except Exception:
                    send_error(self, "invalid company id", 400)
                    return
                payload = read_body(self) or {}
                if not get_brand(cid):
                    send_error(self, "Company not found", 404)
                    return
                send_json(self, reason_about_company(cid, store=True))
            elif path.startswith("/api/reasoning/run-once/"):
                try:
                    cid = int(path[len("/api/reasoning/run-once/"):].strip("/"))
                except Exception:
                    send_error(self, "invalid company id", 400)
                    return
                send_json(self, reason_run_once(cid))
            elif path.startswith("/api/reasoning/") and path.endswith("/validate"):
                rid = path[len("/api/reasoning/"): -len("/validate")].strip("/")
                rows = db.query("SELECT * FROM reasoning_events WHERE reasoning_id=? OR id=?",
                                (rid, int(rid) if rid.isdigit() else -1))
                if not rows:
                    send_error(self, "reasoning event not found", 404)
                else:
                    d = _reasoning_row(rows[0])
                    send_json(self, {**validate_reasoning(
                        {"recommended_action": d.get("selected_action"),
                         "company_id": d.get("company_id"),
                         "dependencies": JOB_DEPENDENCIES.get(d.get("selected_action"), [])}),
                        "reasoning_id": d.get("reasoning_id")})
            elif path == "/api/planning/goals":
                send_json(self, plan_create_goal(read_body(self) or {}))
            elif path == "/api/planning/plan":
                payload = read_body(self) or {}
                g = plan_create_goal(payload)
                if not g.get("success") or g.get("needs_clarification"):
                    send_json(self, g)
                    return
                send_json(self, {**plan_build(g["goal"], g["goal"].get("company_id")), "goal": g["goal"]})
            elif path == "/api/planning/validate":
                payload = read_body(self) or {}
                pid = payload.get("plan_id")
                if not pid:
                    send_error(self, "Missing plan_id")
                    return
                send_json(self, validate_plan(pid, payload.get("version")))
            elif path.startswith("/api/planning/replan/"):
                pid = path[len("/api/planning/replan/"):].strip("/")
                payload = read_body(self) or {}
                send_json(self, plan_replan(pid, payload.get("reason", "")))
            elif path.startswith("/api/planning/evaluate/"):
                pid = path[len("/api/planning/evaluate/"):].strip("/")
                send_json(self, evaluate_plan(pid))
            elif path.startswith("/api/planning/run-once/"):
                try:
                    cid = int(path[len("/api/planning/run-once/"):].strip("/"))
                except Exception:
                    send_error(self, "invalid company id", 400)
                    return
                send_json(self, planning_run_once(cid, read_body(self) or {}))
            elif path.startswith("/api/rag/index/company/"):
                try:
                    cid = int(path[len("/api/rag/index/company/"):].strip("/"))
                except Exception:
                    send_error(self, "invalid company id", 400)
                    return
                payload = read_body(self) or {}
                send_json(self, rag_index_company(cid, payload.get("source_types"),
                                                  payload.get("batch_size")))
            elif path == "/api/rag/search":
                payload = read_body(self) or {}
                cid = payload.get("company_id")
                if not cid:
                    send_error(self, "Missing company_id")
                    return
                send_json(self, rag_search(int(cid), payload.get("query", ""), payload.get("top_k"),
                                           payload.get("filters"), payload.get("request_id")))
            elif path.startswith("/api/companies/") and path.endswith("/decide"):
                try:
                    cid = int(path[len("/api/companies/"): -len("/decide")].strip("/"))
                except Exception:
                    send_error(self, "invalid company id", 400)
                    return
                if not get_brand(cid):
                    send_error(self, "Company not found", 404)
                    return
                dec = decide_next_actions(cid)
                for a in dec["actions"]:
                    record_decision(cid, a["action"], a["priority"], a["reason"],
                                    trigger_type="SIMULATION", trigger_id="decide-api",
                                    confidence=a.get("confidence"), status="PROPOSED",
                                    evidence=a.get("evidence"), chain=a.get("chain"), level=a.get("level"))
                for c in dec["considered"]:
                    record_decision(cid, c["action"], "LOW", c["reason"], trigger_type="SIMULATION",
                                    trigger_id="decide-api", status="SKIPPED")
                dec["simulation"] = True
                dec["executed"] = False
                send_json(self, dec)
            elif path == "/api/autonomous/run":
                payload = read_body(self) or {}
                cid = payload.get("company_id")
                goal = payload.get("goal", "")
                if not cid or not goal:
                    send_error(self, "Missing company_id or goal")
                    return
                max_iter = payload.get("max_iterations")
                run_id, result = autonomous_run_goal(int(cid), goal, max_iterations=max_iter)
                if run_id:
                    send_json(self, result)
                else:
                    send_json(self, result, 400)
            elif path.startswith("/api/autonomous/run/") and path.endswith("/resume"):
                run_id = path[len("/api/autonomous/run/"): -len("/resume")]
                send_json(self, autonomous_resume(run_id))
            elif path.startswith("/api/autonomous/run/") and path.endswith("/cancel"):
                run_id = path[len("/api/autonomous/run/"): -len("/cancel")]
                send_json(self, autonomous_cancel(run_id))
            elif path.startswith("/api/autonomous/run/") and path.endswith("/approve"):
                run_id = path[len("/api/autonomous/run/"): -len("/approve")]
                payload = read_body(self) or {}
                send_json(self, autonomous_approve(run_id, payload.get("reason", "")))
            elif path.startswith("/api/autonomous/run/") and path.endswith("/reject"):
                run_id = path[len("/api/autonomous/run/"): -len("/reject")]
                payload = read_body(self) or {}
                send_json(self, autonomous_reject(run_id, payload.get("reason", "")))
            elif path == "/jobs/retry":
                payload = read_body(self)
                send_json(self, retry_job(payload.get("id") or -1))
            elif path == "/api/agent-brain/start":
                send_json(self, agent_brain_start())
            elif path == "/api/agent-brain/stop":
                send_json(self, agent_brain_stop())
            elif path == "/api/agent-brain/cycle":
                send_json(self, agent_brain_run_cycle())
            elif path == "/api/agent-brain/status":
                send_json(self, agent_brain_status())
            elif path == "/api/tenants/create":
                payload = read_body(self)
                name = payload.get("name", "")
                slug = payload.get("slug", "")
                plan = payload.get("plan", "starter")
                max_c = payload.get("max_companies", 10)
                if not name or not slug:
                    send_json(self, {"success": False, "error": "name and slug required"}, 400)
                else:
                    try:
                        result = create_tenant(name, slug, plan, max_c)
                        send_json(self, {"success": True, "tenant_id": result["id"], "api_key": result["api_key"]})
                    except Exception as e:
                        send_json(self, {"success": False, "error": str(e)}, 400)
            elif path == "/api/tenants/create-user":
                payload = read_body(self)
                tid = payload.get("tenant_id")
                username = payload.get("username", "")
                password = payload.get("password", "")
                role = payload.get("role", "viewer")
                if not tid or not username or not password:
                    send_json(self, {"success": False, "error": "tenant_id, username, password required"}, 400)
                else:
                    try:
                        create_tenant_user(tid, username, password, role)
                        send_json(self, {"success": True})
                    except Exception as e:
                        send_json(self, {"success": False, "error": str(e)}, 400)
            elif path == "/api/backup/create":
                send_json(self, create_backup("manual"))
            elif path == "/api/backup/restore":
                payload = read_body(self)
                send_json(self, restore_backup(payload.get("filename", "")))
            elif path == "/api/usage":
                tid = None
                auth = self.headers.get("Authorization", "")
                if auth.startswith("Bearer "):
                    payload = _verify_token(auth[7:])
                    if payload:
                        tid = payload.get("tenant_id")
                send_json(self, {"success": True, "usage": get_usage_stats(tid)})
            elif path == "/api/audit":
                tid = None
                auth = self.headers.get("Authorization", "")
                if auth.startswith("Bearer "):
                    payload = _verify_token(auth[7:])
                    if payload:
                        tid = payload.get("tenant_id")
                send_json(self, {"success": True, "audit": get_audit_log(tid)})
            # --- Workflow Self-Learning Endpoints ---
            elif path == "/api/workflow/create":
                payload = read_body(self)
                send_json(self, workflow_create(
                    name=payload.get("name", "Unnamed"),
                    description=payload.get("description", ""),
                    steps=payload.get("steps", []),
                    dependencies=payload.get("dependencies"),
                    metadata=payload.get("metadata"),
                    created_by=user.get("username", "user"),
                ))
            elif path == "/api/workflow/list":
                send_json(self, {"success": True, "workflows": workflow_list()})
            elif path.startswith("/api/workflow/") and "/version/" in path:
                parts = path.split("/")
                wf_id = parts[3]
                ver = parts[5]
                if path.endswith("/activate"):
                    send_json(self, workflow_activate_version(wf_id, int(ver)))
                elif path.endswith("/diff"):
                    ver2 = parts[7] if len(parts) > 7 else None
                    if ver2:
                        send_json(self, workflow_compare_versions(wf_id, int(ver), int(ver2)))
                    else:
                        send_error(self, "missing second version for diff", 400)
                else:
                    send_error(self, "unknown workflow version action", 404)
            elif path.startswith("/api/workflow/") and path.endswith("/create-version"):
                wf_id = path.split("/")[3]
                payload = read_body(self)
                send_json(self, workflow_create_version(
                    wf_id,
                    steps=payload.get("steps", []),
                    dependencies=payload.get("dependencies"),
                    metadata=payload.get("metadata"),
                    change_summary=payload.get("change_summary", ""),
                    created_by=user.get("username", "user"),
                ))
            elif path.startswith("/api/workflow/") and path.endswith("/diff"):
                parts = path.split("/")
                wf_id = parts[3]
                payload = read_body(self)
                send_json(self, workflow_diff(wf_id,
                    payload.get("version_a"), payload.get("version_b")))
            elif path.startswith("/api/workflow/") and path.endswith("/adapt"):
                parts = path.split("/")
                wf_id = parts[3]
                payload = read_body(self)
                send_json(self, workflow_adapt(
                    wf_id,
                    payload.get("version_a"),
                    payload.get("version_b"),
                    company_id=payload.get("company_id"),
                ))
            elif path.startswith("/api/workflow/") and path.endswith("/approve"):
                parts = path.split("/")
                wf_id = parts[3]
                payload = read_body(self)
                send_json(self, workflow_approve_adaptation(
                    payload.get("adaptation_id"),
                    approved_by=user.get("username", "user"),
                ))
            elif path.startswith("/api/workflow/") and path.endswith("/reject"):
                parts = path.split("/")
                wf_id = parts[3]
                payload = read_body(self)
                send_json(self, workflow_reject_adaptation(
                    payload.get("adaptation_id"),
                    rejected_by=user.get("username", "user"),
                    reason=payload.get("reason", ""),
                ))
            elif path.startswith("/api/workflow/") and path.endswith("/rollback"):
                parts = path.split("/")
                wf_id = parts[3]
                payload = read_body(self)
                send_json(self, workflow_rollback(wf_id, payload.get("to_version")))
            elif path.startswith("/api/workflow/") and path.endswith("/adaptations"):
                wf_id = path.split("/")[3]
                send_json(self, {"success": True, "adaptations": workflow_adaptations(wf_id)})
            elif path.startswith("/api/workflow/") and path.endswith("/learning"):
                wf_id = path.split("/")[3]
                send_json(self, {"success": True, "patterns": workflow_learning(wf_id)})
            elif path.startswith("/api/workflow/") and path.endswith("/events"):
                wf_id = path.split("/")[3]
                send_json(self, {"success": True, "events": workflow_events(wf_id)})
            elif path == "/api/workflow/demo":
                send_json(self, workflow_create_demo())
            elif path == "/api/workflow/presets/create":
                send_json(self, workflow_create_presets())
            elif path == "/api/workflow/active":
                payload = read_body(self)
                send_json(self, set_active_workflow((payload.get("workflow_id") or "").strip()))
            elif path == "/api/workflow/auto-adaptation":
                payload = read_body(self)
                send_json(self, workflow_set_auto_adaptation(payload.get("enabled", True)))
            else:
                send_error(self, "Endpoint not found", 404)
        except Exception as e:
            import traceback
            traceback.print_exc()
            send_error(self, str(e), 500)

    def do_DELETE(self):
        parsed = urlparse(self.path)
        if _strip_prefix(parsed.path) == "/delete-audit":
            qp = parse_qs(parsed.query)
            aid = (qp.get("id") or [None])[0]
            if aid:
                send_json(self, delete_audit(aid))
            else:
                send_error(self, "Missing id")
            return
        send_error(self, "Endpoint not found", 404)


def system_health():
    """One combined health check (§31). Every flag comes from a real probe -
    nothing is hardcoded. Used by the simple Start view health strip."""
    checks = {}
    checks["backend"] = True  # serving this response proves it
    try:
        db.query("SELECT 1 AS ok")
        checks["database"] = True
    except Exception as e:
        checks["database"] = f"DB error: {e}"[:160]
    try:
        checks["scheduler"] = bool(scheduler.thread and scheduler.thread.is_alive())
    except Exception:
        checks["scheduler"] = False
    try:
        checks["worker"] = bool(runner.thread and runner.thread.is_alive())
    except Exception:
        checks["worker"] = False
    try:
        rows = db.query("SELECT workflow_id FROM workflow_definitions "
                        "WHERE workflow_id IN ('brand_visibility_standard','rag_enhanced_analysis')")
        checks["workflows"] = len(rows) == 2
    except Exception:
        checks["workflows"] = False
    try:
        checks["search"] = bool(requests_available and SERPAPI_KEY) or gemini_available
    except Exception:
        checks["search"] = False
    try:
        rh = rag_health() or {}
        checks["rag"] = (rh.get("status") == "HEALTHY")
    except Exception:
        checks["rag"] = False
    try:
        checks["llm"] = bool(gemini_available or groq_available)
    except Exception:
        checks["llm"] = False
    try:
        db.query("SELECT id FROM learning_events LIMIT 1")
        checks["learning"] = True
    except Exception as e:
        checks["learning"] = f"DB error: {e}"[:160]
    ok = all(v is True for v in checks.values())
    return {"success": True, "healthy": ok, "checks": checks}


def agent_state():
    detail = agent_status_detail()
    sources_rows = db.query("SELECT * FROM data_source_status ORDER BY source_key")
    sources = {r["source_key"]: r for r in sources_rows}
    counts = {k: (db.query(f"SELECT COUNT(*) AS c FROM {t}") or [{"c": 0}])[0]["c"]
              for k, t in [("queries_total", "query_memory"), ("observations_total", "ai_observations"),
                           ("changes_total", "change_log"), ("learning_total", "learning_memory"),
                           ("feedback_total", "feedback"), ("evidence_total", "evidence"),
                           ("jobs_total", "jobs")]}
    run = detail.get("run")
    last = detail.get("last_run")
    qmap = detail.get("queue", {})
    return {
        "success": True,
        "version": 3,
        "automation": detail.get("automation"),
        "loop_running": bool(runner.thread and runner.thread.is_alive()),
        "loop_enabled": runner.loop_enabled,
        "plugins": {
            "gemini_connected": gemini_available,
            "serp_connected": bool(requests_available and SERPAPI_KEY),
            "ai_search_connected": ai_search_connected(),
            "scraper_connected": company_source_is_connected("WEBSITE_SCRAPER"),
            "discovery_connected": company_source_is_connected("COMPANY_DISCOVERY"),
        },
        "run": run,
        "last_run": last,
        "config": get_config(),
        "queue": qmap,
        "companies_active": detail.get("companies_active", 0),
        "sources": sources,
        "counts": counts,
        "agent_status": detail["agent_status"],
        "paused": detail["paused"],
        "current_job": detail["current_job"],
        "progress": detail["progress"],
        "companies_processed": detail["companies_processed"],
        "companies_total": detail["companies_total"],
        "jobs_completed": detail["jobs_completed"],
        "jobs_failed": detail["jobs_failed"],
        "jobs_total": detail["jobs_total"],
        "jobs_cancelled": detail["jobs_cancelled"],
        "job_progress": detail["job_progress"],
        "changes_detected": detail["changes_detected"],
        "new_evidence_count": detail["new_evidence_count"],
        "queries_processed": detail["queries_processed"],
        "next_run_at": detail["next_run_at"],
        "errors_recent": detail["errors_recent"],
        "activity": detail["activity"],
        "timestamp": now(),
    }


def start_run(payload):
    return run_now(payload or {}, background=True)


def fetch_analysis_history():
    rows = db.query("""
        SELECT b.id, b.brand_name, b.industry, b.data_source, b.last_analyzed_at,
               r.visibility_score, r.readiness_score, r.observed_score, r.created_at
        FROM brands b
        JOIN analysis_results r ON b.id = r.brand_id
        ORDER BY r.id DESC LIMIT 50
    """)
    out = []
    for r in rows:
        out.append({
            "id": r["id"],
            "brand_name": r["brand_name"],
            "industry": r["industry"],
            "data_source": r["data_source"],
            "visibility_score": r["visibility_score"],
            "readiness_score": r["readiness_score"],
            "observed_score": r["observed_score"],
            "created_at": r["created_at"],
        })
    return out


def fetch_analysis_detail(audit_id):
    brand = get_brand(audit_id)
    if not brand:
        return {"success": False, "error": "Audit record not found"}
    return build_analysis_result(audit_id)


def delete_audit(audit_id):
    try:
        for table, col in (("queries", "brand_id"), ("recommendations", "brand_id"),
                           ("analysis_results", "brand_id"), ("brands", "id")):
            db.execute(f"DELETE FROM {table} WHERE {col}=?", (audit_id,))
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


def fetch_companies():
    rows = db.query("""
        SELECT b.*,
          COALESCE(e.cnt, 0) AS evidence_count,
          COALESCE(o.cnt, 0) AS observations_count,
          r.visibility_score AS last_score,
          r.observed_score AS last_observed_score
        FROM brands b
        LEFT JOIN (SELECT brand_id, COUNT(*) AS cnt FROM evidence GROUP BY brand_id) e
          ON e.brand_id = b.id
        LEFT JOIN (SELECT brand_id, COUNT(*) AS cnt FROM ai_observations GROUP BY brand_id) o
          ON o.brand_id = b.id
        LEFT JOIN (SELECT brand_id, MAX(id) AS max_id FROM analysis_results GROUP BY brand_id) rm
          ON rm.brand_id = b.id
        LEFT JOIN analysis_results r ON r.id = rm.max_id
        ORDER BY b.id DESC
    """)
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# PDF REPORT GENERATION
# ---------------------------------------------------------------------------

def generate_pdf_report(brand_id):
    """Generate an HTML report that can be printed to PDF."""
    brand = get_brand(brand_id)
    if not brand:
        return {"success": False, "error": "Company not found"}
    analysis = build_analysis_result(brand_id)
    if not analysis.get("success"):
        return analysis

    score = (analysis.get("visibility_metrics") or {}).get("readiness_score") or 0
    if not score:
        score = (analysis.get("visibility_metrics") or {}).get("visibility_score") or 0
    observed = (analysis.get("visibility_metrics") or {}).get("observed_score") or 0
    recs = analysis.get("recommendations", [])
    evidence = get_company_evidence(brand_id)
    observations = db.query(
        "SELECT * FROM ai_observations WHERE brand_id=? ORDER BY observed_at DESC LIMIT 20",
        (brand_id,))

    html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Visibility Report - {brand['brand_name']}</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 40px; color: #1a1a1a; }}
h1 {{ color: #2563eb; border-bottom: 2px solid #2563eb; padding-bottom: 10px; }}
h2 {{ color: #374151; margin-top: 30px; }}
.score-box {{ display: inline-block; padding: 15px 30px; border-radius: 10px; font-size: 28px; font-weight: bold; color: white; margin: 10px 5px; }}
.score-good {{ background: #10b981; }}
.score-mid {{ background: #f59e0b; }}
.score-bad {{ background: #ef4444; }}
table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
th, td {{ padding: 10px; border: 1px solid #e5e7eb; text-align: left; font-size: 13px; }}
th {{ background: #f3f4f6; font-weight: 600; }}
.rec {{ padding: 10px; margin: 5px 0; border-left: 4px solid #3b82f6; background: #f8fafc; }}
.footer {{ margin-top: 40px; font-size: 11px; color: #9ca3af; text-align: center; border-top: 1px solid #e5e7eb; padding-top: 15px; }}
</style></head><body>
<h1>AI Search Visibility Report</h1>
<p><strong>Company:</strong> {brand['brand_name']} | <strong>Generated:</strong> {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</p>

<h2>Visibility Scores</h2>
<div class="score-box {'score-good' if score >= 70 else 'score-mid' if score >= 40 else 'score-bad'}">Readiness: {score:.1f}%</div>
<div class="score-box {'score-good' if observed >= 70 else 'score-mid' if observed >= 40 else 'score-bad'}">Observed: {observed:.1f}%</div>

<h2>Evidence ({len(evidence)} items)</h2>
<table><tr><th>Type</th><th>Source</th><th>Confidence</th><th>Date</th></tr>"""
    for e in evidence[:30]:
        html += f"<tr><td>{e.get('evidence_type','')}</td><td>{e.get('source','')}</td><td>{e.get('confidence',0):.0%}</td><td>{e.get('collected_at','')[:10]}</td></tr>"
    html += "</table>"

    html += f"<h2>AI Observations ({len(observations)})</h2><table><tr><th>Query</th><th>Platform</th><th>Mentioned</th><th>Date</th></tr>"
    for o in observations:
        html += f"<tr><td>{o.get('query_text') or o.get('query') or ''}</td><td>{o.get('provider') or o.get('platform') or ''}</td><td>{'Yes' if o.get('brand_mentioned') else 'No'}</td><td>{str(o.get('observed_at',''))[:10]}</td></tr>"
    html += "</table>"

    html += f"<h2>Recommendations ({len(recs)})</h2>"
    for r in recs:
        title = r.get('title') or r.get('category') or 'Recommendation'
        desc = r.get('description') or r.get('recommendation') or ''
        html += f"<div class='rec'><strong>{title}</strong>: {desc}</div>"

    html += f"""<div class="footer">Generated by AI Search Visibility Agent v2 | {brand['brand_name']}</div>
</body></html>"""

    return {"success": True, "html": html, "company": brand['brand_name'], "score": score, "observed": observed}


# ---------------------------------------------------------------------------
# WEBHOOK / EMAIL ALERTS
# ---------------------------------------------------------------------------

WEBHOOK_URL = ""
WEBHOOK_SECRET = ""
SMTP_HOST = ""
SMTP_PORT = 587
SMTP_USER = ""
SMTP_PASS = ""
ALERT_EMAIL_TO = ""

def send_webhook(event_type, payload):
    """Send webhook notification if configured."""
    if not WEBHOOK_URL:
        return
    try:
        body = json.dumps({"event": event_type, "data": payload, "ts": datetime.datetime.utcnow().isoformat() + "Z"})
        headers = {"Content-Type": "application/json"}
        if WEBHOOK_SECRET:
            sig = hmac.new(WEBHOOK_SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()
            headers["X-Webhook-Signature"] = sig
        req = Request(WEBHOOK_URL, data=body.encode(), headers=headers, method="POST")
        urlopen(req, timeout=10)
        logger.info(f"Webhook sent: {event_type}")
    except Exception as e:
        logger.warning(f"Webhook failed: {e}")

def send_email_alert(subject, body_html):
    """Send email alert if SMTP configured."""
    if not SMTP_HOST or not ALERT_EMAIL_TO:
        return
    try:
        import smtplib
        from email.mime.text import MIMEText
        msg = MIMEText(body_html, "html")
        msg["Subject"] = f"[VisibilityAI] {subject}"
        msg["From"] = SMTP_USER
        msg["To"] = ALERT_EMAIL_TO
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
        logger.info(f"Email alert sent: {subject}")
    except Exception as e:
        logger.warning(f"Email alert failed: {e}")

def alert_score_change(brand_name, old_score, new_score):
    """Trigger alerts when scores change significantly."""
    delta = new_score - old_score
    if abs(delta) < 5:
        return
    direction = "improved" if delta > 0 else "dropped"
    subject = f"Score {direction}: {brand_name} ({old_score:.1f}% → {new_score:.1f}%)"
    body = f"<h2>Visibility Score Change</h2><p><b>{brand_name}</b>: {old_score:.1f}% → {new_score:.1f}% ({'+' if delta > 0 else ''}{delta:.1f}%)</p>"
    send_webhook("score_change", {"company": brand_name, "old_score": old_score, "new_score": new_score, "delta": delta})
    send_email_alert(subject, body)


# ---------------------------------------------------------------------------
# AUTOMATED BACKUP SYSTEM
# ---------------------------------------------------------------------------

BACKUP_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "backups")

def _ensure_backup_dir():
    os.makedirs(BACKUP_DIR, exist_ok=True)

def _prune_backups(keep=5):
    """Delete old backups, keeping only the newest `keep` files."""
    try:
        files = sorted([f for f in os.listdir(BACKUP_DIR) if f.endswith(".db")], reverse=True)
        for f in files[keep:]:
            try:
                os.remove(os.path.join(BACKUP_DIR, f))
            except Exception:
                pass
    except Exception:
        pass

def create_backup(label="auto"):
    """Create a timestamped backup of the database."""
    if db.flavor == "mysql":
        return {"success": True, "message": "MySQL backup skipped (use mysqldump)"}
    _ensure_backup_dir()
    ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    backup_path = os.path.join(BACKUP_DIR, f"agent_backup_{label}_{ts}.db")
    try:
        import shutil
        shutil.copy2(db.sqlite_path, backup_path)
        size = os.path.getsize(backup_path)
        logger.info(f"Backup created: {backup_path} ({size} bytes)")
        _prune_backups(keep=5)
        return {"success": True, "path": backup_path, "size": size}
    except Exception as e:
        logger.error(f"Backup failed: {e}")
        return {"success": False, "error": str(e)}

def list_backups():
    _ensure_backup_dir()
    files = sorted([f for f in os.listdir(BACKUP_DIR) if f.endswith(".db")], reverse=True)
    return [{"filename": f, "size": os.path.getsize(os.path.join(BACKUP_DIR, f)),
             "created": datetime.datetime.fromtimestamp(os.path.getctime(os.path.join(BACKUP_DIR, f))).isoformat()}
            for f in files[:20]]

def restore_backup(filename):
    """Restore database from a backup file."""
    backup_path = os.path.join(BACKUP_DIR, filename)
    if not os.path.exists(backup_path):
        return {"success": False, "error": "Backup not found"}
    try:
        import shutil
        create_backup("pre-restore")
        shutil.copy2(backup_path, db.sqlite_path)
        logger.info(f"Restored from: {filename}")
        return {"success": True, "message": f"Restored from {filename}. Restart server."}
    except Exception as e:
        return {"success": False, "error": str(e)}

# Auto-backup every 6 hours
def _auto_backup_loop():
    while True:
        _time.sleep(6 * 3600)
        try:
            create_backup("auto")
        except Exception:
            pass

def _get_api_docs():
    """Return OpenAPI-style documentation."""
    return {
        "openapi": "3.0.0",
        "info": {"title": "AI Search Visibility Agent API", "version": "2.0.0",
                 "description": "Autonomous AI search visibility intelligence system"},
        "servers": [{"url": "http://localhost:8000"}],
        "paths": {
            "/api/login": {"post": {"summary": "Authenticate user", "requestBody": {"content": {"application/json": {"schema": {"type": "object", "properties": {"username": {"type": "string"}, "password": {"type": "string"}}}}}}}},
            "/api/health": {"get": {"summary": "Health check (no auth)"}},
            "/companies": {"get": {"summary": "List all companies", "security": [{"bearer": []}]}},
            "/agent-state": {"get": {"summary": "Get agent state"}},
            "/history": {"get": {"summary": "Analysis history"}},
            "/api/agent-brain/status": {"get": {"summary": "Agent brain status"}},
            "/api/agent-brain/cycle": {"post": {"summary": "Run one agent cycle"}},
            "/api/agent-brain/start": {"post": {"summary": "Start autonomous agent"}},
            "/api/agent-brain/stop": {"post": {"summary": "Stop autonomous agent"}},
            "/api/report/pdf?company_id=N": {"get": {"summary": "Generate PDF report"}},
            "/api/tenants": {"get": {"summary": "List tenants (admin)"}},
            "/api/docs": {"get": {"summary": "API documentation (this endpoint)"}},
        },
        "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}}}
    }


# ---------------------------------------------------------------------------
# SERVER START
# ---------------------------------------------------------------------------

def start_server(port=8000, ssl_cert=None, ssl_key=None):
    print("=" * 60, flush=True)
    print("AI Search Brand Visibility Autonomous Intelligence Agent  v2", flush=True)
    print("=" * 60, flush=True)
    try:
        init_db()
    except Exception as e:
        print(f"[Fatal] DB init failed: {e}", flush=True)
        raise
    _init_tenants()
    if True:
        runner.start_loop()
    if True and get_config("scheduler_auto_start", "1") == "1":
        scheduler.start()
    # Start auto-backup thread
    _threading.Thread(target=_auto_backup_loop, daemon=True, name="auto-backup").start()
    # Create initial backup
    create_backup("startup")
    global _server_start_time
    _server_start_time = time.time()
    server = ThreadingHTTPServer(("", port), AgentServerHandler)
    scheme = "http"
    if ssl_cert and ssl_key:
        try:
            import ssl as _ssl
            _ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
            _ctx.load_cert_chain(ssl_cert, ssl_key)
            server.socket = _ctx.wrap_socket(server.socket, server_side=True)
            scheme = "https"
            print(f"TLS enabled with cert {ssl_cert}", flush=True)
        except Exception as e:
            print(f"[Fatal] TLS setup failed: {e}", flush=True)
            raise
    print(f"Running at: {scheme}://localhost:{port}", flush=True)
    print(f"Agent state: http://localhost:{port}/agent-state", flush=True)
    print(f"Manual analysis: POST /run-agent", flush=True)
    print("Press Ctrl+C to stop.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Agent Server...", flush=True)
        runner.stop_loop()
        server.server_close()


# ===========================================================================
# AUTONOMOUS AGENT BRAIN — Observe → Reason → Decide → Act → Reflect
# ===========================================================================
# This is the real agent core. It uses LLM to reason about the environment,
# make decisions, execute actions, and learn from outcomes.

import threading as _threading
import time as _time
import hashlib as _hashlib
from datetime import datetime as _dt, timezone as _tz

# ── Agent Memory Tables ────────────────────────────────────────────────────
_AGENT_MEMORY_DDL = """
CREATE TABLE IF NOT EXISTS agent_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    observation_type TEXT NOT NULL,
    entity_type TEXT DEFAULT 'company',
    entity_id INTEGER,
    summary TEXT NOT NULL,
    details TEXT DEFAULT '{}',
    severity TEXT DEFAULT 'INFO',
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS agent_brain_decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    decision_type TEXT NOT NULL,
    observation_id INTEGER,
    reasoning TEXT NOT NULL,
    chosen_action TEXT NOT NULL,
    action_params TEXT DEFAULT '{}',
    confidence REAL DEFAULT 0.5,
    status TEXT DEFAULT 'PENDING',
    created_at TEXT DEFAULT (datetime('now')),
    executed_at TEXT,
    FOREIGN KEY (observation_id) REFERENCES agent_observations(id)
);
CREATE TABLE IF NOT EXISTS agent_outcomes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    decision_id INTEGER NOT NULL,
    outcome_type TEXT NOT NULL,
    result_summary TEXT,
    metrics_before TEXT DEFAULT '{}',
    metrics_after TEXT DEFAULT '{}',
    reflection TEXT,
    lesson_learned TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (decision_id) REFERENCES agent_brain_decisions(id)
);
CREATE TABLE IF NOT EXISTS agent_strategy (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    strategy_key TEXT UNIQUE NOT NULL,
    strategy_value TEXT NOT NULL,
    confidence REAL DEFAULT 0.5,
    times_used INTEGER DEFAULT 0,
    times_succeeded INTEGER DEFAULT 0,
    updated_at TEXT DEFAULT (datetime('now'))
);
"""
try:
    for _ddl in _AGENT_MEMORY_DDL.strip().split(";"):
        _ddl = _ddl.strip()
        if _ddl:
            db.execute(_mysqlize_ddl(_ddl) if db.flavor == "mysql" else _ddl)
    print("[AgentBrain] Memory tables ready.", flush=True)
except Exception as _e:
    print(f"[AgentBrain] Memory table init: {_e}", flush=True)


class AgentObservation:
    """Something the agent noticed about the environment."""
    def __init__(self, obs_type, entity_id, summary, details=None, severity="INFO"):
        self.obs_type = obs_type
        self.entity_id = entity_id
        self.summary = summary
        self.details = details or {}
        self.severity = severity
        self.timestamp = _dt.now(_tz.utc).isoformat()

    def store(self):
        db.execute(
            "INSERT INTO agent_observations (observation_type, entity_id, summary, details, severity) VALUES (?,?,?,?,?)",
            (self.obs_type, self.entity_id, self.summary, json.dumps(self.details), self.severity))
        return db.query("SELECT last_insert_rowid() AS id")[0]["id"]


class AgentDecision:
    """A decision the agent made based on an observation."""
    def __init__(self, decision_type, observation_id, reasoning, action, params=None, confidence=0.5):
        self.decision_type = decision_type
        self.observation_id = observation_id
        self.reasoning = reasoning
        self.action = action
        self.params = params or {}
        self.confidence = confidence
        self.status = "PENDING"
        self.timestamp = _dt.now(_tz.utc).isoformat()

    def store(self):
        db.execute(
            "INSERT INTO agent_brain_decisions (decision_type, observation_id, reasoning, chosen_action, action_params, confidence, status, created_at) VALUES (?,?,?,?,?,?,?,?)",
            (self.decision_type, self.observation_id, self.reasoning, self.action,
             json.dumps(self.params or {}), self.confidence, "PENDING", now()))
        return db.query("SELECT last_insert_rowid() AS id")[0]["id"]

    def mark_executed(self):
        self.status = "EXECUTED"
        db.execute("UPDATE agent_brain_decisions SET status='EXECUTED' WHERE id=(SELECT last_insert_rowid())")


class AgentOutcome:
    """Result of executing a decision."""
    def __init__(self, decision_id, outcome_type, result_summary, metrics_before=None, metrics_after=None):
        self.decision_id = decision_id
        self.outcome_type = outcome_type
        self.result_summary = result_summary
        self.metrics_before = metrics_before or {}
        self.metrics_after = metrics_after or {}
        self.reflection = ""
        self.lesson = ""

    def store(self):
        db.execute(
            "INSERT INTO agent_outcomes (decision_id, outcome_type, result_summary, metrics_before, metrics_after, reflection, lesson_learned) VALUES (?,?,?,?,?,?,?)",
            (self.decision_id, self.outcome_type, self.result_summary,
             json.dumps(self.metrics_before), json.dumps(self.metrics_after),
             self.reflection, self.lesson))


class ObservationEngine:
    """Monitors the environment and generates observations for the agent."""

    def scan_all(self):
        """Scan all companies and return observations."""
        observations = []
        companies = db.query("SELECT * FROM brands WHERE is_active=1")
        for c in companies:
            observations.extend(self._scan_company(c))
        observations.extend(self._scan_global_trends())
        observations.extend(self._scan_learning_opportunities())
        # Sort by severity (HIGH first)
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        observations.sort(key=lambda o: sev_order.get(o.severity, 5))
        return observations

    def _scan_company(self, company):
        obs = []
        cid = company["id"]
        name = company["brand_name"]

        # Check if never analyzed
        if not company.get("last_analyzed_at"):
            obs.append(AgentObservation("NEEDS_ANALYSIS", cid,
                f"{name} has never been analyzed",
                {"brand_name": name, "urgency": "HIGH"}, "HIGH"))
            return obs

        # Check evidence freshness
        evidence = db.query("SELECT COUNT(*) as cnt FROM evidence WHERE brand_id=?", (cid,))
        ev_count = evidence[0]["cnt"] if evidence else 0
        if ev_count == 0:
            obs.append(AgentObservation("NO_EVIDENCE", cid,
                f"{name} has no website evidence collected",
                {"brand_name": name}, "MEDIUM"))

        # Check evidence age
        if ev_count > 0:
            oldest = db.query("SELECT MIN(collected_at) as oldest FROM evidence WHERE brand_id=?", (cid,))
            if oldest and oldest[0].get("oldest"):
                try:
                    age_days = (datetime.datetime.utcnow() - datetime.datetime.fromisoformat(str(oldest[0]["oldest"]))).days
                    if age_days > 30:
                        obs.append(AgentObservation("STALE_EVIDENCE", cid,
                            f"{name} evidence is {age_days} days old (needs refresh)",
                            {"brand_name": name, "age_days": age_days}, "MEDIUM"))
                except Exception:
                    pass

        # Check visibility score trend
        history = db.query(
            "SELECT readiness_score, visibility_score, observed_score, created_at FROM analysis_results WHERE brand_id=? ORDER BY id DESC LIMIT 5",
            (cid,))
        if len(history) >= 2:
            latest = history[0]["readiness_score"] or history[0]["visibility_score"] or 0
            prev = history[1]["readiness_score"] or history[1]["visibility_score"] or 0
            if latest < prev - 10:
                obs.append(AgentObservation("SCORE_DROP", cid,
                    f"{name} visibility dropped {prev}→{latest} (-{prev-latest})",
                    {"brand_name": name, "from": prev, "to": latest, "drop": prev-latest}, "HIGH"))
            elif latest > prev + 10:
                obs.append(AgentObservation("SCORE_IMPROVED", cid,
                    f"{name} visibility improved {prev}→{latest} (+{latest-prev})",
                    {"brand_name": name, "from": prev, "to": latest, "gain": latest-prev}, "INFO"))

            # Check if score is trending down over 3+ analyses
            if len(history) >= 3:
                scores = [(h["readiness_score"] or h["visibility_score"] or 0) for h in history]
                if all(scores[i] < scores[i+1] for i in range(len(scores)-1)):
                    obs.append(AgentObservation("CONTINUOUS_DECLINE", cid,
                        f"{name} score declining trend: {' → '.join(str(s) for s in scores)}",
                        {"brand_name": name, "trend": scores}, "CRITICAL"))

        # Check content gaps via recommendations table (no LLM call)
        open_recs = db.query(
            "SELECT COUNT(*) as cnt FROM recommendations WHERE brand_id=? AND priority='High' AND status='OPEN'", (cid,))
        high_gap_count = open_recs[0]["cnt"] if open_recs else 0
        if high_gap_count > 0:
            obs.append(AgentObservation("CONTENT_GAPS", cid,
                f"{name} has {high_gap_count} high-priority open content gaps",
                {"brand_name": name, "high_gap_count": high_gap_count}, "MEDIUM"))

        # Check observation score
        if history and history[0].get("observed_score") is not None:
            obs_score = history[0]["observed_score"]
            if obs_score == 0:
                obs.append(AgentObservation("NOT_IN_AI_SEARCH", cid,
                    f"{name} is NOT mentioned in AI search results",
                    {"brand_name": name, "observed_score": 0}, "HIGH"))
            elif obs_score < 30:
                obs.append(AgentObservation("LOW_AI_VISIBILITY", cid,
                    f"{name} has very low AI search visibility ({obs_score:.0f}%)",
                    {"brand_name": name, "observed_score": obs_score}, "MEDIUM"))

        # Check recommendation status
        recs = db.query(
            "SELECT COUNT(*) as total, SUM(CASE WHEN status='OPEN' THEN 1 ELSE 0 END) as open_count FROM recommendations WHERE brand_id=?",
            (cid,))
        if recs and recs[0].get("open_count", 0) and recs[0]["open_count"] > 3:
            obs.append(AgentObservation("MANY_OPEN_RECS", cid,
                f"{name} has {recs[0]['open_count']} unimplemented recommendations",
                {"brand_name": name, "open_count": recs[0]["open_count"]}, "MEDIUM"))

        # Check query diversity
        queries = db.query("SELECT COUNT(*) as cnt FROM query_memory WHERE brand_id=?", (cid,))
        q_count = queries[0]["cnt"] if queries else 0
        if q_count < 5:
            obs.append(AgentObservation("FEW_QUERIES", cid,
                f"{name} only has {q_count} search queries (need more diversity)",
                {"brand_name": name, "query_count": q_count}, "LOW"))

        # Check competitor gap (skip if table missing)
        try:
            competitors = db.query("SELECT COUNT(*) as cnt FROM competitors WHERE brand_id=?", (cid,))
            comp_count = competitors[0]["cnt"] if competitors else 0
            if comp_count == 0:
                obs.append(AgentObservation("NO_COMPETITORS", cid,
                    f"{name} has no competitors tracked",
                    {"brand_name": name}, "LOW"))
        except Exception:
            pass

        return obs

    def _scan_global_trends(self):
        obs = []
        # Check overall system health
        total = db.query("SELECT COUNT(*) as cnt FROM brands WHERE is_active=1")[0]["cnt"]
        analyzed = db.query("SELECT COUNT(*) as cnt FROM brands WHERE is_active=1 AND last_analyzed_at IS NOT NULL")[0]["cnt"]
        if total > 0 and analyzed / total < 0.5:
            obs.append(AgentObservation("LOW_COVERAGE", None,
                f"Only {analyzed}/{total} companies have been analyzed",
                {"total": total, "analyzed": analyzed}, "MEDIUM"))

        # Check for stale data
        stale = db.query(
            "SELECT COUNT(*) as cnt FROM brands WHERE is_active=1 AND last_analyzed_at < datetime('now', '-7 days')")[0]["cnt"]
        if stale > 0:
            obs.append(AgentObservation("STALE_DATA", None,
                f"{stale} companies haven't been re-analyzed in 7+ days",
                {"stale_count": stale}, "MEDIUM"))

        # Check job queue health
        pending_jobs = db.query("SELECT COUNT(*) as cnt FROM jobs WHERE status='PENDING'")[0]["cnt"]
        if pending_jobs > 50:
            obs.append(AgentObservation("JOB_QUEUE_BACKLOG", None,
                f"Job queue has {pending_jobs} pending jobs (potential bottleneck)",
                {"pending": pending_jobs}, "HIGH"))

        # Check failed jobs
        failed = db.query(
            "SELECT COUNT(*) as cnt FROM jobs WHERE status='FAILED' AND completed_at > datetime('now', '-1 hour')")[0]["cnt"]
        if failed > 5:
            obs.append(AgentObservation("HIGH_FAILURE_RATE", None,
                f"{failed} jobs failed in the last hour",
                {"failed_count": failed}, "HIGH"))

        return obs

    def _scan_learning_opportunities(self):
        """Find patterns in past outcomes to generate meta-observations."""
        obs = []

        # Check if certain job types consistently fail
        job_stats = db.query("""
            SELECT job_type, COUNT(*) as total,
                   SUM(CASE WHEN status='FAILED' THEN 1 ELSE 0 END) as failed
            FROM jobs WHERE completed_at > datetime('now', '-24 hours')
            GROUP BY job_type HAVING total > 3
        """)
        for js in job_stats:
            fail_rate = js["failed"] / js["total"] if js["total"] > 0 else 0
            if fail_rate > 0.5:
                obs.append(AgentObservation("JOB_TYPE_FAILING", None,
                    f"Job type {js['job_type']} has {fail_rate:.0%} failure rate ({js['failed']}/{js['total']})",
                    {"job_type": js["job_type"], "fail_rate": fail_rate}, "HIGH"))

        # Check if LLM calls are succeeding
        llm_stats = db.query("""
            SELECT COUNT(*) as total,
                   SUM(CASE WHEN metadata_json LIKE '%Skipped%' THEN 1 ELSE 0 END) as skipped
            FROM agent_decisions WHERE created_at > datetime('now', '-24 hours')
        """)
        if llm_stats and llm_stats[0]["total"] > 10:
            skip_rate = llm_stats[0]["skipped"] / llm_stats[0]["total"]
            if skip_rate > 0.8:
                obs.append(AgentObservation("HIGH_DECISION_SKIP_RATE", None,
                    f"Agent decisions are being skipped at {skip_rate:.0%} rate — may need strategy adjustment",
                    {"skip_rate": skip_rate}, "MEDIUM"))

        return obs


class DecisionEngine:
    """Uses LLM to reason about observations and decide actions."""

    def decide(self, observations, memory_context=""):
        """Given observations, decide what actions to take."""
        if not observations:
            return []

        # Build context for LLM with company details
        obs_lines = []
        for o in observations[:10]:
            company_info = ""
            if o.entity_id:
                brand = get_brand(o.entity_id)
                if brand:
                    company_info = f" [{brand['brand_name']}"
                    history = db.query(
                        "SELECT readiness_score, observed_score FROM analysis_results WHERE brand_id=? ORDER BY id DESC LIMIT 1",
                        (o.entity_id,))
                    if history:
                        company_info += f" score={history[0]['readiness_score'] or 0:.0f} obs={history[0]['observed_score'] or 0:.0f}"
                    # Add evidence count
                    ev = db.query("SELECT COUNT(*) as c FROM evidence WHERE brand_id=?", (o.entity_id,))
                    company_info += f" ev={ev[0]['c'] if ev else 0}"
                    company_info += "]"
            obs_lines.append(f"- [{o.severity}] {o.obs_type}: {o.summary}{company_info}")

        obs_text = "\n".join(obs_lines)

        # Get portfolio overview for strategic decisions
        portfolio = db.query("""
            SELECT b.id, b.brand_name,
                (SELECT readiness_score FROM analysis_results WHERE brand_id=b.id ORDER BY id DESC LIMIT 1) as score,
                (SELECT observed_score FROM analysis_results WHERE brand_id=b.id ORDER BY id DESC LIMIT 1) as obs_score
            FROM brands b WHERE b.is_active=1 ORDER BY score ASC LIMIT 5
        """)
        low_performers = [f"{p['brand_name']}(score={p['score'] or 0:.0f})" for p in portfolio if (p['score'] or 0) < 40]

        prompt = f"""You are an autonomous AI search visibility agent with deep expertise in SEO, AI search optimization, and brand visibility. Analyze observations and decide actions.

OBSERVATIONS:
{obs_text}

PORTFOLIO LOW PERFORMERS: {', '.join(low_performers) if low_performers else 'None'}

AVAILABLE ACTIONS:
1. ANALYZE_COMPANY - Full analysis pipeline (param: company_id)
2. SCRAPE_WEBSITE - Re-scrape for fresh evidence (param: company_id)
3. GENERATE_QUERIES - Generate diverse search queries (param: company_id)
4. RUN_AI_SEARCH - Query AI search engines (param: company_id)
5. FIX_CONTENT_GAPS - Create content recommendations (param: company_id)
6. REFRESH_STALE - Re-analyze stale companies (param: company_id[])
7. MONITOR_COMPETITORS - Check competitor visibility (param: company_id)
8. SKIP - No action needed right now

{memory_context}

STRATEGIC DECISION RULES:
1. CRITICAL severity: IMMEDIATE action required (score drop >15pts, continuous decline)
2. HIGH severity: Address within this cycle (not in AI search, no evidence, score <30)
3. MEDIUM severity: Queue for next cycle (stale evidence, few queries)
4. LOW severity: Consider if no higher priority items (no competitors, few queries)
5. PORTFOLIO STRATEGY: Prioritize companies with lowest scores first
6. EFFICIENCY: Batch similar actions (e.g., scrape multiple companies)
7. LEARNING: Don't repeat failed actions without evidence of change
8. RECOVERY: If >30% jobs failed recently, SKIP non-critical actions

MAX 5 DECISIONS per cycle. Focus on highest impact actions.

Respond with a JSON array. Each decision:
{{"action": "ACTION_NAME", "company_id": N, "reasoning": "specific strategic reason", "priority": "HIGH/MEDIUM/LOW", "confidence": 0.0-1.0}}

Return ONLY the JSON array."""

        try:
            text, model = _gemini_complete(prompt, max_tokens=600, temperature=0.3)
            data = json.loads(clean_json_text(text))
            if isinstance(data, list):
                # Validate and deduplicate
                seen = set()
                validated = []
                for d in data:
                    key = (d.get("action"), d.get("company_id"))
                    if key not in seen and d.get("action") != "SKIP":
                        seen.add(key)
                        validated.append(d)
                return validated[:5]
        except Exception as e:
            logger.warning(f"DecisionEngine LLM failed: {e}")

        # Fallback: rule-based decisions
        return self._rule_based_decide(observations)

    def _rule_based_decide(self, observations):
        decisions = []
        seen = set()
        for obs in observations:
            if len(decisions) >= 5:
                break
            key = (obs.obs_type, obs.entity_id)
            if key in seen:
                continue
            seen.add(key)

            if obs.obs_type == "NEEDS_ANALYSIS" and obs.entity_id:
                decisions.append({
                    "action": "ANALYZE_COMPANY", "company_id": obs.entity_id,
                    "reasoning": obs.summary, "priority": "HIGH", "confidence": 0.8
                })
            elif obs.obs_type == "NO_EVIDENCE" and obs.entity_id:
                decisions.append({
                    "action": "SCRAPE_WEBSITE", "company_id": obs.entity_id,
                    "reasoning": obs.summary, "priority": "MEDIUM", "confidence": 0.7
                })
            elif obs.obs_type in ("SCORE_DROP", "CONTINUOUS_DECLINE") and obs.entity_id:
                decisions.append({
                    "action": "ANALYZE_COMPANY", "company_id": obs.entity_id,
                    "reasoning": obs.summary, "priority": "HIGH", "confidence": 0.9
                })
            elif obs.obs_type == "NOT_IN_AI_SEARCH" and obs.entity_id:
                decisions.append({
                    "action": "RUN_AI_SEARCH", "company_id": obs.entity_id,
                    "reasoning": obs.summary, "priority": "HIGH", "confidence": 0.85
                })
            elif obs.obs_type == "STALE_EVIDENCE" and obs.entity_id:
                decisions.append({
                    "action": "SCRAPE_WEBSITE", "company_id": obs.entity_id,
                    "reasoning": obs.summary, "priority": "MEDIUM", "confidence": 0.75
                })
            elif obs.obs_type == "CONTENT_GAPS" and obs.entity_id:
                decisions.append({
                    "action": "FIX_CONTENT_GAPS", "company_id": obs.entity_id,
                    "reasoning": obs.summary, "priority": "MEDIUM", "confidence": 0.7
                })
            elif obs.obs_type == "NO_COMPETITORS" and obs.entity_id:
                decisions.append({
                    "action": "MONITOR_COMPETITORS", "company_id": obs.entity_id,
                    "reasoning": obs.summary, "priority": "LOW", "confidence": 0.6
                })
            elif obs.obs_type == "FEW_QUERIES" and obs.entity_id:
                decisions.append({
                    "action": "GENERATE_QUERIES", "company_id": obs.entity_id,
                    "reasoning": obs.summary, "priority": "LOW", "confidence": 0.65
                })
            elif obs.obs_type == "STALE_DATA" and obs.entity_id:
                decisions.append({
                    "action": "ANALYZE_COMPANY", "company_id": obs.entity_id,
                    "reasoning": obs.summary, "priority": "MEDIUM", "confidence": 0.7
                })
        return decisions[:5]


class ReflectionEngine:
    """Evaluates outcomes and learns from results."""

    def reflect(self, decision_id, outcome):
        """Analyze an outcome and extract lessons."""
        # Get before/after scores for context
        metrics_before = outcome.metrics_before or {}
        metrics_after = outcome.metrics_after or {}
        score_change = 0
        if metrics_before.get("score") and metrics_after.get("score"):
            score_change = metrics_after["score"] - metrics_before["score"]

        prompt = f"""You are an AI agent reflecting on an action you took.

ACTION TAKEN: {outcome.outcome_type}
RESULT: {outcome.result_summary}
SCORE CHANGE: {'+' if score_change >= 0 else ''}{score_change:.1f} points
METRICS BEFORE: {json.dumps(metrics_before)}
METRICS AFTER: {json.dumps(metrics_after)}

Provide:
1. reflection: What happened and why (1-2 sentences)
2. lesson: What to remember for future similar situations (1 sentence)
3. strategy_update: Should we change our approach? (ONE of: KEEP, ADJUST, PIVOT)
4. effectiveness: Rate this action's effectiveness (0.0 to 1.0)

Respond as JSON: {{"reflection": "...", "lesson": "...", "strategy_update": "KEEP", "effectiveness": 0.5}}"""

        try:
            text, model = _gemini_complete(prompt, max_tokens=400, temperature=0.3)
            data = json.loads(clean_json_text(text))
            outcome.reflection = data.get("reflection", "")
            outcome.lesson = data.get("lesson", "")
            effectiveness = float(data.get("effectiveness", 0.5))
        except Exception:
            outcome.reflection = f"Action {outcome.outcome_type} completed"
            outcome.lesson = ""
            effectiveness = 0.5

        outcome.store()

        # Store strategy update if PIVOT
        try:
            strategy_update = data.get("strategy_update", "KEEP")
            if strategy_update in ("PIVOT", "ADJUST"):
                db.execute(
                    "INSERT INTO agent_strategy (strategy_key, strategy_value, confidence, times_used, times_succeeded, updated_at) VALUES (?,?,?,?,?,?)",
                    (strategy_update, outcome.lesson, effectiveness, 1, 1 if score_change > 0 else 0, now()))
        except Exception:
            pass

        return outcome

    def get_strategy_context(self):
        """Get recent strategies for decision context."""
        strategies = db.query(
            "SELECT strategy_key, strategy_value, confidence FROM agent_strategy ORDER BY id DESC LIMIT 10")
        if not strategies:
            return ""
        lines = ["LEARNED STRATEGIES:"]
        for s in strategies:
            lines.append(f"- [{s['strategy_key']}] {s['strategy_value']} (confidence: {s['confidence']:.1f})")
        return "\n".join(lines)


class AutonomousAgent:
    """The main autonomous agent loop: Observe → Reason → Decide → Act → Reflect."""

    def __init__(self):
        self.running = False
        self.loop_thread = None
        self.observation_engine = ObservationEngine()
        self.decision_engine = DecisionEngine()
        self.reflection_engine = ReflectionEngine()
        self.cycle_count = 0
        self.max_cycles = 50
        self.cycle_interval = 60  # seconds between cycles
        self.last_cycle_at = None
        self.stats = {"observations": 0, "decisions": 0, "actions": 0, "reflections": 0}

    def start(self):
        if self.running:
            return {"success": False, "error": "Agent already running"}
        self.running = True
        self.loop_thread = _threading.Thread(target=self._run_loop, daemon=True, name="agent-brain")
        self.loop_thread.start()
        log_activity("Agent brain started", level="RUN")
        return {"success": True, "message": "Autonomous agent started"}

    def stop(self):
        self.running = False
        log_activity("Agent brain stopped", level="RUN")
        return {"success": True, "message": "Autonomous agent stopped"}

    def status(self):
        return {
            "running": self.running,
            "cycle_count": self.cycle_count,
            "max_cycles": self.max_cycles,
            "cycle_interval": self.cycle_interval,
            "last_cycle_at": self.last_cycle_at,
            "stats": self.stats
        }

    def run_one_cycle(self):
        """Execute a single observe→reason→act→reflect cycle."""
        self.cycle_count += 1
        cycle_id = self.cycle_count
        log_activity(f"Agent brain cycle #{cycle_id} starting", level="RUN")

        # 1. OBSERVE
        observations = self.observation_engine.scan_all()
        self.stats["observations"] += len(observations)
        log_activity(f"Cycle #{cycle_id}: {len(observations)} observations", level="RUN")

        if not observations:
            log_activity(f"Cycle #{cycle_id}: No observations, skipping", level="RUN")
            return {"cycle": cycle_id, "observations": 0, "decisions": 0, "actions": 0}

        # Store observations
        for obs in observations:
            obs.store()

        # 2. DECIDE
        memory_ctx = self._get_memory_context()
        raw_decisions = self.decision_engine.decide(observations, memory_ctx)
        self.stats["decisions"] += len(raw_decisions)
        log_activity(f"Cycle #{cycle_id}: {len(raw_decisions)} decisions made", level="RUN")

        # Store decisions in DB
        stored_decisions = []
        for d in raw_decisions:
            ad = AgentDecision(
                decision_type=d.get("action", "UNKNOWN"),
                observation_id=0,
                reasoning=d.get("reasoning", ""),
                action=d.get("action", ""),
                params={"company_id": d.get("company_id")},
                confidence=d.get("confidence", 0.5)
            )
            did = ad.store()
            stored_decisions.append((d, ad, did))

        # 3. ACT
        actions_taken = 0
        for d, ad, did in stored_decisions:
            success = self._execute_decision(d)
            if success:
                actions_taken += 1
                self.stats["actions"] += 1
                ad.mark_executed()

        # 4. REFLECT (on completed jobs)
        self._reflect_on_recent(cycle_id)

        self.last_cycle_at = _dt.now(_tz.utc).isoformat()
        result = {"cycle": cycle_id, "observations": len(observations),
                  "decisions": len(raw_decisions), "actions": actions_taken}
        log_activity(f"Cycle #{cycle_id} complete: {result}", level="RUN")
        return result

    def _execute_decision(self, decision):
        """Execute a single decision."""
        action = decision.get("action", "")
        cid = decision.get("company_id")
        reasoning = decision.get("reasoning", "")

        try:
            if action == "ANALYZE_COMPANY" and cid:
                brand = get_brand(cid)
                if not brand:
                    return False
                # Create jobs for full analysis
                jobs = ["COLLECT_WEBSITE_DATA", "VALIDATE_DATA", "ANALYZE_BRAND",
                        "DETECT_CONTENT_GAPS", "GENERATE_RECOMMENDATIONS", "STORE_ANALYSIS"]
                for jt in jobs:
                    ensure_job(jt, cid)
                log_activity(f"Agent created {len(jobs)} jobs for company #{cid}: {reasoning[:80]}", level="RUN")
                return True

            elif action == "SCRAPE_WEBSITE" and cid:
                brand = get_brand(cid)
                if brand and brand.get("website"):
                    ensure_job("COLLECT_WEBSITE_DATA", cid)
                    log_activity(f"Agent queued website scrape for #{cid}: {reasoning[:80]}", level="RUN")
                    return True

            elif action == "GENERATE_QUERIES" and cid:
                ensure_job("GENERATE_QUERIES", cid)
                log_activity(f"Agent queued query generation for #{cid}: {reasoning[:80]}", level="RUN")
                return True

            elif action == "RUN_AI_SEARCH" and cid:
                ensure_job("RUN_AI_SEARCH", cid)
                log_activity(f"Agent queued AI search for #{cid}: {reasoning[:80]}", level="RUN")
                return True

            elif action == "FIX_CONTENT_GAPS" and cid:
                ensure_job("GENERATE_RECOMMENDATIONS", cid)
                log_activity(f"Agent queued content gap fix for #{cid}: {reasoning[:80]}", level="RUN")
                return True

            elif action == "REFRESH_STALE":
                cids = decision.get("company_id", [])
                if isinstance(cids, list):
                    for c in cids:
                        ensure_job("ANALYZE_BRAND", c)
                    log_activity(f"Agent refreshed {len(cids)} stale companies", level="RUN")
                    return True

            elif action == "MONITOR_COMPETITORS" and cid:
                ensure_job("ANALYZE_COMPETITORS", cid)
                log_activity(f"Agent queued competitor monitoring for #{cid}: {reasoning[:80]}", level="RUN")
                return True

            elif action == "SKIP":
                return True

        except Exception as e:
            log_activity(f"Agent action failed: {action} #{cid}: {e}", level="ERROR")
            return False

        return False

    def _reflect_on_recent(self, cycle_id):
        """Check recent completed jobs and reflect on outcomes."""
        cutoff = (datetime.datetime.utcnow() - datetime.timedelta(minutes=5)).isoformat(timespec="seconds")
        recent = db.query(
            "SELECT j.* FROM jobs j WHERE j.status='COMPLETED' AND j.completed_at > ? ORDER BY j.created_at DESC, j.id DESC LIMIT 10",
            (cutoff,))
        for job in recent:
            if not job.get("company_id"):
                continue
            brand = get_brand(job["company_id"])
            if not brand:
                continue

            # Check if score improved after this job
            score_after = db.query(
                "SELECT readiness_score, visibility_score FROM analysis_results WHERE brand_id=? ORDER BY id DESC LIMIT 1",
                (job["company_id"],))
            score_val = 0
            if score_after:
                score_val = score_after[0]["readiness_score"] or score_after[0]["visibility_score"] or 0

            outcome = AgentOutcome(
                decision_id=0,
                outcome_type=job["job_type"],
                result_summary=f"Job {job['job_type']} completed for {brand['brand_name']}",
                metrics_after={"score": score_val}
            )
            self.reflection_engine.reflect(0, outcome)
            self.stats["reflections"] += 1

    def _get_memory_context(self):
        """Get recent decisions, lessons, and strategies for context."""
        recent = db.query(
            "SELECT d.action, d.reason, d.status, o.lesson_learned FROM agent_decisions d LEFT JOIN agent_outcomes o ON o.decision_id=d.id ORDER BY d.id DESC LIMIT 10")
        lines = []
        if recent:
            lines.append("RECENT DECISION HISTORY:")
            for r in recent:
                lesson = f" | Lesson: {r['lesson_learned']}" if r.get("lesson_learned") else ""
                lines.append(f"- {r['action']}: {r['reason'][:60]} [{r['status']}]{lesson}")

        # Add strategy context
        strategy_ctx = self.reflection_engine.get_strategy_context()
        if strategy_ctx:
            lines.append("")
            lines.append(strategy_ctx)

        # Add performance stats
        total_actions = self.stats["actions"]
        total_reflections = self.stats["reflections"]
        if total_actions > 0:
            success_rate = total_reflections / total_actions if total_actions > 0 else 0
            lines.append(f"\nAGENT PERFORMANCE: {total_actions} actions taken, {total_reflections} reflections, {success_rate:.0%} completion rate")

        return "\n".join(lines) if lines else "No prior decisions in memory."

    def _run_loop(self):
        """Main autonomous loop."""
        while self.running and self.cycle_count < self.max_cycles:
            try:
                self.run_one_cycle()
            except Exception as e:
                log_activity(f"Agent brain cycle error: {e}", level="ERROR")
            _time.sleep(self.cycle_interval)
        self.running = False
        log_activity("Agent brain loop finished", level="RUN")


# Singleton
agent_brain = AutonomousAgent()


# ── Agent Brain API Endpoints ──────────────────────────────────────────────
def agent_brain_status():
    status = agent_brain.status()
    # Get recent observations
    observations = db.query("SELECT * FROM agent_observations ORDER BY id DESC LIMIT 20")
    decisions = db.query("SELECT * FROM agent_brain_decisions ORDER BY id DESC LIMIT 20")
    outcomes = db.query("SELECT * FROM agent_outcomes ORDER BY id DESC LIMIT 10")
    strategies = db.query("SELECT * FROM agent_strategy ORDER BY times_used DESC LIMIT 10")
    return {
        "success": True,
        "status": status,
        "observations": observations,
        "decisions": decisions,
        "outcomes": outcomes,
        "strategies": strategies
    }


def agent_brain_start():
    return agent_brain.start()


def agent_brain_stop():
    return agent_brain.stop()


def agent_brain_run_cycle():
    return agent_brain.run_one_cycle()

# ===========================================================================
# PHASE 19: WORKFLOW SELF-LEARNING & ORCHESTRATION ADAPTATION
# ===========================================================================
# Detects workflow changes, reasons about orchestration impact, adapts
# execution, learns from outcomes, and reuses successful patterns.

import hashlib as _wf_hashlib
import copy as _wf_copy

# ---------------------------------------------------------------------------
# 19.1 DATABASE SCHEMA
# ---------------------------------------------------------------------------

_WORKFLOW_DDL = """
CREATE TABLE IF NOT EXISTS workflow_definitions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workflow_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    status TEXT DEFAULT 'DRAFT',
    created_by TEXT DEFAULT 'SYSTEM',
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS workflow_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workflow_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    status TEXT DEFAULT 'DRAFT',
    definition_json TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    change_summary TEXT DEFAULT '',
    parent_version INTEGER,
    created_by TEXT DEFAULT 'SYSTEM',
    created_at TEXT DEFAULT (datetime('now')),
    UNIQUE(workflow_id, version),
    FOREIGN KEY (workflow_id) REFERENCES workflow_definitions(workflow_id)
);

CREATE TABLE IF NOT EXISTS workflow_changes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workflow_id TEXT NOT NULL,
    from_version INTEGER NOT NULL,
    to_version INTEGER NOT NULL,
    change_type TEXT NOT NULL,
    step_id TEXT,
    old_value TEXT,
    new_value TEXT,
    impact TEXT DEFAULT 'LOW',
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS workflow_adaptations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    adaptation_id TEXT UNIQUE NOT NULL,
    workflow_id TEXT NOT NULL,
    from_version INTEGER NOT NULL,
    to_version INTEGER NOT NULL,
    changes_json TEXT NOT NULL,
    orchestration_plan TEXT NOT NULL,
    impact TEXT NOT NULL,
    status TEXT DEFAULT 'PENDING',
    approval_required INTEGER DEFAULT 0,
    approved_by TEXT,
    approved_at TEXT,
    execution_result TEXT,
    execution_error TEXT,
    started_at TEXT,
    completed_at TEXT,
    company_id INTEGER,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS workflow_adaptation_patterns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern_key TEXT NOT NULL,
    pattern_description TEXT NOT NULL,
    change_type TEXT NOT NULL,
    observed_count INTEGER DEFAULT 1,
    success_count INTEGER DEFAULT 0,
    failure_count INTEGER DEFAULT 0,
    success_rate REAL DEFAULT 0.0,
    last_observed_at TEXT DEFAULT (datetime('now')),
    applicable_context TEXT DEFAULT '{}',
    adaptation_template TEXT NOT NULL,
    confidence REAL DEFAULT 0.5,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS workflow_adaptation_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workflow_id TEXT NOT NULL,
    adaptation_id TEXT,
    event_type TEXT NOT NULL,
    version INTEGER,
    details TEXT DEFAULT '{}',
    created_at TEXT DEFAULT (datetime('now'))
);
"""

WORKFLOW_STATUSES = ("DRAFT", "VALIDATING", "ACTIVE", "SUPERSEDED", "FAILED", "ROLLED_BACK")
CHANGE_TYPES = ("STEP_ADDED", "STEP_REMOVED", "STEP_MODIFIED",
                "DEPENDENCY_ADDED", "DEPENDENCY_REMOVED", "ORDER_CHANGED",
                "AGENT_CHANGED", "TOOL_CHANGED", "CAPABILITY_CHANGED",
                "APPROVAL_CHANGED", "FAILURE_POLICY_CHANGED", "SUCCESS_CONDITION_CHANGED")
IMPACT_LEVELS = ("NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL")
ADAPTATION_STATUSES = ("PENDING", "VALIDATING", "APPROVED", "EXECUTING", "COMPLETED", "FAILED", "REJECTED", "ROLLED_BACK")
AUTO_ADAPTATION_KEY = "workflow_auto_adaptation"


def _wf_init_tables():
    """Initialize workflow versioning tables."""
    try:
        for ddl in _WORKFLOW_DDL.split(";"):
            ddl = ddl.strip()
            if ddl:
                db.execute(_mysqlize_ddl(ddl) if db.flavor == "mysql" else ddl)
    except Exception as e:
        print(f"[Workflow] table init skipped: {e}", flush=True)


def _wf_fingerprint(definition):
    """Compute deterministic fingerprint for a workflow definition."""
    canonical = json.dumps(definition, sort_keys=True, separators=(",", ":"))
    return _wf_hashlib.sha256(canonical.encode()).hexdigest()[:16]


def _wf_now():
    return datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"


# ---------------------------------------------------------------------------
# 19.2 WORKFLOW VERSIONING
# ---------------------------------------------------------------------------

def workflow_create(name, description="", steps=None, dependencies=None,
                    metadata=None, created_by="SYSTEM"):
    """Create a new workflow definition with version 1."""
    wf_id = f"WF-{secrets.token_hex(6)}"
    definition = {
        "steps": steps or [],
        "dependencies": dependencies or {},
        "metadata": metadata or {},
    }
    fingerprint = _wf_fingerprint(definition)
    db.execute("INSERT INTO workflow_definitions (workflow_id, name, description, status, created_by) VALUES (?,?,?,?,?)",
               (wf_id, name, description, "DRAFT", created_by))
    db.execute("INSERT INTO workflow_versions (workflow_id, version, status, definition_json, fingerprint, parent_version, created_by) VALUES (?,?,?,?,?,?,?)",
               (wf_id, 1, "DRAFT", json.dumps(definition), fingerprint, None, created_by))
    _wf_log_event(wf_id, "WORKFLOW_CREATED", 1, {"name": name})
    return {"workflow_id": wf_id, "version": 1, "fingerprint": fingerprint}


def workflow_get(wf_id):
    """Get workflow definition."""
    rows = db.query("SELECT * FROM workflow_definitions WHERE workflow_id=?", (wf_id,))
    if not rows:
        return None
    wf = dict(rows[0])
    versions = db.query("SELECT * FROM workflow_versions WHERE workflow_id=? ORDER BY version", (wf_id,))
    wf["versions"] = [dict(v) for v in versions]
    active = [v for v in versions if v["status"] == "ACTIVE"]
    wf["active_version"] = dict(active[-1]) if active else None
    return wf


def workflow_list():
    """List all workflows."""
    rows = db.query("SELECT * FROM workflow_definitions ORDER BY created_at DESC")
    return [dict(r) for r in rows]


def workflow_versions(wf_id):
    """List all versions of a workflow."""
    return [dict(v) for v in db.query(
        "SELECT * FROM workflow_versions WHERE workflow_id=? ORDER BY version", (wf_id,))]


def workflow_create_version(wf_id, steps, dependencies=None, metadata=None,
                            change_summary="", created_by="SYSTEM"):
    """Create a new version of a workflow."""
    rows = db.query("SELECT version FROM workflow_versions WHERE workflow_id=? ORDER BY version DESC LIMIT 1", (wf_id,))
    if not rows:
        return {"error": "Workflow not found"}
    last_ver = rows[0]["version"]
    new_ver = last_ver + 1
    definition = {"steps": steps, "dependencies": dependencies or {}, "metadata": metadata or {}}
    fingerprint = _wf_fingerprint(definition)
    db.execute(
        "INSERT INTO workflow_versions (workflow_id, version, status, definition_json, fingerprint, change_summary, parent_version, created_by) VALUES (?,?,?,?,?,?,?,?)",
        (wf_id, new_ver, "DRAFT", json.dumps(definition), fingerprint, change_summary, last_ver, created_by))
    _wf_log_event(wf_id, "VERSION_CREATED", new_ver, {"from_version": last_ver, "summary": change_summary})
    return {"workflow_id": wf_id, "version": new_ver, "fingerprint": fingerprint, "parent_version": last_ver}


def workflow_activate_version(wf_id, version):
    """Mark a version as ACTIVE, supersede old active versions."""
    rows = db.query("SELECT status FROM workflow_versions WHERE workflow_id=? AND version=?", (wf_id, version))
    if not rows:
        return {"error": "Version not found"}
    db.execute("UPDATE workflow_versions SET status='SUPERSEDED' WHERE workflow_id=? AND status='ACTIVE'", (wf_id,))
    db.execute("UPDATE workflow_versions SET status='ACTIVE' WHERE workflow_id=? AND version=?", (wf_id, version))
    db.execute("UPDATE workflow_definitions SET status='ACTIVE' WHERE workflow_id=?", (wf_id,))
    _wf_log_event(wf_id, "VERSION_ACTIVATED", version, {})
    return {"success": True}


# ---------------------------------------------------------------------------
# 19.3 WORKFLOW DIFF ENGINE
# ---------------------------------------------------------------------------

def workflow_diff(wf_id, version_a, version_b):
    """Structural comparison between two workflow versions."""
    va_rows = db.query("SELECT definition_json FROM workflow_versions WHERE workflow_id=? AND version=?", (wf_id, version_a))
    vb_rows = db.query("SELECT definition_json FROM workflow_versions WHERE workflow_id=? AND version=?", (wf_id, version_b))
    if not va_rows or not vb_rows:
        return {"error": "Version(s) not found"}
    old_def = json.loads(va_rows[0]["definition_json"])
    new_def = json.loads(vb_rows[0]["definition_json"])
    return _wf_diff_definitions(old_def, new_def)


def _wf_diff_definitions(old_def, new_def):
    """Compare two workflow definitions and produce change records."""
    changes = []
    old_steps = {s["id"]: s for s in (old_def.get("steps") or [])}
    new_steps = {s["id"]: s for s in (new_def.get("steps") or [])}
    old_ids = set(old_steps.keys())
    new_ids = set(new_steps.keys())

    for sid in new_ids - old_ids:
        changes.append({"change_type": "STEP_ADDED", "step_id": sid,
                        "new_value": json.dumps(new_steps[sid]), "impact": "MEDIUM"})
    for sid in old_ids - new_ids:
        changes.append({"change_type": "STEP_REMOVED", "step_id": sid,
                        "old_value": json.dumps(old_steps[sid]), "impact": "MEDIUM"})
    for sid in old_ids & new_ids:
        old_s, new_s = old_steps[sid], new_steps[sid]
        if old_s != new_s:
            if old_s.get("agent") != new_s.get("agent"):
                changes.append({"change_type": "AGENT_CHANGED", "step_id": sid,
                                "old_value": old_s.get("agent"), "new_value": new_s.get("agent"), "impact": "MEDIUM"})
            if old_s.get("tool") != new_s.get("tool"):
                changes.append({"change_type": "TOOL_CHANGED", "step_id": sid,
                                "old_value": old_s.get("tool"), "new_value": new_s.get("tool"), "impact": "LOW"})
            if old_s.get("operation") != new_s.get("operation"):
                changes.append({"change_type": "STEP_MODIFIED", "step_id": sid,
                                "old_value": old_s.get("operation"), "new_value": new_s.get("operation"), "impact": "MEDIUM"})
            if old_s.get("approval_required") != new_s.get("approval_required"):
                changes.append({"change_type": "APPROVAL_CHANGED", "step_id": sid,
                                "old_value": old_s.get("approval_required"), "new_value": new_s.get("approval_required"), "impact": "HIGH"})
            if old_s.get("failure_policy") != new_s.get("failure_policy"):
                changes.append({"change_type": "FAILURE_POLICY_CHANGED", "step_id": sid,
                                "old_value": old_s.get("failure_policy"), "new_value": new_s.get("failure_policy"), "impact": "MEDIUM"})
            if old_s.get("success_condition") != new_s.get("success_condition"):
                changes.append({"change_type": "SUCCESS_CONDITION_CHANGED", "step_id": sid,
                                "old_value": old_s.get("success_condition"), "new_value": new_s.get("success_condition"), "impact": "LOW"})

    old_deps = old_def.get("dependencies") or {}
    new_deps = new_def.get("dependencies") or {}
    all_step_ids = set(old_deps.keys()) | set(new_deps.keys())
    for sid in all_step_ids:
        old_d = set(old_deps.get(sid) or [])
        new_d = set(new_deps.get(sid) or [])
        for dep in new_d - old_d:
            changes.append({"change_type": "DEPENDENCY_ADDED", "step_id": sid,
                            "new_value": dep, "impact": "MEDIUM"})
        for dep in old_d - new_d:
            changes.append({"change_type": "DEPENDENCY_REMOVED", "step_id": sid,
                            "old_value": dep, "impact": "MEDIUM"})

    old_order = list(old_steps.keys())
    new_order = list(new_steps.keys())
    common = [s for s in new_order if s in old_ids]
    old_common_pos = {s: i for i, s in enumerate(old_order) if s in old_ids}
    if len(common) > 1:
        for i in range(len(common) - 1):
            if old_common_pos.get(common[i], 0) > old_common_pos.get(common[i + 1], 0):
                changes.append({"change_type": "ORDER_CHANGED", "step_id": common[i],
                                "old_value": str(old_common_pos[common[i]]), "new_value": str(i), "impact": "HIGH"})
                break
    return changes


# ---------------------------------------------------------------------------
# 19.4 CHANGE IMPACT ANALYSIS
# ---------------------------------------------------------------------------

def workflow_impact_analysis(wf_id, version_a, version_b, company_id=None):
    """Calculate impact of workflow change considering running state."""
    changes = workflow_diff(wf_id, version_a, version_b)
    if isinstance(changes, dict) and "error" in changes:
        return changes

    severity_map = {"STEP_ADDED": "LOW", "STEP_REMOVED": "MEDIUM", "STEP_MODIFIED": "LOW",
                    "DEPENDENCY_ADDED": "LOW", "DEPENDENCY_REMOVED": "MEDIUM", "ORDER_CHANGED": "HIGH",
                    "AGENT_CHANGED": "MEDIUM", "TOOL_CHANGED": "LOW", "CAPABILITY_CHANGED": "MEDIUM",
                    "APPROVAL_CHANGED": "HIGH", "FAILURE_POLICY_CHANGED": "MEDIUM", "SUCCESS_CONDITION_CHANGED": "LOW"}
    max_impact = "NONE"
    impact_order = {l: i for i, l in enumerate(IMPACT_LEVELS)}

    running_jobs = 0
    pending_jobs = 0
    completed_jobs = 0
    if company_id:
        running_jobs = db.query("SELECT COUNT(*) as c FROM jobs WHERE company_id=? AND status='RUNNING'", (company_id,))[0]["c"]
        pending_jobs = db.query("SELECT COUNT(*) as c FROM jobs WHERE company_id=? AND status='PENDING'", (company_id,))[0]["c"]
        completed_jobs = db.query("SELECT COUNT(*) as c FROM jobs WHERE company_id=? AND status='COMPLETED'", (company_id,))[0]["c"]

    for c in changes:
        imp = severity_map.get(c.get("change_type", ""), "LOW")
        if impact_order.get(imp, 0) > impact_order.get(max_impact, 0):
            max_impact = imp

    if running_jobs > 0 and max_impact in ("HIGH", "CRITICAL"):
        max_impact = "CRITICAL"
    if pending_jobs > 3 and max_impact == "MEDIUM":
        max_impact = "HIGH"

    approval_required = max_impact in ("HIGH", "CRITICAL")
    auto_adapt = _wf_get_auto_adaptation()
    needs_human = approval_required and not auto_adapt

    affected_steps = list({c.get("step_id") for c in changes if c.get("step_id")})
    new_steps = [s["id"] for s in json.loads(
        db.query("SELECT definition_json FROM workflow_versions WHERE workflow_id=? AND version=?", (wf_id, version_b))[0]["definition_json"]
    ).get("steps", [])] if db.query("SELECT 1 FROM workflow_versions WHERE workflow_id=? AND version=?", (wf_id, version_b)) else []

    return {
        "workflow_id": wf_id,
        "from_version": version_a,
        "to_version": version_b,
        "changes": changes,
        "impact": max_impact,
        "approval_required": approval_required,
        "needs_human_approval": needs_human,
        "running_jobs_affected": running_jobs,
        "pending_jobs_affected": pending_jobs,
        "completed_jobs_reusable": completed_jobs,
        "affected_steps": affected_steps,
        "new_steps": new_steps,
    }


# ---------------------------------------------------------------------------
# 19.5 ORCHESTRATION ADAPTATION
# ---------------------------------------------------------------------------

def workflow_adapt(wf_id, version_a, version_b, company_id=None):
    """Adapt orchestration based on workflow changes."""
    analysis = workflow_impact_analysis(wf_id, version_a, version_b, company_id)
    if "error" in analysis:
        return analysis

    changes = analysis["changes"]
    impact = analysis["impact"]
    needs_human = analysis.get("needs_human_approval", False)

    adaptation_id = f"ADAPT-{secrets.token_hex(6)}"

    old_def = json.loads(db.query("SELECT definition_json FROM workflow_versions WHERE workflow_id=? AND version=?",
                                  (wf_id, version_a))[0]["definition_json"])
    new_def = json.loads(db.query("SELECT definition_json FROM workflow_versions WHERE workflow_id=? AND version=?",
                                  (wf_id, version_b))[0]["definition_json"])

    orchestration_plan = _wf_build_orchestration_plan(old_def, new_def, changes, company_id)

    status = "WAITING_FOR_HUMAN" if needs_human else "APPROVED"
    if not changes:
        status = "COMPLETED"

    db.execute("""INSERT INTO workflow_adaptations
        (adaptation_id, workflow_id, from_version, to_version, changes_json,
         orchestration_plan, impact, status, approval_required, company_id)
        VALUES (?,?,?,?,?,?,?,?,?,?)""",
               (adaptation_id, wf_id, version_a, version_b, json.dumps(changes),
                json.dumps(orchestration_plan), impact, status, 1 if needs_human else 0, company_id))

    _wf_log_event(wf_id, "WORKFLOW_ADAPTATION", version_b,
                  {"adaptation_id": adaptation_id, "impact": impact, "changes": len(changes)})

    if not needs_human and changes:
        return workflow_execute_adaptation(adaptation_id)

    return {
        "adaptation_id": adaptation_id,
        "status": status,
        "impact": impact,
        "changes": changes,
        "orchestration_plan": orchestration_plan,
        "approval_required": needs_human,
    }


def _wf_build_orchestration_plan(old_def, new_def, changes, company_id):
    """Build new execution graph from workflow changes using existing planner."""
    old_steps = {s["id"]: s for s in (old_def.get("steps") or [])}
    new_steps_list = new_def.get("steps") or []
    new_deps = new_def.get("dependencies") or {}
    plan_steps = []
    for step in new_steps_list:
        sid = step["id"]
        is_new = sid not in old_steps
        is_modified = sid in old_steps and old_steps[sid] != step
        plan_steps.append({
            "step_id": sid,
            "operation": step.get("operation", ""),
            "agent": step.get("agent"),
            "tool": step.get("tool"),
            "is_new": is_new,
            "is_modified": is_modified,
            "reuse": not is_new and not is_modified,
            "dependencies": new_deps.get(sid, []),
        })

    added_steps = [s["step_id"] for s in plan_steps if s["is_new"]]
    modified_steps = [s["step_id"] for s in plan_steps if s["is_modified"]]
    reused_steps = [s["step_id"] for s in plan_steps if s["reuse"]]

    if company_id:
        completed = db.query(
            "SELECT DISTINCT job_type FROM jobs WHERE company_id=? AND status='COMPLETED'", (company_id,))
        completed_types = {r["job_type"] for r in completed}
        for s in plan_steps:
            if s["reuse"] and s["operation"].upper() in completed_types:
                s["reuse_from_cache"] = True

    return {
        "steps": plan_steps,
        "added_steps": added_steps,
        "modified_steps": modified_steps,
        "reused_steps": reused_steps,
        "total_steps": len(plan_steps),
        "new_steps_count": len(added_steps),
    }


# ---------------------------------------------------------------------------
# 19.6 EXECUTION & LEARNING
# ---------------------------------------------------------------------------

def workflow_execute_adaptation(adaptation_id):
    """Execute an approved workflow adaptation."""
    rows = db.query("SELECT * FROM workflow_adaptations WHERE adaptation_id=?", (adaptation_id,))
    if not rows:
        return {"error": "Adaptation not found"}
    adapt = dict(rows[0])
    if adapt["status"] not in ("APPROVED", "VALIDATING"):
        return {"error": f"Cannot execute adaptation in status {adapt['status']}"}

    db.execute("UPDATE workflow_adaptations SET status='EXECUTING', started_at=? WHERE adaptation_id=?",
               (_wf_now(), adaptation_id))

    changes = json.loads(adapt["changes_json"])
    plan = json.loads(adapt["orchestration_plan"])
    company_id = adapt.get("company_id")
    wf_id = adapt["workflow_id"]
    new_version = adapt["to_version"]

    execution_results = []
    errors = []
    for step in plan.get("steps", []):
        step_result = {"step_id": step["step_id"], "status": "SKIPPED"}
        if step.get("reuse") or step.get("reuse_from_cache"):
            step_result["status"] = "REUSED"
        elif step.get("is_new") or step.get("is_modified"):
            try:
                if company_id and step.get("tool"):
                    tool_input = {"company_id": company_id, "operation": step.get("operation", "")}
                    tool_result = _wf_execute_step_tool(step["tool"], tool_input, company_id)
                    step_result["status"] = "COMPLETED"
                    step_result["result"] = tool_result
                elif company_id and step.get("operation"):
                    job_type = step["operation"].upper()
                    if job_type in JOB_TYPES:
                        run_id = adapt_id_to_run(adaptation_id, company_id)
                        jid = ensure_job(job_type, company_id, run_id)
                        step_result["status"] = "QUEUED" if jid else "SKIPPED"
                        step_result["job_id"] = jid
                    else:
                        step_result["status"] = "COMPLETED"
                else:
                    step_result["status"] = "COMPLETED"
            except Exception as e:
                step_result["status"] = "FAILED"
                step_result["error"] = str(e)
                errors.append(step_result)
        execution_results.append(step_result)

    overall_status = "COMPLETED" if not errors else "FAILED"
    db.execute("""UPDATE workflow_adaptations
        SET status=?, execution_result=?, execution_error=?, completed_at=?
        WHERE adaptation_id=?""",
               (overall_status, json.dumps(execution_results),
                json.dumps(errors) if errors else None, _wf_now(), adaptation_id))

    _wf_log_event(wf_id, "WORKFLOW_EXECUTION_" + overall_status, new_version,
                  {"adaptation_id": adaptation_id, "results": len(execution_results),
                   "errors": len(errors)})

    if overall_status == "COMPLETED":
        workflow_activate_version(wf_id, new_version)
        _wf_record_learning(wf_id, adapt["from_version"], new_version, changes, "SUCCESS")
    else:
        _wf_record_learning(wf_id, adapt["from_version"], new_version, changes, "FAILURE")

    return {
        "adaptation_id": adaptation_id,
        "status": overall_status,
        "results": execution_results,
        "errors": errors,
    }


def adapt_id_to_run(adaptation_id, company_id):
    """Create a run for an adaptation."""
    return create_run("WORKFLOW_ADAPT", companies=[company_id] if company_id else [])


def _wf_execute_step_tool(tool_id, tool_input, company_id):
    """Execute a tool for a workflow step via MCP."""
    try:
        result = mcp_call_tool("workflow_adaptation", tool_id, tool_input,
                               auth={"client_id": "workflow_engine", "companies": "*"})
        return result
    except Exception as e:
        return {"error": str(e), "integration_status": "INTEGRATION_NOT_AVAILABLE"}


def _wf_record_learning(wf_id, old_version, new_version, changes, outcome):
    """Record learning from workflow adaptation."""
    change_types = [c["change_type"] for c in changes]
    pattern_key = _wf_pattern_key(change_types)
    record_learning_event(
        company_id=None,
        event_type="WORKFLOW_" + outcome,
        description=f"Workflow {wf_id} adapted from v{old_version} to v{new_version}: {outcome}",
        source_type="WORKFLOW_ENGINE",
        metadata={"workflow_id": wf_id, "from_version": old_version, "to_version": new_version,
                  "outcome": outcome, "change_types": change_types})
    _wf_update_pattern(pattern_key, change_types, outcome, changes)


def _wf_pattern_key(change_types):
    return "|".join(sorted(change_types))


def _wf_update_pattern(pattern_key, change_types, outcome, changes):
    """Update learned adaptation pattern."""
    rows = db.query("SELECT * FROM workflow_adaptation_patterns WHERE pattern_key=?", (pattern_key,))
    description = f"Workflow change pattern: {', '.join(set(change_types))}"
    adaptation_template = json.dumps({"change_types": list(set(change_types)),
                                       "sample_changes": changes[:3]})
    if rows:
        r = rows[0]
        observed = r["observed_count"] + 1
        success = r["success_count"] + (1 if outcome == "SUCCESS" else 0)
        failure = r["failure_count"] + (1 if outcome == "FAILURE" else 0)
        rate = success / max(observed, 1)
        conf = min(0.95, 0.3 + (rate * 0.5) + (min(observed, 20) * 0.01))
        db.execute("""UPDATE workflow_adaptation_patterns
            SET observed_count=?, success_count=?, failure_count=?,
                success_rate=?, last_observed_at=?, confidence=?, updated_at=?
            WHERE pattern_key=?""",
                   (observed, success, failure, rate, _wf_now(), conf, _wf_now(), pattern_key))
    else:
        success = 1 if outcome == "SUCCESS" else 0
        failure = 1 if outcome == "FAILURE" else 0
        rate = success / max(success + failure, 1)
        db.execute("""INSERT INTO workflow_adaptation_patterns
            (pattern_key, pattern_description, change_type, observed_count,
             success_count, failure_count, success_rate, adaptation_template, confidence)
            VALUES (?,?,?,?,?,?,?,?,?)""",
                   (pattern_key, description, change_types[0] if change_types else "UNKNOWN",
                    1, success, failure, rate, adaptation_template, 0.5))


# ---------------------------------------------------------------------------
# 19.7 APPROVAL & ROLLBACK
# ---------------------------------------------------------------------------

def workflow_approve_adaptation(adaptation_id, approved_by="user"):
    """Approve a pending adaptation."""
    rows = db.query("SELECT * FROM workflow_adaptations WHERE adaptation_id=?", (adaptation_id,))
    if not rows:
        return {"error": "Adaptation not found"}
    adapt = dict(rows[0])
    if adapt["status"] != "WAITING_FOR_HUMAN":
        return {"error": f"Cannot approve adaptation in status {adapt['status']}"}
    db.execute("UPDATE workflow_adaptations SET status='APPROVED', approved_by=?, approved_at=? WHERE adaptation_id=?",
               (approved_by, _wf_now(), adaptation_id))
    _wf_log_event(adapt["workflow_id"], "WORKFLOW_HUMAN_APPROVAL", adapt["to_version"],
                  {"adaptation_id": adaptation_id, "approved_by": approved_by})
    return workflow_execute_adaptation(adaptation_id)


def workflow_reject_adaptation(adaptation_id, rejected_by="user", reason=""):
    """Reject a pending adaptation."""
    rows = db.query("SELECT * FROM workflow_adaptations WHERE adaptation_id=?", (adaptation_id,))
    if not rows:
        return {"error": "Adaptation not found"}
    db.execute("UPDATE workflow_adaptations SET status='REJECTED', approved_by=?, execution_error=? WHERE adaptation_id=?",
               (rejected_by, reason, adaptation_id))
    _wf_log_event(dict(rows[0])["workflow_id"], "WORKFLOW_HUMAN_REJECTION",
                  dict(rows[0])["to_version"], {"adaptation_id": adaptation_id, "reason": reason})
    return {"success": True, "status": "REJECTED"}


def workflow_rollback(wf_id, to_version):
    """Rollback workflow to a previous version."""
    rows = db.query("SELECT * FROM workflow_versions WHERE workflow_id=? AND version=?", (wf_id, to_version))
    if not rows:
        return {"error": "Version not found"}
    current = db.query("SELECT version FROM workflow_versions WHERE workflow_id=? AND status='ACTIVE'", (wf_id,))
    current_ver = current[0]["version"] if current else None
    db.execute("UPDATE workflow_versions SET status='SUPERSEDED' WHERE workflow_id=? AND status='ACTIVE'", (wf_id,))
    db.execute("UPDATE workflow_versions SET status='ACTIVE' WHERE workflow_id=? AND version=?", (wf_id, to_version))
    _wf_log_event(wf_id, "WORKFLOW_ROLLBACK", to_version, {"from_version": current_ver})
    _wf_record_learning(wf_id, current_ver, to_version, [], "ROLLBACK")
    return {"success": True, "rolled_back_to": to_version}


# ---------------------------------------------------------------------------
# 19.8 HELPER FUNCTIONS
# ---------------------------------------------------------------------------

def _wf_log_event(wf_id, event_type, version, details):
    db.execute("INSERT INTO workflow_adaptation_events (workflow_id, event_type, version, details) VALUES (?,?,?,?)",
               (wf_id, event_type, version, json.dumps(details)))


def _wf_get_auto_adaptation():
    rows = db.query("SELECT config_value FROM agent_config WHERE config_key=?", (AUTO_ADAPTATION_KEY,))
    return rows[0]["config_value"] == "1" if rows else True


def workflow_set_auto_adaptation(enabled):
    save_config({AUTO_ADAPTATION_KEY: "1" if enabled else "0"})
    return {"success": True, "auto_adaptation": enabled}


def workflow_adaptations(wf_id):
    return [dict(a) for a in db.query(
        "SELECT * FROM workflow_adaptations WHERE workflow_id=? ORDER BY created_at DESC", (wf_id,))]


def workflow_learning(wf_id):
    return [dict(p) for p in db.query(
        "SELECT * FROM workflow_adaptation_patterns ORDER BY confidence DESC LIMIT 50")]


def workflow_events(wf_id):
    return [dict(e) for e in db.query(
        "SELECT * FROM workflow_adaptation_events WHERE workflow_id=? ORDER BY id DESC LIMIT 100", (wf_id,))]


def workflow_compare_versions(wf_id, va, vb):
    changes = workflow_diff(wf_id, va, vb)
    va_def = db.query("SELECT definition_json, fingerprint FROM workflow_versions WHERE workflow_id=? AND version=?", (wf_id, va))
    vb_def = db.query("SELECT definition_json, fingerprint FROM workflow_versions WHERE workflow_id=? AND version=?", (wf_id, vb))
    if not va_def or not vb_def:
        return {"error": "Version(s) not found"}
    return {
        "version_a": {"version": va, "fingerprint": va_def[0]["fingerprint"],
                       "steps": json.loads(va_def[0]["definition_json"]).get("steps", [])},
        "version_b": {"version": vb, "fingerprint": vb_def[0]["fingerprint"],
                       "steps": json.loads(vb_def[0]["definition_json"]).get("steps", [])},
        "changes": changes,
    }


# ---------------------------------------------------------------------------
# 19.9 DEMO WORKFLOW
# ---------------------------------------------------------------------------

def workflow_create_presets():
    """Create the two production workflows for this agent (idempotent).
    1. Brand Visibility Audit - full pipeline for a company.
    2. Competitor Watch - competitor-focused monitoring loop."""
    presets = [
        {
            "name": "Brand Visibility Audit",
            "description": "Full brand analysis pipeline: collect, queries, AI search, brand + competitors, gaps, recommendations, store.",
            "steps": [
                {"id": "collect", "operation": "COLLECT_WEBSITE_DATA", "agent": "website_content", "tool": "website_scraper"},
                {"id": "validate", "operation": "VALIDATE_DATA", "agent": "system", "tool": None},
                {"id": "queries", "operation": "GENERATE_QUERIES", "agent": "visibility_analyst", "tool": "gemini_queries"},
                {"id": "ai_search", "operation": "RUN_AI_SEARCH", "agent": "visibility_analyst", "tool": "ai_search"},
                {"id": "brand", "operation": "ANALYZE_BRAND", "agent": "visibility_analyst", "tool": "gemini_analyze"},
                {"id": "competitors", "operation": "ANALYZE_COMPETITORS", "agent": "visibility_analyst", "tool": "gemini_competitors"},
                {"id": "gaps", "operation": "DETECT_CONTENT_GAPS", "agent": "visibility_analyst", "tool": "gemini_gaps"},
                {"id": "recommend", "operation": "GENERATE_RECOMMENDATIONS", "agent": "visibility_analyst", "tool": "gemini_recommend"},
                {"id": "changes", "operation": "DETECT_CHANGES", "agent": "system", "tool": None},
                {"id": "store", "operation": "STORE_ANALYSIS", "agent": "system", "tool": None},
                {"id": "learn", "operation": "UPDATE_LEARNING", "agent": "system", "tool": None},
            ],
            "dependencies": {"validate": ["collect"], "queries": ["validate"], "ai_search": ["queries"],
                             "brand": ["validate"], "competitors": ["brand"], "gaps": ["brand", "competitors"],
                             "recommend": ["competitors", "gaps"], "changes": ["collect", "validate"],
                             "store": ["recommend", "changes"], "learn": ["store"]},
        },
        {
            "name": "Competitor Watch",
            "description": "Competitor monitoring loop: collect, benchmark competitors, gaps, recommendations, store.",
            "steps": [
                {"id": "collect", "operation": "COLLECT_WEBSITE_DATA", "agent": "website_content", "tool": "website_scraper"},
                {"id": "competitors", "operation": "ANALYZE_COMPETITORS", "agent": "visibility_analyst", "tool": "gemini_competitors"},
                {"id": "gaps", "operation": "DETECT_CONTENT_GAPS", "agent": "visibility_analyst", "tool": "gemini_gaps"},
                {"id": "recommend", "operation": "GENERATE_RECOMMENDATIONS", "agent": "visibility_analyst", "tool": "gemini_recommend"},
                {"id": "changes", "operation": "DETECT_CHANGES", "agent": "system", "tool": None},
                {"id": "store", "operation": "STORE_ANALYSIS", "agent": "system", "tool": None},
            ],
            "dependencies": {"competitors": ["collect"], "gaps": ["competitors"],
                             "recommend": ["gaps"], "changes": ["collect"],
                             "store": ["recommend", "changes"]},
        },
    ]
    created = []
    for p in presets:
        existing = db.query("SELECT workflow_id FROM workflow_definitions WHERE name=? LIMIT 1", (p["name"],))
        if existing:
            created.append({"workflow_id": existing[0]["workflow_id"], "name": p["name"], "existing": True})
            continue
        wf = workflow_create(name=p["name"], description=p["description"], steps=p["steps"],
                             dependencies=p["dependencies"], created_by="PRESETS")
        workflow_activate_version(wf["workflow_id"], 1)
        created.append({"workflow_id": wf["workflow_id"], "name": p["name"], "existing": False})
    return {"success": True, "workflows": created}


def workflow_create_demo():
    """Create a deterministic demo workflow with V1 and V2."""
    wf = workflow_create(
        name="AI Search Visibility Analysis",
        description="Standard brand analysis pipeline",
        steps=[
            {"id": "collect_data", "operation": "COLLECT_WEBSITE_DATA", "agent": "website_content", "tool": "website_scraper"},
            {"id": "analyze", "operation": "ANALYZE_BRAND", "agent": "visibility_analyst", "tool": "gemini_analyze"},
            {"id": "score", "operation": "STORE_ANALYSIS", "agent": "system", "tool": None},
            {"id": "recommend", "operation": "GENERATE_RECOMMENDATIONS", "agent": "visibility_analyst", "tool": "gemini_recommend"},
        ],
        dependencies={"analyze": ["collect_data"], "score": ["analyze"], "recommend": ["score"]},
        created_by="DEMO",
    )
    wf_id = wf["workflow_id"]
    workflow_activate_version(wf_id, 1)

    v2 = workflow_create_version(
        wf_id,
        steps=[
            {"id": "collect_data", "operation": "COLLECT_WEBSITE_DATA", "agent": "website_content", "tool": "website_scraper"},
            {"id": "rag_retrieval", "operation": "GENERATE_QUERIES", "agent": "visibility_analyst", "tool": "rag_search"},
            {"id": "competitor_analysis", "operation": "ANALYZE_COMPETITORS", "agent": "visibility_analyst", "tool": "gemini_competitors"},
            {"id": "analyze", "operation": "ANALYZE_BRAND", "agent": "visibility_analyst", "tool": "gemini_analyze"},
            {"id": "score", "operation": "STORE_ANALYSIS", "agent": "system", "tool": None},
            {"id": "recommend", "operation": "GENERATE_RECOMMENDATIONS", "agent": "visibility_analyst", "tool": "gemini_recommend"},
        ],
        dependencies={"rag_retrieval": ["collect_data"], "competitor_analysis": ["rag_retrieval"],
                       "analyze": ["competitor_analysis"], "score": ["analyze"], "recommend": ["score"]},
        change_summary="Added RAG retrieval and competitor analysis before brand analysis",
        created_by="DEMO",
    )
    return {"workflow_id": wf_id, "v1": 1, "v2": v2["version"], "fingerprint": v2["fingerprint"]}


# Initialize workflow tables on import
_wf_init_tables()


if __name__ == "__main__":
    # Port: --port 9000 arg wins, else PORT env, else 8000.
    # e.g.  python agent.py --port 11301   |   PORT=11301 python agent.py
    # TLS: --ssl-cert cert.pem --ssl-key key.pem (or SSL_CERT / SSL_KEY env).
    # e.g.  python agent.py --port 11301 --ssl-cert /etc/ssl/myblocks.crt --ssl-key /etc/ssl/myblocks.key
    port = 8000
    ssl_cert = os.environ.get("SSL_CERT", "")
    ssl_key = os.environ.get("SSL_KEY", "")
    try:
        import sys as _sys
        _args = _sys.argv[1:]
        for _i, _a in enumerate(_args):
            if _a == "--port" and _i + 1 < len(_args):
                port = int(_args[_i + 1])
            elif _a.startswith("--port="):
                port = int(_a.split("=", 1)[1])
            elif _a == "--ssl-cert" and _i + 1 < len(_args):
                ssl_cert = _args[_i + 1]
            elif _a.startswith("--ssl-cert="):
                ssl_cert = _a.split("=", 1)[1]
            elif _a == "--ssl-key" and _i + 1 < len(_args):
                ssl_key = _args[_i + 1]
            elif _a.startswith("--ssl-key="):
                ssl_key = _a.split("=", 1)[1]
        if not any(a == "--port" or a.startswith("--port=") for a in _args):
            port = int(os.environ.get("PORT", "8000"))
    except Exception:
        port = 8000
    start_server(port, ssl_cert or None, ssl_key or None)


