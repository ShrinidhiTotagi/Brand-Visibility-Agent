"""VisibilityAI MCP server (Phase 9) - REAL Model Context Protocol over stdio.

Exposes the framework tool registry (tools), read-only company resources and
structured prompts through the actual MCP protocol (mcp package, v2 API).
Every tool call routes through agent.mcp_call_tool: registry validation,
capability/permission checks, company scoping, risk policy, timeouts, audit.
No bypasses, no fabricated data.

Run:  python mcp_server.py   (speaks MCP on stdin/stdout)
Env:  AGENT_DB_PATH  - sqlite file (default: production agent_storage.db)
      MCP_AUTH_TOKEN - when set, per-call auth is enforced
      MCP_CLIENT_SCOPES_JSON - {"token": {"client_id": "...", "companies": [...]|"*"}}

Per-call auth travels as explicit `auth_token` / `client_id` tool & prompt
arguments (documented dev-grade convention for stdio transport). Resources use
a dual-URI scheme: clean `company://{id}/{name}` URIs work only when no auth
token is configured; with auth configured, `auth://{token}/{id}/{name}` URIs
carry the credential (wrong token -> UNAUTHORIZED, out-of-scope -> DENIED).
"""
import asyncio
import contextlib
import functools
import json
import os
import sys

WORKDIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, WORKDIR)

with contextlib.redirect_stdout(sys.stderr):
    import agent  # noqa: E402

    agent.init_db()


def _quiet(fn):
    """Keep stdout clean for the MCP protocol: library prints go to stderr."""
    @functools.wraps(fn)
    def _w(*a, **k):
        with contextlib.redirect_stdout(sys.stderr):
            return fn(*a, **k)
    return _w

try:
    from mcp.server.mcpserver import MCPServer
except Exception as e:  # pragma: no cover
    print(f"mcp package required: {e}", file=sys.stderr, flush=True)
    raise SystemExit(2)

mcp = MCPServer("visibility-agent")


def _auth_of(auth_token="", client_id="anonymous"):
    return agent.mcp_auth_client(auth_token or None, client_id or None)


def _call(tool_id, company_id=None, auth_token="", client_id="anonymous", **kwargs):
    with contextlib.redirect_stdout(sys.stderr):
        return _call_inner(tool_id, company_id, auth_token, client_id, **kwargs)


def _call_inner(tool_id, company_id=None, auth_token="", client_id="anonymous", **kwargs):
    auth = _auth_of(auth_token, client_id)
    if auth is None:
        return {"status": "FAILED",
                "error": {"code": "MCP_UNAUTHORIZED", "message": "Missing or invalid credentials.",
                          "retryable": False}}
    args = dict(kwargs)
    if company_id is not None:
        args["company_id"] = company_id
    res = agent.mcp_call_tool("ai-search-visibility", tool_id, args, client_id=auth["client_id"],
                              auth_token=auth_token or "", request_id=args.pop("request_id", None))
    if not res.get("success"):
        return {"status": "FAILED",
                "error": {"code": res.get("error", "MCP_EXECUTION_FAILED"),
                          "message": res.get("reason", "rejected"), "retryable": False}}
    if res.get("waiting_for_human"):
        out = dict(res.get("result") or {})
        out["status"] = "WAITING_FOR_HUMAN"
        return out
    return res.get("result")


# ---------------------------------------------------------------- tools ---
@mcp.tool(name="get_company_profile", description="Brand record, industry, website, keywords and status.")
def get_company_profile(company_id: int, request_id: str = "", auth_token: str = "",
                        client_id: str = "anonymous") -> dict:
    return _call("get_company_profile", company_id, auth_token, client_id, request_id=request_id or None)


@mcp.tool(name="get_company_evidence", description="Stored evidence rows with sources and verification.")
def get_company_evidence(company_id: int, limit: int = 50, request_id: str = "",
                         auth_token: str = "", client_id: str = "anonymous") -> dict:
    return _call("get_company_evidence", company_id, auth_token, client_id,
                 limit=limit, request_id=request_id or None)


@mcp.tool(name="get_analysis_history", description="Past visibility scores newest-first.")
def get_analysis_history(company_id: int, limit: int = 10, request_id: str = "",
                         auth_token: str = "", client_id: str = "anonymous") -> dict:
    return _call("get_analysis_history", company_id, auth_token, client_id,
                 limit=limit, request_id=request_id or None)


@mcp.tool(name="get_detected_changes", description="Change log entries newest-first.")
def get_detected_changes(company_id: int, limit: int = 30, request_id: str = "",
                         auth_token: str = "", client_id: str = "anonymous") -> dict:
    return _call("get_detected_changes", company_id, auth_token, client_id,
                 limit=limit, request_id=request_id or None)


@mcp.tool(name="get_learning_memory", description="Active learning memories for the company.")
def get_learning_memory(company_id: int, limit: int = 20, request_id: str = "",
                        auth_token: str = "", client_id: str = "anonymous") -> dict:
    return _call("get_learning_memory", company_id, auth_token, client_id,
                 limit=limit, request_id=request_id or None)


@mcp.tool(name="generate_search_queries", description="Generate and store customer search queries.")
def generate_search_queries(company_id: int, intent: str = "", limit: int = 10, request_id: str = "",
                            auth_token: str = "", client_id: str = "anonymous") -> dict:
    return _call("generate_search_queries", company_id, auth_token, client_id,
                 intent=intent, limit=limit, request_id=request_id or None)


@mcp.tool(name="run_ai_search", description="Execute stored queries against connected providers.")
def run_ai_search(company_id: int, query: str = "", request_id: str = "",
                  auth_token: str = "", client_id: str = "anonymous") -> dict:
    return _call("run_ai_search", company_id, auth_token, client_id,
                 query=query, request_id=request_id or None)


@mcp.tool(name="analyze_brand_visibility", description="Deterministic brand visibility analysis.")
def analyze_brand_visibility(company_id: int, request_id: str = "",
                             auth_token: str = "", client_id: str = "anonymous") -> dict:
    return _call("analyze_brand_visibility", company_id, auth_token, client_id,
                 request_id=request_id or None)


@mcp.tool(name="analyze_competitors", description="Competitor visibility rows from profile and observations.")
def analyze_competitors(company_id: int, request_id: str = "",
                        auth_token: str = "", client_id: str = "anonymous") -> dict:
    return _call("analyze_competitors", company_id, auth_token, client_id,
                 request_id=request_id or None)


@mcp.tool(name="detect_content_gaps", description="Missing content surfaces vs evidence.")
def detect_content_gaps(company_id: int, request_id: str = "",
                        auth_token: str = "", client_id: str = "anonymous") -> dict:
    return _call("detect_content_gaps", company_id, auth_token, client_id,
                 request_id=request_id or None)


@mcp.tool(name="generate_recommendations", description="Deterministic recommendations from gaps and evidence.")
def generate_recommendations(company_id: int, request_id: str = "",
                             auth_token: str = "", client_id: str = "anonymous") -> dict:
    return _call("generate_recommendations", company_id, auth_token, client_id,
                 request_id=request_id or None)


@mcp.tool(name="get_query_history", description="Stored queries with test counts and results.")
def get_query_history(company_id: int, limit: int = 50, request_id: str = "",
                      auth_token: str = "", client_id: str = "anonymous") -> dict:
    return _call("get_query_history", company_id, auth_token, client_id,
                 limit=limit, request_id=request_id or None)


@mcp.tool(name="get_recommendation_history", description="Recommendations with lifecycle status.")
def get_recommendation_history(company_id: int, limit: int = 50, request_id: str = "",
                               auth_token: str = "", client_id: str = "anonymous") -> dict:
    return _call("get_recommendation_history", company_id, auth_token, client_id,
                 limit=limit, request_id=request_id or None)


@mcp.tool(name="get_company_snapshot", description="Latest (or previous) evidence snapshot.")
def get_company_snapshot(company_id: int, which: str = "latest", request_id: str = "",
                         auth_token: str = "", client_id: str = "anonymous") -> dict:
    return _call("get_company_snapshot", company_id, auth_token, client_id,
                 which=which, request_id=request_id or None)


@mcp.tool(name="compare_snapshots", description="Diff two analyses' evidence snapshots.")
def compare_snapshots(company_id: int, previous_snapshot_id: int = 0, current_snapshot_id: int = 0,
                      request_id: str = "", auth_token: str = "", client_id: str = "anonymous") -> dict:
    kw = {}
    if previous_snapshot_id:
        kw["previous_snapshot_id"] = previous_snapshot_id
    if current_snapshot_id:
        kw["current_snapshot_id"] = current_snapshot_id
    return _call("compare_snapshots", company_id, auth_token, client_id,
                 request_id=request_id or None, **kw)


@mcp.tool(name="search_knowledge", description="Semantic vector search over indexed company knowledge.")
def search_knowledge(company_id: int, query: str, top_k: int = 5, request_id: str = "",
                     auth_token: str = "", client_id: str = "anonymous") -> dict:
    return _call("search_knowledge", company_id, auth_token, client_id,
                 query=query, top_k=top_k, request_id=request_id or None)


# --------------------------------------------------------------- resources --
def _read_resource(uri, auth):
    with contextlib.redirect_stdout(sys.stderr):
        return agent.mcp_read_resource(uri, auth)


def _resource_fn(name):
    def _fn(company_id: str) -> str:
        import os as _os
        if _os.environ.get("MCP_AUTH_TOKEN", ""):
            return json.dumps({"success": False, "error": "MCP_UNAUTHORIZED",
                               "reason": "Use auth://{token}/{company_id}/" + name + " when auth is configured."})
        auth = _auth_of("", "anonymous")
        if auth is None:
            return json.dumps({"success": False, "error": "MCP_UNAUTHORIZED",
                               "reason": "Missing or invalid credentials."})
        return json.dumps(_read_resource(f"company://{company_id}/{name}", auth))
    _fn.__name__ = f"resource_{name.replace('-', '_')}"
    return _fn


_RESOURCE_NAMES = ["profile", "evidence", "analysis-history", "snapshots", "changes",
                   "queries", "recommendations", "learning"]
for _rn in _RESOURCE_NAMES:
    mcp.resource(f"company://{{company_id}}/{_rn}", name=_rn,
                 description=f"Read-only {_rn.replace('-', ' ')} scoped by company_id.")(_resource_fn(_rn))


def _auth_resource_fn(name):
    def _fn(token: str, company_id: str) -> str:
        auth = _auth_of(token, "mcp-client")
        if auth is None:
            return json.dumps({"success": False, "error": "MCP_UNAUTHORIZED",
                               "reason": "Missing or invalid credentials."})
        return json.dumps(_read_resource(f"company://{company_id}/{name}", auth))
    _fn.__name__ = f"auth_resource_{name.replace('-', '_')}"
    return _fn


for _rn in _RESOURCE_NAMES:
    mcp.resource(f"auth://{{token}}/{{company_id}}/{_rn}", name=f"auth_{_rn}",
                 description=f"Authenticated read-only {_rn.replace('-', ' ')}.")(_auth_resource_fn(_rn))


def _knowledge_fn(token, company_id):
    import os as _os
    try:
        cid = int(company_id)
    except Exception:
        return json.dumps({"success": False, "error": "MCP_RESOURCE_NOT_FOUND",
                           "reason": f"Malformed resource URI."})
    if _os.environ.get("MCP_AUTH_TOKEN", ""):
        if token == "company":
            return json.dumps({"success": False, "error": "MCP_UNAUTHORIZED",
                               "reason": "Use auth://{token}/{company_id}/knowledge when auth is configured."})
        auth = _auth_of(token, "mcp-client")
    else:
        auth = _auth_of("", "anonymous")
    if auth is None:
        return json.dumps({"success": False, "error": "MCP_UNAUTHORIZED",
                           "reason": "Missing or invalid credentials."})
    with contextlib.redirect_stdout(sys.stderr):
        return json.dumps(agent.mcp_read_knowledge(cid, auth))


def _knowledge_clean(company_id: str) -> str:
    return _knowledge_fn("company", company_id)


def _knowledge_auth(token: str, company_id: str) -> str:
    return _knowledge_fn(token, company_id)


mcp.resource("knowledge://company/{company_id}", name="knowledge",
             description="Read-only semantic knowledge context, company-scoped.")(_knowledge_clean)
mcp.resource("auth://{token}/{company_id}/knowledge", name="auth_knowledge",
             description="Authenticated read-only semantic knowledge context.")(_knowledge_auth)


# ----------------------------------------------------------------- prompts --
def _prompt_fn(name):
    def _fn(company_id: int = 0, auth_token: str = "", client_id: str = "anonymous") -> str:
        with contextlib.redirect_stdout(sys.stderr):
            return _prompt_inner(name, company_id, auth_token, client_id)
    _fn.__name__ = f"prompt_{name}"
    return _fn


def _prompt_inner(name, company_id=0, auth_token="", client_id="anonymous"):
    auth = _auth_of(auth_token, client_id)
    if auth is None:
        return "MCP_UNAUTHORIZED: missing or invalid credentials."
    r = agent.mcp_get_prompt(name, {"company_id": company_id} if company_id else {}, auth)
    if not r.get("success"):
        return f"{r.get('error')}: {r.get('reason', '')}"
    return "\n\n".join(m.get("content", "") for m in r.get("messages", []))


for _pn in ["visibility_analysis", "competitor_analysis", "content_gap_analysis",
            "historical_visibility_analysis", "change_analysis", "recommendation_review"]:
    mcp.prompt(name=_pn, description=f"Structured context for {_pn.replace('_', ' ')}.")(_prompt_fn(_pn))


async def _main():
    await mcp.run_stdio_async()


if __name__ == "__main__":
    import asyncio
    asyncio.run(_main())



