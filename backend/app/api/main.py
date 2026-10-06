"""FastAPI surface. REST for inspectability. Demo/playground endpoints exist only when FILIGREE_DEMO=1 (D-23)."""
import json
import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .. import service as svc
from ..agent import scripted
from ..analyzer.impl import CACHE_PATH
from ..audit import chain
from ..gate.gate import gate_call
from ..manifest.canonicalize import build_manifest, fingerprint
from ..manifest.diff import diff_manifests
from ..manifest.display import escape_for_display, hidden_stats, human_rendering
from ..mcp.client import CaptureError
from ..mcp.proxy import add_proxy
from ..scanner.rules import scan
from ..policy.evaluate import eligibility, risk_of
from .schemas import ToolTrustView

SCENARIOS = {"benign": "srv-benign", "poisoned": "srv-poisoned", "invisible": "srv-invisible",
             "rugpull": "srv-rugpull", "shadow": "srv-shadow"}
EVAL_RESULTS = Path(__file__).resolve().parents[3] / "fixtures" / "evaluation" / "results.json"


class ApproveBody(BaseModel):
    confirm: bool = False


class CallBody(BaseModel):
    server_id: str
    tool: str
    args: dict = {}


class AttackBody(BaseModel):
    server_id: str
    tool: str
    protected: bool = True


class PlaygroundBody(BaseModel):
    description: str
    baseline_description: str = "Search documents by keyword."
    name: str = "search_documents"


def create_app(ctx: svc.Ctx) -> FastAPI:
    app = FastAPI(title="Filigree")
    app.state.ctx = ctx
    app.add_middleware(CORSMiddleware, allow_origins=os.environ.get("FILIGREE_CORS", "http://localhost:5173,http://127.0.0.1:5173").split(","),
                       allow_methods=["*"], allow_headers=["*"])

    def need_view(tid: str) -> ToolTrustView:
        sid, name = svc.split_id(tid)
        v = svc.view(ctx, sid, name)
        if v is None:
            raise HTTPException(404, "unknown tool")
        return v

    def demo_only():
        if not ctx.demo:
            raise HTTPException(404, "demo endpoints disabled")

    @app.get("/api/mode")
    def mode():
        recorded = None
        if ctx.analyzer.mode == "replay":  # say what the replayed analysis is: recorded model output or authored text
            try:
                p = json.loads(CACHE_PATH.read_text(encoding="utf-8")).get("_provenance")
                recorded = f"{p['provider']}/{p['model']}" if p else None
            except (OSError, ValueError, KeyError):
                pass
        return {"analyzer": ctx.analyzer.mode, "demo": ctx.demo, "recorded": recorded}

    @app.get("/api/servers")
    def servers():
        return [dict(r) for r in ctx.store.servers()]

    @app.post("/api/servers/{sid}/discover")
    async def discover(sid: str):
        if not ctx.store.server(sid):
            raise HTTPException(404, "unknown server")
        try:
            return {"tools": await svc.discover(ctx, sid)}
        except CaptureError as e:
            raise HTTPException(502, f"CAPTURE_FAILURE: {e}")

    @app.get("/api/tools", response_model=list[ToolTrustView])
    def tools():
        return svc.all_views(ctx)

    @app.get("/api/tools/{tid}/view", response_model=ToolTrustView)
    def tool_view(tid: str):
        return need_view(tid)

    @app.get("/api/tools/{tid}/manifest")
    def manifest(tid: str):
        v = need_view(tid)
        m = ctx.store.manifest(v.current_fingerprint)
        return {"fingerprint": v.current_fingerprint, "manifest": m,
                "escaped_json": escape_for_display(json.dumps(m, indent=2, sort_keys=True, ensure_ascii=False)),
                "approval": v.approval.model_dump(), "policy_version": svc.POLICY_VERSION, "analysis_mode": v.analysis.mode}

    @app.get("/api/tools/{tid}/diff")
    def diff(tid: str):
        v = need_view(tid)
        if not v.approval.fingerprint or v.approval.fingerprint == v.current_fingerprint:
            return {"changes": []}
        esc = lambda x: escape_for_display(x) if isinstance(x, str) else x  # hidden chars shown as [U+XXXX] markers
        out = []
        for c in diff_manifests(ctx.store.manifest(v.approval.fingerprint), ctx.store.manifest(v.current_fingerprint)):
            c["before"], c["after"] = esc(c["before"]), esc(c["after"])
            c["lines"] = [esc(l) for l in c.get("lines", [])]
            out.append(c)
        return {"changes": out}

    @app.post("/api/tools/{tid}/approve", response_model=ToolTrustView)
    def approve(tid: str, body: ApproveBody = ApproveBody()):
        sid, name = svc.split_id(tid)
        try:
            return svc.approve(ctx, sid, name, body.confirm)
        except svc.Refused as e:
            raise HTTPException(409, str(e))

    @app.post("/api/tools/{tid}/deny", response_model=ToolTrustView)
    def deny(tid: str):
        sid, name = svc.split_id(tid)
        try:
            return svc.deny(ctx, sid, name)
        except svc.Refused as e:
            raise HTTPException(404, str(e))

    @app.post("/api/tools/{tid}/recheck", response_model=ToolTrustView)
    async def recheck(tid: str):
        sid, name = svc.split_id(tid)
        await svc.discover(ctx, sid)
        return need_view(tid)

    @app.get("/api/audit")
    def audit(limit: int = 200):
        broken = chain.first_broken(ctx.store)
        return {"events": chain.events(ctx.store, limit), "chain_verified": broken is None, "broken_at": broken}

    @app.get("/api/audit/export")
    def audit_export():
        broken = chain.first_broken(ctx.store)
        return JSONResponse({"chain_verified": broken is None, "broken_at": broken, "events": chain.export(ctx.store)},
                            headers={"Content-Disposition": 'attachment; filename="filigree-audit.json"'})

    @app.get("/api/metrics")
    def metrics():
        ev = chain.events(ctx.store, 10000)
        n = lambda t: sum(1 for e in ev if e["event_type"] == t)
        out = {"analysis_count": n("ANALYSIS_COMPLETED"), "approval_count": n("APPROVED"),
               "blocked_count": n("EXECUTION_BLOCKED"), "manifest_drift_count": n("MANIFEST_DRIFT"),
               "execution_count": n("EXECUTION_ALLOWED"), "evaluation": None}
        if EVAL_RESULTS.exists():
            out["evaluation"] = json.loads(EVAL_RESULTS.read_text(encoding="utf-8"))
        v3 = EVAL_RESULTS.with_name("results_v3_with_llm.json")
        out["evaluation_v3"] = json.loads(v3.read_text(encoding="utf-8")) if v3.exists() else None
        return out

    @app.get("/api/agent/registry")
    def registry():
        return scripted.registry(ctx)

    @app.post("/api/agent/call")
    async def agent_call(b: CallBody):
        return await gate_call(ctx, b.server_id, b.tool, b.args)

    # ---- demo / playground (FILIGREE_DEMO=1) ----
    @app.get("/api/demo/scenarios")
    def scenarios():
        demo_only()
        return {"scenarios": list(SCENARIOS), "agent_label": scripted.LABEL}

    @app.post("/api/demo/reset")
    async def reset():
        demo_only()
        ctx.store.reset()
        try:
            await ctx.http.post(f"{ctx.fixture_base}/control/reset", timeout=5)
        except Exception:
            pass
        return {"ok": True}

    @app.post("/api/demo/scenario")
    async def scenario(body: dict):
        demo_only()
        name = body.get("name")
        if name not in SCENARIOS:
            raise HTTPException(400, "unknown scenario")
        sid = SCENARIOS[name]
        ctx.store.upsert_server(sid, name, f"{ctx.fixture_base}/s/{name}")
        return {"server_id": sid, "tools": await svc.discover(ctx, sid)}

    @app.post("/api/demo/mutate")
    async def mutate(body: dict | None = None):
        demo_only()
        mode_ = (body or {}).get("mode", "modified")
        await ctx.http.post(f"{ctx.fixture_base}/control/rug_pull/{mode_}", timeout=5)
        return {"mode": mode_}

    tampered: dict = {}  # ponytail: single remembered edit; one tamper at a time is all the demo needs

    @app.post("/api/demo/tamper")
    def tamper():
        """Rewrite history in the audit table directly, bypassing the app, so the broken chain can be shown live."""
        demo_only()
        if tampered:
            raise HTTPException(409, "already tampered")
        rows = ctx.store.q("SELECT id, reason FROM audit WHERE event_type='APPROVED' ORDER BY id DESC LIMIT 1") \
            or ctx.store.q("SELECT id, reason FROM audit ORDER BY id DESC LIMIT 1")
        if not rows:
            raise HTTPException(409, "no audit events to tamper with")
        tampered.update(id=rows[0]["id"], reason=rows[0]["reason"])
        ctx.store.x("UPDATE audit SET reason=? WHERE id=?", (tampered["reason"] or "") + " [edited]", tampered["id"])
        return {"tampered_id": tampered["id"]}

    @app.post("/api/demo/untamper")
    def untamper():
        demo_only()
        if tampered:
            ctx.store.x("UPDATE audit SET reason=? WHERE id=?", tampered["reason"], tampered["id"])
            tampered.clear()
        return {"ok": True}

    @app.post("/api/demo/attack")
    async def attack(b: AttackBody):
        demo_only()
        return await scripted.run_attack(ctx, b.server_id, b.tool, b.protected)

    @app.post("/api/playground/analyze")
    def playground(b: PlaygroundBody):
        demo_only()
        base_t = {"name": b.name, "description": b.baseline_description}
        cur_t = {"name": b.name, "description": b.description}
        bm, cm = build_manifest(base_t, "srv-playground"), build_manifest(cur_t, "srv-playground")
        findings = scan(cm)
        count, decoded = hidden_stats(b.description)
        return {"baseline_fingerprint": fingerprint(bm), "current_fingerprint": fingerprint(cm),
                "approval_stale": fingerprint(bm) != fingerprint(cm), "findings": [f.model_dump() for f in findings],
                "decision": eligibility(findings, True).model_dump(), "risk": risk_of(findings),
                "views": {"human_rendering": human_rendering(b.description), "model_visible_escaped": escape_for_display(b.description),
                          "hidden_char_count": count, "decoded_hidden_text": decoded},
                "note": "scanner only (stage 1); no LLM in the playground"}

    add_proxy(app, ctx)
    return app


def build() -> FastAPI:  # uvicorn app.api.main:build --factory
    return create_app(svc.Ctx.from_env())
