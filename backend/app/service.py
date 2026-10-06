"""Orchestration: capture -> manifest -> scanner -> analyzer -> policy -> ToolTrustView / approvals."""
import json
import os
from dataclasses import dataclass, field

import httpx

from .analyzer.base import PROMPT_VERSION, SemanticAnalyzer
from .envfile import load_dotenv
from .analyzer.impl import LiveAnalyzer, ReplayAnalyzer
from .api.schemas import (Analysis, Approval, Decision, Drift, Finding, ToolTrustView, Views)
from .audit import chain
from .manifest.canonicalize import build_manifest, canonical_bytes, fingerprint
from .manifest.diff import changed_fields
from .manifest.display import escape_for_display, hidden_stats, human_rendering
from .mcp.client import McpClient
from .policy.evaluate import eligibility, gate_decision, merge_findings, risk_of
from .scanner.rules import scan, strings
from .storage.store import Store

POLICY_VERSION = "1.0"


@dataclass
class Ctx:
    store: Store
    analyzer: SemanticAnalyzer
    http: httpx.AsyncClient
    fixture_base: str = "http://127.0.0.1:9000"
    demo: bool = False
    extra: dict = field(default_factory=dict)

    def client(self, endpoint: str, identity: str = "filigree") -> McpClient:
        return McpClient(self.http, endpoint, identity)

    @classmethod
    def from_env(cls) -> "Ctx":
        load_dotenv()
        http = httpx.AsyncClient()
        mode = os.environ.get("ANALYZER", "replay")
        analyzer = LiveAnalyzer(http) if mode == "live" else ReplayAnalyzer()
        return cls(Store(os.environ.get("FILIGREE_DB", "filigree.db")), analyzer, http,
                   os.environ.get("FIXTURE_BASE", "http://127.0.0.1:9000"), os.environ.get("FILIGREE_DEMO") == "1")


def tool_id(sid: str, name: str) -> str:
    return f"{sid}:{name}"


def split_id(tid: str) -> tuple[str, str]:
    sid, _, name = tid.partition(":")
    return sid, name


PROBE_IDENTITY = "claude-code"  # ponytail: one alternate identity; a server that cloaks on IP or timing still passes


def scan_for(ctx: Ctx, manifest: dict) -> list[Finding]:
    known = {r["tool_name"] for r in ctx.store.tools()}
    out = scan(manifest, approved=ctx.store.approved_pairs(), known_tools=known)
    if ev := ctx.extra.get("cloaked", {}).get(fingerprint(manifest)):
        out.append(Finding(source="scanner", category="cloaking", severity="high", evidence=ev[:200], confidence="high"))
    return out


async def probe_cloaking(ctx: Ctx, sid: str, endpoint: str, tools: list[dict], instructions: str | None) -> None:
    """Ask again as a different client. A definition that differs by who is asking is marked cloaked (blocked)."""
    other, other_ins = await ctx.client(endpoint, PROBE_IDENTITY).capture()
    theirs = {t.get("name"): build_manifest(t, sid, other_ins) for t in other}
    for t in tools:
        m = build_manifest(t, sid, instructions)
        om = theirs.get(t.get("name"))
        if om is None or fingerprint(om) != fingerprint(m):
            seen = escape_for_display(om["tool"].get("description", "")) if om else "(tool not offered)"
            ctx.extra.setdefault("cloaked", {})[fingerprint(m)] = f"client '{PROBE_IDENTITY}' is served a different definition: {seen}"


async def analyze(ctx: Ctx, manifest: dict, fp: str, force: bool = False) -> None:
    """Run stage 2 once per fingerprint (cached in the DB) and record the scanner stage for the audit record."""
    sf = scan_for(ctx, manifest)
    ctx.store.save_analysis(fp, "scanner", "live", "complete", risk_of(sf), [f.model_dump() for f in sf], 0, "rules-1")
    cached = ctx.store.analysis(fp, "llm")
    if cached and cached["status"] == "complete" and not force:
        return
    res = await ctx.analyzer.analyze(manifest, fp, sf)
    ctx.store.save_analysis(fp, "llm", res.mode, res.status, risk_of(res.findings),
                            [f.model_dump() for f in res.findings], res.latency_ms, PROMPT_VERSION)
    chain.append(ctx.store, "ANALYSIS_COMPLETED", manifest["server"]["id"], manifest["tool"]["name"], cur_fp=fp,
                 reason=f"scanner:{risk_of(sf)} llm:{res.status}/{risk_of(res.findings)} mode:{res.mode}")


def record_capture(ctx: Ctx, sid: str, tool: dict, instructions: str | None) -> tuple[dict, str]:
    """Build + persist the manifest for one live tool. Audits first sight and any change of current definition."""
    m = build_manifest(tool, sid, instructions)
    fp = fingerprint(m)
    prev = ctx.store.current_fp(sid, tool["name"])
    ctx.store.save_manifest(sid, tool["name"], fp, canonical_bytes(m).decode("utf-8"))
    if prev is None:
        chain.append(ctx.store, "TOOL_DISCOVERED", sid, tool["name"], cur_fp=fp)
    elif prev != fp:
        pm = ctx.store.manifest(prev) or {}
        chain.append(ctx.store, "TOOL_DEFINITION_CHANGED", sid, tool["name"], prev, fp, changed_fields(pm, m))
    return m, fp


async def discover(ctx: Ctx, sid: str) -> list[str]:
    srv = ctx.store.server(sid)
    tools, instructions = await ctx.client(srv["endpoint"]).capture()
    await probe_cloaking(ctx, sid, srv["endpoint"], tools, instructions)
    names = []
    for t in tools:
        m, fp = record_capture(ctx, sid, t, instructions)
        await analyze(ctx, m, fp)
        names.append(t["name"])
    return names


def _llm_findings(ctx: Ctx, fp: str) -> tuple[list[Finding], str, str]:
    r = ctx.store.analysis(fp, "llm")
    if not r:
        return [], "unavailable", "replay"
    return [Finding(**f) for f in json.loads(r["findings_json"])], r["status"], r["mode"]


def view(ctx: Ctx, sid: str, name: str) -> ToolTrustView | None:
    fp = ctx.store.current_fp(sid, name)
    if fp is None:
        return None
    m = ctx.store.manifest(fp)
    llm, status, mode = _llm_findings(ctx, fp)
    findings = merge_findings(scan_for(ctx, m), llm)
    ok = status == "complete"
    appr = ctx.store.active_approval(sid, name)
    elig = eligibility(findings, ok)
    drift = Drift(detected=False)
    if appr:
        apm = ctx.store.manifest(appr["fingerprint"]) or {}
        decision, drift = gate_decision(fp, appr["fingerprint"], findings, changed_fields(apm, m))
        state = "STALE" if drift.detected else ("TRUSTED" if decision.action == "allow" else "BLOCKED")
        approval = Approval(status="stale" if drift.detected else "approved", fingerprint=appr["fingerprint"],
                            approved_at=_iso(appr["approved_at"]))
    elif ctx.store.is_denied(sid, name, fp):
        decision, state, approval = Decision(action="block", reason_codes=["USER_DENIED"]), "BLOCKED", Approval(status="denied")
    else:
        decision = elig
        state = "BLOCKED" if elig.action == "block" else "REVIEW"
        approval = Approval(status="none")
    text = "\n".join(s for _, s in strings(m["tool"]))
    desc = m["tool"].get("description", "")
    count, decoded = hidden_stats(text)
    return ToolTrustView(
        tool={"id": tool_id(sid, name), "name": name, "title": m["tool"].get("title", name)},
        server={"id": sid}, trust_state=state, approval=approval, current_fingerprint=fp,
        views=Views(human_rendering=human_rendering(desc), model_visible_escaped=escape_for_display(desc),
                    hidden_char_count=count, decoded_hidden_text=decoded),
        analysis=Analysis(mode=mode, status=status if status in ("complete", "unavailable") else "pending",
                          risk=risk_of(findings), findings=findings),
        drift=drift, decision=decision, eligibility=elig)


def all_views(ctx: Ctx) -> list[ToolTrustView]:
    return [v for r in ctx.store.tools() if (v := view(ctx, r["server_id"], r["tool_name"]))]


class Refused(Exception):
    pass


def approve(ctx: Ctx, sid: str, name: str, confirm: bool = False) -> ToolTrustView:
    v = view(ctx, sid, name)
    if v is None:
        raise Refused("unknown tool")
    e = v.eligibility
    if e.action == "block":  # D-12: no override for high/critical
        raise Refused(f"not eligible: {','.join(e.reason_codes)}")
    if e.action == "review" and not confirm:
        raise Refused("confirmation required: " + ",".join(e.reason_codes))
    ctx.store.add_approval(sid, name, v.current_fingerprint, "approved", confirm, POLICY_VERSION, v.analysis.mode)
    chain.append(ctx.store, "APPROVED", sid, name, cur_fp=v.current_fingerprint,
                 reason=f"policy {POLICY_VERSION}; analysis {v.analysis.status}/{v.analysis.mode}")
    return view(ctx, sid, name)


def deny(ctx: Ctx, sid: str, name: str) -> ToolTrustView:
    fp = ctx.store.current_fp(sid, name)
    if fp is None:
        raise Refused("unknown tool")
    ctx.store.add_approval(sid, name, fp, "denied", False, POLICY_VERSION, "n/a")
    chain.append(ctx.store, "DENIED", sid, name, cur_fp=fp)
    return view(ctx, sid, name)


def _iso(ts: float) -> str:
    from datetime import datetime, timezone
    return datetime.fromtimestamp(ts, timezone.utc).isoformat()
