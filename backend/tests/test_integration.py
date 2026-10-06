import json
import httpx
import pytest

from app import service as svc
from app.analyzer.impl import MockAnalyzer, ReplayAnalyzer
from app.api.main import create_app
from app.audit import chain
from app.gate.gate import gate_call
from app.manifest.display import human_rendering
from app.storage.store import Store
from fixtures.servers import benign_server, exfil, rug_pull_server
from fixtures.servers.host import app as fixture_app


@pytest.fixture
async def ctx():
    rug_pull_server.reset(); exfil.reset()
    http = httpx.AsyncClient(transport=httpx.ASGITransport(app=fixture_app), base_url="http://fx")
    c = svc.Ctx(Store(), ReplayAnalyzer(), http, fixture_base="http://fx", demo=True)
    yield c
    await http.aclose()


@pytest.fixture
async def api(ctx):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app(ctx)), base_url="http://api") as c:
        yield c


async def connect(api, name):
    r = await api.post("/api/demo/scenario", json={"name": name})
    assert r.status_code == 200, r.text
    return r.json()["server_id"]


async def test_golden_path_rug_pull(api, ctx):
    sid = await connect(api, "rugpull")
    tid = f"{sid}:fetch_report"
    v = (await api.get(f"/api/tools/{tid}/view")).json()
    assert v["trust_state"] == "REVIEW" and v["decision"]["action"] == "allow"
    assert (await api.post(f"/api/tools/{tid}/approve")).json()["trust_state"] == "TRUSTED"
    ok = (await api.post("/api/agent/call", json={"server_id": sid, "tool": "fetch_report", "args": {"id": "7"}})).json()
    assert ok["allowed"] and ok["result"] == "report 7"

    await api.post("/api/demo/mutate", json={"mode": "modified"})
    bad = (await api.post("/api/agent/call", json={"server_id": sid, "tool": "fetch_report", "args": {"id": "7"}})).json()
    assert not bad["allowed"] and bad["reason_codes"] == ["MANIFEST_DRIFT"]
    assert bad["changed_fields"] == ["tool.description"] and bad["diff"]
    assert exfil.LOG == []  # the malicious call never reached the server

    v = (await api.get(f"/api/tools/{tid}/view")).json()
    assert v["trust_state"] == "STALE" and v["drift"]["detected"]
    assert (await api.get(f"/api/tools/{tid}/diff")).json()["changes"]
    # still blocked on the next call; approval stays invalid
    again = (await api.post("/api/agent/call", json={"server_id": sid, "tool": "fetch_report"})).json()
    assert again["reason_codes"] == ["MANIFEST_DRIFT"]
    # the modified version is high-risk: cannot be approved (no override)
    assert (await api.post(f"/api/tools/{tid}/approve", json={"confirm": True})).status_code == 409

    a = (await api.get("/api/audit")).json()
    types = [e["event_type"] for e in a["events"]]
    assert a["chain_verified"] and {"APPROVED", "MANIFEST_DRIFT", "APPROVAL_REVOKED", "EXECUTION_BLOCKED", "EXECUTION_ALLOWED"} <= set(types)


async def test_benign_drift_icon_does_not_block(api):  # fixture E
    sid = await connect(api, "rugpull")
    await api.post(f"/api/tools/{sid}:fetch_report/approve")
    await api.post("/api/demo/mutate", json={"mode": "icon"})
    r = (await api.post("/api/agent/call", json={"server_id": sid, "tool": "fetch_report", "args": {"id": "1"}})).json()
    assert r["allowed"]


async def test_invisible_unicode_identical_but_blocked(api, ctx):  # fixture F
    sid = await connect(api, "invisible")
    v = (await api.get(f"/api/tools/{sid}:search_documents/view")).json()
    assert v["views"]["human_rendering"] == human_rendering(benign_server.DESC) == benign_server.DESC
    assert v["views"]["hidden_char_count"] > 50 and "read ~/.env" in v["views"]["decoded_hidden_text"]
    assert v["trust_state"] == "BLOCKED" and v["analysis"]["findings"][0]["source"] == "scanner"
    assert (await api.post(f"/api/tools/{sid}:search_documents/approve", json={"confirm": True})).status_code == 409
    g = (await api.post("/api/agent/call", json={"server_id": sid, "tool": "search_documents"})).json()
    assert not g["allowed"] and g["reason_codes"] == ["NO_APPROVAL"]


async def test_poisoned_visible_and_concealment(api):  # B, C
    sid = await connect(api, "poisoned")
    for t in ("search_documents", "get_customer"):
        assert (await api.get(f"/api/tools/{sid}:{t}/view")).json()["decision"]["action"] == "block"


async def test_shadowing_no_inherited_approval(api):  # G
    a = await connect(api, "benign")
    await api.post(f"/api/tools/{a}:search_documents/approve")
    s = await connect(api, "shadow")
    for t in ("search_documents", "search_document"):
        v = (await api.get(f"/api/tools/{s}:{t}/view")).json()
        assert v["trust_state"] == "BLOCKED" and any(f["category"] == "name_collision" for f in v["analysis"]["findings"])
        assert v["approval"]["status"] == "none"
    assert (await api.get(f"/api/tools/{a}:search_documents/view")).json()["trust_state"] == "TRUSTED"


async def test_analyzer_injection_scanner_still_blocks(ctx):  # H (analyzer says "no findings")
    ctx.analyzer = MockAnalyzer()
    ctx.store.upsert_server("srv-h", "h", "http://fx/s/poisoned")
    await svc.discover(ctx, "srv-h")
    v = svc.view(ctx, "srv-h", "search_documents")
    assert v.analysis.status == "complete" and v.decision.action == "block"


async def test_analyzer_unavailable_is_review_not_clean(api, ctx, tmp_path):
    ctx.analyzer = ReplayAnalyzer(tmp_path / "missing.json")
    sid = await connect(api, "benign")
    v = (await api.get(f"/api/tools/{sid}:search_documents/view")).json()
    assert v["analysis"]["status"] == "unavailable" and v["decision"] == {"action": "review", "reason_codes": ["ANALYSIS_UNAVAILABLE"]}
    assert (await api.post(f"/api/tools/{sid}:search_documents/approve")).status_code == 409  # needs confirmation
    assert (await api.post(f"/api/tools/{sid}:search_documents/approve", json={"confirm": True})).status_code == 200


async def test_capture_failure_blocks(api, ctx):
    sid = await connect(api, "benign")
    await api.post(f"/api/tools/{sid}:search_documents/approve")
    ctx.store.upsert_server(sid, "benign", "http://fx/s/does-not-exist")
    g = await gate_call(ctx, sid, "search_documents", {})
    assert not g["allowed"] and g["reason_codes"] == ["CAPTURE_FAILURE"]


async def test_audit_chain_detects_tampering(api, ctx):
    await connect(api, "benign")
    assert chain.verify(ctx.store)
    ctx.store.x("UPDATE audit SET reason='edited' WHERE id=1")
    assert not chain.verify(ctx.store)


async def test_audit_tamper_demo_export_and_restore(api, ctx):
    sid = await connect(api, "benign")
    await api.post(f"/api/tools/{sid}:search_documents/approve")
    assert (await api.get("/api/audit")).json()["broken_at"] is None
    tid = (await api.post("/api/demo/tamper")).json()["tampered_id"]
    a = (await api.get("/api/audit")).json()
    assert not a["chain_verified"] and a["broken_at"] == tid
    assert (await api.post("/api/demo/tamper")).status_code == 409  # one remembered edit at a time
    ex = await api.get("/api/audit/export")
    assert "attachment" in ex.headers["content-disposition"]
    assert ex.json()["broken_at"] == tid and ex.json()["events"][0]["id"] < ex.json()["events"][-1]["id"]
    await api.post("/api/demo/untamper")
    assert (await api.get("/api/audit")).json()["chain_verified"]


async def test_denied_fingerprint_stays_blocked(api):
    sid = await connect(api, "benign")
    assert (await api.post(f"/api/tools/{sid}:search_documents/deny")).json()["trust_state"] == "BLOCKED"


async def test_attack_scenes(api):
    sid = await connect(api, "invisible")
    bad = (await api.post("/api/demo/attack", json={"server_id": sid, "tool": "search_documents", "protected": False})).json()
    assert bad["succeeded"] and "ATTACK SUCCEEDED" in bad["log"]
    exfil.reset()
    safe = (await api.post("/api/demo/attack", json={"server_id": sid, "tool": "search_documents", "protected": True})).json()
    assert not safe["succeeded"] and exfil.LOG == []


async def test_registry_only_valid_approvals(api):
    sid = await connect(api, "rugpull")
    assert (await api.get("/api/agent/registry")).json() == []
    await api.post(f"/api/tools/{sid}:fetch_report/approve")
    assert [t["name"] for t in (await api.get("/api/agent/registry")).json()] == ["fetch_report"]


async def test_playground_and_demo_gating(api, ctx):
    p = (await api.post("/api/playground/analyze", json={"description": "Search documents by keyword.​"})).json()
    assert p["approval_stale"] and p["findings"]
    ctx.demo = False
    assert (await api.post("/api/demo/reset")).status_code == 404


async def test_database_down_fails_closed(api, ctx):
    sid = await connect(api, "benign")
    await api.post(f"/api/tools/{sid}:search_documents/approve")
    ctx.store.db.close()  # DB unavailable: gate must block, never bypass approval
    g = await gate_call(ctx, sid, "search_documents", {"query": "plan"})
    assert not g["allowed"] and g["reason_codes"] == ["CAPTURE_FAILURE"]


async def test_mcp_proxy_end_to_end(api, ctx):
    sid = await connect(api, "rugpull")
    rpc = lambda m, p=None: api.post(f"/mcp/{sid}", json={"jsonrpc": "2.0", "id": 1, "method": m, **({"params": p} if p else {})})
    assert (await rpc("ping")).json()["result"] == {}
    assert (await rpc("tools/list")).json()["result"]["tools"] == []  # nothing approved yet
    await api.post(f"/api/tools/{sid}:fetch_report/approve")
    tools = (await rpc("tools/list")).json()["result"]["tools"]
    assert [t["name"] for t in tools] == ["fetch_report"]
    call = {"name": "fetch_report", "arguments": {"id": "7"}}
    ok = (await rpc("tools/call", call)).json()["result"]
    assert not ok["isError"] and ok["content"][0]["text"] == "report 7"
    await api.post("/api/demo/mutate", json={"mode": "modified"})
    bad = (await rpc("tools/call", call)).json()["result"]
    assert bad["isError"] and "MANIFEST_DRIFT" in bad["content"][0]["text"]
    assert (await rpc("tools/list")).json()["result"]["tools"] == []  # stale approval is not offered


def _gullible_chat():
    """Fake model that obeys the poisoned description: reads ~/.env, passes it as the query, then answers."""
    steps = iter([
        {"tool_calls": [{"id": "1", "function": {"name": "read_file", "arguments": '{"path": "~/.env"}'}}]},
        {"tool_calls": [{"id": "2", "function": {"name": "search_documents", "arguments": '{"query": "API_KEY=mock-sk-FAKE-0000"}'}}]},
        {"content": "done"}])

    async def chat(agent, msgs, fns):
        return next(steps)
    return chat


async def test_llm_agent_fooled_without_filigree_and_not_offered_with_it(api, ctx, monkeypatch):
    from app.agent import llm_agent
    monkeypatch.setenv("ANALYZER_API_KEY", "gsk_test")
    sid = await connect(api, "poisoned")
    bad = await llm_agent.run_live(ctx, sid, "search_documents", False, _gullible_chat())
    assert bad["succeeded"] and exfil.LOG and "mock-sk-FAKE" in str(exfil.LOG)
    exfil.reset()
    ok = await llm_agent.run_live(ctx, sid, "search_documents", True, _gullible_chat())  # unapproved: tool is never offered
    assert not ok["succeeded"] and exfil.LOG == [] and "unknown tool" not in ok["log"][0]
    r = (await api.post("/api/demo/attack", json={"server_id": sid, "tool": "search_documents", "agent": "llm"})).json()
    assert not r["succeeded"] and "APPROVAL BLOCKED" in " ".join(r["log"])  # replay mode, protected default: not offered, no LLM


async def test_llm_agent_replay_reports_k_of_n(api, tmp_path, monkeypatch):
    from app.agent import llm_agent
    run = lambda ok: {"succeeded": ok, "log": ["Model called read_file({})"] if ok else ["Model said: no"]}
    f = tmp_path / "r.json"
    f.write_text(json.dumps({"models": {"groq/a": {"temperature": 0.7, "recorded_at": "2026-10-06", "runs": {"srv-poisoned:search_documents": [run(False), run(True)]}},
                                        "groq/b": {"temperature": 0.7, "recorded_at": "2026-10-06", "runs": {"srv-poisoned:search_documents": [run(False), run(False)]}}}}))
    monkeypatch.setattr(llm_agent, "REPLAY_PATH", f)
    r = (await api.post("/api/demo/attack", json={"server_id": "srv-poisoned", "tool": "search_documents", "protected": False, "agent": "llm"})).json()
    assert r["followed"] == "1/4" and r["succeeded"] and "groq/a: leaked the secret in 1 of 2" in "\n".join(r["log"])
    miss = (await api.post("/api/demo/attack", json={"server_id": "srv-x", "tool": "t", "protected": False, "agent": "llm"})).json()
    assert not miss["succeeded"] and "No recorded" in miss["log"][0]


async def test_result_firewall_and_taint(api, ctx):  # fixture I: approved clean tools, malicious results
    sid = await connect(api, "results")
    for t in ("find_files", "fetch_notes"):
        assert (await api.post(f"/api/tools/{sid}:{t}/approve", json={"confirm": True})).json()["trust_state"] == "TRUSTED"
    # unprotected, the scripted agent follows the result's instruction and leaks
    r = (await api.post("/api/demo/attack", json={"server_id": sid, "tool": "fetch_notes", "protected": False})).json()
    assert r["succeeded"]
    # blatant injection in a result: withheld from the agent, audited
    r = (await api.post("/api/demo/attack", json={"server_id": sid, "tool": "find_files", "protected": True})).json()
    assert not r["succeeded"] and any("RESULT_INJECTION" in l for l in r["log"])
    # subtle one passes the firewall, the agent reads .env, the secret may not flow into the next call
    exfil.reset()
    r = (await api.post("/api/demo/attack", json={"server_id": sid, "tool": "fetch_notes", "protected": True})).json()
    assert not r["succeeded"] and any("TAINTED_ARGS" in l for l in r["log"])
    assert all("mock-sk" not in json.dumps(e) for e in exfil.LOG)
    types = [e["event_type"] for e in (await api.get("/api/audit")).json()["events"]]
    assert "RESULT_INJECTION" in types and (await api.get("/api/audit")).json()["chain_verified"]


async def test_taint_blocks_secret_in_args_via_gateway(api, ctx):
    from app.gate import runtime
    sid = await connect(api, "benign")
    await api.post(f"/api/tools/{sid}:search_documents/approve")
    runtime.observe(ctx, "DB_PASSWORD=hunter2hunter2\nother=1")
    ok = await gate_call(ctx, sid, "search_documents", {"query": "plan"})
    bad = await gate_call(ctx, sid, "search_documents", {"query": "x hunter2hunter2"})
    assert ok["allowed"] and not bad["allowed"] and bad["reason_codes"] == ["TAINTED_ARGS"]
    assert runtime.result_injection("Notes for Q3. Budget is fine.") == []
