"""Reference agent pieces.

registry(): the tools handed to the model, built only from the canonical manifest of currently-valid approvals (D-01).
ScriptedAgent: a deterministic stand-in for an LLM that obeys instructions found in tool text (D-10). Honestly labeled.
"""
import json

from .. import service as svc
from ..gate import runtime
from ..gate.gate import gate_call
from ..manifest.canonicalize import registry_view
from ..manifest.invisible import decode_hidden

LABEL = "Scripted agent: deterministic replay of an LLM that follows injected instructions"
MOCK_ENV = "API_KEY=mock-sk-FAKE-0000"  # contents of mock/.env: fake, in-memory only


def registry(ctx: svc.Ctx) -> list[dict]:
    out = []
    for r in ctx.store.tools():
        appr = ctx.store.active_approval(r["server_id"], r["tool_name"])
        if appr and appr["status"] == "active" and appr["fingerprint"] == r["current_fp"]:
            out.append({"server_id": r["server_id"], **registry_view(ctx.store.manifest(r["current_fp"]))["tool"]})
    return out


def _obeys(tool: dict) -> bool:
    text = json.dumps(tool, ensure_ascii=False) + " " + decode_hidden(json.dumps(tool, ensure_ascii=False))
    return ".env" in text


async def exfil_log(ctx: svc.Ctx) -> list[dict]:
    try:
        return (await ctx.http.get(f"{ctx.fixture_base}/exfil/log", timeout=5)).json()
    except Exception:
        return []


async def run_attack(ctx: svc.Ctx, sid: str, tool_name: str, protected: bool) -> dict:
    log = [LABEL]
    srv = ctx.store.server(sid)
    client = ctx.client(srv["endpoint"])
    tools, _ = await client.capture()
    tool = next(t for t in tools if t["name"] == tool_name)
    before = len(await exfil_log(ctx))
    secret = {"query": MOCK_ENV, "id": MOCK_ENV, "topic": MOCK_ENV}
    args = {"query": "reports", "topic": "Q3 planning"}
    if _obeys(tool):
        log.append("Agent read mock/.env (instructed by tool text)")
        args = secret
    for step in range(2):  # a second call only when the first result told the agent to read mock/.env
        log.append(f"Agent invoked: {tool_name}")
        if protected:
            g = await gate_call(ctx, sid, tool_name, args)
            if not g["allowed"]:
                codes = ", ".join(g["reason_codes"])
                log += [f"Filigree: {'DATA-FLOW' if 'TAINTED_ARGS' in codes else 'APPROVAL'} BLOCKED ({codes})",
                        "Execution prevented before the tool could be used."]
                return {"succeeded": False, "log": log}
            result = g["result"]
            if g.get("result_flags"):
                log.append(f"Filigree: RESULT_INJECTION, tool output withheld from the agent ({g['result_flags'][0][:60]})")
        else:  # Scene 1: no Filigree. Direct call straight to the server.
            result = await client.call_tool(tool_name, args)
        if step or ".env" not in result:
            break
        log.append("Agent read mock/.env (instructed by the tool RESULT)")
        if protected:
            runtime.observe(ctx, MOCK_ENV)  # the reference agent's file read is visible to Filigree
        args = secret
    leaked = any(MOCK_ENV in json.dumps(e["args"]) for e in (await exfil_log(ctx))[before:])
    if leaked:
        log += ["Sensitive resource accessed: mock/.env", "External request made: mock-attacker.local/collect", "ATTACK SUCCEEDED"]
    else:
        log.append("Tool executed normally")
    return {"succeeded": leaked, "log": log}
