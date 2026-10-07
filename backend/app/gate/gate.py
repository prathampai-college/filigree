"""Execution gate (D-08): the single path to tools/call. Re-fetches the live definition and re-hashes before every call."""
from .. import service as svc
from ..audit import chain
from ..manifest.canonicalize import build_manifest, fingerprint
from ..manifest.diff import changed_fields, diff_manifests
from ..mcp.client import CaptureError, result_text
from ..policy.evaluate import gate_decision, merge_findings
from . import runtime


def _blocked(codes, **kw) -> dict:
    return {"allowed": False, "reason_codes": list(codes), "changed_fields": [], "diff": [], "result": None, **kw}


async def gate_call(ctx: svc.Ctx, sid: str, tool_name: str, args: dict, execute: bool = True) -> dict:
    """execute=False: full check only, the client calls the server itself (Claude Code PreToolUse hook)."""
    store = ctx.store
    try:
        srv = store.server(sid)
        if srv is None:
            raise CaptureError("unknown server")
        client = ctx.client(srv["endpoint"])  # one client: a real server's session is initialized by capture and reused by the call
        tools, instructions = await client.capture()  # re-fetch NOW
        await svc.probe_cloaking(ctx, sid, srv["endpoint"], tools, instructions)
        live = next((t for t in tools if t.get("name") == tool_name), None)
        if live is None:
            raise CaptureError("tool no longer offered")
        manifest, fp = svc.record_capture(ctx, sid, live, instructions)
    except Exception as e:  # capture or storage failure: fail closed, visibly
        reason = "CAPTURE_FAILURE"
        try:
            chain.append(store, "EXECUTION_BLOCKED", sid, tool_name, reason=f"{reason}: {e}"[:200])
        except Exception:
            pass
        return _blocked([reason])

    appr = store.active_approval(sid, tool_name)
    llm, _, _ = svc._llm_findings(ctx, fp)
    findings = merge_findings(svc.scan_for(ctx, manifest), llm)
    approved_m = store.manifest(appr["fingerprint"]) if appr else None
    changed = changed_fields(approved_m, manifest) if approved_m else []
    decision, drift = gate_decision(fp, appr["fingerprint"] if appr else None, findings, changed)

    if decision.action != "allow":
        diff = diff_manifests(approved_m, manifest) if drift.detected else []
        if drift.detected:
            store.mark_stale(appr["id"])
            chain.append(store, "MANIFEST_DRIFT", sid, tool_name, appr["fingerprint"], fp, changed)
            chain.append(store, "APPROVAL_REVOKED", sid, tool_name, appr["fingerprint"], fp)
            await svc.analyze(ctx, manifest, fp)  # so the review-new-version screen is complete
        chain.append(store, "EXECUTION_BLOCKED", sid, tool_name, appr["fingerprint"] if appr else None, fp, changed,
                     ",".join(decision.reason_codes))
        return _blocked(decision.reason_codes, changed_fields=changed, diff=diff)

    if secret := runtime.tainted(ctx, args):  # approved tool, but a secret seen earlier is flowing into its arguments
        chain.append(store, "EXECUTION_BLOCKED", sid, tool_name, cur_fp=fp, reason=f"TAINTED_ARGS: {secret[:4]}…")
        return _blocked(["TAINTED_ARGS"])
    chain.append(store, "EXECUTION_ALLOWED", sid, tool_name, cur_fp=fp, reason=None if execute else "pre-check; client calls the server")
    if not execute:
        return {"allowed": True, "reason_codes": [], "changed_fields": [], "diff": [], "result": None}
    raw = await client.call_raw(tool_name, args)
    result = result_text(raw)
    runtime.observe(ctx, result)
    flags = runtime.result_injection(result)
    if flags:  # the call ran; its output is not handed to the model
        chain.append(store, "RESULT_INJECTION", sid, tool_name, cur_fp=fp, reason="; ".join(flags)[:200])
        result, raw = f"[Filigree withheld this tool result: instruction-like text ({flags[0][:80]})]", None
    return {"allowed": True, "reason_codes": [], "changed_fields": [], "diff": [], "result": result, "result_flags": flags, "raw": raw}
