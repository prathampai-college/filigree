"""filigree.lock: the approved tool definitions, pinned like a package lockfile, verifiable without a Filigree backend.

export(): every currently valid approval -> {"sid:tool": {endpoint, fingerprint, manifest}} (canonical, diff-friendly).
verify(): re-capture each endpoint, re-hash, report drift with a field diff. Used by scripts/filigree_verify.py and CI.
"""
import httpx

from .manifest.canonicalize import build_manifest, fingerprint
from .manifest.diff import diff_manifests
from .mcp import stdio
from .mcp.client import McpClient

LOCK_VERSION = 1


def export(ctx) -> dict:
    tools = {}
    for r in ctx.store.tools():
        sid, name = r["server_id"], r["tool_name"]
        appr = ctx.store.active_approval(sid, name)
        if appr and appr["status"] == "active":
            tools[f"{sid}:{name}"] = {"endpoint": stdio.redact(ctx.store.server(sid)["endpoint"]), "fingerprint": appr["fingerprint"],
                                      "manifest": ctx.store.manifest(appr["fingerprint"])}
    return {"lock_version": LOCK_VERSION, "tools": dict(sorted(tools.items()))}


async def verify(lock: dict, http: httpx.AsyncClient) -> list[str]:
    """Problems found; empty means every pinned tool is served exactly as approved."""
    problems, cache = [], {}
    for key, pin in lock["tools"].items():
        sid, _, name = key.partition(":")
        try:
            if pin["endpoint"] not in cache:
                cache[pin["endpoint"]] = await McpClient(http, stdio.expand(pin["endpoint"])).capture()
            tools, ins = cache[pin["endpoint"]]
        except Exception as e:  # unreachable server = not verified
            problems.append(f"{key}: CAPTURE_FAILURE {e}")
            continue
        live = next((t for t in tools if t.get("name") == name), None)
        if live is None:
            problems.append(f"{key}: tool no longer offered")
            continue
        m = build_manifest(live, sid, ins)
        if fingerprint(m) != pin["fingerprint"]:
            changes = diff_manifests(pin["manifest"], m)
            problems.append(f"{key}: MANIFEST_DRIFT in {', '.join(c['field'] for c in changes)}" +
                            "".join(f"\n    {c['field']}: {c['before']!r} -> {c['after']!r}" for c in changes))
    return problems
