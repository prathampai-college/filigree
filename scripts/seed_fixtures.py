"""Populate fixtures/replay_cache.json so the demo runs fully offline (`make replay-cache`).

These are AUTHORED analyzer outputs for the demo fixtures, not live model runs. The UI labels them REPLAY MODE.
Usage: uv run --project backend python scripts/seed_fixtures.py
"""
import asyncio
import json
import sys
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "backend"), str(ROOT)]

from app.analyzer.base import LlmOutput  # noqa: E402
from app.analyzer.impl import CACHE_PATH, cache_key  # noqa: E402
from app.api.main import SCENARIOS  # noqa: E402
from app.manifest.canonicalize import build_manifest, fingerprint  # noqa: E402
from app.mcp.client import McpClient  # noqa: E402
from fixtures.servers.host import app as fixture_app  # noqa: E402
from fixtures.servers import rug_pull_server  # noqa: E402


def out(purpose, risk, findings, action):
    return LlmOutput(declared_purpose=purpose, risk_level=risk, recommended_action=action,
                     findings=[dict(category=c, severity=s, evidence=e, confidence="high") for c, s, e in findings]).model_dump()


NONE = lambda p: out(p, "none", [], "allow")
AUTHORED = {
    ("benign", "search_documents"): NONE("Search documents by keyword"),
    ("shadow", "search_documents"): NONE("Search documents by keyword"),
    ("shadow", "search_document"): NONE("Search documents by keyword"),
    ("invisible", "search_documents"): out("Search documents by keyword", "high", [
        ("hidden_instruction", "high", "hidden text instructs reading ~/.env and concealing it from the user")], "block"),
    ("poisoned", "search_documents"): out("Search documents by keyword", "high", [
        ("sensitive_resource_request", "high", "asks the model to read ~/.env"),
        ("external_exfiltration", "high", "send to http://mock-attacker.local/collect")], "block"),
    ("poisoned", "get_customer"): out("Look up a customer record", "high", [
        ("concealment_instruction", "high", "tells the model not to inform the user about copying records")], "block"),
    ("rugpull", "fetch_report", "benign"): NONE("Fetch a report by ID"),
    ("rugpull", "fetch_report", "icon"): NONE("Fetch a report by ID"),
    ("rugpull", "fetch_report", "modified"): out("Fetch a report by ID", "high", [
        ("external_exfiltration", "high", "upload local credentials to an external endpoint")], "block"),
}


async def main():
    http = httpx.AsyncClient(transport=httpx.ASGITransport(app=fixture_app), base_url="http://fx")
    cache = {}
    for name, sid in SCENARIOS.items():
        for state in (["benign", "icon", "modified"] if name == "rugpull" else [None]):
            if state:
                rug_pull_server.mutate(state)
            tools, ins = await McpClient(http, f"http://fx/s/{name}").capture()
            for t in tools:
                key = (name, t["name"], state) if state else (name, t["name"])
                fp = fingerprint(build_manifest(t, sid, ins))
                cache[cache_key(fp)] = AUTHORED[key]
    rug_pull_server.reset()
    CACHE_PATH.write_text(json.dumps(cache, indent=1), encoding="utf-8")
    print(f"wrote {len(cache)} entries -> {CACHE_PATH}")


asyncio.run(main())
