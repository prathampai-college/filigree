"""Populate fixtures/replay_cache.json so the demo runs fully offline (`make replay-cache`).

Default: AUTHORED analyzer outputs for the demo fixtures (not model output).
--live: call the configured model once per demo tool and record its real output plus provenance (provider, model, date).
Any failed call aborts without writing, so authored and recorded entries are never mixed. The UI labels both REPLAY MODE.
Usage: uv run --project backend python scripts/seed_fixtures.py [--live]
"""
import asyncio
import datetime
import json
import os
import sys
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "backend"), str(ROOT)]

from app.analyzer.base import PROMPT_VERSION, LlmOutput  # noqa: E402
from app.analyzer.impl import CACHE_PATH, LiveAnalyzer, build_user_message, cache_key, resolve_key  # noqa: E402
from app.api.main import SCENARIOS  # noqa: E402
from app.envfile import load_dotenv  # noqa: E402
from app.manifest.canonicalize import build_manifest, fingerprint  # noqa: E402
from app.mcp.client import McpClient  # noqa: E402
from app.scanner.rules import scan  # noqa: E402
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
    ("results", "find_files"): NONE("Find project files by name"),
    ("results", "fetch_notes"): NONE("Fetch meeting notes on a topic"),
    ("cloak", "search_documents"): NONE("Search documents by keyword"),
    ("rugpull", "fetch_report", "benign"): NONE("Fetch a report by ID"),
    ("rugpull", "fetch_report", "icon"): NONE("Fetch a report by ID"),
    ("rugpull", "fetch_report", "modified"): out("Fetch a report by ID", "high", [
        ("external_exfiltration", "high", "upload local credentials to an external endpoint")], "block"),
}


async def main():
    http = httpx.AsyncClient(transport=httpx.ASGITransport(app=fixture_app), base_url="http://fx")
    cache = {}
    live = None
    if "--live" in sys.argv:
        load_dotenv()
        if not resolve_key(os.environ.get("ANALYZER_PROVIDER")):
            sys.exit("--live needs ANALYZER_API_KEY (see .env.example)")
        live = LiveAnalyzer(httpx.AsyncClient(timeout=60))
        try:  # keep earlier recordings; only tools without one are sent to the model
            cache = json.loads(CACHE_PATH.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            cache = {}
    for name, sid in SCENARIOS.items():
        for state in (["benign", "icon", "modified"] if name == "rugpull" else [None]):
            if state:
                rug_pull_server.mutate(state)
            tools, ins = await McpClient(http, f"http://fx/s/{name}").capture()
            for t in tools:
                key = (name, t["name"], state) if state else (name, t["name"])
                m = build_manifest(t, sid, ins)
                fp = fingerprint(m)
                if live and cache_key(fp) not in cache:
                    try:  # the model sees the scanner findings, exactly as in the running product
                        cache[cache_key(fp)] = LlmOutput(**await live._call_retry(build_user_message(m, scan(m)))).model_dump()
                    except Exception as e:  # noqa: BLE001 - any failure must abort, never fall back to authored text
                        sys.exit(f"live call failed for {name}/{t['name']}: {type(e).__name__}: {e}; nothing written")
                    print(f"recorded {name}/{t['name']}{'/' + state if state else ''}: {cache[cache_key(fp)]['recommended_action']}")
                elif not live:
                    cache[cache_key(fp)] = AUTHORED[key]
    rug_pull_server.reset()
    if live:
        cache["_provenance"] = {"source": "live model", "provider": live.provider, "model": live.model,
                                "prompt_version": PROMPT_VERSION, "recorded_at": datetime.date.today().isoformat()}
    CACHE_PATH.write_text(json.dumps(cache, indent=1), encoding="utf-8")
    print(f"wrote {len(cache) - ('_provenance' in cache)} entries -> {CACHE_PATH}")


asyncio.run(main())
