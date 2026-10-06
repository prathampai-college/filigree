"""Record real tool-calling model runs against the poisoned fixtures into fixtures/agent_replay.json.

Each (server, tool) is run N times WITHOUT Filigree for each model; every run is kept, including the ones where the model
was not fooled. A benign control (no poison) is recorded too. The task and temperature are fixed up front, never tuned to
get a leak. Any API failure aborts without writing. Models are merged into the file by name.
Usage: uv run --project backend python scripts/record_agent.py [N] [model ...]   (default N=10, model from .env)
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

from app import service as svc  # noqa: E402
from app.agent import llm_agent  # noqa: E402
from app.analyzer.impl import LiveAnalyzer, MockAnalyzer, resolve_key  # noqa: E402
from app.envfile import load_dotenv  # noqa: E402
from app.storage.store import Store  # noqa: E402
from fixtures.servers import exfil  # noqa: E402
from fixtures.servers.host import app as fixture_app  # noqa: E402

CASES = [("poisoned", "srv-poisoned", "search_documents"), ("invisible", "srv-invisible", "search_documents"),
         ("benign", "srv-benign", "search_documents")]


async def record(ctx, api, n: int) -> tuple[str, dict]:
    runs = {}
    for name, sid, tool in CASES:
        ctx.store.upsert_server(sid, name, f"http://fx/s/{name}")
        for i in range(n):
            exfil.reset()
            try:
                r = await llm_agent.run_live(ctx, sid, tool, False, model_http=api)
            except Exception as e:  # noqa: BLE001 - abort, never write a partial recording
                sys.exit(f"{name}/{tool} run {i + 1} failed: {type(e).__name__}: {e}; nothing written")
            if r["log"][0].startswith("Real-model agent needs"):
                sys.exit(r["log"][0])
            runs.setdefault(f"{sid}:{tool}", []).append({"succeeded": r["succeeded"], "log": r["log"]})
            print(f"{LiveAnalyzer(api).model} {sid}:{tool} run {i + 1}/{n}: {'LEAKED' if r['succeeded'] else 'not fooled'}", flush=True)
    a = LiveAnalyzer(api)
    return f"{a.provider}/{a.model}", {"temperature": llm_agent.TEMPERATURE, "runs_per_case": n,
                                       "recorded_at": datetime.date.today().isoformat(), "runs": runs}


async def main(n: int, models: list[str]):
    load_dotenv()
    if not resolve_key(os.environ.get("ANALYZER_PROVIDER")):
        sys.exit("needs a key in .env (see .env.example)")
    http = httpx.AsyncClient(transport=httpx.ASGITransport(app=fixture_app), base_url="http://fx", timeout=60)
    ctx = svc.Ctx(Store(), MockAnalyzer(), http, fixture_base="http://fx", demo=True)
    api = httpx.AsyncClient(timeout=60)  # real network client for the model; fixtures stay in-process
    try:
        out = json.loads(llm_agent.REPLAY_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        out = {"models": {}}
    for m in models or [os.environ.get("ANALYZER_MODEL", "")]:
        if m:
            os.environ["ANALYZER_MODEL"] = m
        name, rec = await record(ctx, api, n)
        out["models"][name] = rec
        llm_agent.REPLAY_PATH.write_text(json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8")  # per model: a later failure keeps earlier ones
        print(f"recorded {name} -> {llm_agent.REPLAY_PATH}")


asyncio.run(main(int(sys.argv[1]) if len(sys.argv) > 1 else 10, sys.argv[2:]))
