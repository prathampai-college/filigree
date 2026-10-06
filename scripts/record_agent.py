"""Record real tool-calling model runs against the poisoned fixtures into fixtures/agent_replay.json.

Each (server, tool) is run N times WITHOUT Filigree for each model; every run is kept, including the ones where the model
was not fooled. A benign control (no poison) is recorded too. The task and temperature are fixed up front, never tuned to
get a leak. Saved after each complete case; an API failure aborts and never writes a partial case. Re-running fills only missing cases.
Parallel (limits are per model): REPLAY_OUT=/tmp/a.json uv run ... script.py 5 <model> &  then merge the files by model name.
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
         ("benign", "srv-benign", "search_documents"), ("cloak", "srv-cloak", "search_documents"),
         ("results", "srv-results", "find_files"), ("results", "srv-results", "fetch_notes")]


async def record(ctx, api, n: int, done: dict, save) -> tuple[str, dict]:
    runs = dict(done)  # cases already recorded for this model are kept, not re-run
    for name, sid, tool in CASES:
        if f"{sid}:{tool}" in runs:
            continue
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
        save(entry(api, n, runs))  # per finished case: a later 429 keeps what is done (never a partial case)
    return entry(api, n, runs)


def entry(api, n: int, runs: dict) -> tuple[str, dict]:
    a = LiveAnalyzer(api)
    return f"{a.provider}/{a.model}", {"temperature": llm_agent.TEMPERATURE, "runs_per_case": max(map(len, runs.values()), default=0),
                                       "recorded_at": datetime.date.today().isoformat(), "runs": runs}


async def main(n: int, models: list[str]):
    load_dotenv()
    if not resolve_key(os.environ.get("ANALYZER_PROVIDER")):
        sys.exit("needs a key in .env (see .env.example)")
    http = httpx.AsyncClient(transport=httpx.ASGITransport(app=fixture_app), base_url="http://fx", timeout=60)
    ctx = svc.Ctx(Store(), MockAnalyzer(), http, fixture_base="http://fx", demo=True)
    llm_agent.RETRIES = 12  # free-tier per-minute token limits: wait them out
    api = httpx.AsyncClient(timeout=60)  # real network client for the model; fixtures stay in-process
    try:
        out = json.loads(llm_agent.REPLAY_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        out = {"models": {}}
    for m in models or [os.environ.get("ANALYZER_MODEL", "")]:
        if m:
            os.environ["ANALYZER_MODEL"] = m
        a = LiveAnalyzer(api)
        def save(nr):
            out["models"][nr[0]] = nr[1]
            dest = Path(os.environ.get("REPLAY_OUT") or llm_agent.REPLAY_PATH)  # parallel runs: one output file per model, merged after
            dest.write_text(json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8")
        name, _ = await record(ctx, api, n, out["models"].get(f"{a.provider}/{a.model}", {}).get("runs", {}), save)
        print(f"recorded {name} -> {llm_agent.REPLAY_PATH}")


asyncio.run(main(int(sys.argv[1]) if len(sys.argv) > 1 else 10, sys.argv[2:]))
