"""Drive the gateway with the official MCP Python SDK client (streamable HTTP): list, call, rug pull, blocked call.
Starts the fixture servers and backend itself on spare ports with a throwaway DB.
Usage: uv run --project backend --with "mcp>=2" python scripts/sdk_client_check.py
"""
import asyncio
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

ROOT = Path(__file__).resolve().parents[1]
FX, API = 9100, 8100


def start() -> list[subprocess.Popen]:
    env = {**os.environ, "FILIGREE_DEMO": "1", "FILIGREE_DB": str(Path(tempfile.mkdtemp()) / "sdk.db"), "ANALYZER": "replay",
           "FIXTURE_BASE": f"http://127.0.0.1:{FX}"}
    up = lambda mod, port, cwd, *a: subprocess.Popen([sys.executable, "-m", "uvicorn", mod, "--port", str(port), "--host", "127.0.0.1", *a],
                                                     cwd=cwd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return [up("fixtures.servers.host:app", FX, ROOT), up("app.api.main:build", API, ROOT / "backend", "--factory")]


async def main():
    api = httpx.AsyncClient(base_url=f"http://127.0.0.1:{API}", timeout=10)
    for _ in range(50):  # wait for both servers
        try:
            await api.get("/api/mode"); await api.get(f"http://127.0.0.1:{FX}/exfil/log"); break
        except httpx.HTTPError:
            await asyncio.sleep(0.2)
    sid = (await api.post("/api/demo/scenario", json={"name": "rugpull"})).json()["server_id"]
    url = f"http://127.0.0.1:{API}/mcp/{sid}"
    async with streamable_http_client(url) as (r, w), ClientSession(r, w) as s:
        await s.initialize()
        before = [t.name for t in (await s.list_tools()).tools]
        await api.post(f"/api/tools/{sid}:fetch_report/approve")
        tools = [t.name for t in (await s.list_tools()).tools]
        ok = await s.call_tool("fetch_report", {"id": "7"})
        await api.post("/api/demo/mutate", json={"mode": "modified"})
        bad = await s.call_tool("fetch_report", {"id": "7"})
        after = [t.name for t in (await s.list_tools()).tools]
    print(f"before approval: {before}\nafter approval: {tools}\ncall: isError={ok.is_error} {ok.content[0].text}\n"
          f"after rug pull: isError={bad.is_error} {bad.content[0].text}\nafter rug pull tools: {after}")
    assert before == [] and tools == ["fetch_report"] and not ok.is_error and ok.content[0].text == "report 7"
    assert bad.is_error and "MANIFEST_DRIFT" in bad.content[0].text and after == []
    print("OK: official MCP SDK client verified")


procs = start()
try:
    asyncio.run(main())
finally:
    for p in procs:
        p.terminate()
