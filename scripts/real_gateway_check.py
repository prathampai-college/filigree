"""End to end on a REAL server: the official filesystem MCP server behind `filigree run`, driven by the official MCP Python SDK.

Checks: nothing is offered before approval; after a human approves two tools only those two are listed; an approved call works;
an unapproved tool is blocked and never reaches the server (the file is not written). Needs npx and network the first time.
Usage: uv run --project backend --with "mcp>=2" python scripts/real_gateway_check.py
"""
import asyncio
import os
import sys
import tempfile
from pathlib import Path

import httpx
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from app import service as svc  # noqa: E402
from app.analyzer.impl import ReplayAnalyzer  # noqa: E402
from app.storage.store import Store  # noqa: E402


async def main() -> int:
    work, db = tempfile.mkdtemp(prefix="filigree-fs-"), os.path.join(tempfile.mkdtemp(), "f.db")
    (Path(work) / "notes.txt").write_text("quarterly plan", encoding="utf-8")
    params = StdioServerParameters(command=sys.executable, args=["-m", "app.cli", "run", "fs", "--", "npx", "-y",
                                   "@modelcontextprotocol/server-filesystem", work],
                                   env={**os.environ, "FILIGREE_DB": db, "PYTHONPATH": str(ROOT / "backend")}, cwd=str(ROOT / "backend"))
    failures = []

    def check(name, ok):
        print(("PASS " if ok else "FAIL ") + name)
        if not ok:
            failures.append(name)

    async with stdio_client(params) as (r, w), ClientSession(r, w) as s:
        await s.initialize()
        check("nothing offered before approval", (await s.list_tools()).tools == [])
        ctx = svc.Ctx(Store(db), ReplayAnalyzer(), httpx.AsyncClient())  # the human approval (the UI does this on the same DB)
        for t in ("read_text_file", "list_directory"):
            v = svc.view(ctx, "fs", t)
            check(f"{t} reviewable (state {v.trust_state})", v.trust_state in ("REVIEW", "TRUSTED"))
            svc.approve(ctx, "fs", t, confirm=True)
        check("only the two approved tools are listed",
              sorted(t.name for t in (await s.list_tools()).tools) == ["list_directory", "read_text_file"])
        res = await s.call_tool("read_text_file", {"path": str(Path(work) / "notes.txt")})
        check("approved call reaches the real server", "quarterly plan" in res.content[0].text and not res.is_error)
        target = Path(work) / "evil.txt"
        res = await s.call_tool("write_file", {"path": str(target), "content": "x"})
        check("unapproved write_file is blocked", res.is_error and "blocked" in res.content[0].text.lower())
        check("and never reached the server", not target.exists())
    print(f"{'FAILED' if failures else 'OK'}: {len(failures)} failing")
    return 1 if failures else 0


sys.exit(asyncio.run(main()))
