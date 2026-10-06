"""Verify that MCP servers still serve exactly the tool definitions pinned in filigree.lock. Exit 1 on any drift.

Get a lock from a running backend:  curl http://127.0.0.1:8000/api/lock > filigree.lock  (or "Download filigree.lock" in the UI)
Usage: uv run --project backend python scripts/filigree_verify.py [filigree.lock]
"""
import asyncio
import json
import sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from app.lock import verify  # noqa: E402


async def main(path: str) -> int:
    lock = json.loads(Path(path).read_text(encoding="utf-8"))
    async with httpx.AsyncClient() as http:
        problems = await verify(lock, http)
    for p in problems:
        print("FAIL", p)
    print(f"{len(lock['tools']) - len(problems)}/{len(lock['tools'])} pinned tools verified")
    return 1 if problems else 0


sys.exit(asyncio.run(main(sys.argv[1] if len(sys.argv) > 1 else "filigree.lock")))
