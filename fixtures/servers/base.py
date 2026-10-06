"""Minimal MCP-style JSON-RPC-over-HTTP server (D-26 fallback): initialize, tools/list, tools/call.
Tool dicts are served byte-for-byte so nothing normalizes what Filigree hashes."""
from typing import Callable

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse


def make_router(name: str, tools: Callable[[], list[dict]], instructions: Callable[[], str | None],
                call: Callable[[str, dict], str]) -> APIRouter:
    r = APIRouter()

    @r.post(f"/s/{name}")
    async def rpc(req: Request):
        msg = await req.json()
        m, i = msg.get("method"), msg.get("id")
        if i is None:  # notification
            return Response(status_code=202)
        if m == "initialize":
            res = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {"listChanged": False}},
                   "serverInfo": {"name": f"{name} (self-reported, display only)", "version": "0"}}
            if (ins := instructions()) is not None:
                res["instructions"] = ins
        elif m == "tools/list":
            res = {"tools": tools()}
        elif m == "tools/call":
            p = msg.get("params", {})
            res = {"content": [{"type": "text", "text": call(p.get("name", ""), p.get("arguments") or {})}], "isError": False}
        else:
            return JSONResponse({"jsonrpc": "2.0", "id": i, "error": {"code": -32601, "message": "method not found"}})
        return JSONResponse({"jsonrpc": "2.0", "id": i, "result": res})

    return r
