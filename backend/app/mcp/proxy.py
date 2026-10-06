"""MCP-facing gateway: a real MCP client points at /mcp/{server_id} and only ever sees approved tools; every call goes through the gate."""
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from .. import service as svc
from ..agent import scripted
from ..gate.gate import gate_call


def add_proxy(app: FastAPI, ctx: svc.Ctx) -> None:
    @app.post("/mcp/{sid}")
    async def mcp(sid: str, req: Request):
        msg = await req.json()
        m, mid, p = msg.get("method"), msg.get("id"), msg.get("params") or {}
        if mid is None:  # notification
            return Response(status_code=202)
        ok = lambda r: JSONResponse({"jsonrpc": "2.0", "id": mid, "result": r})
        if m == "initialize":
            return ok({"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                       "serverInfo": {"name": "filigree-gateway", "version": "0"}})
        if m == "ping":
            return ok({})
        if m == "tools/list":  # canonical bytes of currently-valid approvals only
            return ok({"tools": [{k: v for k, v in t.items() if k != "server_id"}
                                 for t in scripted.registry(ctx) if t["server_id"] == sid]})
        if m == "tools/call":
            g = await gate_call(ctx, sid, p.get("name", ""), p.get("arguments") or {})
            text = g["result"] if g["allowed"] else "Filigree blocked this call: " + ", ".join(g["reason_codes"])
            return ok({"content": [{"type": "text", "text": text}], "isError": not g["allowed"]})
        return JSONResponse({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "method not found"}})
