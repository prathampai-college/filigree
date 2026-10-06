"""Capture client: JSON-RPC over HTTP. Raw tool dicts are returned untouched (strict JSON parse only)."""
import itertools

import httpx

from ..manifest.canonicalize import loads_strict

_ids = itertools.count(1)


class CaptureError(Exception):
    pass


class McpClient:
    def __init__(self, http: httpx.AsyncClient, endpoint: str, identity: str = "filigree"):
        self.http, self.endpoint, self.identity = http, endpoint, identity

    async def _rpc(self, method: str, params: dict | None = None, notify: bool = False):
        body = {"jsonrpc": "2.0", "method": method, **({"params": params} if params else {})}
        if not notify:
            body["id"] = next(_ids)
        try:
            r = await self.http.post(self.endpoint, json=body, timeout=10, headers={"User-Agent": f"{self.identity}/0"})
            r.raise_for_status()
            if notify:
                return None
            msg = loads_strict(r.text)
        except (httpx.HTTPError, ValueError) as e:
            raise CaptureError(f"{method}: {e}") from e
        if "error" in msg:
            raise CaptureError(f"{method}: {msg['error']}")
        return msg["result"]

    async def capture(self) -> tuple[list[dict], str | None]:
        """Returns (tools, server_instructions). Fresh initialize + tools/list every time."""
        init = await self._rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                              "clientInfo": {"name": self.identity, "version": "0"}})
        await self._rpc("notifications/initialized", notify=True)
        tools: list[dict] = []
        cursor = None
        for _ in range(20):
            res = await self._rpc("tools/list", {"cursor": cursor} if cursor else None)
            tools += res["tools"]
            if not (cursor := res.get("nextCursor")):
                return tools, init.get("instructions")
        raise CaptureError("tools/list pagination did not terminate")

    async def call_tool(self, name: str, args: dict) -> str:
        res = await self._rpc("tools/call", {"name": name, "arguments": args})
        return "".join(c.get("text", "") for c in res.get("content", []))
