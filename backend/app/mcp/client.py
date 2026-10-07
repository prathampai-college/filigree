"""Capture client: JSON-RPC over HTTP (plain JSON or SSE replies, Mcp-Session-Id) or stdio. Raw tool dicts are returned
untouched (strict JSON parse only)."""
import itertools
import json

import httpx

from ..manifest.canonicalize import loads_strict
from . import stdio

_ids = itertools.count(1)
PROTOCOL = "2025-06-18"


class CaptureError(Exception):
    pass


def result_text(res: dict) -> str:
    """Everything in a tool result that the model would read: text blocks plus structured content."""
    text = "".join(c.get("text", "") for c in res.get("content", []))
    if res.get("structuredContent") is not None:
        text += ("\n" if text else "") + json.dumps(res["structuredContent"], ensure_ascii=False)
    return text


def _sse_message(text: str, want_id) -> str:
    """The JSON payload of the SSE event answering request `want_id` (streamable HTTP servers may reply this way)."""
    for block in text.replace("\r\n", "\n").split("\n\n"):
        data = "\n".join(l[5:].lstrip(" ") for l in block.split("\n") if l.startswith("data:"))
        if data and (m := loads_strict(data)).get("id") == want_id and ("result" in m or "error" in m):
            return data
    raise ValueError("no response for this request in the event stream")


class McpClient:
    def __init__(self, http: httpx.AsyncClient, endpoint: str, identity: str = "filigree"):
        self.http, self.endpoint, self.identity = http, endpoint, identity
        self.session_id: str | None = None

    async def _rpc(self, method: str, params: dict | None = None, notify: bool = False):
        body = {"jsonrpc": "2.0", "method": method, **({"params": params} if params else {})}
        if not notify:
            body["id"] = next(_ids)
        headers = {"User-Agent": f"{self.identity}/0", "Accept": "application/json, text/event-stream"}
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        if method != "initialize":
            headers["MCP-Protocol-Version"] = PROTOCOL
        try:
            r = await self.http.post(self.endpoint, json=body, timeout=10, headers=headers)
            r.raise_for_status()
            if method == "initialize":
                self.session_id = r.headers.get("mcp-session-id")
            if notify:
                return None
            sse = r.headers.get("content-type", "").startswith("text/event-stream")
            msg = loads_strict(_sse_message(r.text, body["id"]) if sse else r.text)
        except (httpx.HTTPError, ValueError) as e:
            raise CaptureError(f"{method}: {e}") from e
        if "error" in msg:
            raise CaptureError(f"{method}: {msg['error']}")
        return msg["result"]

    async def capture(self) -> tuple[list[dict], str | None]:
        """Returns (tools, server_instructions). Fresh tools/list every time (HTTP: fresh initialize too)."""
        if stdio.is_stdio(self.endpoint):
            try:
                return await stdio.capture(self.endpoint, self.identity)
            except stdio.StdioError as e:
                raise CaptureError(str(e)) from e
        init = await self._rpc("initialize", {"protocolVersion": PROTOCOL, "capabilities": {},
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

    async def call_raw(self, name: str, args: dict) -> dict:
        """The full tools/call result (content, structuredContent, isError), so a gateway can pass it on unchanged."""
        if stdio.is_stdio(self.endpoint):
            try:
                return await stdio.call_tool(self.endpoint, self.identity, name, args)
            except stdio.StdioError as e:
                raise CaptureError(str(e)) from e
        return await self._rpc("tools/call", {"name": name, "arguments": args})

    async def call_tool(self, name: str, args: dict) -> str:
        return result_text(await self.call_raw(name, args))
