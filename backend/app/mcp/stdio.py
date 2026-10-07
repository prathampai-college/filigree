"""stdio MCP upstream: one persistent child process per (command, client identity), newline-delimited JSON-RPC.

Endpoint form: "stdio:" + JSON {"argv": [...], "env": {...}}. The child gets our environment minus anything that looks like a
secret, plus the entry's own env. Blocking I/O runs in threads (asyncio.to_thread), so it works on any event loop (Windows too).
"""
import asyncio
import json
import os
import queue
import shutil
import subprocess
import threading

from ..manifest.canonicalize import loads_strict

PREFIX = "stdio:"
_SECRETISH = ("KEY", "TOKEN", "SECRET", "PASSWORD")
_SESSIONS: dict[tuple[str, str], "StdioSession"] = {}
_LOCK = threading.Lock()


def endpoint_for(argv: list[str], env: dict | None = None) -> str:
    return PREFIX + json.dumps({"argv": argv, "env": env or {}}, sort_keys=True)


def is_stdio(endpoint: str) -> bool:
    return endpoint.startswith(PREFIX)


class StdioError(Exception):
    pass


class StdioSession:
    def __init__(self, endpoint: str, identity: str):
        spec = json.loads(endpoint[len(PREFIX):])
        argv = list(spec["argv"])
        argv[0] = shutil.which(argv[0]) or argv[0]  # npx -> npx.cmd on Windows
        env = {k: v for k, v in os.environ.items() if not any(s in k.upper() for s in _SECRETISH)} | spec.get("env", {})
        self.identity, self.instructions, self._id = identity, None, 0
        self.io = threading.Lock()
        self.lines: queue.Queue = queue.Queue()
        try:
            self.p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                      text=True, encoding="utf-8", env=env)
        except OSError as e:
            raise StdioError(f"cannot start {argv[0]}: {e}") from e
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self):
        for line in self.p.stdout:
            self.lines.put(line)
        self.lines.put(None)  # EOF: the process exited

    @property
    def alive(self) -> bool:
        return self.p.poll() is None

    def _send(self, msg: dict):
        try:
            self.p.stdin.write(json.dumps(msg) + "\n")
            self.p.stdin.flush()
        except OSError as e:
            raise StdioError(f"server process is gone: {e}") from e

    def _rpc(self, method: str, params: dict | None = None, timeout: float = 60):
        self._id += 1
        self._send({"jsonrpc": "2.0", "id": self._id, "method": method, **({"params": params} if params else {})})
        while True:
            try:
                line = self.lines.get(timeout=timeout)
            except queue.Empty:
                raise StdioError(f"{method}: timed out after {timeout}s") from None
            if line is None:
                raise StdioError(f"{method}: server process exited")
            try:
                msg = loads_strict(line)
            except ValueError:
                continue  # not protocol output (stray log line)
            if msg.get("id") != self._id or "method" in msg:
                continue  # notification or a server-initiated request: not our answer
            if "error" in msg:
                raise StdioError(f"{method}: {msg['error']}")
            return msg["result"]

    def initialize(self):
        res = self._rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                       "clientInfo": {"name": self.identity, "version": "0"}}, 120)
        self.instructions = res.get("instructions")
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def list_tools(self) -> list[dict]:
        tools, cursor = [], None
        for _ in range(20):
            res = self._rpc("tools/list", {"cursor": cursor} if cursor else None)
            tools += res["tools"]
            if not (cursor := res.get("nextCursor")):
                return tools
        raise StdioError("tools/list pagination did not terminate")

    def call(self, name: str, args: dict) -> str:
        res = self._rpc("tools/call", {"name": name, "arguments": args}, 120)
        return "".join(c.get("text", "") for c in res.get("content", []))

    def close(self):
        self.p.kill()


def _session(endpoint: str, identity: str) -> StdioSession:
    with _LOCK:
        s = _SESSIONS.get((endpoint, identity))
        if s is None or not s.alive:
            s = StdioSession(endpoint, identity)
            s.initialize()
            _SESSIONS[(endpoint, identity)] = s
        return s


async def capture(endpoint: str, identity: str) -> tuple[list[dict], str | None]:
    """Fresh tools/list on the live process; the process (and its initialize) is reused between calls."""
    def run():
        s = _session(endpoint, identity)
        with s.io:
            return s.list_tools(), s.instructions
    try:
        return await asyncio.to_thread(run)
    except StdioError:
        close(endpoint, identity)
        raise


async def call_tool(endpoint: str, identity: str, name: str, args: dict) -> str:
    def run():
        s = _session(endpoint, identity)
        with s.io:
            return s.call(name, args)
    return await asyncio.to_thread(run)


def close(endpoint: str | None = None, identity: str | None = None) -> None:
    """Kill sessions (all, or one endpoint/identity). Tests and the probe identity use this."""
    with _LOCK:
        for key in [k for k in _SESSIONS if (endpoint is None or k[0] == endpoint) and (identity is None or k[1] == identity)]:
            _SESSIONS.pop(key).close()
