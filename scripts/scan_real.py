"""Scan real MCP servers over stdio: spawn, initialize, tools/list, fingerprint, run the deterministic scanner. No tool is called.

Only runs the packages listed in TARGETS (official modelcontextprotocol servers). Each runs in a temp dir with secrets stripped
from its environment. Writes fixtures/real_world_scan.json; docs/REAL-WORLD-SCAN.md is written from it by hand.
Usage: uv run --project backend python scripts/scan_real.py
"""
import json
import os
import subprocess
import sys
import tempfile
import threading
import queue
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "backend")]

from app.manifest.canonicalize import build_manifest, fingerprint  # noqa: E402
from app.scanner.rules import scan  # noqa: E402

WORK = tempfile.mkdtemp(prefix="filigree-scan-")
TARGETS = {  # name -> argv. Official reference servers only.
    "filesystem": ["npx", "-y", "@modelcontextprotocol/server-filesystem", WORK],
    "memory": ["npx", "-y", "@modelcontextprotocol/server-memory"],
    "sequential-thinking": ["npx", "-y", "@modelcontextprotocol/server-sequential-thinking"],
    "everything": ["npx", "-y", "@modelcontextprotocol/server-everything"],
    "git": ["uvx", "mcp-server-git", "--repository", str(ROOT)],
    "fetch": ["uvx", "mcp-server-fetch"],
    "time": ["uvx", "mcp-server-time"],
}


def clean_env() -> dict:
    return {k: v for k, v in os.environ.items() if not any(s in k.upper() for s in ("KEY", "TOKEN", "SECRET", "PASSWORD"))}


def capture(argv: list[str], timeout: int = 180) -> tuple[list[dict], str | None]:
    p = subprocess.Popen(argv if os.name != "nt" else ["cmd", "/c", *argv], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL, text=True, cwd=WORK, env=clean_env())
    lines: queue.Queue = queue.Queue()
    threading.Thread(target=lambda: [lines.put(l) for l in p.stdout], daemon=True).start()

    def rpc(method, params=None, i=None):
        msg = {"jsonrpc": "2.0", "method": method, **({"params": params} if params else {}), **({"id": i} if i else {})}
        p.stdin.write(json.dumps(msg) + "\n"); p.stdin.flush()
        while i:
            r = json.loads(lines.get(timeout=timeout))
            if r.get("id") == i:
                if "error" in r:
                    raise RuntimeError(r["error"])
                return r["result"]
    try:
        init = rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "filigree-scan", "version": "0"}}, 1)
        rpc("notifications/initialized")
        tools, cursor = [], None
        for n in range(2, 22):
            res = rpc("tools/list", {"cursor": cursor} if cursor else None, n)
            tools += res["tools"]
            if not (cursor := res.get("nextCursor")):
                break
        return tools, init.get("instructions")
    finally:
        p.kill()


def main():
    out = {}
    for name, argv in TARGETS.items():
        try:
            tools, ins = capture(argv)
        except Exception as e:  # noqa: BLE001 - a server that does not start is reported, not hidden
            out[name] = {"error": f"{type(e).__name__}: {e}"[:200]}
            print(f"{name}: NOT SCANNED ({out[name]['error']})", flush=True)
            continue
        rows = []
        for t in tools:
            m = build_manifest(t, f"real-{name}", ins)
            fs = scan(m, known_tools={x["name"] for x in tools})
            rows.append({"tool": t["name"], "fingerprint": fingerprint(m),
                         "findings": [{"category": f.category, "severity": f.severity, "evidence": f.evidence} for f in fs]})
        out[name] = {"argv": argv[:3] if argv[0] != "uvx" else argv[:2], "tools": rows}
        flagged = [r for r in rows if r["findings"]]
        print(f"{name}: {len(rows)} tools, {len(flagged)} with findings", flush=True)
    path = ROOT / "fixtures" / "real_world_scan.json"
    path.write_text(json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8")
    print(f"wrote {path}")


main()
