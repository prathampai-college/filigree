"""The `filigree` command: audit your MCP config, run a stdio server behind the gate, verify a lockfile, serve the UI/API.

    filigree audit [config] [--yes] [--json]      scan every server in .mcp.json / claude_desktop_config.json (no tool is called)
    filigree run <id> -- <command...>             stdio gateway in front of one server (approve tools in the UI, same FILIGREE_DB)
    filigree verify [filigree.lock]               exit 1 if any pinned tool is served differently
    filigree serve [--port 8000]                  API + gateway (the UI is the frontend/ dev server)
"""
import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

import httpx

from .manifest.canonicalize import build_manifest
from .mcp import stdio
from .mcp.client import McpClient
from .policy.evaluate import eligibility
from .scanner.rules import scan


def config_candidates() -> list[Path]:
    home = Path.home()
    return [Path(".mcp.json"), Path(os.environ.get("APPDATA", "")) / "Claude" / "claude_desktop_config.json",
            home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
            home / ".config" / "Claude" / "claude_desktop_config.json"]


def read_servers(path: Path) -> dict[str, str]:
    """name -> endpoint, from the mcpServers (or VS Code's servers) block of an MCP config file."""
    cfg = json.loads(path.read_text(encoding="utf-8-sig"))
    out = {}
    for name, e in (cfg.get("mcpServers") or cfg.get("servers") or {}).items():
        if e.get("command"):
            out[name] = stdio.endpoint_for([e["command"], *e.get("args", [])], e.get("env") or {}, clean_env=True)
        elif str(e.get("url", "")).startswith(("http://", "https://")):
            out[name] = e["url"]
    return out


def describe(endpoint: str) -> str:
    return " ".join(json.loads(endpoint[len(stdio.PREFIX):])["argv"]) if stdio.is_stdio(endpoint) else endpoint


async def audit_server(http, name: str, endpoint: str) -> dict:
    try:
        tools, ins = await McpClient(http, endpoint).capture()
    except Exception as e:  # noqa: BLE001 - a server that will not start is reported, never hidden
        return {"server": name, "error": f"{type(e).__name__}: {e}"[:200], "tools": []}
    finally:
        stdio.close(endpoint)
    names = {t["name"] for t in tools}
    rows = []
    for t in tools:
        fs = scan(build_manifest(t, name, ins), known_tools=names)
        rows.append({"tool": t["name"], "action": eligibility(fs, True).action,
                     "findings": [{"category": f.category, "severity": f.severity, "evidence": f.evidence} for f in fs]})
    return {"server": name, "tools": rows}


async def cmd_audit(a) -> int:
    path = Path(a.config) if a.config else next((p for p in config_candidates() if p.is_file()), None)
    if path is None or not path.is_file():
        print("no MCP config found; pass a path to .mcp.json or claude_desktop_config.json", file=sys.stderr)
        return 2
    servers = read_servers(path)
    print(f"config: {path}  ({len(servers)} servers)", file=sys.stderr)
    spawn = {n: describe(e) for n, e in servers.items() if stdio.is_stdio(e)}
    if spawn and not a.yes:  # auditing starts the configured commands (tools/list only, nothing is called)
        print("Auditing starts these commands from your config, with a minimal environment (PATH, home dirs, and the entry's own env):",
              file=sys.stderr)
        for n, c in spawn.items():
            print(f"  {n}: {c}", file=sys.stderr)
        print("Re-run with --yes to proceed.", file=sys.stderr)
        return 2
    async with httpx.AsyncClient() as http:
        reports = [await audit_server(http, n, e) for n, e in servers.items()]
    if a.json:
        print(json.dumps(reports, indent=1, ensure_ascii=False))
    else:
        for r in reports:
            if r.get("error"):
                print(f"{r['server']}: NOT AUDITED ({r['error']})")
                continue
            c = {k: sum(t["action"] == k for t in r["tools"]) for k in ("block", "review", "allow")}
            print(f"{r['server']}: {len(r['tools'])} tools  blocked {c['block']}  review {c['review']}  clean {c['allow']}")
            for t in r["tools"]:
                for f in t["findings"]:
                    if f["severity"] != "low":
                        print(f"  [{f['severity']}] {t['tool']}: {f['category']} - {f['evidence']}")
    return 1 if any(r.get("error") or any(t["action"] == "block" for t in r["tools"]) for r in reports) else 0


async def cmd_run(a) -> int:
    from . import service as svc
    from .mcp.proxy import handle
    cmd = a.command[1:] if a.command[:1] == ["--"] else a.command
    if not cmd:
        print("usage: filigree run <id> -- <command...>", file=sys.stderr)
        return 2
    ctx = svc.Ctx.from_env()
    ctx.store.upsert_server(a.id, a.id, stdio.endpoint_for(cmd))
    try:
        names = await svc.discover(ctx, a.id)
        print(f"filigree: {len(names)} tools captured; only approved tools are offered (approve them in the UI, same FILIGREE_DB)",
              file=sys.stderr)
    except Exception as e:  # noqa: BLE001 - the gateway still starts: it offers nothing until a capture works and a human approves
        print(f"filigree: capture failed ({e}); no tools offered", file=sys.stderr)
    while line := await asyncio.to_thread(sys.stdin.readline):
        if not line.strip():
            continue
        try:
            msg = json.loads(line)
            res = await handle(ctx, a.id, msg)
        except Exception as e:  # noqa: BLE001 - never crash the client's session; answer with an error
            res = {"jsonrpc": "2.0", "id": msg.get("id") if isinstance(msg, dict) else None, "error": {"code": -32603, "message": str(e)[:200]}}
        if res is not None:
            sys.stdout.write(json.dumps(res, ensure_ascii=False) + "\n")
            sys.stdout.flush()
    stdio.close()
    return 0


async def cmd_verify(a) -> int:
    from .lock import verify
    lock = json.loads(Path(a.lock).read_text(encoding="utf-8-sig"))
    async with httpx.AsyncClient() as http:
        problems = await verify(lock, http)
    for p in problems:
        print("FAIL", p)
    print(f"{len(lock['tools']) - len(problems)}/{len(lock['tools'])} pinned tools verified")
    stdio.close()
    return 1 if problems else 0


def cmd_serve(a) -> int:
    import uvicorn
    uvicorn.run("app.api.main:build", factory=True, host=a.host, port=a.port)
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="filigree", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    au = sub.add_parser("audit")
    au.add_argument("config", nargs="?")
    au.add_argument("--yes", action="store_true", help="allow starting the stdio servers listed in the config")
    au.add_argument("--json", action="store_true")
    ru = sub.add_parser("run")
    ru.add_argument("id")
    ru.add_argument("command", nargs=argparse.REMAINDER)
    ve = sub.add_parser("verify")
    ve.add_argument("lock", nargs="?", default="filigree.lock")
    se = sub.add_parser("serve")
    se.add_argument("--host", default="127.0.0.1")
    se.add_argument("--port", type=int, default=8000)
    a = p.parse_args(argv)
    if a.cmd == "serve":
        return cmd_serve(a)
    return asyncio.run({"audit": cmd_audit, "run": cmd_run, "verify": cmd_verify}[a.cmd](a))


if __name__ == "__main__":
    sys.exit(main())
