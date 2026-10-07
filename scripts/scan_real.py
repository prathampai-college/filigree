"""Scan real MCP servers over stdio: spawn, initialize, tools/list, fingerprint, run the deterministic scanner. No tool is called.

Only runs the packages listed in TARGETS (official modelcontextprotocol servers). The Filigree stdio client strips secret-looking
variables from the child environment. Writes fixtures/real_world_scan.json (findings) and, with --freeze, the raw definitions to
fixtures/evaluation/real_benign.json + FROZEN_real_benign.sha256 (the false-positive regression set).
Usage: uv run --project backend python scripts/scan_real.py [--freeze]
"""
import asyncio
import hashlib
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "backend")]

from app.manifest.canonicalize import build_manifest, fingerprint  # noqa: E402
from app.mcp import stdio  # noqa: E402
from app.mcp.client import McpClient  # noqa: E402
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
EV = ROOT / "fixtures" / "evaluation"


async def main(freeze: bool):
    out, raw = {}, []
    for name, argv in TARGETS.items():
        ep = stdio.endpoint_for(argv)
        try:
            tools, ins = await McpClient(None, ep).capture()
        except Exception as e:  # noqa: BLE001 - a server that does not start is reported, not hidden
            out[name] = {"error": f"{type(e).__name__}: {e}"[:200]}
            print(f"{name}: NOT SCANNED ({out[name]['error']})", flush=True)
            continue
        finally:
            stdio.close(ep)
        rows = []
        for t in tools:
            m = build_manifest(t, f"real-{name}", ins)
            fs = scan(m, known_tools={x["name"] for x in tools})
            rows.append({"tool": t["name"], "fingerprint": fingerprint(m),
                         "findings": [{"category": f.category, "severity": f.severity, "evidence": f.evidence} for f in fs]})
            raw.append({"id": f"{name}/{t['name']}", "label": "benign", "server": name, "instructions": ins,
                        "tool_names": [x["name"] for x in tools], "tool": t})
        out[name] = {"argv": argv[:3] if argv[0] != "uvx" else argv[:2], "tools": rows}
        print(f"{name}: {len(rows)} tools, {sum(1 for r in rows if r['findings'])} with findings", flush=True)
    path = ROOT / "fixtures" / "real_world_scan.json"
    path.write_text(json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8")
    print(f"wrote {path}")
    if freeze:
        text = json.dumps(raw, indent=1, ensure_ascii=False)
        (EV / "real_benign.json").write_text(text, encoding="utf-8")
        (EV / "FROZEN_real_benign.sha256").write_text(hashlib.sha256(text.encode("utf-8")).hexdigest() + "\n", encoding="utf-8")
        print(f"froze {len(raw)} real tool definitions")


asyncio.run(main("--freeze" in sys.argv))
