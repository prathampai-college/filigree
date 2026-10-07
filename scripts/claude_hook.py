"""Claude Code PreToolUse hook: every MCP tool call is checked by Filigree first. Exit 2 blocks the call (stderr goes to Claude).

The Claude Code MCP server name must equal the Filigree server id (or map it: FILIGREE_MAP="claudename=srv-id,...").
Fails closed: backend down or server not registered = blocked. Set FILIGREE_HOOK_FAIL_OPEN=1 to allow instead.
Set FILIGREE_TOKEN when the backend runs with FILIGREE_TOKENS. Stdlib only. Wire it in .claude/settings.json (see README).
"""
import json
import os
import sys
import urllib.request

try:
    event = json.loads(sys.stdin.buffer.read().decode("utf-8-sig"))
except Exception as e:  # noqa: BLE001 - exit 1 would be non-blocking in Claude Code: a crash must block too
    sys.stderr.write(f"Filigree hook could not read the event ({e}); call blocked.\n")
    sys.exit(2)
tool = event.get("tool_name", "")
if not tool.startswith("mcp__"):
    sys.exit(0)
server, _, name = tool[len("mcp__"):].partition("__")
sid = dict(p.split("=", 1) for p in os.environ.get("FILIGREE_MAP", "").split(",") if "=" in p).get(server, server)
body = json.dumps({"server_id": sid, "tool": name, "args": event.get("tool_input") or {}}).encode()
headers = {"Content-Type": "application/json", **({"Authorization": f"Bearer {os.environ['FILIGREE_TOKEN']}"} if os.environ.get("FILIGREE_TOKEN") else {})}
req = urllib.request.Request(f"{os.environ.get('FILIGREE_URL', 'http://127.0.0.1:8000')}/api/check", body, headers)
try:
    with urllib.request.urlopen(req, timeout=20) as r:
        g = json.load(r)
except Exception as e:  # noqa: BLE001
    if os.environ.get("FILIGREE_HOOK_FAIL_OPEN") == "1":
        sys.exit(0)
    sys.stderr.write(f"Filigree unreachable ({e}); MCP call blocked (fail closed).\n")
    sys.exit(2)
if g["allowed"]:
    sys.exit(0)
sys.stderr.write(f"Filigree blocked {tool}: {', '.join(g['reason_codes'])}"
                 + (f" (changed: {', '.join(g['changed_fields'])})" if g.get("changed_fields") else "")
                 + ". A human must review and approve the current definition in Filigree.\n")
sys.exit(2)
