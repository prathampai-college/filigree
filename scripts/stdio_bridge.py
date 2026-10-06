"""stdio -> HTTP bridge so stdio-only MCP clients (Claude Desktop) can use the Filigree gateway.

Usage: python scripts/stdio_bridge.py <server_id> [gateway_base]   (stdlib only, no install needed)
"""
import json
import sys
import urllib.request

sid = sys.argv[1]
url = f"{sys.argv[2] if len(sys.argv) > 2 else 'http://127.0.0.1:8000'}/mcp/{sid}"

for line in sys.stdin:
    if not line.strip():
        continue
    msg = json.loads(line)
    req = urllib.request.Request(url, line.encode(), {"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            body = r.read()
    except Exception as e:  # gateway down: answer requests with an error rather than hang the client
        if "id" not in msg:
            continue
        body = json.dumps({"jsonrpc": "2.0", "id": msg["id"],
                           "error": {"code": -32000, "message": f"Filigree gateway unreachable: {e}"}}).encode()
    if body:  # notifications get 202 with no body
        sys.stdout.write(body.decode() + "\n")
        sys.stdout.flush()
