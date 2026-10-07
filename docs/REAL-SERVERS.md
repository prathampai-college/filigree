# Using Filigree with real MCP servers

Until 2026-10-07 Filigree only protected its own fixture servers: the upstream client spoke plain JSON-RPC over HTTP, and the
servers people actually run (all seven official reference servers we scanned) are stdio. This page documents what changed, how to
use it, and what is still not covered. Every claim here is backed by a test or a script listed under each section.

## What works now

| Upstream | How it is reached | Code | Tests |
|---|---|---|---|
| HTTP, plain JSON replies | as before | `backend/app/mcp/client.py` | `test_integration.py` |
| HTTP, `text/event-stream` (SSE) replies | the event answering our request id is picked out of the stream; no match = capture failure (fail closed) | `client.py::_sse_message` | `test_upstream.py::test_sse_*` |
| HTTP session (`Mcp-Session-Id`, `MCP-Protocol-Version`) | taken from `initialize`, sent on every later request of the same client | `client.py` | `test_sse_reply_and_session_id_are_handled` |
| stdio (a command we spawn) | one persistent child process per (command, client identity), newline-delimited JSON-RPC, restarted if it dies | `backend/app/mcp/stdio.py` | `test_upstream.py`, `test_cli.py` |

Details that matter:
- **One client per gated call.** `gate_call` captures and calls through the same client object, so a server that needs an
  initialized session gets one. Before this fix the call went out on a fresh client.
- **Full results pass through.** The gateway returns the server's whole `tools/call` result (`content`, `structuredContent`,
  `isError`), not just text. This was found by running the official filesystem server behind the gateway: the MCP SDK client
  rejects a result without `structuredContent` when the tool declares an `outputSchema`. The taint tracker and the result
  firewall still inspect all of it (`client.result_text` joins text blocks and the JSON of `structuredContent`). A result the
  firewall withholds is replaced by a short text, never passed on.
- **stdio environment.** The child gets the caller's environment minus names containing KEY, TOKEN, SECRET or PASSWORD, plus the
  entry's own `env`. `filigree audit` uses a stricter mode (`clean_env`): only PATH, home/temp directories and locale variables.
- **Cloaking probe on stdio runs once per endpoint**, at discovery (a second process per call would be too slow); HTTP servers are
  still probed before every call. A stdio server that cloaks later is not caught.

## The `filigree` command

Installed by `uv sync --project backend` (entry point `filigree` -> `app.cli:main`; the top-level Python package is still called
`app`, rename before publishing to PyPI).

```bash
uv run --project backend filigree audit [config] [--yes] [--json]
uv run --project backend filigree run <id> -- <command...>
uv run --project backend filigree verify [filigree.lock]
uv run --project backend filigree serve [--port 8000]
```

### `filigree audit`
Reads `.mcp.json` (project), or Claude Desktop's `claude_desktop_config.json`, or a path you pass. Handles `mcpServers` (and VS
Code's `servers`), entries with `command`/`args`/`env` or an http(s) `url`. For each server it runs `initialize` and `tools/list`
and the **deterministic scanner only** (no LLM, no tool is called) and prints blocked / review / clean counts plus every
non-low finding. Exit code 1 if any tool would be blocked or any server could not be audited, 2 for usage errors.
Because auditing starts the commands in your config, it prints them and refuses to run without `--yes`.
Tests: `backend/tests/test_cli.py` (refuses without `--yes`, clean server exits 0, poisoned exits 1, unstartable server reported as
`NOT AUDITED`). Run on the official filesystem, memory and time servers it reported 25 tools, 0 blocked, 2 review (the same two
review-level false positives listed in `docs/REAL-WORLD-SCAN.md`).

### `filigree run <id> -- <command...>`
A stdio gateway in front of one server, for stdio-only clients such as Claude Desktop. Example `claude_desktop_config.json`:

```json
{ "mcpServers": { "files": { "command": "filigree",
  "args": ["run", "files", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "C:/work"],
  "env": { "FILIGREE_DB": "C:/filigree/filigree.db" } } } }
```

On start it registers the server and captures its tools into `FILIGREE_DB` (default `filigree.db`). `tools/list` returns only
tools with a currently valid approval; `tools/call` goes through the same gate as the HTTP gateway (`backend/app/mcp/proxy.py::handle`
serves both transports). Approve tools in the UI running on the **same database** (`filigree serve`, or the demo backend with
`FILIGREE_DB` set). Without an analyzer key the replay cache has no analysis for third-party tools, so the UI asks for an explicit
confirmation when approving (status `unavailable`, not a clean bill). Set `ANALYZER=live` and a key in `.env` for real analysis.
Diagnostics go to stderr only; stdout carries nothing but JSON-RPC.

### Connecting a server in the UI
The Tools page has a **Connect and scan** form: a server id, then either an `http(s)` MCP URL or a stdio command (quote arguments that
contain spaces). It calls the endpoint below, so a command only works when the backend runs with `FILIGREE_ALLOW_STDIO=1`; otherwise the
UI shows the 403 message. Checked on 2026-10-07 in the browser against a live `filigree serve`: connecting the stdio echo server
listed its tool as REVIEW REQUIRED (`ANALYSIS_UNAVAILABLE`, because no analyzer key was set), approval made it TRUSTED, an agent
call through the gate returned `echo:hello`, and `/mcp/echo` listed exactly that tool.

### Registering a server through the API
`POST /api/servers` with `{"id", "endpoint"}` (http/https only) or `{"id", "command": [...], "env": {...}}`. **A `command` makes
the backend spawn a process, which is remote code execution if the port is reachable**, so it is refused (403) unless the backend
was started with `FILIGREE_ALLOW_STDIO=1`. Use it on a machine you control, together with `FILIGREE_TOKENS` below.

## Authentication and approver identity
Approval is the security boundary, and until now anyone who could reach port 8000 could approve a tool.

- Start the backend with `FILIGREE_TOKENS="alice:token-a,bob:token-b"`. Every `POST` to `/api/*` and `/mcp/*` then needs
  `Authorization: Bearer <token>` (constant-time comparison), otherwise 401. `GET` requests (reading tools, audit, lock) stay open.
  Unset = open, as in the local demo; the backend prints a warning at start when it is not a demo and no tokens are set.
- The token's owner is stored on the approval (`approvals.approved_by`) and written into the audit event reason (`by bob`). Without
  tokens it reads `by unauthenticated`. Databases created earlier are migrated in place (`ALTER TABLE`).
- Clients: the UI has an "approver token" field in the nav bar (kept in `localStorage`, optional); `scripts/claude_hook.py` and
  `scripts/stdio_bridge.py` send `FILIGREE_TOKEN` when set; `claude mcp add --transport http ... --header "Authorization: Bearer <token>"`.
- Limits: tokens are shared secrets in an environment variable, there is no TLS (put it behind localhost or a reverse proxy), no
  expiry or revocation short of restarting, and `GET /api/*` is readable by anyone who can reach the port.
Tests: `test_integration.py::test_tokens_protect_writes_and_name_the_approver`, `test_old_database_without_approver_column_is_migrated`.

## Secrets in the lockfile and the API
A stdio server entry can carry an `env` block with credentials. Env **values** are never exported: `filigree.lock` and
`GET /api/servers` show `${NAME}` instead, and `filigree verify` reads the value from the verifying machine's environment (an unset
variable becomes an empty string, so a server that needs it will fail to start and be reported as not verified). The command's
**arguments are stored as written**, so do not put secrets in arguments (`--token abc`); pass them through `env`.
Tests: `test_upstream.py::test_secrets_in_a_stdio_env_never_reach_the_lock_or_the_server_list`, `test_lock_and_server_list_redact_stdio_env`.

## Verified end to end on a real server
`scripts/real_gateway_check.py` runs the **official filesystem server** behind `filigree run`, driven by the **official MCP Python
SDK client** over stdio: nothing is offered before approval; after a human approves `read_text_file` and `list_directory` only
those two are listed; an approved read returns the real file content; an unapproved `write_file` is blocked and the file is never
created. Last run 2026-10-07: 7/7 checks passed. It needs `npx` and network the first time, so it is not in CI:

```bash
uv run --project backend --with "mcp>=2" python scripts/real_gateway_check.py
```

Drift on a real server was not exercised (we cannot change the official server's definition); it is covered by
`test_stdio_server_through_the_gate_with_drift` and `test_run_gateway_offers_only_approved_tools_and_blocks_drift` on the stdio
fixture `fixtures/servers/stdio_echo.py`.

## Still not covered
- Streamable-HTTP **server-initiated** messages (a GET stream, notifications such as `tools/list_changed`) are ignored; we answer
  only requests. Resources and prompts are not proxied: the gateway exposes tools only.
- A `tools/call` whose upstream result is an image or resource passes through unchanged and is **not** inspected (only text and
  structured content are).
- stdio servers that ask the client for something (sampling, roots) get no answer.
- No TLS, no token expiry, no per-server permissions between approvers.
