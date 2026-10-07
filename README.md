# Filigree

**What you approve is exactly what the agent sees.** An approval-integrity layer for MCP agent tools: the human-approved
representation, the model-visible representation and the execution-bound representation must be the same object, checked at
every call. Design docs live in [`docs/`](docs/) (PRD, DESIGN, TECH-STACK, REFINEMENTS, PLAN, pitch deck), plus [`REAL-SERVERS`](docs/REAL-SERVERS.md), [`INDEPENDENT-EVAL`](docs/INDEPENDENT-EVAL.md), [`REAL-WORLD-SCAN`](docs/REAL-WORLD-SCAN.md) and the judge [`QA`](docs/QA.md).

## Use it on your own MCP servers (2 minutes)

```bash
uv sync --project backend
uv run --project backend filigree audit --yes        # scans every server in .mcp.json / Claude Desktop config; no tool is called
```

`filigree audit` finds your `.mcp.json` (or `claude_desktop_config.json`, or pass a path), starts each configured server just long
enough to read its `tools/list`, runs the deterministic scanner and prints blocked / review / clean counts with the findings.
Exit code 1 if any tool would be blocked. To enforce approval, put the gate in front of a server:

```bash
uv run --project backend filigree serve                                        # API + gateway on :8000 (UI: npm run dev in frontend/)
uv run --project backend filigree run files -- npx -y @modelcontextprotocol/server-filesystem C:/work   # as a stdio command in claude_desktop_config.json
```

`serve` and `run` must use the same `FILIGREE_DB` file (default `filigree.db` in the working directory), which is how approvals made in the UI reach the stdio gateway. Only tools a human approved in the UI are offered, and every call is re-checked against the approved fingerprint. Works with stdio
servers, HTTP servers and SSE replies; set `FILIGREE_TOKENS="alice:tok"` so only approvers can approve and the audit names them.
Verified end to end on the official filesystem server with the official MCP SDK client (`scripts/real_gateway_check.py`, 7/7).
Full guide and limits: [`docs/REAL-SERVERS.md`](docs/REAL-SERVERS.md).

## Run the demo (one command, fully offline)

```bash
powershell -File scripts/demo.ps1     # Windows
sh scripts/demo.sh                     # macOS / Linux; then open http://127.0.0.1:5173
```

Starts fixture MCP servers (:9000, mock exfil sink included), the backend (:8000, `FILIGREE_DEMO=1`) and the UI (:5173).
Analysis runs in **REPLAY MODE** so the demo works offline. `fixtures/replay_cache.json` holds **real model output recorded on 2026-10-06** (Groq `openai/gpt-oss-120b`, one call per demo tool; the nav badge names the source). Re-record with `uv run --project backend python scripts/seed_fixtures.py --live` (needs a key in `.env`); without `--live` the script writes authored text and the badge says so. `run_demo.py` never overwrites an existing cache.
Live analysis works with Anthropic, Groq or Gemini (also any OpenAI-compatible API): put one key in `.env` (gitignored; see `.env.example`), the provider is auto-detected from the key prefix, or set `ANALYZER_PROVIDER` / `ANALYZER_MODEL`. `ANALYZER=live` switches the demo to it.

Demo script (Demo page): connect *Invisible-text* → **Run WITHOUT Filigree** (ATTACK SUCCEEDED) → **Run WITH Filigree**
(APPROVAL BLOCKED) → Tools page shows the identical-looking human view vs. the decoded hidden instruction. Connect *Benign* and
*Rug pull*, approve `fetch_report`, hit **Trigger rug pull**, then **Call via gate** → `MANIFEST_DRIFT`, field diff on the Diff tab.
The Playground lets a judge add a zero-width character to an approved description and watch the approval go stale.
The agent scenes have an **Agent** selector: *Scripted agent* (deterministic stand-in) or *Real model*. Real model hands a tool-calling LLM the tools and a harmless task ("find the Q3 planning notes") plus a simulated `read_file`; unprotected it sees the raw tools, with Filigree it only sees tools with a valid approval. Runs recorded in `fixtures/agent_replay.json` (with k/N counts per model) are replayed offline; with `ANALYZER=live` and a key it runs the model now. Re-record with `uv run --project backend python scripts/record_agent.py 10 <model> ...`.
The Demo page also has **Run gateway session**: a full MCP session over `/mcp/srv-rugpull` as raw JSON-RPC (list, human approval, call, rug pull, blocked call), the same messages a real client sends.

## Beyond approval: what flows through an approved tool

Approval decides *which* tools the model gets. Three runtime checks cover what approval cannot see:

- **Data-flow taint** (`TAINTED_ARGS`): a secret that came back from a tool, or from the reference agent's file read, may not
  flow into a later call's arguments. This holds even for an approved tool with a clean definition. The match is a
  verbatim substring, so a secret the model re-encodes (base64, split) gets through. `backend/app/gate/runtime.py`.
- **Result firewall** (`RESULT_INJECTION`): a tool *result* carrying model-directed instructions is withheld from the
  model and audited. It is a heuristic on the scanner's imperative, concealment and analyzer patterns. File paths alone
  are not flagged.
- **Cloaking probe** (`CLOAKING_SUSPECTED`): at discovery and before every call, Filigree asks again as a different client.
  A definition that changes with who is asking cannot be approved. It catches cheap cloaking keyed on client identity, not
  a server that cloaks by IP or timing.

Demo scenes: *Result injection* (`find_files` is caught by the firewall; `fetch_notes` is subtle, passes the firewall, and
taint stops the exfil call) and *Cloaking*.

## Pin it: `filigree.lock`

**Download filigree.lock** (Audit page, or `GET /api/lock`) pins every approved tool: its endpoint, fingerprint and
canonical manifest, like a package lockfile. Commit it. Then CI can check that the servers still serve exactly the
approved definitions, without a Filigree backend:

```bash
uv run --project backend python scripts/filigree_verify.py filigree.lock   # exit 1 + field diff on drift
```

```yaml
# .github/workflows/mcp-lock.yml
- run: uv run --project backend python scripts/filigree_verify.py filigree.lock
```

## Claude Code hook: no gateway URL swap needed

`scripts/claude_hook.py` is a PreToolUse hook. Every `mcp__*` call is checked by Filigree (`/api/check`, the full gate
without the call) and blocked with the reason code if the tool is unapproved, drifted, cloaked or carrying tainted args.
It fails closed if the backend is down. The Claude Code server name must equal the Filigree server id (or set
`FILIGREE_MAP="name=srv-id"`). In `.claude/settings.json` (use an absolute script path from other projects):

```json
{ "hooks": { "PreToolUse": [ { "matcher": "mcp__.*",
  "hooks": [ { "type": "command", "command": "python scripts/claude_hook.py" } ] } ] } }
```

Limit: the hook checks the definition Filigree fetches. The text Claude Code already showed its model is not visible
to it; the cloaking probe narrows that gap.

## Red-team arena

In the Playground, **Red-team arena: try it on a real model** hands your description to a tool-calling model (needs an
OpenAI-compatible key in `.env`; one live call per attempt) and scores it: model fooled or not, scanner caught it or not.
"Model fooled and scanner missed" is shown as a win for the attacker. Attempts are audited (`ARENA_ATTEMPT`).

## Use it as a real MCP gateway

Each connected server is also exposed at `http://127.0.0.1:8000/mcp/<server_id>` (JSON-RPC over HTTP). `tools/list` returns only
tools whose approval is currently valid (built from the canonical approved manifest); `tools/call` goes through the gate and returns
`isError` with the reason code when blocked. Tests: `test_mcp_proxy_end_to_end`, and `scripts/sdk_client_check.py` drives it with the official MCP Python SDK client (list, call, rug pull, blocked call; also run in CI): `uv run --project backend --with "mcp>=2" python scripts/sdk_client_check.py`. The server id is shown on the Tools page.

HTTP clients (Claude Code, Cursor):

```bash
claude mcp add --transport http filigree http://127.0.0.1:8000/mcp/<server_id>
```

stdio-only clients (Claude Desktop) use the stdlib bridge `scripts/stdio_bridge.py`. In `claude_desktop_config.json`:

```json
{ "mcpServers": { "filigree": { "command": "python",
  "args": ["C:/path/to/hacksprint/scripts/stdio_bridge.py", "<server_id>"] } } }
```

## Tests and evaluation

```bash
cd backend && uv run pytest                                   # 75 tests: manifest, scanner, policy, gate, rug pull, failure drills, real-model agent, taint, result firewall, cloaking, lock, hook check, arena, stdio/SSE upstreams, CLI, tokens
python fixtures/evaluation/build_sets.py                      # (re)generate frozen sets; do not tune after freezing
uv run --project backend python scripts/evaluate.py           # writes fixtures/evaluation/results.json
```

Measured. The table below is scanner only. **Live LLM run** (Groq `openai/gpt-oss-120b`, 47 v1 samples, 0 failed calls, p50 5.9 s / p95 8.6 s): LLM-only 100% blocked and 100% flagged, 100% benign accepted; combined with the scanner the same. These are the team's own samples and the model was shown the scanner findings in its prompt, so read them as an upper bound; On the unseen v3 set (22 samples, run once, 0 failed calls) LLM-only and combined both reached 100% blocked / 100% flagged, but accepted only 80% of benign tools (false positives: `read_config` with a `path` parameter and the "Silently queue notifications" decoy), versus 90% for the scanner alone. Rules were changed once,
after seeing the v1 misses, so each set means something different:

| Set | Status for current rules | Poisoned blocked / flagged | Benign accepted |
|---|---|---|---|
| v1 (authored + public + evasive, 32+15) before tuning | unbiased | 62.5% / 75.0% | 86.7% |
| v1 after tuning | **in-sample** (rules written from its misses) | 78.1% / 90.6% | 100% |
| v2 (20+20) before tuning | unbiased | 45.0% / 50.0% | 65.0% |
| v2 after tuning | **in-sample** (tuned after seeing v2 misses) | 95.0% / 100% | 100% |
| v3 (12+10), run once, not tuned | was unseen; **seen** for the "silently" rule since 2026-10-07 | 58.3% / 83.3% (unchanged by the 2026-10-07 rules) | 90.0% (false positive: "Silently queue notifications") |
| **v4 (12+12), written and frozen before the 2026-10-07 rule change** | **unseen** (baseline, old rules) | **66.7% / 75.0%** | 66.7%; **25% of benign tools blocked** (3: "succeeds silently" style). After the change: same recall, **0% blocked**, in-sample now |
| **MCPTox, independent** (485 real poisoned tool descriptions, 362 clean) | **independent, scanner only, run once** | **14.8% blocked**, 77.5% flagged beyond cross-tool refs (99.2% counting that medium rule) | 86.5%; 1.4% blocked, 12.2% review. See [`docs/INDEPENDENT-EVAL.md`](docs/INDEPENDENT-EVAL.md) |
| 52 real tools from 7 official servers (assumed benign) | in-sample for the two 2026-10-07 fixes | n/a | 71.2% -> **96.2%**; blocked 1.9% -> 0% |

Read the unseen and independent rows as the honest numbers. On team-authored samples roughly 6 to 7 in 10 poisoned tools are
blocked outright; on MCPTox, written by other people to look like ordinary tool text, the scanner alone blocks about 1 in 7, and
the model stage plus human review carry the rest (the LLM-sample result is in `docs/INDEPENDENT-EVAL.md`). Rug-pull drift detection is 100% (5/5) with 0/15 false drift; scanner latency p50 0.08 ms. Raw files:
`fixtures/evaluation/results*.json` (`results_v1_pretuning.json` keeps the original numbers). The 12 "public" samples are
**illustrative**: modeled on published attack classes, not quoted from them (checked 2026-10-06, see `fixtures/evaluation/SOURCES.md`; one cited link is dead).

Real-world check: the scanner was run on 52 tool definitions from 7 official MCP servers ([`docs/REAL-WORLD-SCAN.md`](docs/REAL-WORLD-SCAN.md)). None are poisoned. The first run raised one **blocking false positive** ("succeed silently" in `create_directory`) and 14 review-level ones and exposed a `$schema` bug; both were fixed, the fixes were measured on a new frozen set written first (v4), and the 52 tools are now a frozen false-positive regression set (`fixtures/evaluation/real_benign.json`).

Remaining known misses: paraphrases without a known path or verb ("private configuration directory"), cross-field references,
"keychain"-style paths on other OSes, non-English concealment. Those are for the advisory LLM stage and human review.

## Architecture in one paragraph

`capture` (raw JSON-RPC over HTTP with JSON or SSE replies, or over stdio; no SDK normalization) → `manifest` (canonical JSON, strings verbatim, SHA-256 over server id +
server instructions + tool definition) → `scanner` (deterministic, cannot be downgraded) → `analyzer` (advisory, tool text framed as
untrusted data, schema-validated, failure = REVIEW) → `policy` → human approval → `gate` (re-fetches `tools/list` and re-hashes
before **every** `tools/call`; any capture/DB failure blocks). Audit events form a hash chain: the Audit page can verify it, export it as JSON, and (in demo mode) tamper with one row to show the break and which event it is. The reference agent registry is
built only from the canonical manifest of currently-valid approvals.

## Not protected (state this plainly)

Anyone who can reach the port when `FILIGREE_TOKENS` is not set (the local demo is open; tokens are shared secrets, no TLS, reads stay open) · resources and prompts (the gateway proxies tools only) · image/resource tool results (not inspected) · server-initiated messages · a stdio server that cloaks after the one probe at discovery · detection of MCPTox-style poisonings by the scanner alone (14.8% blocked) · malicious server behavior with an unchanged definition (partially: taint blocks known secrets flowing into it) · instructions
inside tool *results* (partially: heuristic result firewall) · secrets the model re-encodes before sending · clients that
bypass both the gateway and the hook · a server that cloaks by IP or timing rather than client identity · the race between
the gate's re-fetch and the call · subtle semantic injections the scanner misses and the analyzer also misses.
