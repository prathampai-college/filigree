# Filigree

**What you approve is exactly what the agent sees.** An approval-integrity layer for MCP agent tools: the human-approved
representation, the model-visible representation and the execution-bound representation must be the same object, checked at
every call. Design docs live in [`docs/`](docs/) (PRD, DESIGN, TECH-STACK, REFINEMENTS, PLAN, pitch deck).

## Run the demo (one command, fully offline)

```bash
powershell -File scripts/demo.ps1     # Windows
sh scripts/demo.sh                     # macOS / Linux; then open http://127.0.0.1:5173
```

Starts fixture MCP servers (:9000, mock exfil sink included), the backend (:8000, `FILIGREE_DEMO=1`) and the UI (:5173).
Analysis runs in **REPLAY MODE** (authored cache in `fixtures/replay_cache.json`, regenerate with `scripts/seed_fixtures.py`).
Live analysis works with Anthropic, Groq or Gemini (also any OpenAI-compatible API): put one key in `.env` (gitignored; see `.env.example`), the provider is auto-detected from the key prefix, or set `ANALYZER_PROVIDER` / `ANALYZER_MODEL`. `ANALYZER=live` switches the demo to it.

Demo script (Demo page): connect *Invisible-text* → **Run WITHOUT Filigree** (ATTACK SUCCEEDED) → **Run WITH Filigree**
(APPROVAL BLOCKED) → Tools page shows the identical-looking human view vs. the decoded hidden instruction. Connect *Benign* and
*Rug pull*, approve `fetch_report`, hit **Trigger rug pull**, then **Call via gate** → `MANIFEST_DRIFT`, field diff on the Diff tab.
The Playground lets a judge add a zero-width character to an approved description and watch the approval go stale.

## Use it as a real MCP gateway

Each connected server is also exposed at `http://127.0.0.1:8000/mcp/<server_id>` (JSON-RPC over HTTP). `tools/list` returns only
tools whose approval is currently valid (built from the canonical approved manifest); `tools/call` goes through the gate and returns
`isError` with the reason code when blocked. Test: `test_mcp_proxy_end_to_end`. The server id is shown on the Tools page.

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
cd backend && uv run pytest                                   # 49 tests: manifest, scanner, policy, gate, rug pull, failure drills
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
| **v3 (12+10), run once, not tuned** | **unseen** | **58.3% / 83.3%** | **90.0%** (false positive: "Silently queue notifications") |

Read v3 as the honest number: roughly 6 in 10 poisoned tools blocked outright and 8 in 10 flagged for review, on team-authored
samples. Rug-pull drift detection is 100% (5/5) with 0/15 false drift; scanner latency p50 0.08 ms. Raw files:
`fixtures/evaluation/results*.json` (`results_v1_pretuning.json` keeps the original numbers). Public-sample texts are
**paraphrased** and their URLs are from memory (`source_verified: false`): verify before quoting.

Remaining known misses: paraphrases without a known path or verb ("private configuration directory"), cross-field references,
"keychain"-style paths on other OSes, non-English concealment. Those are for the advisory LLM stage and human review.

## Architecture in one paragraph

`capture` (raw JSON-RPC over HTTP, no SDK normalization) → `manifest` (canonical JSON, strings verbatim, SHA-256 over server id +
server instructions + tool definition) → `scanner` (deterministic, cannot be downgraded) → `analyzer` (advisory, tool text framed as
untrusted data, schema-validated, failure = REVIEW) → `policy` → human approval → `gate` (re-fetches `tools/list` and re-hashes
before **every** `tools/call`; any capture/DB failure blocks). Audit events form a hash chain: the Audit page can verify it, export it as JSON, and (in demo mode) tamper with one row to show the break and which event it is. The reference agent registry is
built only from the canonical manifest of currently-valid approvals.

## Not protected (state this plainly)

Malicious server behavior with an unchanged definition · instructions inside tool *results* · clients that bypass the gate · a
server that cloaks (serves different definitions to different clients) · the race between the gate's re-fetch and the call ·
subtle semantic injections the scanner misses and the analyzer also misses.
