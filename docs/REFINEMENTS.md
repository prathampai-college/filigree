# Filigree — Doc Refinements (supersede PRD/TECH-STACK/DESIGN on conflict)

| ID | Issue | Amendment |
|---|---|---|
| D-16 | **Name split**: docs said TrustLens, submitted deck + repo say Filigree. | Project name is **Filigree** everywhere; all TrustLens mentions removed from docs (Step 0). |
| D-17 | **`initialize.instructions`** (server-level instructions) is model-visible in many hosts but not in the manifest. | Capture it as a server-level manifest object, hash it, scan it. Approval fingerprint = tool def + server instructions hash reference; change → drift. |
| D-18 | **Scanner Unicode coverage too narrow.** Misses variation selectors (U+FE00–FE0F, U+E0100–E01EF), soft hyphen, U+2061–2064, Hangul fillers, any `Cf`/`Co`/`Cn` category chars. | Scan by `unicodedata.category` in {Cf, Co, Cn} + explicit lists; decode tag chars *and* variation-selector byte encodings. Ordinary accents/CJK/emoji (ZWJ inside emoji sequences) must not fire — allowlist ZWJ only between emoji. |
| D-19 | **Name-collision via edit distance alone** misses homoglyphs. | Compare on a confusables "skeleton" (NFKC + casefold + small confusable map) *for comparison only*; never for hashing (D-04 stands). |
| D-20 | **Keyword rules (`token`, `credentials`) false-positive** on benign schemas (pagination `token`). | Sensitive-keyword hits are medium alone; high only with imperative/path context (`read`, `~/`, `.ssh`, `send to`). Benign set must include such decoys. |
| D-21 | **Canonical JSON details unspecified.** | `json.dumps(sort_keys, separators=(',',':'), ensure_ascii=False)`→UTF-8; reject NaN/Infinity, duplicate keys (parse with `object_pairs_hook`), lone surrogates; ints/floats round-trip tested. The agent registry is built by *parsing the canonical bytes* — structurally guarantees representation invariant. |
| D-22 | **Replay cache key** unspecified; Playground edits would always miss. | Key = fingerprint + analyzer prompt version. A miss is shown honestly as `ANALYSIS_UNAVAILABLE` (scanner still runs) — never silently live-call or fake. |
| D-23 | **Local API is unauthenticated**; approve/mutate endpoints are dangerous if exposed. | Bind 127.0.0.1, same-origin/CORS allowlist, `/api/demo/*` and `/api/playground/*` only under `FILIGREE_DEMO=1`. |
| D-24 | **Cloaking** (server shows benign to one client, poison to another) and the list→call TOCTOU race. | Document as limitations (already half-stated); gate uses the *same* MCP session as the agent. Residual race stays on the "not protected" slide. |
| D-25 | **Approval state vocabulary**: user "deny" vs policy "BLOCKED" conflated. | Store `decision ∈ approved|denied`, `policy ∈ allow|review|block` separately; UI trust state derived. |
| D-26 | **SDK risk** (docs cite unverified SDK v2/protocol rev). | Capture spike capped at **60 min**; default to the official SDK v1.x pinned to whatever installs cleanly; else the minimal JSON-RPC client. Fixtures served by FastMCP/plain FastAPI JSON-RPC. |
| D-27 | **Eval honesty**: held-out public samples need real sources; time is tight. | Time-box to ~15 sourced public samples + ~10 evasive; each carries source URL; freeze file hash committed before tuning. |


## Outcomes recorded during the build

| ID | Outcome |
|---|---|
| D-26 (result) | The MCP Python SDK (v2.3.0) installed, but the build uses the **minimal JSON-RPC-over-HTTP client/server** (`backend/app/mcp/client.py`, `fixtures/servers/base.py`): it serves and hashes raw tool dicts byte-for-byte, so no SDK layer can normalize what is hashed, and fixtures stay fully controllable. `mcp` was removed from dependencies. |
| D-28 | Evaluation numbers are produced by `scripts/evaluate.py` only. LLM-only/combined are reported "not run" unless `ANALYZER_API_KEY` is set. Public-sample entries are illustrative (modeled on published attack classes); sources were checked after the fact, see `fixtures/evaluation/SOURCES.md`. |
| D-29 | Fixture rug-pull tool is `fetch_report` (not `search_documents`) so multiple scenarios can coexist on one dashboard without tripping the name-collision rule; the shadow fixture (G) is the one that collides with `search_documents` on purpose. |

### D-30 Scanner v2 and the in-sample caveat
After the v1 misses were known the scanner got: generic `~/.<dir>` and `mcp.json` paths, base64/hex payload decoding, spaced-letter
detection, soft-concealment and analyzer-addressing phrases, email as an exfil action, and fewer false positives (`url`/`path`
parameters whose purpose is evident from the tool; plain https links are low). v2 sets were frozen before the change and then tuned
on, so their post-change numbers are in-sample. v3 was authored after, frozen, and run once: that is the number to quote. Tuning
never changed a frozen file (hash-checked). v1 pre-tuning results are kept in `results_v1_pretuning.json`.

### D-31 MCP gateway
`/mcp/{server_id}` exposes approved tools only and routes calls through the existing gate (no second enforcement path). HTTP only.
