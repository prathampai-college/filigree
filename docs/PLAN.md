# Filigree — Phase-wise Implementation Plan

## Context
Project: 24h hackathon prototype (HackSprint, track T.03, team recurSON) — an **Approval Integrity** layer for MCP agent tools. Human-approved = model-visible = execution-bound, enforced by a canonical manifest + SHA-256 fingerprint + deterministic scanner (+ advisory LLM) + call-time gate that re-fetches `tools/list` before every `tools/call`.
The repo currently holds only docs (no code, not a git repo): `PRD.md`, `DESIGN.md`, `TECH-STACK.md`, `Filigree.pdf`, `Filigree.pptx`. The docs are strong and internally consistent (Freeze List D-01…D-15). This plan sequences the build and amends the docs where they have gaps.

## Step 0 (first action after approval): reorganize
1. Create `docs/` and move all five existing files into it (PRD.md, DESIGN.md, TECH-STACK.md, Filigree.pdf, Filigree.pptx).
2. **Rename before any other work:** in the three .md docs replace every `TrustLens` → `Filigree`, `trustlens` → `filigree`, `TRUSTLENS` → `FILIGREE` (incl. titles, taglines, the repo tree `trustlens/`). Verify with a case-insensitive grep that zero occurrences remain. The .pdf/.pptx already say Filigree (binary, untouched).
3. Repo root = `hacksprint/` itself (backend/, frontend/, fixtures/, scripts/ as siblings of docs/ — no extra nested `filigree/` dir). Add `docs/REFINEMENTS.md` (amendments below) and `docs/PLAN.md` (this plan). Original docs otherwise keep their text; amendments get new IDs D-16+ that supersede where they conflict.

## Refinements to the docs (what's missing / questionable)
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

## Phases (maps to the PRD 24h plan; each ends with a runnable exit check)

### Phase 0 — Setup & contracts (h0–1)
- Move docs; init git; `uv` project (`backend/pyproject.toml`, pinned), Vite React-TS app (`frontend/`), `Makefile` stubs (`demo`, `test`, `replay-cache`).
- Write `ToolTrustView` Pydantic models + TS types and 5 mock JSON views (benign trusted, invisible-poison blocked, rug-pull stale, review, shadow) in `frontend/src/fixtures/`.
- **Exit:** `pytest` runs (empty), `npm run dev` serves, contract files committed.

### Phase 1 — Security core, no I/O (h1–4, backend dev) ‖ Frontend shell (h1–4, frontend dev)
- `backend/app/manifest/`: `canonicalize.py`, `fingerprint.py`, `diff.py`, `display.py` (`escape_for_display`, `human_rendering`). Includes D-17/D-21.
- `backend/app/scanner/`: rule families per TECH-STACK §10.1 + D-18/19/20.
- `backend/app/policy/`: priority-ordered evaluator (integrity > authz > high > medium > clean), D-25.
- Unit tests first (TECH-STACK §16.1): zero-width char → new hash + finding; key-order → same hash; same tool on other server → different hash; ordinary Unicode no false positive; LLM can't clear scanner finding.
- Frontend: AppShell, TopBar+ModeBadge, ToolTable, ToolStatusBadge, ApprovalCard (Human/Model panels, HiddenCharMarker, FindingCard) against mock JSON.
- **Exit:** core test suite green; approval card renders fixture F with decoded hidden text from mock JSON.

### Phase 2 — Capture spike & fixture servers (h2–4, security dev, parallel)
- `fixtures/servers/`: benign (A), poisoned (B,C), invisible (F — generate tag-char payload programmatically, verify it renders identical to A), rug_pull (D,E, mutate via control endpoint), shadow (G); `scenarios.json` incl. H.
- `backend/app/mcp/`: capture client (`list_tools`, `call_tool`, `initialize`), 60-min cap per D-26.
- **Exit:** script prints canonical manifest + fingerprint for each fixture; F's description == A's when rendered by `human_rendering`.

### Phase 3 — Vertical slice (h4–8)
- SQLite storage (servers, manifests, analyses, approvals, audit) behind a small interface.
- FastAPI: `/api/servers`, `/tools`, `/tools/{id}/view`, `/approve`, `/deny`, `/recheck`, `/api/agent/call`.
- `gate/`: re-fetch → rebuild manifest → compare → policy → forward or block with reason code. Single execution path; reference agent registry built from canonical bytes.
- Frontend swaps mock JSON for real API; Dashboard + Tool Detail + approve/block buttons obeying DESIGN §5 button rules.
- **Exit (golden path A, B, F):** benign → approve → call succeeds; invisible fixture → scanner high → Approve not rendered; call blocked `NO_APPROVAL`.

### Phase 4 — Analyzer, replay, audit (h8–12)
- `analyzer/`: `SemanticAnalyzer` protocol, `MockAnalyzer`, `ReplayAnalyzer` (D-22), one live provider adapter with structured output; injection-hardened prompt (TECH-STACK §10.3); schema validation failure → REVIEW; additive merge only.
- `make replay-cache` pre-populates all fixtures. Mode stored per analysis; ModeBadge always visible.
- Audit events + hash chain (single writer, transactional) + `/api/audit`; AuditTimeline + "chain verified".
- **Exit:** fixture H still blocked by scanner when LLM says "no findings"; analyzer-down → REVIEW banner; offline demo works from cache.

### Phase 5 — Rug pull & shadowing (h10–15)
- Call-time drift: `MANIFEST_DRIFT`, mark stale, field-level diff incl. invisible-char entries; `DiffViewer`, "APPROVAL INVALID" banner (+/− gutters, no color-only), "Review new version" (no override; BLOCKED terminal per fingerprint).
- Fixtures D, E (display-only change → same hash), G (collision → separate fingerprint, no inherited approval).
- **Exit:** integration test `connect→discover→analyze→approve→call→mutate→call→block` green; diff shows exact changed fields.

### Phase 6 — Demo orchestration & Playground (h14–18)
- Scripted agent (honestly labeled) + mock exfil endpoint (:9100); `/demo` page: Scene 1 (attack succeeds without Filigree), Scene 2 (blocked), Scene 3 (rug pull), Scene 4 (audit). `/api/demo/*` gated by D-23.
- Playground (P1): edit text → live fingerprint/findings/stale. `make demo` one-command start.
- **Cut line at h14:** drop Playground, eval page UI, animations; keep Scenes 1–3 + audit.
- **Exit:** full 90-second script runs 3× in a row from `make demo` cold start.

### Phase 7 — Evaluation (h17–20)
- `fixtures/evaluation/{authored,public_heldout,evasive}` (D-27), `scripts/evaluate.py` → scanner-only / LLM-only / combined: recall, benign acceptance, FPR, p50/p95 latency, named false negatives; drift recall; canonicalization false-drift test. Frozen before tuning.
- `/api/metrics` + Evaluation page (P1). Only measured numbers go in slides.
- **Exit:** results JSON committed; numbers drop into deck.

### Phase 8 — Pitch & hardening (h20–24)
- Update deck with measured metrics + screenshots A/B/C; Q&A sheet rehearsal (PRD §22); backup screen recording; README with run steps and limits; dry runs incl. analyzer-offline and DB-down failure modes; freeze dependencies.
- Usability walkthrough with a teammate (DESIGN §26).
- **Exit:** cold-start dry run + backup video done.

## Critical files (to be created)
`backend/app/manifest/{canonicalize,fingerprint,diff,display}.py`, `backend/app/scanner/rules.py`, `backend/app/policy/evaluate.py`, `backend/app/gate/gate.py`, `backend/app/analyzer/*`, `backend/app/storage/*`, `backend/app/audit/chain.py`, `backend/app/api/*`, `fixtures/servers/*`, `frontend/src/components/{ApprovalCard,DiffViewer,AuditTimeline,HiddenCharMarker}.tsx`, `scripts/{run_demo,evaluate,seed_fixtures}.py`, `Makefile`.

## Verification
- `make test` — unit (manifest/scanner/policy/diff) + integration (gate, rug pull, fixture H) + golden path.
- `make demo` cold start, then walk Scenes 1–3 and the Playground in the browser; confirm: F identical to A on the left panel, decoded text on the right, Approve button absent, rug-pull call blocked with diff, audit chain verified.
- Failure drills: kill analyzer, kill DB, kill fixture server — each must block or show REVIEW, never allow.
- Eval run reproduces the numbers in the deck.
