# Real-world scan: official MCP servers

Date: 2026-10-06; re-scanned 2026-10-07 after two rule fixes (see the last section). The tables below are the **first scan, 2026-10-06**. Script: `scripts/scan_real.py` (raw data: `fixtures/real_world_scan.json`). It spawns each server over stdio, runs `initialize` and `tools/list`, fingerprints every tool and runs the **deterministic scanner only** (no LLM). No tool was called. Servers ran in a temp directory with key/token variables stripped from their environment. Versions are whatever `npx -y` / `uvx` resolved that day (not pinned), so re-running later can differ.

Targets: the official reference servers `@modelcontextprotocol/server-filesystem`, `-memory`, `-sequential-thinking`, `-everything`, and `mcp-server-git`, `-fetch`, `-time`. Servers needing credentials (GitHub, Brave, Slack) were not scanned.

## Result
52 tools, 7 servers. **15 tools flagged, none poisoned.** Every flag is a false positive or a style the scanner treats as review-worthy. We read all of them.

| Finding | Count | Verdict |
|---|---|---|
| `cross_tool_instruction` (medium), `server-everything` | 48 findings on 13 tools | False positive. The server's `instructions` text documents its own tools by name, and the rule runs on that text for every tool. A medium means "review", not "blocked". |
| `cross_tool_instruction` (medium), `filesystem/read_file` | 1 | A description pointing at `read_text_file`. Legitimate guidance; the rule cannot tell guidance from an injected cross-tool instruction. |
| `concealment_instruction` (**high**), `filesystem/create_directory` | 1 | **False positive that blocks approval.** The description says the operation "will succeed silently", and the concealment rule matches the word "silently". High findings cannot be approved. |
| `external_exfiltration` (low), `everything/gzip-file-as-resource` | 1 | A default value pointing at a raw GitHub URL. Low, does not gate. |

## What this told us
- **The scanner found a real bug here, and we fixed it.** The first run flagged 37 of 52 tools because every JSON Schema `$schema` URI (`http://json-schema.org/...`) was read as an exfiltration destination. Metadata keys `$schema` and `$id` are now skipped. We compared scanner output before and after on all 109 frozen evaluation samples: **0 differ**, so no frozen number changed. Test: `test_schema_metadata_uri_is_not_flagged`.
- **We did not fix the "silently" false positive on 2026-10-06.** Narrowing it then would have been tuning against the frozen unseen set. It was fixed the next day with a fresh frozen set written first (see below).

## Limits
7 servers is a small sample, and the official reference servers are the ones most likely to be clean. This is a false-positive check on real definitions, not a measure of detection. Scanner only: the LLM analyzer was not run on these tools. Do not cite this as "Filigree found nothing malicious"; cite it as "on 52 real tool definitions the scanner raised one blocking false positive and 14 review-level ones".

## Re-scan after the rule fixes (2026-10-07)
Two rule changes came out of this scan, made in this order so the effect could be measured honestly:
1. A new frozen set `v4` (12 poisoned + 12 benign, `fixtures/evaluation/build_sets_v4.py`, includes benign "succeeds silently / quietly"
   phrasings and poisoned "silently send X" ones) was written and hashed **before** touching the rules, and run once on the old rules
   (`results_v4_baseline.json`): 66.7% of poisoned blocked, 75.0% flagged, 66.7% of benign accepted, **25% of benign blocked** (3 of 12).
2. Then the rules changed: a bare "silently"/"quietly" is a *medium* (review) finding and is *high* (blocking) only when a data-movement
   verb (send, forward, upload, ...) or a sensitive path is in the same text; and `cross_tool_instruction` is no longer raised on
   the server's `instructions` text (a server naming its own tools). Everything else in the scanner is unchanged, and instruction text
   is still scanned for invisible characters, concealment, imperatives, paths and URLs, so poisoned instructions still block every tool.
3. Result on v4 with the new rules (`results_v4_after_rules.json`): same recall (66.7% blocked, 75.0% flagged), **0% of benign blocked**.
   The three previously blocked benign samples now need review (benign "accepted" stays 66.7% because review is not acceptance).
   v4 is in-sample for this rule from now on. On v2 and v3 nothing changed (`results_v2_after_v4_rules.json`, `results_v3_after_v4_rules.json`);
   v3 is no longer unseen for the "silently" rule, because it contained that weakness and we have now fixed it.

The 52 definitions were captured again with the new stdio client (`scripts/scan_real.py --freeze`) and frozen as
`fixtures/evaluation/real_benign.json` (hash in `FROZEN_real_benign.sha256`, checked by `test_frozen_evaluation_sets_unchanged`). They
are **assumed benign** (official servers, scanner output read, not audited line by line). Same definitions, old vs new rules
(`scripts/evaluate_real.py real_benign.json ...`):

| | Benign accepted | Review | Blocked |
|---|---|---|---|
| old rules (`results_real_benign_before_rules.json`) | 71.2% (37/52) | 26.9% (14) | 1.9% (1: `create_directory`) |
| new rules (`results_real_benign_after_rules.json`) | **96.2%** (50/52) | 3.8% (`read_file`, `create_directory`) | **0%** |

Caution: the two fixes were derived from these very tools, so this improvement is **in-sample**. The blind number is the v4 baseline
above. The remaining findings are two review-level ones (`read_file`, `create_directory`) and one low (`gzip-file-as-resource` default URL), described in the table above.
