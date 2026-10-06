# Real-world scan: official MCP servers

Date: 2026-10-06. Script: `scripts/scan_real.py` (raw data: `fixtures/real_world_scan.json`). It spawns each server over stdio, runs `initialize` and `tools/list`, fingerprints every tool and runs the **deterministic scanner only** (no LLM). No tool was called. Servers ran in a temp directory with key/token variables stripped from their environment. Versions are whatever `npx -y` / `uvx` resolved that day (not pinned), so re-running later can differ.

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
- **We did not fix the "silently" false positive.** Narrowing it would be tuning against the frozen unseen set, which already contains the same weakness (the "Silently queue notifications" benign sample). It is reported as a known limit, with the cost stated: on today's rules a user cannot approve the official `create_directory` tool.
- Cross-tool instruction on `server_instructions` needs a smarter rule (flag instructions that address tools in *other* servers), not a looser one.

## Limits
7 servers is a small sample, and the official reference servers are the ones most likely to be clean. This is a false-positive check on real definitions, not a measure of detection. Scanner only: the LLM analyzer was not run on these tools. Do not cite this as "Filigree found nothing malicious"; cite it as "on 52 real tool definitions the scanner raised one blocking false positive and 14 review-level ones".
