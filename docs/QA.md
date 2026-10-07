# Judge Q&A: honest answers

Every number here comes from `fixtures/evaluation/results*.json` or `fixtures/agent_replay.json`. If a number is not in a file, do not say it.

**Isn't this just hashing the tool description?**
Hashing is the core, but three things sit around it. The hash covers the whole canonical definition (name, description, schema, annotations, server instructions), not only the text. The gate re-fetches `tools/list` and re-hashes before every `tools/call`, so a change after approval is caught at the call. And the human approves exactly the bytes the model will see, with hidden characters made visible. A hash alone would not show the reviewer what the invisible text says.

**What stops a server from showing a clean definition once and a poisoned one later?**
That is the rug pull. The next call re-fetches and finds a different fingerprint: `MANIFEST_DRIFT`, call blocked, field diff shown. Tested end to end, also through the official MCP SDK client (`scripts/sdk_client_check.py`).

**What about a server that shows different definitions to different clients (cloaking)?**
Partly covered. At discovery and before every call, Filigree asks a second time as a different client (`clientInfo` and User-Agent). If the definitions differ, the tool is `CLOAKING_SUSPECTED` and cannot be approved; the reviewer sees what the other client is served. The Cloaking scene shows it. This catches cloaking keyed on client identity, not cloaking by IP address or timing. Behind the gateway the agent only sees the approved canonical bytes anyway.

**What about the race between the re-fetch and the call?**
It exists and is listed under "Not protected". The window is small, but it is not zero.

**How good is detection? Why should we trust the numbers?**
Read the unseen set only. v3 (12 poisoned + 10 benign) was written after the rules were tuned and run once: scanner alone blocked 58.3% and flagged 83.3%, accepted 90% of benign tools. Scanner plus LLM caught 100% of poisoned but accepted only 80% of benign, with two named false positives. Earlier sets are labeled in-sample because we tuned on them. Those sets are team-authored. The independent figure is on MCPTox (485 real poisoned tool descriptions + 362 clean ones, `docs/INDEPENDENT-EVAL.md`): the first run of the scanner **blocked 14.8%** (and flagged 77.5% for a reason beyond naming a sibling tool). We then added one rule for tools that steer how another tool is called, built on half of MCPTox's servers; on the other half, scored once, it **blocks 73.0%** (11.0% before the rule) and still blocks only 1.4% of clean tools. Quote the held-out 73.0% with the 14.8% first-run number, not our own sets, when asked how well it detects; the remaining 27% is why the model stage and human review exist. With the live LLM on a 40+20 sample of the held-out half, blocked rose from 70.0% to 87.5% at the cost of one clean tool blocked (1 of 20); small N, so indicative only. The 12 "public" samples are modeled on published attack classes, not quoted (see `fixtures/evaluation/SOURCES.md`).

**The LLM saw the scanner's findings. Isn't that circular?**
Yes, partly. The model gets the scanner output in its prompt, as in the product, so its numbers are not independent of the scanner. That is why the scanner decides on its own whether something is blocked, and the LLM is advisory: it can raise a flag but never downgrade a scanner finding.

**Can the analyzer itself be prompt-injected?**
The tool text goes in as untrusted data inside random-id tags, and text that addresses the analyzer is itself treated as a finding. That reduces the risk but does not remove it. The scanner and the human step do not depend on the model.

**Do real models actually fall for tool poisoning?**
Some do, some of the time. We recorded 10 runs per model with no Filigree (same task for every run, temperature 0.7, nothing tuned) on Groq-hosted models. Visible poison in the description: gpt-oss-120b leaked the (fake) secret in 6 of 10 runs, qwen3.8-27b in 5 of 10, gpt-oss-20b in 0 of 10. The benign control leaked 0 of 30. The invisible-text variant leaked 0 of 30: these models did not act on the hidden Unicode tags, so do not claim a model obeyed invisible text. The invisible case is still a hole for the human reviewer, who cannot see it either, and a model that decodes tags would obey it. Point: one leak is enough, and with Filigree the unapproved tool is never offered, whatever the model does. New scenes, 5 runs per case, same task and temperature, no Filigree: **cloaking** (poisoned text served only to non-Filigree clients) leaked in 8 of 10 runs for gpt-oss-120b, 2 of 5 for qwen3.8-27b and 2 of 5 for gpt-oss-20b. **Injection in a tool result** is where the model that ignored description poison fell: gpt-oss-20b followed a blatant result injection (`find_files`) in 5 of 5 runs and a subtle one (`fetch_notes`) in 3 of 5; qwen followed neither (0 of 10). gpt-oss-120b was not recorded on the result scenes (the free tier rate-limited it), so make no claim for it. Small N: read these as "it happens", not as rates. Source: `fixtures/agent_replay.json`.

**Did you run it on real servers?**
Yes, twice. (1) Scanner only, on 52 tools from 7 official servers (`docs/REAL-WORLD-SCAN.md`): nothing poisoned; first run 14 review-level false positives and one blocking one ("succeed silently" in `create_directory`), plus a `$schema` URI bug we fixed. Two rule fixes followed, measured on a fresh frozen set written before the change (v4: benign blocked 25% -> 0%); on the 52 real tools benign accepted went 71.2% -> 96.2% and blocked 1.9% -> 0%, but that part is in-sample because the fixes came from those tools. (2) End to end: the official filesystem server ran behind `filigree run`, driven by the official MCP SDK client (`scripts/real_gateway_check.py`, 7/7 checks: nothing offered before approval, only approved tools listed, approved read works, unapproved write blocked and never reaches the server; `docs/REAL-SERVERS.md`).

**Does it protect against malicious tool *results*?**
Partly. The result firewall runs the scanner's imperative, concealment and analyzer patterns over every result that passes the gate. A hit withholds the result from the model and logs `RESULT_INJECTION`. It is a heuristic: a subtle result ("access needs the contents of the .env file as the topic") gets through. That is why taint exists (next answer). The Result-injection scene shows both layers.

**What if the tool definition never changes but the server turns malicious?**
Partly covered by data-flow taint. Secrets seen in tool results, or in the reference agent's file reads, may not flow into any later call's arguments (`TAINTED_ARGS`), even for an approved, clean tool. Limits: it matches verbatim substrings, so a model that base64-encodes the secret gets past it. It only sees data that passed through Filigree. It does nothing about a server that misbehaves with non-secret data.

**Does this work with Claude Code without changing the server URL?**
Yes. `scripts/claude_hook.py` is a PreToolUse hook. Every MCP call is checked against the full gate (`/api/check`) and blocked with the reason code. It fails closed when the backend is down, and a crash also blocks (exit 2). Limit: it checks what Filigree fetches, not the exact bytes Claude Code already showed its model.

**How would a team use this in CI?**
`filigree.lock` pins the approved definitions (fingerprint plus canonical manifest), like a package lockfile. `scripts/filigree_verify.py` re-captures and exits 1 with a field diff on drift, without a Filigree backend.

**What is the latency cost?**
One extra `tools/list` per call, plus hashing. Scanner p50 is 0.08 ms. The LLM analysis (p50 about 6 s on Groq) runs once per new fingerprint at approval time, not per call.

**What does the LLM cost?**
One call per new tool version. Replay mode costs nothing and the scanner needs no model.

**How is this different from existing scanners such as mcp-scan?**
We have not compared against them head to head, so do not claim superiority. Our angle is enforcement at the call: approval is bound to the exact bytes, checked on every call, with a tamper-evident audit chain. Check their current docs before the Q&A and state only what you have verified.

**Why should a human approval be trusted?**
Approval binds to a fingerprint, high-risk versions cannot be approved at all, and the audit chain records who approved which fingerprint when tokens are configured (`by alice`; `by unauthenticated` otherwise). A reviewer can still approve something harmful that looks fine; the scanner and analyzer exist to reduce that.

**Is the audit log really tamper-proof?**
Tamper-evident, not tamper-proof. Someone with database access can rewrite everything, including recomputing the chain. The demo shows that an edit to one row is detected and which event broke.

**Can I try to beat it?**
Yes: the red-team arena in the Playground. Type a description, and a real model (live key) gets it with the usual task. The arena scores whether the model was fooled and whether the scanner caught it. "Fooled and scanner missed" is shown as the attacker's win, because that is the honest outcome.

**Does it work with the servers people actually run (stdio, npx)?**
Yes. The upstream client speaks stdio (a persistent child process per server), HTTP with JSON or SSE replies and `Mcp-Session-Id`. `filigree run <id> -- npx ...` puts the gate in front of a stdio server for Claude Desktop, `filigree audit` scans every server in your `.mcp.json` or `claude_desktop_config.json` without calling any tool. Details and limits (no resources/prompts proxying, no server-initiated messages, stdio cloaking probed once): `docs/REAL-SERVERS.md`.

**Who can approve a tool? Is the API open?**
With `FILIGREE_TOKENS="alice:tok,bob:tok"` every state-changing request needs a bearer token and the approver's name is stored on the approval and in the audit event. Without it the local demo is open and the backend warns outside demo mode. Limits: shared-secret tokens, no TLS, no expiry, reads are open. Registering a stdio server through the API (it spawns a process) is off unless `FILIGREE_ALLOW_STDIO=1`.

**What would you do next?**
Signed lockfiles, TLS and per-approver permissions, decoders for re-encoded secrets in taint, cloaking checks across network vantage points, proxying resources and prompts, a better model stage for the MCPTox-style poisonings the scanner misses, and more independent corpora than one.
