# Judge Q&A: honest answers

Every number here comes from `fixtures/evaluation/results*.json` or `fixtures/agent_replay.json`. If a number is not in a file, do not say it.

**Isn't this just hashing the tool description?**
Hashing is the core, but three things sit around it. The hash covers the whole canonical definition (name, description, schema, annotations, server instructions), not only the text. The gate re-fetches `tools/list` and re-hashes before every `tools/call`, so a change after approval is caught at the call. And the human approves exactly the bytes the model will see, with hidden characters made visible. A hash alone would not show the reviewer what the invisible text says.

**What stops a server from showing a clean definition once and a poisoned one later?**
That is the rug pull. The next call re-fetches and finds a different fingerprint: `MANIFEST_DRIFT`, call blocked, field diff shown. Tested end to end, also through the official MCP SDK client (`scripts/sdk_client_check.py`).

**What about a server that shows different definitions to different clients (cloaking)?**
Not protected. If the server serves Filigree a clean definition and the agent a poisoned one, we cannot tell. The gateway closes most of this gap because the agent only sees what Filigree serves, from the approved canonical bytes. A client that bypasses the gateway is unprotected.

**What about the race between the re-fetch and the call?**
It exists and is listed under "Not protected". The window is small, but it is not zero.

**How good is detection? Why should we trust the numbers?**
Read the unseen set only. v3 (12 poisoned + 10 benign) was written after the rules were tuned and run once: scanner alone blocked 58.3% and flagged 83.3%, accepted 90% of benign tools. Scanner plus LLM caught 100% of poisoned but accepted only 80% of benign, with two named false positives. Earlier sets are labeled in-sample because we tuned on them. All sets are team-authored, so this is not an independent benchmark. The 12 "public" samples are modeled on published attack classes, not quoted (see `fixtures/evaluation/SOURCES.md`).

**The LLM saw the scanner's findings. Isn't that circular?**
Yes, partly. The model gets the scanner output in its prompt, as in the product, so its numbers are not independent of the scanner. That is why the scanner decides on its own whether something is blocked, and the LLM is advisory: it can raise a flag but never downgrade a scanner finding.

**Can the analyzer itself be prompt-injected?**
The tool text goes in as untrusted data inside random-id tags, and text that addresses the analyzer is itself treated as a finding. That reduces the risk but does not remove it. The scanner and the human step do not depend on the model.

**Do real models actually fall for tool poisoning?**
Some do, some of the time. We recorded 10 runs per model with no Filigree (same task for every run, temperature 0.7, nothing tuned) on Groq-hosted models. Visible poison in the description: gpt-oss-120b leaked the (fake) secret in 6 of 10 runs, qwen3.8-27b in 5 of 10, gpt-oss-20b in 0 of 10. The benign control leaked 0 of 30. The invisible-text variant leaked 0 of 30: these models did not act on the hidden Unicode tags, so do not claim a model obeyed invisible text. The invisible case is still a hole for the human reviewer, who cannot see it either, and a model that decodes tags would obey it. Point: one leak is enough, and with Filigree the unapproved tool is never offered, whatever the model does. Source: `fixtures/agent_replay.json`.

**Does it protect against malicious tool *results*?**
No. Injection inside a tool's output is a different problem. We say so under "Not protected".

**What if the tool definition never changes but the server turns malicious?**
Not protected. Approval integrity covers what the model is told, not what the server does with the call.

**What is the latency cost?**
One extra `tools/list` per call, plus hashing. Scanner p50 is 0.08 ms. The LLM analysis (p50 about 6 s on Groq) runs once per new fingerprint at approval time, not per call.

**What does the LLM cost?**
One call per new tool version. Replay mode costs nothing and the scanner needs no model.

**How is this different from existing scanners such as mcp-scan?**
We have not compared against them head to head, so do not claim superiority. Our angle is enforcement at the call: approval is bound to the exact bytes, checked on every call, with a tamper-evident audit chain. Check their current docs before the Q&A and state only what you have verified.

**Why should a human approval be trusted?**
Approval binds to a fingerprint, high-risk versions cannot be approved at all, and the audit chain shows who approved which fingerprint. A reviewer can still approve something harmful that looks fine; the scanner and analyzer exist to reduce that.

**Is the audit log really tamper-proof?**
Tamper-evident, not tamper-proof. Someone with database access can rewrite everything, including recomputing the chain. The demo shows that an edit to one row is detected and which event broke.

**What would you do next?**
Authenticate the gateway, handle server-side cloaking with attested transports, run against real-world servers rather than our fixtures, and an independent evaluation set.
