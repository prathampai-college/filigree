# Why this matters

AI agents now pick up tools from third-party MCP servers and obey the text in their descriptions. A person approves a tool once;
the model then reads a different, hidden or later-changed definition. The harm lands wherever agents act with real access:
finance and payments assistants, health and records tools, public-service and government workflows, developer machines holding
keys and source. One silently changed tool can move credentials or data out, and nobody sees it happen.

Filigree makes the approval mean something: what the human approved, what the model sees and what gets executed are the same
object, checked at every call. That is a precondition for trusting agents in the places that matter most
(SDG 9 resilient digital infrastructure, SDG 16 accountable institutions).

Who can adopt it today: anyone running Claude Code, Cursor or Claude Desktop with MCP servers, through the PreToolUse hook, the
HTTP gateway or `filigree run`, plus CI via `filigree.lock`. Limits are listed honestly in [`QA.md`](QA.md) and
[`RESULTS.md`](RESULTS.md).

Slide text (one slide, after "The attack"): *Agents inherit trust from tool text. Finance, health and public-service agents
cannot afford a tool that changes after approval. Filigree binds approval to every call.*
