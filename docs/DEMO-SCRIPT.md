# Short cut: 90 seconds, 4 beats

Use when time is tight or judges walk by. Lead with enforcement, not detection rates.

1. **Invisible-text** tool, Tools page: identical to the benign tool on screen; highlight shows the decoded hidden instruction. "You cannot approve what you cannot see."
2. **Poisoned**, Real model: WITHOUT leaks the fake secret, WITH never offers the tool. "Nothing to obey."
3. **Rug pull** gateway session: approved, server changes, next call `MANIFEST_DRIFT`. "Approval is bound to every call."
4. **`filigree audit` on the judge's own `.mcp.json`** (or yours): blocked / review / clean in seconds, no tool called.

Taint, result firewall, cloaking and the numbers go to Q&A (see QA.md). If asked for detection rates, quote the held-out MCPTox 73.0% next to the 14.8% first run.

# 3-minute demo script

Start: `powershell -File scripts/demo.ps1` (or `sh scripts/demo.sh`), open http://127.0.0.1:5173. The badge must read REPLAY MODE · recorded from groq/openai/gpt-oss-120b. Everything below runs offline. Click **Reset** on the Demo page before you start.

| Time | Screen | Do | Say |
|---|---|---|---|
| 0:00 | Demo | Connect **Poisoned**; agent selector = **Real model**; click **1 · Run WITHOUT Filigree** | "A tool description is text the model obeys. This one tells the model to read ~/.env and send it out. These are real recorded model runs: gpt-oss-120b leaked the fake secret in 6 of 10 runs, qwen in 5 of 10. One leak is enough." |
| 0:35 | Demo | Click **2 · Run WITH Filigree** | "Same server, same task. The tool has no valid approval, so it is never offered to the model. There is nothing to obey." |
| 0:55 | Tools | Connect **Invisible-text**; open the tool; toggle "Highlight what the scanner flagged" | "Identical to the benign one on screen. Underneath is hidden text. The reviewer sees it decoded, and approval is blocked." |
| 1:20 | Demo | Connect **Rug pull**, approve `fetch_report` on Tools, **Run gateway session** | "A real MCP session through our gateway. Clean when approved, the server changes it later, the next call is blocked with MANIFEST_DRIFT. The client sees no tool." |
| 1:50 | Demo | Connect **Result injection**; run `fetch_notes` WITHOUT, then WITH | "Approval is not enough: this tool is clean, but its result carries an instruction. The result firewall catches the obvious one; for the subtle one, data-flow taint blocks the secret from leaving in the next call. A model that ignores description poison, gpt-oss-20b, followed result injection in 5 of 5 and 3 of 5 recorded runs." |
| 2:20 | Terminal | Show the saved output of `scripts/real_gateway_check.py` (or run it) | "And it is not only our fixtures. The official filesystem server, behind `filigree run`, driven by the official MCP SDK client: nothing offered before approval, only approved tools listed, an unapproved write blocked and never reaches the server. 7 of 7 checks." |
| 2:40 | Evaluation | Unseen-set card, then say the MCPTox line | "Honest numbers. On a set we wrote after tuning, run once: 58% blocked, 83% flagged. On MCPTox, an independent benchmark of real poisonings, our first run blocked 14.8%. We added one rule for tools that steer other tools, built on half the servers: on the held-out half it blocks 73%, with 1.4% of clean tools blocked. With the model stage on a small sample it reaches 87.5%, at the cost of one clean tool blocked in 20. The rest is human review, and enforcement at the call does not depend on detection." |
| 2:55 | any | | "The approved text, the model-visible text and the executed text are the same object, checked on every call." |

Optional, if there are questions or extra time (not in the 3 minutes): **Audit** page: **Tamper (demo)**, **Verify chain**; **Download filigree.lock** and `filigree verify`; **Cloaking** scene; the Playground red-team arena (needs a live key); `filigree audit` on your own `.mcp.json`.

## If something breaks
- Backend not up: re-run the demo script; `backend/demo.db` resets on start.
- Weird state: **Reset** on the Demo page, reconnect the scenario.
- Model scene fails to show: switch the selector back to **Scripted agent**; the story is the same.
- Last resort: play the backup video (record it in replay mode beforehand).
- Terminal scene fails (no npx or network): show `docs/REAL-SERVERS.md` section "Verified end to end on a real server" instead; do not claim a live run.

## Deck outline
1. The attack: invisible text + the model obeying it (screenshot of the Real-model run).
2. The gap: approval, model-visible text and execution are three different objects today.
3. Filigree: fingerprint, scanner + advisory LLM, human approval, gate on every call.
4. Live demo.
5. Numbers: unseen v3 and the independent MCPTox run (first run 14.8% blocked; held-out half 73.0% after the steering rule; N=485 + 362), plus the recorded model runs (6/10, 5/10 description poison; 5/5, 3/5 result injection). Cite CyberArk's "Poison everywhere" by title, not link; call the public samples "modeled on published attack classes".
6. Honest limits: team-authored sets, one independent benchmark, cloaking by IP or timing, subtle tool results, race window, shared-secret tokens.
7. Next steps and ask.
