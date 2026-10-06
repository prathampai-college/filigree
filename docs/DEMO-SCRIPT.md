# 3-minute demo script

Start: `powershell -File scripts/demo.ps1` (or `sh scripts/demo.sh`), open http://127.0.0.1:5173. The badge must read REPLAY MODE · recorded from groq/openai/gpt-oss-120b. Everything below runs offline. Click **Reset** on the Demo page before you start.

| Time | Screen | Do | Say |
|---|---|---|---|
| 0:00 | Demo | Connect **Poisoned**; agent selector = **Real model**; click **1 · Run WITHOUT Filigree** | "A tool description is text the model obeys. This one tells the model to read ~/.env and send it out. These are real recorded model runs: gpt-oss-120b leaked the fake secret in 6 of 10 runs, qwen in 5 of 10. One leak is enough." |
| 0:40 | Demo | Click **2 · Run WITH Filigree** | "Same server, same task. The tool has no valid approval, so it is never offered to the model. There is nothing to obey." |
| 1:00 | Tools | Connect **Invisible-text**; open the tool; toggle "Highlight what the scanner flagged" | "This description looks identical to the benign one. Underneath is hidden text. The reviewer sees it decoded, and approval is blocked." |
| 1:40 | Demo | Connect **Rug pull**, approve `fetch_report` on Tools, then click **Run gateway session** | "Now a real MCP session through our gateway. The tool is clean when approved, the server changes it later, and the very next call is blocked with MANIFEST_DRIFT. The client sees no tool." |
| 2:20 | Audit | Click **Tamper (demo)**, then **Verify chain** | "Every decision is in a hash chain. Edit one row behind our back and the chain breaks at that event." |
| 2:40 | Evaluation | Point at the unseen-set card | "On a set we wrote after tuning and ran once: scanner alone flagged 83%, blocked 58%. With the LLM, 100% of poisoned and 80% of benign accepted. Team-authored, so not an independent benchmark." |
| 2:55 | any | | "The approved text, the model-visible text and the executed text are the same object, checked on every call." |

## If something breaks
- Backend not up: re-run the demo script; `backend/demo.db` resets on start.
- Weird state: **Reset** on the Demo page, reconnect the scenario.
- Model scene fails to show: switch the selector back to **Scripted agent**; the story is the same.
- Last resort: play the backup video (record it in replay mode beforehand).

## Deck outline
1. The attack: invisible text + the model obeying it (screenshot of the Real-model run).
2. The gap: approval, model-visible text and execution are three different objects today.
3. Filigree: fingerprint, scanner + advisory LLM, human approval, gate on every call.
4. Live demo.
5. Numbers: unseen v3 only, plus the 6/10 and 5/10 recorded model runs. Cite CyberArk's "Poison everywhere" by title, not link; call the public samples "modeled on published attack classes".
6. Honest limits: team-authored sets, cloaking servers, tool results, race window, no auth.
7. Next steps and ask.
