# Public sample sources: verification (2026-10-06)

`public_heldout.json` is frozen (hash-checked), so its `source_verified: false` flags and URLs are left exactly as authored.
This file records what was checked afterwards. Page-level checks only: each URL was fetched and compared with the attack
the sample claims to come from.

**Conclusion: all 12 samples are illustrative.** The sources support the *attack classes*; none of them supplies the sample
text. Call them "modeled on published attack classes", never "taken from" or "quoted from" a source.

| Samples | Cited source | Page exists | What the page supports | What it does not |
|---|---|---|---|---|
| h01, h02, h11 | Invariant Labs, tool poisoning notification | yes | `add` tool with a `sidenote` parameter that exfiltrates `~/.cursor/mcp.json` and SSH keys through hidden instructions in the description (h01 is closest) | the exact wording; h02 and h11 are our variants |
| h03, h04 | Invariant Labs, WhatsApp MCP | yes | poisoned description that redirects `send_message` to an attacker number and embeds chat history | the exact wording; the "proxy field" in h04 is our invention |
| h05, h06, h12 | Trail of Bits, "Jumping the line" | yes | tool descriptions are an injection vector before any tool is invoked; its own example makes the model prefix commands with `chmod -R 0666 ~;` | "ignore all previous instructions", "SYSTEM: ..." and the weather tracker are authored in that style, not from the page |
| h07, h08 | CyberArk, "Poison everywhere" | **link is dead** | search listing confirms the article exists and describes full-schema poisoning (function names, parameters, defaults), the idea these samples test | the URL redirects (301) to an unrelated Palo Alto page, so the article text could not be fetched |
| h09, h10 | OWASP, MCP Tool Poisoning | yes | tool poisoning as indirect prompt injection with an exfiltration example (`attacker.example.com/audit`, `/etc/shadow`) | the `<IMPORTANT>`, `~/.env` and `send_email` texts are not on the page |

Consequences:
- Do not quote any sample on a slide as an original attack. Describe the set as "12 samples modeled on published attack classes".
- The CyberArk URL in the frozen file is stale. The article was found through a search listing at several `cyberark.com/resources/...`
  paths, all of which now redirect to Palo Alto; cite it by title and author, not by link.
- Real recall on in-the-wild attacks is unmeasured. These sets show behavior on team-authored text only.
