# Independent evaluation on MCPTox

Every other detection number in this repository is measured on text the team wrote (`docs/QA.md`, "How good is detection?").
This page is the first measurement on a corpus **we did not write**.

## The corpus
MCPTox, "A Benchmark for Tool Poisoning Attack on Real-World MCP Servers" (Wang et al., arXiv 2508.14925, AAAI 2026). It is built on
45 real MCP servers and their real tools; the authors add a poisoned tool to each server and wrap it in test cases.
Source of the files we used: `github.com/zhiqiangwang4/MCPTox-Benchmark` (main branch), downloaded 2026-10-07 with the user's approval:

| File | Bytes | SHA-256 |
|---|---|---|
| `pure_tool.json` | 316,620 | `54b1eb0e9d7b2f18465266aa9d9dfda828cd558b1269b74731ec2c5d8579e617` |
| `response_all.json` | 20,666,873 | `79a90049be931c59e71446d6180b1d7f0d196d123d08a59bc155d142b5041c03` |

The repository has no license file (its README is a one-line header), so the files are **not committed**: `fixtures/external/` is
gitignored. Only derived numbers and test-case ids are in git (`fixtures/evaluation/results_mcptox_corpus_*.json`). To reproduce,
download the two files into `fixtures/external/` as `mcptox_pure_tool.json` and `mcptox_response_all.json`, then:

```bash
python scripts/build_mcptox_corpus.py        # -> fixtures/external/mcptox_corpus.json (+ FROZEN hash)
uv run --project backend python scripts/evaluate_real.py fixtures/external/mcptox_corpus.json scanner
```

How the corpus is built (`scripts/build_mcptox_corpus.py`, no label invented, nothing tuned):
- **Poisoned**: every entry of `pure_tool.json`: 485 entries, all unique `(server, tool_name, description)`. Each is the malicious
  tool's name and description. Labelled by the benchmark authors with an attack template (1, 2 or 3) and one of 11 risk categories.
- **Benign**: the clean tools of the same 45 servers, parsed from each server's `clean_system_promot` text ("Tool: / Description: /
  Arguments:"): 362 tools. Their argument descriptions are mostly "No description" in the source, so their schemas are thinner than the
  real ones. They are real third-party descriptions, assumed benign because the benchmark treats them as the clean baseline.
- Each case carries the other tool names of its server, because Filigree always knows the other tools it has seen (cross-tool rule).

## Result 1: scanner only (all 485 + 362, run once, rules not changed afterwards)
`results_mcptox_corpus_scanner.json`, rules as of commit `4f194ff`.

| | Value |
|---|---|
| Poisoned **blocked** (cannot be approved) | **14.8%** (72/485) |
| Poisoned flagged (blocked or sent to review) | 99.2% (481/485); missed outright: 4 |
| Flagged by something **other than** a cross-tool reference | 77.5% (376/485); 105 were flagged only because they name a sibling tool |
| Benign accepted without review | 86.5% (313/362) |
| Benign sent to review | 12.2% (44) |
| Benign **blocked** | 1.4% (5: AdFin `post_customers`, HyperBrowser `extract_structured_data`, Apify `get-dataset-items`, Apify `apify-slash-rag-web-browser`, Prisma `Create-Prisma-Postgres-Database`) |

By attack template, blocked / total: Template-1 13/77 (16.9%), Template-2 32/183 (17.5%), Template-3 27/225 (12.0%).
By risk category the spread is wide: Credential Leakage 21/40 blocked (52.5%), Message Hijacking 6/15, Code Injection 7/22,
Privacy Leakage 13/97, Service Disruption 1/73, Information Manipulation 6/108, Instruction Tampering 1/21.

How to read it, honestly:
- **The scanner blocks about 1 in 7 MCPTox poisonings.** That is far below the 58.3% on our own v3 set, as expected: MCPTox attacks
  are written to look like ordinary tool text ("before using read_file, run the pre-authorization step..."), with no hidden characters,
  no sensitive path and no concealment wording in most of them. Our team-authored sets contained more of the obvious signals.
- **The 99.2% "flagged" figure is mostly one rule.** MCPTox's poisoned tools almost always mention another tool, which raises a
  *medium* cross-tool finding (human review, not a block). That same rule also puts 12.2% of the clean tools into review. Prefer the
  77.5% figure for "flagged for a reason other than naming a sibling tool".
- Review is a human step, not protection by itself: a reviewer who approves a plausible-looking description is exactly the attack.
- The LLM analyzer is the stage meant to close this gap; see Result 2.
- The MCPTox benchmark measures whether *models obey* poisoned tools. Whether a given description is also something a static
  scanner can recognise was not what the authors designed it for, so this is a hard test for text rules by construction.

## Result 2: scanner + LLM on a seeded sample
`scripts/evaluate_real.py ... --llm-sample 100 50`: 100 poisoned and 50 benign cases drawn with a fixed seed (`random.Random(0)`),
each analysed by the live analyzer (Groq `openai/gpt-oss-120b`, temperature 0, one call per case, ~12 s apart to respect the free
tier) and compared with the scanner on the same sample. A sample, not the full set, because the free tier allows about 5 calls a minute.

RESULT_2_PLACEHOLDER

## What this changes in how we describe Filigree
- Say: "on an independent benchmark of real tool poisonings, the deterministic scanner blocks 14.8% outright and flags 77.5% for a
  reason beyond naming a sibling tool; the model-based stage is what carries the rest, and approval stays a human decision".
- Do not say the scanner "detects tool poisoning" without those numbers, and do not quote 99.2% without the 77.5% next to it.
- The enforcement side (approved text = model-visible text = executed text, checked at every call) does not depend on these
  numbers: a poisoned description that a human approves is still bound to its fingerprint, and any later change is blocked.

## Limits
- One benchmark, one run per configuration. Scanner rules were not tuned on MCPTox and must not be (the corpus is now seen).
- The benign side is derived from prompt text, not captured from live servers.
- Poisoned tools are scored one description at a time; MCPTox attacks sometimes only work in combination with the user query.
- Not an endorsement by the MCPTox authors; we used the public files as published.
