"""Turn the downloaded MCPTox files into a corpus for scripts/evaluate_real.py. Nothing is tuned here and no label is invented.

Inputs (downloaded by hand from github.com/zhiqiangwang4/MCPTox-Benchmark, kept out of git, no license file there):
  fixtures/external/mcptox_pure_tool.json       poisoned tools: 45 groups, 485 entries (tool_name + poisoned tool_content)
  fixtures/external/mcptox_response_all.json    "servers": per server, the clean tool list as text ("Tool: / Description: / Arguments:")
poisoned = every unique (server, tool_name, tool_content) in pure_tool.json.
benign   = every unique clean tool parsed from the servers' clean_system_promot.
Each case carries the other tool names of its server (the scanner uses them for cross-tool references).
Usage: python scripts/build_mcptox_corpus.py
"""
import hashlib
import json
import re
from pathlib import Path

X = Path(__file__).resolve().parents[1] / "fixtures" / "external"
pure = json.loads((X / "mcptox_pure_tool.json").read_text(encoding="utf-8"))
servers = json.loads((X / "mcptox_response_all.json").read_text(encoding="utf-8"))["servers"]

clean, names = {}, {}
for s in servers.values():
    blocks = re.split(r"\n\n+Tool: ", "\n\n" + s["clean_system_promot"].split("access to these tools:", 1)[1])[1:]
    for b in blocks:
        name, _, rest = b.partition("\nDescription: ")
        desc, _, args = rest.partition("\nArguments:")
        props = {}
        for line in args.strip().splitlines():
            if m := re.match(r"- ([^:]+): (.*?)(?: \(required\))?$", line.strip()):
                props[m.group(1)] = {"type": "string", **({} if m.group(2) == "No description" else {"description": m.group(2)})}
        clean[(s["server_name"], name.strip())] = {"name": name.strip(), "description": desc.strip(),
                                                    "inputSchema": {"type": "object", "properties": props}}
        names.setdefault(s["server_name"], set()).add(name.strip())

poisoned = {}
for group in pure:
    for key, e in group.items():
        names.setdefault(e["server_name"], set())
        poisoned.setdefault((e["server_name"], e["tool_name"], e["tool_content"]),
                            {"id": f"mcptox-{key}", "label": "poisoned", "server": e["server_name"], "paradigm": e["paradigm"],
                             "risk": e["security risk"], "tool": {"name": e["tool_name"], "description": e["tool_content"]}})
cases = [dict(c, tool_names=sorted(names[c["server"]])) for c in poisoned.values()]
cases += [{"id": f"mcptox-clean-{srv}-{n}", "label": "benign", "server": srv, "tool": t, "tool_names": sorted(names[srv])}
          for (srv, n), t in clean.items()]
out = json.dumps(cases, indent=1, ensure_ascii=False)
(X / "mcptox_corpus.json").write_text(out, encoding="utf-8")
(X / "FROZEN_mcptox_corpus.sha256").write_text(hashlib.sha256(out.encode("utf-8")).hexdigest() + "\n", encoding="utf-8")
print(f"poisoned {len(poisoned)} unique of {sum(len(g) for g in pure)} entries; benign {len(clean)}; servers {len(servers)}")
