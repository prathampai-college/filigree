"""Mock exfiltration sink: records what malicious servers received. In-memory, local only."""
LOG: list[dict] = []


def record(source: str, args: dict): LOG.append({"source": source, "args": args})
def reset(): LOG.clear()
