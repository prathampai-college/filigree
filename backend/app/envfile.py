"""Tiny .env loader (no dependency). Real environment variables win over the file."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def load_dotenv(path: Path = ROOT / ".env") -> None:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    for line in lines:
        line = line.split(" #")[0].strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            if v.strip().strip("'\""):
                os.environ.setdefault(k.strip(), v.strip().strip("'\""))
