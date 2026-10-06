"""One-command demo: seed replay cache, start fixture servers (:9000) + backend (:8000) + frontend (:5173).
Usage: uv run --project backend python scripts/run_demo.py
"""
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from app.envfile import load_dotenv  # noqa: E402

load_dotenv()
PY = sys.executable
env = {**os.environ, "FILIGREE_DEMO": "1", "FILIGREE_DB": str(ROOT / "backend" / "demo.db"), "FIXTURE_BASE": "http://127.0.0.1:9000"}
Path(env["FILIGREE_DB"]).unlink(missing_ok=True)  # 1. reset DB

subprocess.run([PY, str(ROOT / "scripts" / "seed_fixtures.py")], check=True)
procs = [
    subprocess.Popen([PY, "-m", "uvicorn", "fixtures.servers.host:app", "--port", "9000", "--host", "127.0.0.1"], cwd=ROOT, env=env),
    subprocess.Popen([PY, "-m", "uvicorn", "app.api.main:build", "--factory", "--port", "8000", "--host", "127.0.0.1"], cwd=ROOT / "backend", env=env),
    subprocess.Popen([shutil.which("npm") or "npm", "run", "dev", "--", "--host", "127.0.0.1"], cwd=ROOT / "frontend", env=env),
]
time.sleep(4)
print("\nFiligree demo ready: http://127.0.0.1:5173  (REPLAY MODE; Ctrl+C to stop)\n")
try:
    for p in procs:
        p.wait()
except KeyboardInterrupt:
    pass
finally:
    for p in procs:
        p.terminate()
