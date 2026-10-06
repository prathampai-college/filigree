#!/usr/bin/env sh
# One command from a fresh clone: installs dependencies if missing, then starts the demo (http://127.0.0.1:5173).
set -e
cd "$(dirname "$0")/.."
command -v uv >/dev/null || { echo "uv is required but not on PATH"; exit 1; }
command -v npm >/dev/null || { echo "npm is required but not on PATH"; exit 1; }
uv sync --project backend
[ -d frontend/node_modules ] || npm --prefix frontend ci
exec uv run --project backend python scripts/run_demo.py
