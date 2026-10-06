# One command from a fresh clone: installs dependencies if missing, then starts the demo (http://127.0.0.1:5173).
$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)
foreach ($tool in "uv", "npm") {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) { throw "$tool is required but not on PATH" }
}
uv sync --project backend
if (-not (Test-Path frontend/node_modules)) { npm --prefix frontend ci }
uv run --project backend python scripts/run_demo.py
