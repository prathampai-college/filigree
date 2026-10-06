# Windows without make: run the commands directly.
test:
	cd backend && uv run pytest
demo:
	uv run --project backend python scripts/run_demo.py
replay-cache:
	uv run --project backend python scripts/seed_fixtures.py
