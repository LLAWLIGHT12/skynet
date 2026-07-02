# Contributing

Thanks for your interest in Skynet Audit.

## Setup

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate

pip install -r requirements.txt
pip install -r requirements-audit.txt
pip install -r requirements-dev.txt

cp .env.example .env
# Edit .env — never commit real API keys
```

## Tests

```bash
pytest tests/ -q --ignore=tests/benchmark
```

Some integration tests (`tests/test_smoke.py`, `tests/test_overrides.py`) require a built graph and optional LSP; CI skips them by default.

## Pull requests

- Keep changes focused; match existing module layout under `skynet/`.
- Run `pytest` before opening a PR.
- Do not commit `.env`, `.venv/`, `reports/`, `results/`, or `.skynet/` artifacts.
