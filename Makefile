# Mandate — cross-platform (Linux/macOS via python3, Windows via WSL or `py`).
# A judge can run: make setup && make test && make lint && make eval
PY ?= python
VENV ?= .venv
ifeq ($(OS),Windows_NT)
BIN := $(VENV)/Scripts
PY := py
else
BIN := $(VENV)/bin
endif

.PHONY: setup test lint eval e2e dev seed keys fixtures clean

setup:
	$(PY) -m venv $(VENV)
	$(BIN)/python -m pip install --upgrade pip
	$(BIN)/python -m pip install -r requirements-dev.txt fastapi "uvicorn[standard]" "sqlalchemy>=2" pypdf httpx python-multipart
	$(BIN)/python -m apps.api.db.keys || $(PY) -c "import sys; sys.path[:0]=['packages','services','apps','.']; from api.db.keys import main; main()"

keys:
	$(BIN)/python -c "import sys; sys.path[:0]=['packages','services','apps','.']; from api.db.keys import main; main()"

fixtures:
	$(BIN)/python -m eval.fixtures_gen

test:
	$(BIN)/python -m pytest

lint:
	$(BIN)/python -m ruff check packages apps services tests eval

eval:
	$(BIN)/python -m eval.attacks.generate
	$(BIN)/python -m eval.run_eval

e2e:
	cd apps/web && npm install && npx playwright install chromium && npm run e2e

dev:
	$(BIN)/python -m uvicorn api.main:app --reload --port 8000

clean:
	rm -rf $(VENV) .pytest_cache .ruff_cache .hypothesis
