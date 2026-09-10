.DEFAULT_GOAL := help
UV ?= uv

.PHONY: help install fmt lint type imports test cov check run docker clean schema

help: ## Show available targets
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-12s\033[0m %s\n", $$1, $$2}'

install: ## Create the virtualenv and install everything
	$(UV) sync --all-extras --group dev

fmt: ## Format the codebase
	$(UV) run ruff format .
	$(UV) run ruff check --fix .

lint: ## Lint (no fixes)
	$(UV) run ruff format --check .
	$(UV) run ruff check .

type: ## Strict type check
	$(UV) run mypy

imports: ## Enforce the architectural layering contracts
	$(UV) run lint-imports

test: ## Run the test suite with 100% branch coverage enforced
	$(UV) run pytest --cov --cov-report=term-missing

cov: ## Write an HTML coverage report to htmlcov/
	$(UV) run pytest --cov --cov-report=html

check: lint type imports test ## Everything CI runs

schema: ## Regenerate the checked-in schema snapshot after changing a migration
	$(UV) run python scripts/dump_schema.py

smoke: ## End-to-end check against a keyring already running on :8099
	$(UV) run python scripts/smoke.py

run: ## Serve the API on :8001 with reload
	$(UV) run uvicorn keyring_api.api.app:create_app --factory --reload --port 8001

docker: ## Build the container image
	docker build -t keyring-api:local .

clean: ## Remove caches and build output
	rm -rf .pytest_cache .mypy_cache .ruff_cache .hypothesis htmlcov .coverage build dist
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
