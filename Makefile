.DEFAULT_GOAL := help
UV ?= uv

.PHONY: help install fmt lint type imports test cov check matrix run docker clean schema

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

check: lint type imports test ## Everything CI runs, on one interpreter

matrix: ## Run the tests on every Python CI runs, because one is not enough
	@# `check` uses whichever Python is default here, and a green run on it is not a
	@# green CI run. Coverage in particular differs between versions: until 3.12,
	@# isinstance() against a runtime-checkable Protocol executed property getters, so a
	@# property with no test of its own looked covered on 3.11 and did not on 3.12.
	for version in 3.11 3.12; do \
		echo "== python $$version =="; \
		$(UV) run --python $$version pytest --cov -q || exit 1; \
	done

schema: ## Regenerate the checked-in schema snapshot after changing a migration
	$(UV) run python scripts/dump_schema.py

smoke: ## End-to-end check against a keyring already running on :8099
	$(UV) run python scripts/smoke.py

run: ## Serve the API on :8001 with reload
	$(UV) run uvicorn keyring_api.api.app:create_app --factory --reload --port 8001

# Signed-in gh fetches private client packages; with no session git fetches anonymously.
docker: ## Build the container image
	@GITHUB_TOKEN="$$(gh auth token 2>/dev/null)" docker build --secret id=github_token,env=GITHUB_TOKEN -t keyring-api:local .

clean: ## Remove caches and build output
	rm -rf .pytest_cache .mypy_cache .ruff_cache .hypothesis htmlcov .coverage build dist
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
