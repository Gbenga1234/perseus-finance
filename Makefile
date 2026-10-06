.DEFAULT_GOAL := help
SERVICES := auth accounts ledger fraud notifications audit

.PHONY: help
help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

.PHONY: install
install: ## Install all packages and dev tools into .venv
	uv sync --all-packages

.PHONY: lint
lint: ## Lint and check formatting
	uv run ruff check .
	uv run ruff format --check .

.PHONY: format
format: ## Auto-format and fix lint issues
	uv run ruff check --fix .
	uv run ruff format .

.PHONY: typecheck
typecheck: ## Static type checking
	uv run mypy libs/perseus-common/src services/*/src

.PHONY: test
test: ## Run the full test suite
	uv run pytest

.PHONY: security
security: ## Bandit SAST + dependency vulnerability audit
	uv run bandit -r libs services -c pyproject.toml -ll
	uv run pip-audit --skip-editable --strict

.PHONY: check
check: lint typecheck test security ## Run all quality and security checks (run before pushing)

.PHONY: secrets
secrets: ## Generate .env with all secrets (git-ignored; refuses to overwrite)
	uv run python scripts/generate_secrets.py

.PHONY: dev-cert
dev-cert: ## Self-signed localhost certificate in certbot layout (local dev only)
	uv run python scripts/dev_cert.py --domain localhost
	mkdir -p certbot-www

.PHONY: up
up: ## Build and start the stack with the dev mail sink (https://localhost:8443)
	docker compose --profile dev up -d --build

.PHONY: up-prod
up-prod: ## Build and start the stack without dev-only services
	docker compose up -d --build

.PHONY: down
down: ## Stop the stack (keeps data volumes)
	docker compose down

.PHONY: logs
logs: ## Tail service logs
	docker compose logs -f --tail=100 $(SERVICES)

.PHONY: admin
admin: ## Create an admin user: make admin EMAIL=ops@example.com NAME="Ops Admin"
	docker compose exec auth python -m auth_service.cli create-user --email "$(EMAIL)" --name "$(NAME)" --role admin --role auditor

.PHONY: smoke
smoke: ## End-to-end smoke test against the running stack
	uv run python scripts/smoke_test.py
