.PHONY: help up down logs migrate revision test lint format

# Load POSTGRES_* from .env so host-side commands can reach the compose database.
-include .env
export

BACKEND := cd backend &&
HOST_DB := postgresql+psycopg://$(POSTGRES_USER):$(POSTGRES_PASSWORD)@localhost:5432

help: ## List targets
	@grep -hE '^[a-z-]+:.*## ' $(firstword $(MAKEFILE_LIST)) | awk -F ':.*## ' '{printf "  %-9s %s\n", $$1, $$2}'

.env:
	cp .env.example .env

up: .env ## Build and start the stack
	docker compose up -d --build

down: ## Stop the stack
	docker compose down

logs: ## Follow service logs
	docker compose logs -f

migrate: ## Apply database migrations (stack must be up)
	docker compose exec api alembic upgrade head

revision: ## Autogenerate a migration: make revision m="add foo"
	@test -n "$(m)" || (echo 'usage: make revision m="message"' && exit 1)
	@# @-prefixed so the DB password in the URL isn't echoed.
	@$(BACKEND) DATABASE_URL=$(HOST_DB)/$(POSTGRES_DB) uv run alembic revision --autogenerate -m "$(m)"

test: .env ## Run backend tests (starts the db container if needed)
	docker compose up -d --wait db
	@echo "pytest against database $(POSTGRES_DB)_test"
	@$(BACKEND) TEST_DATABASE_URL=$(HOST_DB)/$(POSTGRES_DB)_test uv run pytest

lint: ## Ruff lint + format check, mypy
	$(BACKEND) uv run ruff check . ../sandbox ../scripts
	$(BACKEND) uv run ruff format --check . ../sandbox ../scripts
	$(BACKEND) uv run mypy app tests alembic

format: ## Auto-fix lint issues and format
	$(BACKEND) uv run ruff check --fix . ../sandbox ../scripts
	$(BACKEND) uv run ruff format . ../sandbox ../scripts
