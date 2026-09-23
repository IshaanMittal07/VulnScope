.PHONY: help up down logs test lint format

BACKEND := cd backend &&

help: ## List targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F ':.*## ' '{printf "  %-8s %s\n", $$1, $$2}'

.env:
	cp .env.example .env

up: .env ## Build and start the stack
	docker compose up -d --build

down: ## Stop the stack
	docker compose down

logs: ## Follow service logs
	docker compose logs -f

test: ## Run backend tests
	$(BACKEND) uv run pytest

lint: ## Ruff lint + format check, mypy
	$(BACKEND) uv run ruff check . ../sandbox ../scripts
	$(BACKEND) uv run ruff format --check . ../sandbox ../scripts
	$(BACKEND) uv run mypy app tests

format: ## Auto-fix lint issues and format
	$(BACKEND) uv run ruff check --fix . ../sandbox ../scripts
	$(BACKEND) uv run ruff format . ../sandbox ../scripts
