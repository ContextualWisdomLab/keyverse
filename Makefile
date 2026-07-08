# cwl-idp — developer entrypoints. Works with docker OR podman compose.
COMPOSE ?= docker compose
SERVICE_DIR := services/account_unification

.PHONY: help up down logs ready seed-bootstrap test lint install

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n",$$1,$$2}'

up: ## Bring up the IdP stack (ZITADEL + Postgres + admin service)
	$(COMPOSE) up -d

down: ## Tear down the stack (keep volumes)
	$(COMPOSE) down

logs: ## Follow logs for all services
	$(COMPOSE) logs -f

ready: ## Poll readiness of every component
	./deploy/scripts/healthz.sh

seed-bootstrap: ## Create a local sqlite KV bootstrap store for dev
	python $(SERVICE_DIR)/tools/seed_config_store.py

install: ## Install the admin service with dev extras
	cd $(SERVICE_DIR) && python -m pip install -e '.[dev]'

test: ## Run the account-unification unit tests
	cd $(SERVICE_DIR) && python -m pytest -q

lint: ## Ruff lint the admin service
	cd $(SERVICE_DIR) && python -m ruff check app tests
