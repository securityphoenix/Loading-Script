.PHONY: help build up down logs clean test dev

# ============================================================================
# Phoenix Scanner Service - Makefile
# ============================================================================

help: ## Show this help message
	@echo "Phoenix Scanner Service - Available Commands:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

# Docker commands
build: ## Build Docker images
	docker-compose build

up: ## Start all services
	docker-compose up -d
	@echo "✅ Services started!"
	@echo "   API: http://localhost:$${PHOENIX_API_HOST_PORT:-8001}"
	@echo "   Docs: http://localhost:$${PHOENIX_API_HOST_PORT:-8001}/docs"
	@echo "   Flower: http://localhost:5555"

down: ## Stop all services
	docker-compose down

restart: ## Restart all services
	docker-compose restart

logs: ## Show logs from all services
	docker-compose logs -f

logs-api: ## Show API logs
	docker-compose logs -f api

logs-worker: ## Show worker logs
	docker-compose logs -f worker

status: ## Show service status
	docker-compose ps

# Development commands
dev: ## Run in development mode (with reload)
	docker-compose -f docker-compose.yml -f docker-compose.dev.yml up

shell-api: ## Open shell in API container
	docker-compose exec api /bin/bash

shell-worker: ## Open shell in worker container
	docker-compose exec worker /bin/bash

# Maintenance commands
clean: ## Remove all containers, volumes, and data
	docker-compose down -v
	rm -rf uploads/* logs/* data/*.db

clean-jobs: ## Clean old completed jobs
	docker-compose exec api python -c "from app.services.job_manager import job_manager; from app.models.database import SessionLocal; db = SessionLocal(); job_manager.cleanup_old_jobs(db, days=7); print('✅ Cleaned up old jobs')"

# Database commands
db-migrate: ## Run database migrations
	docker-compose exec api alembic upgrade head

db-reset: ## Reset database
	docker-compose exec api python -c "from app.models.database import Base, engine; Base.metadata.drop_all(engine); Base.metadata.create_all(engine); print('✅ Database reset')"

# Testing commands
test: ## Run tests
	docker-compose exec api pytest tests/ -v

test-cov: ## Run tests with coverage
	docker-compose exec api pytest tests/ --cov=app --cov-report=html

# Health check
health: ## Check service health
	@curl -s http://localhost:8000/api/v1/health | python -m json.tool

ping: ## Simple ping test
	@curl -s http://localhost:8000/api/v1/ping | python -m json.tool

# Initialize
init: ## Initialize service (first time setup)
	@echo "🚀 Initializing Phoenix Scanner Service..."
	@if [ ! -f .env ]; then \
		cp .env.example .env; \
		echo "✅ Created .env file from template"; \
		echo "⚠️  Please edit .env with your configuration!"; \
	fi
	@mkdir -p uploads logs data
	@echo "✅ Created data directories"
	@echo ""
	@echo "Next steps:"
	@echo "  1. Edit .env with your Phoenix API credentials"
	@echo "  2. Run: make build"
	@echo "  3. Run: make up"
	@echo "  4. Visit: http://localhost:8000/docs"

