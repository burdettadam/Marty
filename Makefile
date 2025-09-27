# Makefile for Marty project

# Define log file paths
LOG_DIR := /tmp/logs
LOG_FILE_DS := $(LOG_DIR)/document-signer.log
LOG_FILE_MDL := $(LOG_DIR)/mdl-engine.log
LOG_FILE_MDOC := $(LOG_DIR)/mdoc-engine.log
LOG_FILE_UI := $(LOG_DIR)/ui-app.log

# Define virtual environment activation script path
VENV_DIR := .venv
VENV_ACTIVATE := $(VENV_DIR)/bin/activate

# Extract ports from config/development.yaml
# This assumes a structure like:
# services:
#   service_name:
#     port: 12345
# Service port definitions
SIGNER_PORT := $(shell awk '/document_signer:/ {f=1} f && /port:/ {print $$2; exit}' config/development.yaml)
MDL_PORT := $(shell awk '/mdl_engine:/ {f=1} f && /port:/ {print $$2; exit}' config/development.yaml)
MDOC_PORT := $(shell awk '/mdoc_engine:/ {f=1} f && /port:/ {print $$2; exit}' config/development.yaml)
UI_PORT := 8090
TRUST_ANCHOR_PORT := 9080
CSCA_SERVICE_PORT := 8081
DOCUMENT_SIGNER_PORT := 8082
INSPECTION_SYSTEM_PORT := 8083
PASSPORT_ENGINE_PORT := 8084
MDL_ENGINE_PORT := 8085
MDOC_ENGINE_PORT := 8086
DTC_ENGINE_PORT := 8087
PKD_SERVICE_PORT := 8088
POSTGRES_PORT := 5432

# Proto Compilation Targets
.PHONY: compile-protos clean-protos

compile-protos:
	@echo "Compiling protocol buffers..."
	$(UV) run python -m src.compile_protos

clean-protos:
	@echo "Cleaning generated proto files..."
	rm -rf src/proto/*_pb2.py src/proto/*_pb2_grpc.py src/proto/*_pb2.pyi src/proto/*_pb2_grpc.pyi

# Code Quality Targets
.PHONY: format lint type-check complexity security quality-check pre-commit-install pre-commit-run

format:
	@echo "Running code formatters..."
	black --line-length=100 src/ tests/
	isort --profile=black --line-length=100 src/ tests/

lint:
	@echo "Running linting checks..."
	ruff check src/ tests/ --fix
	ruff format src/ tests/

type-check:
	@echo "Running type checking..."
	mypy src/

complexity:
	@echo "Running complexity analysis..."
	xenon --max-average B --max-modules B --max-absolute B src/
	@echo "Running radon complexity check..."
	radon cc src/ -a -s --total-average
	radon mi src/ -s

security:
	@echo "Running security checks..."
	bandit -r src/ -f json -o bandit-report.json
	safety check --json --output safety-report.json

quality-check: format lint type-check complexity security
	@echo "All code quality checks completed!"

pre-commit-install:
	@echo "Installing pre-commit hooks..."
	pre-commit install
	pre-commit install --hook-type commit-msg

pre-commit-run:
	@echo "Running pre-commit hooks on all files..."
	pre-commit run --all-files

pre-commit-update:
	@echo "Updating pre-commit hooks..."
	pre-commit autoupdate

setup-openxpki:
	@echo "Setting up OpenXPKI for certificate management..."
	@if [ ! -f ./scripts/development/setup_openxpki.sh ]; then \
		echo "Error: OpenXPKI setup script not found"; \
		exit 1; \
	fi
	@chmod +x ./scripts/development/setup_openxpki.sh
	@./scripts/development/setup_openxpki.sh
	@echo "OpenXPKI setup completed!"
	@echo "Access the OpenXPKI web interface at: https://localhost:8443/openxpki/"
	@echo "Default credentials: pkiadmin / secret"

.PHONY: setup clean test lint format proto compile-protos clean-protos build run docker-build docker-run test-unit test-integration test-integration-docker test-e2e test-e2e-docker test-cert-validator test-unit-orchestrated test-mock start-integration-services start-e2e-services stop-orchestrated-services test-integration-orchestrated test-e2e-orchestrated test-orchestrator-validation test-orchestrator-base test-e2e-ui playwright-install generate-test-data help run-ui run-service-ui run-services-dev check-services stop-services dev-environment demo-environment dev-minimal dev-full dev-status dev-logs dev-clean dev-restart wait-for-services show-endpoints test-performance test-coverage test-security test-setup setup-openxpki test-doc-processing test-doc-processing-unit test-doc-processing-integration test-doc-processing-e2e test-doc-processing-docker test-doc-processing-api test-doc-processing-health doc-processing-start doc-processing-stop doc-processing-status doc-processing-logs doc-processing-clean

PYTHON := uv run python
UV := uv
DOCKER := docker
DOCKER_COMPOSE := docker compose -f docker/docker-compose.yml

# Default target
all: help

# Setup development environment
setup:
	@echo "Setting up development environment..."
	@bash scripts/setup_environment.sh

# Clean built files and caches
clean:
	@echo "Cleaning up..."
	@find . -type d -name __pycache__ -exec rm -rf {} +
	@find . -type d -name "*.egg-info" -exec rm -rf {} +
	@find . -type f -name "*.pyc" -delete
	@find . -type f -name "*.pyo" -delete
	@find . -type f -name "*.pyd" -delete
	@rm -f src/proto/*_pb2.py src/proto/*_pb2_grpc.py # Corrected path
	@rm -rf src/proto/__pycache__
	@find . -type f -name ".coverage" -delete
	@find . -type d -name ".pytest_cache" -exec rm -rf {} +
	@find . -type d -name ".mypy_cache" -exec rm -rf {} +
	@find . -type d -name ".ruff_cache" -exec rm -rf {} +
	@find . -type f -name "*.log" -delete

# Run all tests with proper orchestration
test: test-unit test-integration test-e2e test-cert-validator

# Run unit tests (no services needed)
test-unit:
	@echo "Running unit tests with UV..."
	@$(UV) run pytest tests/unit/ -v --ignore=tests/unit/test_monitoring.py --ignore=tests/unit/test_complete_certificate_lifecycle.py

# Run integration tests (with required services)
test-integration:
	@echo "Running integration tests..."
	@$(UV) run pytest tests/integration/ -v --maxfail=3 --disable-warnings

# Run integration tests with Docker services (using TestEnvironmentManager)
test-integration-docker:
	@echo "Running integration tests with TestEnvironmentManager..."
	@$(UV) run python -m tests.test_orchestrator integration tests/integration/

# Run end-to-end tests (with full service stack)
test-e2e: ## Run end-to-end tests
	@echo "Running end-to-end tests..."
	@$(UV) run pytest tests/e2e/ -v --maxfail=3 --disable-warnings

# Run E2E tests with Docker services (using TestEnvironmentManager)
test-e2e-docker:
	@echo "Running E2E tests with TestEnvironmentManager..."
	@$(UV) run python -m tests.test_orchestrator e2e tests/e2e/

# Run certificate validator tests (no services needed)
test-cert-validator:
	@echo "Running certificate validation tests..."
	@$(UV) run pytest tests/cert_validator/ -v

# =============================================================================
# TEST ENVIRONMENT MANAGER COMMANDS (Recommended)
# =============================================================================

# Run unit tests (no services)
test-unit-orchestrated:
	@echo "Running unit tests with TestEnvironmentManager..."
	@$(UV) run python -m tests.test_orchestrator unit tests/unit/

# Run mock tests
test-mock:
	@echo "Running mock tests with TestEnvironmentManager..."
	@$(UV) run python -m tests.test_orchestrator mock tests/

# Start services for development (integration mode)
start-integration-services:
	@echo "Starting services for integration testing..."
	@$(UV) run python -c "from tests.test_orchestrator import get_orchestrator, TestMode; get_orchestrator().start_services_for_mode(TestMode.INTEGRATION)"

# Start services for development (e2e mode)
start-e2e-services:
	@echo "Starting services for E2E testing..."
	@$(UV) run python -c "from tests.test_orchestrator import get_orchestrator, TestMode; get_orchestrator().start_services_for_mode(TestMode.E2E)"

# Stop all orchestrated services
stop-orchestrated-services:
	@echo "Stopping all orchestrated services..."
	@$(UV) run python -c "from tests.test_orchestrator import get_orchestrator; get_orchestrator().stop_all_services()"

# New orchestrated test targets with fixed base class
test-integration-orchestrated:
	@echo "Running integration tests with orchestrated services..."
	@$(UV) run pytest tests/integration/docker/e2e/test_passport_orchestrated_clean.py::PassportFlowE2ETest::test_service_connectivity -v
	@$(UV) run pytest tests/integration/docker/e2e/test_passport_orchestrated_clean.py::PassportFlowE2ETest::test_service_health_checks -v

test-e2e-orchestrated:
	@echo "Running E2E tests with orchestrated services..."
	@$(UV) run pytest tests/integration/docker/e2e/test_passport_orchestrated_clean.py::PassportFlowE2ETest::test_passport_flow_with_injected_data -v

test-orchestrator-validation:
	@echo "Validating TestEnvironmentManager functionality..."
	@$(UV) run python -m tests.test_orchestrator integration tests/integration/

# Test the environment manager base class specifically
test-environment-manager-base:
	@echo "Testing environment manager base class functionality..."
	@$(UV) run pytest tests/integration/docker/e2e/test_passport_orchestrated_clean.py -v

# Legacy integration test (with conflicts - deprecated)
test-integration-legacy:
	@echo "Running legacy integration tests (may have conflicts)..."
	@$(UV) run pytest tests/integration/docker/e2e/test_passport_flow.py -v

# =============================================================================
# ADDITIONAL TESTING COMMANDS
# =============================================================================

# Install test dependencies for comprehensive testing
test-setup:
	@echo "Installing comprehensive test dependencies..."
	@$(UV) add --dev pytest pytest-asyncio pytest-cov pytest-html pytest-xdist coverage psutil
	@echo "✅ Test dependencies installed!"

# Run performance and scalability tests
test-performance:
	@echo "⚡ Running Performance & Scalability Tests..."
	@$(UV) run pytest tests/test_performance_suite.py -v -m "performance" --tb=short

# Run security-focused tests
test-security:
	@echo "🛡️ Running Security Tests..."
	@$(UV) run pytest tests/ -v -m "security" --tb=short

# Run comprehensive test coverage analysis
test-coverage:
	@echo "📊 Running Comprehensive Coverage Analysis..."
	@if [ -f "generate_test_coverage.py" ]; then \
		$(UV) run python generate_test_coverage.py; \
	else \
		echo "Running basic coverage analysis..."; \
		$(UV) run pytest --cov=src --cov-report=html --cov-report=term-missing --cov-report=json --cov-fail-under=75 tests/unit/ tests/integration/ tests/e2e/ tests/test_performance_suite.py; \
		echo "📈 Coverage report generated in htmlcov/index.html"; \
	fi

# Clean test artifacts and reports
test-clean:
	@echo "🧹 Cleaning test artifacts..."
	@find . -name ".coverage*" -delete
	@rm -rf htmlcov/ test-reports/ coverage-reports/ .pytest_cache/
	@find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@echo "✅ Test artifacts cleaned!"

# =============================================================================
# E2E TESTING COMMANDS
# =============================================================================

# Install Playwright browsers (required for E2E UI tests)
playwright-install:
	@echo "Installing Playwright browsers..."
	@$(UV) run python -m playwright install chromium
	@echo "Playwright browsers installed!"

# Run MVP E2E tests with mock data
test-e2e-mvp:
	@echo "Running MVP E2E tests..."
	@$(UV) run pytest tests/e2e/ -m mvp -v --tb=short

# Run all E2E tests (MVP + integration)
test-e2e-all:
	@echo "Running all E2E tests..."
	@$(UV) run pytest tests/e2e/ -v --tb=short

# Run E2E tests with HTML report generation  
test-e2e-report-mvp:
	@echo "Running E2E tests with HTML report generation..."
	@mkdir -p tests/e2e/reports
	@$(UV) run pytest tests/e2e/ -m mvp --html=tests/e2e/reports/report.html --self-contained-html -v
	@echo "📊 Test report generated: tests/e2e/reports/report.html"

# Run only smoke tests (quick validation)
test-e2e-smoke:
	@echo "Running Playwright smoke tests..."
	@echo "Starting UI service for smoke testing..."
	@docker run -d -p 8090:8090 --name smoke-ui-test --env UI_ENABLE_MOCK_DATA=true marty-ui-app || \
		(echo "Building UI image first..." && $(DOCKER_COMPOSE) build ui-app && \
		 docker run -d -p 8090:8090 --name smoke-ui-test --env UI_ENABLE_MOCK_DATA=true marty-ui-app)
	@echo "Waiting for UI service to be ready..."
	@timeout=30; while [ $$timeout -gt 0 ]; do \
		if curl -s http://localhost:8090/health >/dev/null 2>&1; then \
			echo "✅ UI Service is ready for smoke testing"; break; \
		fi; \
		echo "⏳ Waiting for UI Service... ($$timeout seconds left)"; \
		sleep 2; timeout=$$((timeout-2)); \
	done
	@echo "Running smoke tests..."
	@$(UV) run pytest tests/e2e/ -m smoke -v --tb=short || TEST_RESULT=$$?; \
		echo "Cleaning up test container..."; \
		docker stop smoke-ui-test >/dev/null 2>&1; \
		docker rm smoke-ui-test >/dev/null 2>&1; \
		exit $${TEST_RESULT:-0}

# Run E2E tests with existing UI service (assumes UI is already running on 8090)
test-e2e-ui-existing:
	@echo "Running Playwright E2E tests against existing UI service..."
	@if ! curl -s http://localhost:8090/health >/dev/null 2>&1; then \
		echo "❌ UI service not found at localhost:8090"; \
		echo "💡 Start UI service first: make run-ui or make dev-minimal"; \
		exit 1; \
	fi
	@echo "✅ UI service detected, running tests..."
	@$(UV) run pytest tests/e2e/ -v --tb=short

# Run Playwright tests requiring the full real service stack (no UI_ENABLE_MOCK_DATA)
test-e2e-ui-integration:
	@echo "Running full-stack Playwright integration UI tests (real services)..."
	@echo "Starting minimal service stack for integration tests..."
	@docker compose -f docker/docker-compose.integration.yml up --build -d
	@echo "Waiting for services to be ready..."
	@sleep 10
	@echo "Running integration tests..."
	@$(UV) run pytest tests/e2e/ -m "integration and ui" -v --tb=short || (docker compose -f docker/docker-compose.integration.yml down && exit 1)
	@echo "Stopping services..."
	@docker compose -f docker/docker-compose.integration.yml down

# Run specific E2E test categories
test-e2e-dashboard:
	@echo "Running dashboard E2E tests..."
	@$(UV) run pytest tests/e2e/test_ui_e2e.py::TestDashboard -v

test-e2e-passport:
	@echo "Running passport workflow E2E tests..."
	@$(UV) run pytest tests/e2e/test_ui_e2e.py::TestPassportWorkflow -v

test-e2e-mdl:
	@echo "Running MDL workflow E2E tests..."
	@$(UV) run pytest tests/e2e/test_ui_e2e.py::TestMDLWorkflow -v

test-e2e-responsive:
	@echo "Running responsive design E2E tests..."
	@$(UV) run pytest tests/e2e/test_ui_e2e.py::TestUIResponsiveness -v

# Generate E2E test report with HTML output
test-e2e-report:
	@echo "Running E2E tests with HTML report generation..."
	@mkdir -p tests/e2e/reports
	@docker run -d -p 8090:8090 --name report-ui-test --env UI_ENABLE_MOCK_DATA=true marty-ui-app || \
		(echo "Building UI image first..." && $(DOCKER_COMPOSE) build ui-app && \
		 docker run -d -p 8090:8090 --name report-ui-test --env UI_ENABLE_MOCK_DATA=true marty-ui-app)
	@echo "Waiting for UI service..."
	@timeout=30; while [ $$timeout -gt 0 ]; do \
		if curl -s http://localhost:8090/health >/dev/null 2>&1; then break; fi; \
		sleep 2; timeout=$$((timeout-2)); \
	done
	@$(UV) run pytest tests/e2e/ --html=tests/e2e/reports/report.html --self-contained-html -v || TEST_RESULT=$$?; \
		docker stop report-ui-test >/dev/null 2>&1; \
		docker rm report-ui-test >/dev/null 2>&1; \
		echo "📊 Test report generated: tests/e2e/reports/report.html"; \
		exit $${TEST_RESULT:-0}

# Quick smoke tests (unit tests only)
test-smoke: test-unit

# Test specific service integrations
test-csca:
	@echo "Running CSCA service integration tests..."
	@$(PYTHON) tests/test_orchestrator.py integration tests/integration/test_csca_lifecycle.py

test-mdl-mdoc:
	@echo "Running MDL/MDOC integration tests..."
	@$(PYTHON) tests/test_orchestrator.py integration tests/integration/test_integration_mdl_mdoc.py

# Test with mock services only\ntest-mock:\n\t@echo \"Running tests with mock services...\"\n\t@$(UV) run -m pytest tests/unit tests/integration -k \"not docker\" -v\n\n# Generate protobuf code\nproto:\n\t@echo \"Compiling protobuf files...\"\n\t@$(PYTHON) -m src.compile_protos

# Run a specific service locally
run-service-%:
	@echo "Running $* service..."
	@SERVICE_NAME=$* GRPC_PORT=$(shell sed -n -e "s/^  $*/port: //p" config/development.yaml | head -n 1 | tr -d '[:space:]') $(UV) run src/main.py

# Run the server (deprecated, use run-service-<name>)
run:
	@echo "Running the server (deprecated, use run-service-<name>)..."
	@echo "Please specify a service to run, e.g., make run-service-csca-service"

# Run UI service
run-ui:
	@echo "Starting UI service on port $(UI_PORT)..."
	@mkdir -p $(LOG_DIR)
	@export PYTHONPATH=./src && $(UV) run uvicorn src.ui_app.app:create_app --factory --host 0.0.0.0 --port $(UI_PORT) --reload 2>&1 | tee $(LOG_FILE_UI)

run-service-ui: run-ui

# Run all development services (requires building first)
run-services-dev: compile-protos
	@echo "Starting all development services..."
	@echo "This will start services using docker compose..."
	@$(DOCKER_COMPOSE) up --build -d
	@echo "Waiting for services to be ready..."
	@sleep 10
	@echo "Services should be running. UI will be started separately..."
	@$(MAKE) run-ui

# Build project (includes proto compilation)
build: compile-protos
	@echo "Building project..."
	@echo "Proto files compiled successfully"

# Build Docker images
docker-build: build
	@echo "Building Docker images..."
	@$(DOCKER_COMPOSE) build

# Run with Docker
docker-run:
	@echo "Running with Docker..."
	@$(DOCKER_COMPOSE) up

# Check service health
check-services:
	@echo "Checking service health..."
	@echo "Docker services:"
	@$(DOCKER_COMPOSE) ps
	@echo "Checking service endpoints..."
	@curl -s http://localhost:8088/ && echo "PKD Service: OK" || echo "PKD Service: FAILED"
	@curl -s http://localhost:$(UI_PORT)/health && echo "UI Service: OK" || echo "UI Service: FAILED"

# Stop all services
stop-services:
	@echo "Stopping all services..."
	@$(DOCKER_COMPOSE) down
	@pkill -f "uvicorn.*ui_app" || true
	@echo "Services stopped"

# =============================================================================
# DEVELOPMENT ENVIRONMENT COMMANDS
# =============================================================================

# Complete development environment setup for manual testing
dev-environment: dev-clean build
	@echo "🚀 Setting up complete development environment..."
	@$(MAKE) --no-print-directory dev-full
	@echo "⏳ Waiting for all services to be ready..."
	@$(MAKE) --no-print-directory wait-for-services
	@echo "✅ Development environment ready!"
	@$(MAKE) --no-print-directory show-endpoints

# Demo environment - optimized for demonstrations
demo-environment: dev-clean build generate-test-data
	@echo "🎬 Setting up demo environment..."
	@$(MAKE) --no-print-directory dev-full
	@echo "⏳ Waiting for all services to be ready..."
	@$(MAKE) --no-print-directory wait-for-services
	@echo "📊 Loading demo data..."
	@sleep 5  # Give services time to fully initialize
	@echo "🎉 Demo environment ready with sample data!"
	@$(MAKE) --no-print-directory show-endpoints

# Minimal development setup (UI + essential services only)
dev-minimal: dev-clean build
	@echo "🏃 Setting up minimal development environment..."
	@mkdir -p $(LOG_DIR)
	@echo "Starting essential services..."
	@$(DOCKER_COMPOSE) up postgres pkd-service -d
	@echo "Starting UI service..."
	@export PYTHONPATH=./src && $(UV) run uvicorn src.ui_app.app:create_app --factory --host 0.0.0.0 --port $(UI_PORT) --reload > $(LOG_FILE_UI) 2>&1 &
	@echo "⏳ Waiting for services to be ready..."
	@sleep 10
	@echo "✅ Minimal development environment ready!"
	@echo "📍 UI available at: http://localhost:$(UI_PORT)"
	@echo "📍 PKD Service at: http://localhost:$(PKD_SERVICE_PORT)"

# Full development setup (all services)
dev-full: dev-clean build
	@echo "🔧 Starting full development environment..."
	@mkdir -p $(LOG_DIR)
	@echo "Building and starting all Docker services..."
	@$(DOCKER_COMPOSE) up --build -d
	@echo "Starting UI service..."
	@export PYTHONPATH=./src && $(UV) run uvicorn src.ui_app.app:create_app --factory --host 0.0.0.0 --port $(UI_PORT) --reload > $(LOG_FILE_UI) 2>&1 &
	@echo "All services started!"

# Check development environment status
dev-status:
	@echo "📊 Development Environment Status"
	@echo "================================="
	@echo "Docker Services:"
	@$(DOCKER_COMPOSE) ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null || echo "No Docker services running"
	@echo ""
	@echo "Service Health Checks:"
	@$(MAKE) --no-print-directory check-services
	@echo ""
	@echo "Process Status:"
	@pgrep -f "uvicorn.*ui_app" > /dev/null && echo "✅ UI Service: Running (PID: $$(pgrep -f 'uvicorn.*ui_app'))" || echo "❌ UI Service: Not running"
	@$(DOCKER_COMPOSE) ps postgres --format "{{.Status}}" 2>/dev/null | grep -q "Up" && echo "✅ PostgreSQL: Running" || echo "❌ PostgreSQL: Not running"

# Show development logs
dev-logs:
	@echo "📋 Development Service Logs"
	@echo "==========================="
	@echo "UI Service logs (last 20 lines):"
	@tail -n 20 $(LOG_FILE_UI) 2>/dev/null || echo "No UI logs found"
	@echo ""
	@echo "Docker services logs:"
	@$(DOCKER_COMPOSE) logs --tail=10

# Clean development environment
dev-clean:
	@echo "🧹 Cleaning development environment..."
	@$(MAKE) --no-print-directory stop-services
	@$(MAKE) --no-print-directory clean
	@echo "Removing old logs..."
	@rm -rf $(LOG_DIR)/*
	@echo "Development environment cleaned!"

# Restart development environment
dev-restart:
	@echo "🔄 Restarting development environment..."
	@$(MAKE) --no-print-directory stop-services
	@sleep 3
	@$(MAKE) --no-print-directory dev-environment

# Wait for services to be ready
wait-for-services:
	@echo "⏳ Waiting for services to be ready..."
	@echo "Checking PostgreSQL..."
	@timeout=60; while [ $$timeout -gt 0 ]; do \
		if $(DOCKER_COMPOSE) exec -T postgres pg_isready -U martyuser -d martydb >/dev/null 2>&1; then \
			echo "✅ PostgreSQL is ready"; break; \
		fi; \
		echo "⏳ Waiting for PostgreSQL... ($$timeout seconds left)"; \
		sleep 2; timeout=$$((timeout-2)); \
	done
	@echo "Checking PKD Service..."
	@timeout=60; while [ $$timeout -gt 0 ]; do \
		if curl -s http://localhost:$(PKD_SERVICE_PORT)/ >/dev/null 2>&1; then \
			echo "✅ PKD Service is ready"; break; \
		fi; \
		echo "⏳ Waiting for PKD Service... ($$timeout seconds left)"; \
		sleep 2; timeout=$$((timeout-2)); \
	done
	@echo "Checking UI Service..."
	@timeout=60; while [ $$timeout -gt 0 ]; do \
		if curl -s http://localhost:$(UI_PORT)/health >/dev/null 2>&1; then \
			echo "✅ UI Service is ready"; break; \
		fi; \
		echo "⏳ Waiting for UI Service... ($$timeout seconds left)"; \
		sleep 2; timeout=$$((timeout-2)); \
	done
	@echo "🎉 All essential services are ready!"

# Show all service endpoints
show-endpoints:
	@echo "🌐 Service Endpoints"
	@echo "==================="
	@echo "📱 UI Console:        http://localhost:$(UI_PORT)"
	@echo "🏥 UI Health Check:    http://localhost:$(UI_PORT)/health"
	@echo "🔐 PKD Service:        http://localhost:$(PKD_SERVICE_PORT)"
	@echo "🛡️  Trust Anchor:       http://localhost:$(TRUST_ANCHOR_PORT)"
	@echo "📜 CSCA Service:       http://localhost:$(CSCA_SERVICE_PORT)"
	@echo "✍️  Document Signer:    http://localhost:$(DOCUMENT_SIGNER_PORT)"
	@echo "🔍 Inspection System:  http://localhost:$(INSPECTION_SYSTEM_PORT)"
	@echo "🛂 Passport Engine:    http://localhost:$(PASSPORT_ENGINE_PORT)"
	@echo "🪪 MDL Engine:         http://localhost:$(MDL_ENGINE_PORT)"
	@echo "📄 mDoc Engine:        http://localhost:$(MDOC_ENGINE_PORT)"
	@echo "🎯 DTC Engine:         http://localhost:$(DTC_ENGINE_PORT)"
	@echo "🗄️  PostgreSQL:        localhost:$(POSTGRES_PORT)"
	@echo ""
	@echo "💡 Quick Start Commands:"
	@echo "   make dev-status     - Check environment status"
	@echo "   make dev-logs       - View service logs"
	@echo "   make dev-restart    - Restart all services"
	@echo "   make stop-services  - Stop all services"

# Generate test data
generate-test-data:
	@echo "Generating test data..."
	@$(PYTHON) scripts/generate_test_data.py

mdl_mdoc_integration_tests: proto
	. $(VENV_ACTIVATE); \
	export PYTHONPATH=./src; \
	DUMMY_VAR="test"; \
	echo "DUMMY_VAR is $$(DUMMY_VAR)"; \
	TEST_NAME="mdl_mdoc_integration_tests"; \
	CONFIG_FILE_PATH="config/testing.yaml"; \
	echo "Running test: $$TEST_NAME with config $$CONFIG_FILE_PATH"; \
	pytest -s tests/integration/test_integration_mdl_mdoc.py::test_mdl_mdoc_flow \
	    --config-file="$$CONFIG_FILE_PATH" \
	    --log-cli-level=DEBUG; \
	RESULT=$$?; \
	echo "Test $$TEST_NAME finished with result: $$RESULT"; \
	exit $$RESULT

# =============================================================================
# =============================================================================
# DOCUMENT PROCESSING API TESTS
# =============================================================================

# Document Processing service port
DOC_PROCESSING_PORT := 8091
DOC_PROCESSING_BASE_URL := http://localhost:$(DOC_PROCESSING_PORT)

# Run all document processing tests
test-doc-processing: test-doc-processing-unit test-doc-processing-integration test-doc-processing-e2e
	@echo "✅ All document processing tests completed!"

# Run unit tests for document processing service
test-doc-processing-unit:
	@echo "🧪 Running document processing unit tests..."
	$(UV) run pytest tests/document_processing/unit/ -v --tb=short

# Run integration tests for document processing API endpoints
test-doc-processing-integration: test-doc-processing-api test-doc-processing-health
	@echo "✅ Document processing integration tests completed!"

# Run end-to-end tests for document processing workflows
test-doc-processing-e2e:
	@echo "🎬 Running document processing E2E tests..."
	$(UV) run python tests/document_processing/e2e/test_e2e_workflow.py

# Test document processing API endpoints with live service
test-doc-processing-api:
	@echo "🔍 Testing document processing API endpoints..."
	@echo "Checking if service is running..."
	@curl -s -f $(DOC_PROCESSING_BASE_URL)/api/ping > /dev/null || (echo "❌ Service not running. Start with 'make doc-processing-start'" && exit 1)
	@echo "✓ Service is responding"
	@echo ""
	@echo "Testing health endpoints..."
	@curl -s $(DOC_PROCESSING_BASE_URL)/api/health | jq '.' > /dev/null && echo "✓ Health endpoint working" || echo "❌ Health endpoint failed"
	@curl -s $(DOC_PROCESSING_BASE_URL)/api/ping | grep -q "OK" && echo "✓ Ping endpoint working" || echo "❌ Ping endpoint failed"
	@curl -s $(DOC_PROCESSING_BASE_URL)/api/readyz | jq '.' > /dev/null && echo "✓ Readiness endpoint working" || echo "❌ Readiness endpoint failed"
	@echo ""
	@echo "Testing API documentation..."
	@curl -s $(DOC_PROCESSING_BASE_URL)/docs > /dev/null && echo "✓ API docs available" || echo "❌ API docs failed"
	@curl -s $(DOC_PROCESSING_BASE_URL)/openapi.json | jq '.' > /dev/null && echo "✓ OpenAPI spec available" || echo "❌ OpenAPI spec failed"

# Test document processing health and status endpoints
test-doc-processing-health:
	@echo "💚 Testing document processing health endpoints..."
	@echo "Service URL: $(DOC_PROCESSING_BASE_URL)"
	@echo ""
	@echo "=== Health Check Details ==="
	@curl -s $(DOC_PROCESSING_BASE_URL)/api/health | jq '.' || echo "❌ Failed to get health details"
	@echo ""
	@echo "=== Service Info ==="
	@curl -s $(DOC_PROCESSING_BASE_URL)/ | jq '.' || echo "❌ Failed to get service info"

# Run document processing tests with Docker
test-doc-processing-docker:
	@echo "🐳 Running document processing tests with Docker..."
	docker-compose -f src/document_processing/docker-compose.yml --profile test up --build doc-processing-test

# Start document processing service for testing
doc-processing-start:
	@echo "🚀 Starting document processing service..."
	cd src/document_processing && \
		$(UV) run uvicorn app.main:app --host localhost --port $(DOC_PROCESSING_PORT) --reload &
	@echo "Service PID: $$!"
	@echo "Waiting for service to start..."
	@sleep 3
	@echo "Service should be available at: $(DOC_PROCESSING_BASE_URL)"
	@echo "API Documentation: $(DOC_PROCESSING_BASE_URL)/docs"

# Start document processing service in Docker
doc-processing-start-docker:
	@echo "🐳 Starting document processing service with Docker..."
	@cd src/document_processing && docker-compose up --build -d doc-processing
	@echo "Service started in Docker"
	@echo "Service available at: $(DOC_PROCESSING_BASE_URL)"

# Stop document processing service
doc-processing-stop:
	@echo "🛑 Stopping document processing service..."
	@pkill -f "uvicorn app.main:app" || echo "No running uvicorn process found"
	@cd src/document_processing && docker-compose down || echo "Docker services stopped"

# Check document processing service status
doc-processing-status:
	@echo "📊 Document processing service status:"
	@echo "Local service:"
	@curl -s -f $(DOC_PROCESSING_BASE_URL)/api/ping && echo "  ✅ Service is running" || echo "  ❌ Service is not responding"
	@echo "Docker service:"
	@cd src/document_processing && docker-compose ps

# View document processing service logs
doc-processing-logs:
	@echo "📋 Document processing service logs:"
	@cd src/document_processing && docker-compose logs -f doc-processing

# Clean document processing test artifacts
doc-processing-clean:
	@echo "🧹 Cleaning document processing test artifacts..."
	@cd src/document_processing && find . -name "__pycache__" -type d -exec rm -rf {} +
	@cd src/document_processing && find . -name "*.pyc" -delete
	@cd src/document_processing && find . -name ".pytest_cache" -type d -exec rm -rf {} +
	@cd src/document_processing && docker-compose down -v
	@echo "✅ Document processing cleanup completed"

# =============================================================================
# HELP COMMAND
# =============================================================================

# Show help (default target)
help:
	@echo "Marty - Document Management System"
	@echo "==================================="
	@echo ""
	@echo "🚀 Development Environment:"
	@echo "  dev-environment    - Complete development setup (recommended)"
	@echo "  demo-environment   - Demo setup with sample data"
	@echo "  dev-minimal        - Minimal setup (UI + essential services)"
	@echo "  dev-full           - Full setup (all services)"
	@echo "  dev-status         - Check environment status"
	@echo "  dev-logs           - View service logs"
	@echo "  dev-clean          - Clean development environment"
	@echo "  dev-restart        - Restart development environment"
	@echo "  show-endpoints     - Display all service URLs"
	@echo ""
	@echo "🔧 Build & Setup:"
	@echo "  setup              - Set up virtual environment and install dependencies"
	@echo "  setup-openxpki     - Set up OpenXPKI certificate management system"
	@echo "  build              - Build the project (compile protos + install)"
	@echo "  compile-protos     - Compile protocol buffers"
	@echo "  clean              - Clean build artifacts"
	@echo "  clean-protos       - Clean compiled protocol buffers"
	@echo ""
	@echo "🧪 Testing:"
	@echo "  test               - Run all tests"
	@echo "  test-unit          - Run unit tests"
	@echo "  test-integration   - Run integration tests"
	@echo "  test-integration-docker - Run integration tests with Docker services"
	@echo "  test-e2e           - Run end-to-end tests"
	@echo "  test-e2e-docker    - Run E2E tests with Docker services"
	@echo "  test-cert-validator - Run certificate validator tests"
	@echo ""
	@echo "🎯 TestEnvironmentManager Commands:"
	@echo "  test-unit-orchestrated - Run unit tests with TestEnvironmentManager"
	@echo "  test-integration-orchestrated - Run integration tests with orchestrated services"
	@echo "  test-e2e-orchestrated - Run E2E tests with orchestrated services"
	@echo "  test-orchestrator-validation - Validate TestEnvironmentManager functionality"
	@echo "  test-environment-manager-base - Test environment manager base class"
	@echo "  start-integration-services - Start services for integration testing"
	@echo "  start-e2e-services - Start services for E2E testing"
	@echo "  stop-orchestrated-services - Stop all orchestrated services"
	@echo ""
	@echo "🔐 Phase 2/3 Passport Verification Testing:"
	@echo "  test-setup           - Install test dependencies"
	@echo "  test-all-phases      - Run all Phase 2/3 tests (comprehensive)"
	@echo "  test-phase2          - Run all Phase 2 RFID tests"
	@echo "  test-phase3          - Run all Phase 3 Security tests"
	@echo "  test-phase2-units    - Run Phase 2 RFID unit tests"
	@echo "  test-phase2-integration - Run Phase 2 RFID integration tests"
	@echo "  test-phase3-units    - Run Phase 3 Security unit tests"
	@echo "  test-phase3-integration - Run Phase 3 Security integration tests"
	@echo "  test-performance     - Run performance & scalability tests"
	@echo "  test-security        - Run security-focused tests"
	@echo "  test-quick           - Run quick tests (no slow/performance tests)"
	@echo "  test-coverage        - Run comprehensive coverage analysis"
	@echo "  test-clean           - Clean test artifacts and reports"
	@echo ""
	@echo "🎭 Playwright E2E Testing:"
	@echo "  playwright-install    - Install Playwright browsers"
	@echo "  test-e2e-ui          - Run UI E2E tests (auto-starts UI service)"
	@echo "  test-e2e-smoke       - Run smoke E2E tests (quick validation)"
	@echo "  test-e2e-ui-existing - Run E2E tests against running UI service"
	@echo "  test-e2e-dashboard   - Run dashboard-specific E2E tests"
	@echo "  test-e2e-passport    - Run passport workflow E2E tests"
	@echo "  test-e2e-mdl         - Run MDL workflow E2E tests"
	@echo "  test-e2e-responsive  - Run responsive design E2E tests"
	@echo "  test-e2e-report      - Run E2E tests with HTML report"
	@echo ""
	@echo "✨ Code Quality:"
	@echo "  lint               - Run linting tools"
	@echo "  format             - Format code"
	@echo "  type-check         - Run type checking"
	@echo ""
	@echo "🛠️ Services:"
	@echo "  run-ui             - Start UI service only"
	@echo "  run-services-dev   - Start all Docker services"
	@echo "  check-services     - Health check all services"
	@echo "  stop-services      - Stop all services"
	@echo ""
	@echo "🐳 Docker:"
	@echo "  docker-build       - Build Docker images"
	@echo "  docker-run         - Run full Docker environment"
	@echo ""
	@echo "📊 Data:"
	@echo "  generate-test-data - Generate test data"
	@echo ""
	@echo "📄 Document Processing API:"
	@echo "  test-doc-processing      - Run all document processing tests"
	@echo "  test-doc-processing-unit - Run document processing unit tests"
	@echo "  test-doc-processing-integration - Run document processing integration tests"
	@echo "  test-doc-processing-e2e  - Run document processing E2E tests"
	@echo "  test-doc-processing-api  - Test API endpoints (requires running service)"
	@echo "  test-doc-processing-health - Test health endpoints"
	@echo "  test-doc-processing-docker - Run tests with Docker"
	@echo "  doc-processing-start     - Start document processing service"
	@echo "  doc-processing-start-docker - Start service with Docker"
	@echo "  doc-processing-stop      - Stop document processing service"
	@echo "  doc-processing-status    - Check service status"
	@echo "  doc-processing-logs      - View service logs"
	@echo "  doc-processing-clean     - Clean test artifacts"
	@echo ""
	@echo "🎯 Quick Start for Manual Testing:"
	@echo "  make dev-environment    # Complete setup"
	@echo "  make show-endpoints     # View all URLs"
	@echo "  make dev-status         # Check status"
	@echo ""
	@echo "🎬 Quick Start for Demo:"
	@echo "  make demo-environment   # Setup with sample data"

# Default target
.DEFAULT_GOAL := help