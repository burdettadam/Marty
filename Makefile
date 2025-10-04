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
TRUST_SVC_PORT := 8090
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
.PHONY: format lint type-check complexity security security-quick security-deps security-code security-secrets security-containers security-compliance quality-check pre-commit-install pre-commit-run

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
	cd src && $(UV) run mypy services/ marty_common/ trust_svc/ \
		--ignore-missing-imports \
		--show-error-codes \
		--pretty \
		--color-output \
		--error-summary \
		--config-file ../pyproject.toml
	@echo "Type checking services with strict mode..."
	cd src && $(UV) run mypy services/ trust_svc/ \
		--ignore-missing-imports \
		--disable-error-code=misc \
		--disable-error-code=attr-defined \
		--show-error-codes \
		--pretty \
		--color-output \
		--config-file ../pyproject.toml

complexity:
	@echo "Running complexity analysis..."
	xenon --max-average B --max-modules B --max-absolute B src/
	@echo "Running radon complexity check..."
	radon cc src/ -a -s --total-average
	radon mi src/ -s

security:
	@echo "Running comprehensive security checks..."
	./scripts/security_scan.sh full

security-quick:
	@echo "Running quick security checks..."
	$(UV) run bandit -r src/ -f json -o reports/security/code/bandit_report.json || true
	$(UV) run safety check --json --output reports/security/dependency/safety_report.json || true

security-deps:
	@echo "Running dependency vulnerability scan..."
	./scripts/security_scan.sh deps

security-code:
	@echo "Running code security analysis..."
	./scripts/security_scan.sh code

security-secrets:
	@echo "Running secrets detection..."
	./scripts/security_scan.sh secrets

security-containers:
	@echo "Running container security scan..."
	./scripts/security_scan.sh containers

security-compliance:
	@echo "Running compliance checks..."
	./scripts/security_scan.sh compliance

quality-check: format lint type-check complexity security-quick
	@echo "All code quality checks completed!"

# Documentation Targets
.PHONY: docs docs-build docs-serve docs-clean

docs: docs-build
	@echo "API documentation generated successfully!"
	@echo "📖 Open docs/api/index.html to view the documentation"

docs-build:
	@echo "🚀 Generating API documentation for Marty Platform..."
	./scripts/generate_docs.sh

docs-serve: docs-build
	@echo "🌐 Serving API documentation on http://localhost:8000"
	@echo "Press Ctrl+C to stop the server"
	cd docs/api && python -m http.server 8000

docs-clean:
	@echo "🧹 Cleaning generated documentation..."
	rm -rf docs/api/

# Performance Testing Targets
.PHONY: perf-test perf-test-load perf-test-stress perf-test-all perf-test-quick perf-reports-clean

perf-test: perf-test-quick
	@echo "Performance testing completed!"

perf-test-quick:
	@echo "🚀 Running quick performance tests on all services..."
	./scripts/run_perf_test.sh pkd_service load 5 30
	./scripts/run_perf_test.sh document_processing load 5 30
	./scripts/run_perf_test.sh ui_app load 5 30

perf-test-load:
	@echo "🚀 Running load tests..."
	./scripts/run_perf_test.sh $(SERVICE) load $(USERS) $(DURATION)

perf-test-stress:
	@echo "🔥 Running stress tests..."
	$(UV) run python scripts/performance_test.py stress $(SERVICE) --max-users $(MAX_USERS) --ramp-up $(RAMP_UP)

perf-test-all:
	@echo "🚀 Running comprehensive performance tests..."
	@for service in pkd_service document_processing ui_app; do \
		echo "Testing $$service with load test..."; \
		./scripts/run_perf_test.sh $$service load 10 60; \
		echo "Testing $$service with stress test..."; \
		$(UV) run python scripts/performance_test.py stress $$service --max-users 50 --ramp-up 180; \
	done

perf-reports-clean:
	@echo "🧹 Cleaning performance test reports..."
	rm -rf reports/performance/

# Centralized Logging Targets
.PHONY: logging-setup logging-start logging-stop logging-status logging-logs logging-clean
logging-setup: ## Set up centralized logging infrastructure
	@echo "🔧 Setting up centralized logging..."
	./scripts/setup_logging.sh

logging-start: ## Start logging infrastructure
	@echo "🚀 Starting logging infrastructure..."
	docker-compose -f docker/docker-compose.logging.yml up -d

logging-stop: ## Stop logging infrastructure
	@echo "🛑 Stopping logging infrastructure..."
	docker-compose -f docker/docker-compose.logging.yml down

logging-status: ## Check logging infrastructure status
	@echo "📊 Logging infrastructure status:"
	docker-compose -f docker/docker-compose.logging.yml ps

logging-logs: ## View logging infrastructure logs
	@echo "📝 Viewing logging infrastructure logs..."
	docker-compose -f docker/docker-compose.logging.yml logs -f

logging-clean: ## Clean logging data and stop services
	@echo "🧹 Cleaning logging infrastructure..."
	docker-compose -f docker/docker-compose.logging.yml down -v
	docker volume prune -f

mypy-services:
	@echo "Running mypy type checking on services..."
	cd src && $(UV) run mypy services/ marty_common/ \
		--config-file ../pyproject.toml \
		--show-error-codes \
		--pretty \
		--color-output \
		--error-summary

mypy-strict:
	@echo "Running strict mypy checking (for CI/CD)..."
	$(UV) run mypy src/services/ src/marty_common/ \
		--config-file pyproject.toml \
		--strict \
		--show-error-codes \
		--pretty \
		--color-output \
		--error-summary \
		--junit-xml mypy-report.xml

validate-types:
	@echo "Validating type annotations across all services..."
	@echo "Checking service dependencies protocol compliance..."
	$(UV) run python -c "from src.marty_common.grpc_types import ServiceDependencies; print('✓ ServiceDependencies protocol is valid')"
	@echo "Running type validation on core services..."
	$(UV) run mypy --no-error-summary src/services/trust_anchor.py src/services/document_signer.py src/services/certificate_lifecycle_manager.py src/services/csca.py src/services/pkd_service.py src/services/mdl_engine.py src/services/dtc_engine.py src/services/passport_engine.py src/services/mdoc_engine.py
	@echo "✓ All service type annotations validated successfully!"

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
	@echo "Development credentials loaded from docker/openxpki.env and data/openxpki/secrets/*.txt (DO NOT USE IN PROD)"

.PHONY: setup clean test lint format proto compile-protos clean-protos build run docker-build docker-run test-unit test-integration test-e2e test-e2e-k8s test-e2e-k8s-existing test-e2e-k8s-smoke test-e2e-k8s-monitoring test-e2e-clean test-e2e-docker-legacy test-integration-docker-legacy test-cert-validator test-e2e-ui playwright-install generate-test-data help run-ui run-service-ui run-services-dev check-services stop-services dev-environment demo-environment dev-minimal dev-full dev-status dev-logs dev-clean dev-restart wait-for-services show-endpoints test-performance test-coverage test-security test-setup setup-openxpki test-doc-processing test-doc-processing-unit test-doc-processing-integration test-doc-processing-e2e test-doc-processing-docker test-doc-processing-api test-doc-processing-health doc-processing-start doc-processing-stop doc-processing-status doc-processing-logs doc-processing-clean test-trust-svc test-trust-svc-unit test-trust-svc-integration test-trust-svc-e2e test-trust-svc-docker test-trust-svc-api test-trust-svc-health trust-svc-start trust-svc-start-docker trust-svc-stop trust-svc-status trust-svc-logs trust-svc-dev-job trust-svc-load-data trust-svc-clean

PYTHON := uv run python
UV := uv
DOCKER := docker
DOCKER_COMPOSE := docker compose -f docker/docker-compose.yml

# List of all deployable services (used for image build/tag/load loops)
SERVICES ?= trust-anchor csca-service document-signer inspection-system passport-engine mdl-engine mdoc-engine dtc-engine credential-ledger pkd-service ui-app

# Minimal set of services required for core passport/mvp UI flows
MINIMAL_SERVICES ?= trust-anchor csca-service document-signer passport-engine ui-app

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

# Run all tests with proper orchestration (now K8s-based for E2E)
test: test-unit test-integration test-e2e test-cert-validator

# Run comprehensive tests including OpenID4VP integration tests
test-comprehensive: test-unit test-integration test-e2e test-cert-validator test-openid4vp
	@echo "✅ All comprehensive tests completed including OpenID4VP!"

# Run all OpenID4VP and presentation-related tests
test-presentations: test-openid4vp test-mdl-mdoc
	@echo "✅ All presentation tests completed!"

# Run unit tests (no services needed)
test-unit:
	@echo "Running unit tests with UV..."
	@$(UV) run pytest tests/unit/ -v --ignore=tests/unit/test_monitoring.py --ignore=tests/unit/test_complete_certificate_lifecycle.py

# Run integration tests (with required services)
test-integration:
	@echo "Running integration tests..."
	@$(UV) run pytest tests/integration/ -v --maxfail=3 --disable-warnings



# Run end-to-end tests with Kubernetes (recommended)
test-e2e: test-e2e-k8s
	@echo "✅ E2E tests completed with Kubernetes"



# Run certificate validator tests (no services needed)
test-cert-validator:
	@echo "Running certificate validation tests..."
	@$(UV) run pytest tests/cert_validator/ -v

# =============================================================================
# KUBERNETES-BASED E2E TESTING COMMANDS
# =============================================================================

# Run E2E tests with Kubernetes (recommended)
test-e2e-k8s: k8s-setup
	@echo "🎯 Running E2E tests with Kubernetes..."
	@echo "📦 Deploying services for E2E testing..."
	@$(MAKE) k8s-deploy
	@echo "⏳ Waiting for all pods to be ready..."
	@kubectl wait --for=condition=ready pod --all -n $(K8S_NAMESPACE) --timeout=300s
	@echo "🌐 Setting up port forwarding for tests..."
	@$(MAKE) k8s-port-forward &
	@sleep 10  # Allow port forwarding to establish
	@echo "🧪 Running E2E tests..."
	@$(UV) run pytest tests/e2e/ -v --tb=short -m "not docker" || TEST_RESULT=$$?; \
		echo "🧹 Cleaning up port forwarding..."; \
		pkill -f "kubectl port-forward" || true; \
		exit $${TEST_RESULT:-0}

# Run E2E tests with existing K8s cluster (faster for development)
test-e2e-k8s-existing:
	@echo "🎯 Running E2E tests with existing Kubernetes cluster..."
	@if ! kubectl cluster-info --context $(K8S_CONTEXT) >/dev/null 2>&1; then \
		echo "❌ Kubernetes cluster not found. Run 'make k8s-setup' first."; \
		exit 1; \
	fi
	@echo "🔍 Checking if services are deployed..."
	@if ! kubectl get deployment ui-app -n $(K8S_NAMESPACE) >/dev/null 2>&1; then \
		echo "⚠️  Services not deployed. Deploying now..."; \
		$(MAKE) k8s-deploy; \
	fi
	@echo "⏳ Ensuring all pods are ready..."
	@kubectl wait --for=condition=ready pod --all -n $(K8S_NAMESPACE) --timeout=120s
	@echo "🧪 Running E2E tests..."
	@$(UV) run pytest tests/e2e/ -v --tb=short -m "not docker"

# Run E2E smoke tests with K8s (quick validation)
test-e2e-k8s-smoke:
	@echo "💨 Running E2E smoke tests with Kubernetes..."
	@$(MAKE) k8s-setup
	@$(MAKE) k8s-deploy
	@kubectl wait --for=condition=ready pod --all -n $(K8S_NAMESPACE) --timeout=300s
	@$(MAKE) k8s-port-forward &
	@sleep 10
	@$(UV) run pytest tests/e2e/ -v --tb=short -m "smoke and not docker" || TEST_RESULT=$$?; \
		pkill -f "kubectl port-forward" || true; \
		exit $${TEST_RESULT:-0}

# Run E2E tests with monitoring enabled
test-e2e-k8s-monitoring:
	@echo "📊 Running E2E tests with monitoring stack..."
	@$(MAKE) k8s-setup
	@$(MAKE) k8s-deploy
	@$(MAKE) k8s-monitoring
	@kubectl wait --for=condition=ready pod --all -n $(K8S_NAMESPACE) --timeout=300s
	@kubectl wait --for=condition=ready pod --all -n marty-system --timeout=300s
	@$(MAKE) k8s-port-forward &
	@kubectl port-forward svc/marty-monitoring-grafana 3000:3000 -n marty-system &
	@sleep 15
	@echo "🧪 Running E2E tests with monitoring..."
	@$(UV) run pytest tests/e2e/ -v --tb=short -m "monitoring" || TEST_RESULT=$$?; \
		pkill -f "kubectl port-forward" || true; \
		exit $${TEST_RESULT:-0}

# Clean E2E test environment
test-e2e-clean:
	@echo "🧹 Cleaning E2E test environment..."
	@pkill -f "kubectl port-forward" || true
	@$(MAKE) k8s-undeploy || true
	@$(MAKE) k8s-destroy || true
	@echo "✅ E2E environment cleaned"

# Legacy Docker-based E2E (deprecated - will be removed in next release)
test-e2e-docker-legacy:
	@echo "⚠️  DEPRECATED: Docker-based E2E testing"
	@echo "   Use 'make test-e2e-k8s' instead for production parity"
	@echo "   This command will be removed in the next major release."
	@echo "🐳 Running legacy Docker E2E tests..."
	@$(UV) run python -m tests.test_orchestrator e2e tests/e2e/

# Legacy integration tests (deprecated)
test-integration-docker-legacy:
	@echo "⚠️  DEPRECATED: Docker-based integration testing"
	@echo "   Use 'make test-integration' with Kubernetes instead"
	@echo "   This command will be removed in the next major release."
	@echo "🐳 Running legacy Docker integration tests..."
	@$(UV) run python -m tests.test_orchestrator integration tests/integration/

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

# Run only smoke tests (quick validation) with Kubernetes
test-e2e-smoke:
	@echo "Running Playwright smoke tests with Kubernetes..."
	@echo "Setting up K8s environment for smoke testing..."
	@$(MAKE) k8s-setup >/dev/null 2>&1 || true
	@$(MAKE) k8s-deploy >/dev/null 2>&1 || true
	@kubectl wait --for=condition=ready pod --all -n $(K8S_NAMESPACE) --timeout=120s >/dev/null 2>&1 || true
	@$(MAKE) k8s-port-forward &
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
		echo "Cleaning up..."; \
		pkill -f "kubectl port-forward" >/dev/null 2>&1 || true; \
		exit $${TEST_RESULT:-0}

# Run E2E tests with existing service (checks K8s port-forward or local service)
test-e2e-ui-existing:
	@echo "Running Playwright E2E tests against existing service..."
	@if ! curl -s http://localhost:8090/health >/dev/null 2>&1; then \
		echo "❌ UI service not found at localhost:8090"; \
		echo "💡 Options:"; \
		echo "  1. Start K8s port forwarding: make k8s-port-forward"; \
		echo "  2. Start local UI service: make run-ui"; \
		echo "  3. Use automated K8s setup: make test-e2e-k8s"; \
		exit 1; \
	fi
	@echo "✅ UI service detected, running tests..."
	@$(UV) run pytest tests/e2e/ -v --tb=short

# Run Playwright tests requiring the full real service stack with Kubernetes
test-e2e-ui-integration:
	@echo "Running full-stack Playwright integration UI tests with Kubernetes..."
	@echo "Setting up K8s environment for integration tests..."
	@$(MAKE) k8s-setup
	@$(MAKE) k8s-deploy
	@kubectl wait --for=condition=ready pod --all -n $(K8S_NAMESPACE) --timeout=300s
	@$(MAKE) k8s-port-forward &
	@echo "Waiting for services to be ready..."
	@sleep 15
	@echo "Running integration tests..."
	@$(UV) run pytest tests/e2e/ -m "integration and ui" -v --tb=short || TEST_RESULT=$$?; \
		echo "Cleaning up..."; \
		pkill -f "kubectl port-forward" || true; \
		exit $${TEST_RESULT:-0}

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

# Generate E2E test report with HTML output using Kubernetes
test-e2e-report:
	@echo "Running E2E tests with HTML report generation (Kubernetes)..."
	@mkdir -p tests/e2e/reports
	@echo "Setting up K8s environment for report generation..."
	@$(MAKE) k8s-setup >/dev/null 2>&1
	@$(MAKE) k8s-deploy >/dev/null 2>&1
	@kubectl wait --for=condition=ready pod --all -n $(K8S_NAMESPACE) --timeout=300s >/dev/null 2>&1
	@$(MAKE) k8s-port-forward &
	@echo "Waiting for UI service..."
	@timeout=30; while [ $$timeout -gt 0 ]; do \
		if curl -s http://localhost:8090/health >/dev/null 2>&1; then break; fi; \
		sleep 2; timeout=$$((timeout-2)); \
	done
	@$(UV) run pytest tests/e2e/ --html=tests/e2e/reports/report.html --self-contained-html -v || TEST_RESULT=$$?; \
		pkill -f "kubectl port-forward" >/dev/null 2>&1 || true; \
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

# OpenID4VP Integration Testing Commands
test-openid4vp: test-openid4vp-setup
	@echo "Running OpenID4VP integration tests..."
	@$(UV) run pytest tests/integration/test_mdoc_mdl_openid4vp_integration.py -m openid4vp -v

test-openid4vp-mdoc:
	@echo "Running mDoc OpenID4VP presentation tests..."
	@$(UV) run pytest tests/integration/test_mdoc_mdl_openid4vp_integration.py -m mdoc_presentation -v

test-openid4vp-mdl:
	@echo "Running mDL OpenID4VP presentation tests..."
	@$(UV) run pytest tests/integration/test_mdoc_mdl_openid4vp_integration.py -m mdl_presentation -v

test-openid4vp-setup:
	@echo "Setting up OpenID4VP test environment..."
	@$(UV) run python scripts/setup_openid4vp_tests.py

test-openid4vp-quick:
	@echo "Running quick OpenID4VP smoke tests..."
	@$(UV) run pytest tests/integration/test_mdoc_mdl_openid4vp_integration.py::TestMDocOpenID4VPIntegration::test_complete_mdoc_openid4vp_flow -v
	@$(UV) run pytest tests/integration/test_mdoc_mdl_openid4vp_integration.py::TestMDLOpenID4VPIntegration::test_complete_mdl_openid4vp_flow -v

test-openid4vp-selective-disclosure:
	@echo "Running selective disclosure tests..."
	@$(UV) run pytest tests/integration/test_mdoc_mdl_openid4vp_integration.py -k "selective_disclosure" -v

test-openid4vp-age-verification:
	@echo "Running age verification tests..."
	@$(UV) run pytest tests/integration/test_mdoc_mdl_openid4vp_integration.py -k "age_verification" -v

test-openid4vp-privacy:
	@echo "Running privacy-preserving presentation tests..."
	@$(UV) run pytest tests/integration/test_mdoc_mdl_openid4vp_integration.py -k "privacy" -v

test-openid4vp-real-world:
	@echo "Running real-world scenario tests..."
	@$(UV) run pytest tests/integration/test_mdoc_mdl_openid4vp_integration.py -k "venue_access or rental or border" -v

test-openid4vp-collect:
	@echo "Collecting OpenID4VP tests without running..."
	@$(UV) run pytest tests/integration/test_mdoc_mdl_openid4vp_integration.py --collect-only -q

# Test with mock services only\ntest-mock:\n\t@echo \"Running tests with mock services...\"\n\t@$(UV) run -m pytest tests/unit tests/integration -k \"not docker\" -v\n\n# Generate protobuf code\nproto:\n\t@echo \"Compiling protobuf files...\"\n\t@$(PYTHON) -m src.compile_protos

# Run a specific service locally
run-service-%:
	@echo "Running $* service..."
	@MODULE=$(subst -,_,$*); \
	SERVICE_NAME=$* GRPC_PORT=$(shell sed -n -e "s/^  $*/port: //p" config/development.yaml | head -n 1 | tr -d '[:space:]') $(UV) run python -m src.apps.$$MODULE

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
	@curl -s http://localhost:$(TRUST_SVC_PORT)/api/v1/admin/status && echo "Trust Service: OK" || echo "Trust Service: FAILED"
	@curl -s http://localhost:$(UI_PORT)/health && echo "UI Service: OK" || echo "UI Service: FAILED"

# Stop all services
stop-services:
	@echo "Stopping all services..."
	@$(DOCKER_COMPOSE) down
	@pkill -f "uvicorn.*ui_app" || true
	@echo "Services stopped"

# =============================================================================
# KUBERNETES DEVELOPMENT COMMANDS
# =============================================================================

# Kubernetes configuration
K8S_CLUSTER_NAME ?= marty-dev
K8S_NAMESPACE ?= marty
K8S_CONTEXT ?= kind-$(K8S_CLUSTER_NAME)
KUBECTL_VERSION ?= v1.28.0
KIND_VERSION ?= v0.20.0
HELM_VERSION ?= v3.13.0
SKAFFOLD_VERSION ?= v2.7.0

# Port forwarding configuration
GRAFANA_PORT ?= 3000
PROMETHEUS_PORT ?= 9090
ALERTMANAGER_PORT ?= 9093
PUSHGATEWAY_PORT ?= 9091

.PHONY: k8s-check-tools k8s-setup k8s-destroy k8s-status k8s-deploy k8s-undeploy k8s-restart k8s-logs k8s-port-forward k8s-port-forward-stop k8s-port-forward-status k8s-get-passwords k8s-monitoring k8s-dev k8s-dev-full

# Check if required Kubernetes tools are installed
k8s-check-tools:
	@echo "🔧 Checking Kubernetes tools..."
	@command -v docker >/dev/null 2>&1 || { echo "❌ Docker is required but not installed. Please install Docker Desktop."; exit 1; }
	@docker info >/dev/null 2>&1 || { echo "❌ Docker is not running. Please start Docker Desktop."; exit 1; }
	@command -v kubectl >/dev/null 2>&1 || { echo "❌ kubectl is required. Installing..."; $(MAKE) k8s-install-kubectl; }
	@command -v kind >/dev/null 2>&1 || { echo "❌ kind is required. Installing..."; $(MAKE) k8s-install-kind; }
	@command -v helm >/dev/null 2>&1 || { echo "❌ helm is required. Installing..."; $(MAKE) k8s-install-helm; }
	@echo "✅ All required tools are available"

# Install kubectl
k8s-install-kubectl:
	@echo "📦 Installing kubectl..."
	@if [[ "$$OSTYPE" == "darwin"* ]]; then \
		if command -v brew >/dev/null 2>&1; then \
			brew install kubectl; \
		else \
			curl -LO "https://dl.k8s.io/release/$(KUBECTL_VERSION)/bin/darwin/amd64/kubectl" && \
			chmod +x kubectl && \
			sudo mv kubectl /usr/local/bin/; \
		fi \
	elif [[ "$$OSTYPE" == "linux-gnu"* ]]; then \
		curl -LO "https://dl.k8s.io/release/$(KUBECTL_VERSION)/bin/linux/amd64/kubectl" && \
		chmod +x kubectl && \
		sudo mv kubectl /usr/local/bin/; \
	else \
		echo "❌ Unsupported OS: $$OSTYPE"; exit 1; \
	fi

# Install kind
k8s-install-kind:
	@echo "📦 Installing kind..."
	@if [[ "$$OSTYPE" == "darwin"* ]]; then \
		if command -v brew >/dev/null 2>&1; then \
			brew install kind; \
		else \
			curl -Lo ./kind "https://kind.sigs.k8s.io/dl/$(KIND_VERSION)/kind-darwin-amd64" && \
			chmod +x ./kind && \
			sudo mv ./kind /usr/local/bin/kind; \
		fi \
	elif [[ "$$OSTYPE" == "linux-gnu"* ]]; then \
		curl -Lo ./kind "https://kind.sigs.k8s.io/dl/$(KIND_VERSION)/kind-linux-amd64" && \
		chmod +x ./kind && \
		sudo mv ./kind /usr/local/bin/kind; \
	else \
		echo "❌ Unsupported OS: $$OSTYPE"; exit 1; \
	fi

# Install helm
k8s-install-helm:
	@echo "📦 Installing helm..."
	@curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

# Install skaffold
k8s-install-skaffold:
	@echo "📦 Installing skaffold..."
	@if [[ "$$OSTYPE" == "darwin"* ]]; then \
		if command -v brew >/dev/null 2>&1; then \
			brew install skaffold; \
		else \
			curl -Lo skaffold "https://storage.googleapis.com/skaffold/releases/$(SKAFFOLD_VERSION)/skaffold-darwin-amd64" && \
			chmod +x skaffold && \
			sudo mv skaffold /usr/local/bin; \
		fi \
	elif [[ "$$OSTYPE" == "linux-gnu"* ]]; then \
		curl -Lo skaffold "https://storage.googleapis.com/skaffold/releases/$(SKAFFOLD_VERSION)/skaffold-linux-amd64" && \
		chmod +x skaffold && \
		sudo mv skaffold /usr/local/bin; \
	else \
		echo "❌ Unsupported OS: $$OSTYPE"; exit 1; \
	fi

# Set up local Kubernetes development environment
k8s-setup: k8s-check-tools
	@echo "🚀 Setting up Kubernetes development environment..."
	@if kind get clusters | grep -q "^$(K8S_CLUSTER_NAME)$$"; then \
		echo "⚠️  Kind cluster '$(K8S_CLUSTER_NAME)' already exists. Skipping creation."; \
	else \
		echo "🏗️  Creating Kind cluster '$(K8S_CLUSTER_NAME)'..."; \
		echo 'kind: Cluster\napiVersion: kind.x-k8s.io/v1alpha4\nname: $(K8S_CLUSTER_NAME)\nnodes:\n- role: control-plane\n  kubeadmConfigPatches:\n  - |\n    kind: InitConfiguration\n    nodeRegistration:\n      kubeletExtraArgs:\n        node-labels: "ingress-ready=true"\n  extraPortMappings:\n  - containerPort: 80\n    hostPort: 80\n    protocol: TCP\n  - containerPort: 443\n    hostPort: 443\n    protocol: TCP\n  - containerPort: 8085\n    hostPort: 8085\n    protocol: TCP\n  - containerPort: 8090\n    hostPort: 8090\n    protocol: TCP\n- role: worker\n- role: worker\nnetworking:\n  apiServerAddress: "127.0.0.1"\n  apiServerPort: 6443' > /tmp/kind-config.yaml; \
		kind create cluster --config=/tmp/kind-config.yaml; \
		rm /tmp/kind-config.yaml; \
	fi
	@echo "🌐 Setting up NGINX Ingress Controller..."
	@kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/kind/deploy.yaml
	@echo "⏳ Waiting for ingress controller to be ready..."
	@kubectl wait --namespace ingress-nginx --for=condition=ready pod --selector=app.kubernetes.io/component=controller --timeout=90s
	@echo "📁 Creating namespaces..."
	@kubectl create namespace $(K8S_NAMESPACE) --dry-run=client -o yaml | kubectl apply -f -
	@kubectl create namespace marty-system --dry-run=client -o yaml | kubectl apply -f -
	@kubectl config set-context --current --namespace=$(K8S_NAMESPACE)
	@echo "📦 Adding Helm repositories..."
	@helm repo add prometheus-community https://prometheus-community.github.io/helm-charts || true
	@helm repo add grafana https://grafana.github.io/helm-charts || true
	@helm repo add bitnami https://charts.bitnami.com/bitnami || true
	@helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx || true
	@helm repo update
	@echo "💾 Setting up local storage..."
	@echo 'apiVersion: storage.k8s.io/v1\nkind: StorageClass\nmetadata:\n  name: marty-local-storage\n  annotations:\n    storageclass.kubernetes.io/is-default-class: "true"\nprovisioner: rancher.io/local-path\nvolumeBindingMode: WaitForFirstConsumer\nreclaimPolicy: Delete' | kubectl apply -f -
	@echo "🔒 Creating TLS certificate..."
	@openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /tmp/tls.key -out /tmp/tls.crt -subj "/CN=marty.local/O=marty.local" -addext "subjectAltName=DNS:marty.local,DNS:*.marty.local,DNS:localhost" 2>/dev/null || true
	@kubectl create secret tls marty-tls --key /tmp/tls.key --cert /tmp/tls.crt --namespace $(K8S_NAMESPACE) --dry-run=client -o yaml | kubectl apply -f - || true
	@rm -f /tmp/tls.key /tmp/tls.crt
	@echo "✅ Kubernetes development environment ready!"
	@echo "📋 Summary:"
	@echo "  - Cluster: $(K8S_CLUSTER_NAME)"
	@echo "  - Context: $(K8S_CONTEXT)"
	@echo "  - Namespaces: $(K8S_NAMESPACE), marty-system"
	@echo "  - Ingress: NGINX (localhost:80, localhost:443)"
	@echo ""
	@echo "🚀 Next steps:"
	@echo "  make k8s-deploy       # Deploy all services"
	@echo "  make k8s-port-forward # Set up port forwarding"
	@echo "  make k8s-monitoring   # Deploy monitoring stack"

# Destroy the local Kubernetes cluster
k8s-destroy:
	@echo "💥 Destroying Kind cluster '$(K8S_CLUSTER_NAME)'..."
	@kind delete cluster --name "$(K8S_CLUSTER_NAME)"
	@echo "✅ Cluster '$(K8S_CLUSTER_NAME)' destroyed"

# Check cluster and pod status
k8s-status:
	@echo "📊 Checking Kubernetes cluster status..."
	@if kind get clusters | grep -q "^$(K8S_CLUSTER_NAME)$$"; then \
		echo "✅ Cluster '$(K8S_CLUSTER_NAME)' is running"; \
		kubectl cluster-info --context $(K8S_CONTEXT); \
		echo ""; \
		echo "📦 Nodes:"; \
		kubectl get nodes; \
		echo ""; \
		echo "🚀 Pods in $(K8S_NAMESPACE) namespace:"; \
		kubectl get pods -n $(K8S_NAMESPACE); \
		echo ""; \
		echo "🌐 Services in $(K8S_NAMESPACE) namespace:"; \
		kubectl get svc -n $(K8S_NAMESPACE); \
	else \
		echo "❌ Cluster '$(K8S_CLUSTER_NAME)' does not exist. Run 'make k8s-setup' first."; \
	fi

# Deploy all services to Kubernetes
k8s-deploy: compile-protos
	@echo "🚀 Deploying Marty services to Kubernetes..."
	@echo "🏗️  Building Docker images first..."
	@$(MAKE) docker-build
	@echo "🏷️  Tagging images for Kubernetes..."
	@echo "Using service set: $(SERVICES)"; \
	for service in $(SERVICES); do \
		echo "Tagging docker-$$service:latest -> marty/$$service:latest"; \
		docker tag docker-$$service:latest marty/$$service:latest; \
	done
	@echo "📦 Loading images into Kind cluster..."
	@for service in $(SERVICES); do \
		echo "Loading marty/$$service:latest..."; \
		kind load docker-image marty/$$service:latest --name $(K8S_CLUSTER_NAME) || true; \
	done
	@echo "📋 Ensuring namespace exists..."
	@kubectl create namespace $(K8S_NAMESPACE) --dry-run=client -o yaml | kubectl apply -f -
	@echo "📋 Deploying infrastructure components..."
	@helm upgrade --install postgres bitnami/postgresql \
		--namespace $(K8S_NAMESPACE) \
		--set auth.username=martyuser \
		--set auth.password=martypassword \
		--set auth.database=martydb \
		--set primary.persistence.size=1Gi \
		--wait --timeout=300s
	@echo "🔄 Deploying Marty services..."
	@for chart in helm/charts/*; do \
		if [ -d "$$chart" ] && [ -f "$$chart/Chart.yaml" ]; then \
			service=$$(basename $$chart); \
			echo "Deploying $$service..."; \
			helm upgrade --install $$service $$chart \
				--namespace $(K8S_NAMESPACE) \
				--set image.tag=latest \
				--set image.pullPolicy=Never \
				--wait --timeout=300s || true; \
		fi \
	done
	@echo "✅ All services deployed to Kubernetes!"
	@echo "🌐 Access the application:"
	@echo "  kubectl port-forward svc/ui-app 8090:8090 -n $(K8S_NAMESPACE)"

# Deploy only minimal subset of services (space-saving / faster loop)
.PHONY: k8s-deploy-minimal
k8s-deploy-minimal: compile-protos
	@echo "🚀 Deploying minimal Marty service set to Kubernetes ($(MINIMAL_SERVICES))..."
	@$(MAKE) docker-build
	@echo "🏷️  Tagging minimal images..."
	@for service in $(MINIMAL_SERVICES); do \
		echo "Tagging docker-$$service:latest -> marty/$$service:latest"; \
		docker tag docker-$$service:latest marty/$$service:latest; \
	done
	@echo "📦 Loading minimal images into Kind cluster..."
	@for service in $(MINIMAL_SERVICES); do \
		echo "Loading marty/$$service:latest..."; \
		kind load docker-image marty/$$service:latest --name $(K8S_CLUSTER_NAME) || true; \
	done
	@echo "📋 Ensuring namespace exists..."
	@kubectl create namespace $(K8S_NAMESPACE) --dry-run=client -o yaml | kubectl apply -f -
	@echo "📋 Deploying infrastructure components (Postgres)..."
	@helm upgrade --install postgres bitnami/postgresql \
		--namespace $(K8S_NAMESPACE) \
		--set auth.username=martyuser \
		--set auth.password=martypassword \
		--set auth.database=martydb \
		--set primary.persistence.size=1Gi \
		--wait --timeout=300s
	@echo "🔄 Deploying minimal Marty services..."
	@for chart in helm/charts/*; do \
		if [ -d "$$chart" ] && [ -f "$$chart/Chart.yaml" ]; then \
			service=$$(basename $$chart); \
			case " $(MINIMAL_SERVICES) " in *" $$service "*) \
				echo "Deploying $$service (minimal)..."; \
				helm upgrade --install $$service $$chart \
					--namespace $(K8S_NAMESPACE) \
					--set image.tag=latest \
					--set image.pullPolicy=Never \
					--wait --timeout=300s || true; \
			;; \
			*) echo "Skipping $$service (not in minimal set)";; \
			esac; \
		fi; \
	done
	@echo "✅ Minimal services deployed!"
	@echo "🌐 Access the application:"
	@echo "  kubectl port-forward svc/ui-app 8090:8090 -n $(K8S_NAMESPACE)"

# Remove all services from Kubernetes
k8s-undeploy:
	@echo "🧹 Removing all Marty services from Kubernetes..."
	@helm list -n $(K8S_NAMESPACE) --short | xargs -r helm uninstall -n $(K8S_NAMESPACE) || true
	@echo "✅ All services removed"

# Restart all services in Kubernetes
k8s-restart:
	@echo "🔄 Restarting all services in Kubernetes..."
	@kubectl rollout restart deployment -n $(K8S_NAMESPACE)
	@kubectl rollout status deployment --all -n $(K8S_NAMESPACE) --timeout=300s
	@echo "✅ All services restarted"

# Show logs from all services
k8s-logs:
	@echo "📋 Showing logs from all services..."
	@kubectl logs -l app.kubernetes.io/name --all-containers=true --tail=50 -n $(K8S_NAMESPACE)

# Set up port forwarding for development
k8s-port-forward:
	@echo "🌐 Setting up port forwarding for development..."
	@echo "Stopping any existing port forwards..."
	@pkill -f "kubectl port-forward" || true
	@sleep 2
	@echo "Starting port forwards in background..."
	@echo "📊 Setting up monitoring services..."
	@kubectl port-forward svc/grafana $(GRAFANA_PORT):80 -n marty-system > /dev/null 2>&1 &
	@kubectl port-forward svc/prometheus-server $(PROMETHEUS_PORT):80 -n marty-system > /dev/null 2>&1 &
	@kubectl port-forward svc/prometheus-alertmanager $(ALERTMANAGER_PORT):9093 -n marty-system > /dev/null 2>&1 &
	@kubectl port-forward svc/prometheus-prometheus-pushgateway $(PUSHGATEWAY_PORT):9091 -n marty-system > /dev/null 2>&1 &
	@echo "🚀 Setting up application services..."
	@kubectl port-forward svc/ui-app 8090:8090 -n $(K8S_NAMESPACE) > /dev/null 2>&1 & 2>/dev/null || true
	@kubectl port-forward svc/csca-service 8081:8081 -n $(K8S_NAMESPACE) > /dev/null 2>&1 & 2>/dev/null || true
	@kubectl port-forward svc/document-signer 8082:8082 -n $(K8S_NAMESPACE) > /dev/null 2>&1 & 2>/dev/null || true
	@kubectl port-forward svc/inspection-system 8083:8083 -n $(K8S_NAMESPACE) > /dev/null 2>&1 & 2>/dev/null || true
	@kubectl port-forward svc/passport-engine 8084:8084 -n $(K8S_NAMESPACE) > /dev/null 2>&1 & 2>/dev/null || true
	@kubectl port-forward svc/mdl-engine 8085:8085 -n $(K8S_NAMESPACE) > /dev/null 2>&1 & 2>/dev/null || true
	@kubectl port-forward svc/mdoc-engine 8086:8086 -n $(K8S_NAMESPACE) > /dev/null 2>&1 & 2>/dev/null || true
	@kubectl port-forward svc/dtc-engine 8087:8087 -n $(K8S_NAMESPACE) > /dev/null 2>&1 & 2>/dev/null || true
	@kubectl port-forward svc/pkd-service 8088:8088 -n $(K8S_NAMESPACE) > /dev/null 2>&1 & 2>/dev/null || true
	@sleep 3
	@echo "✅ Port forwarding active. Use 'make k8s-port-forward-stop' to stop."
	@echo "📊 Monitoring URLs:"
	@echo "  Grafana:            http://localhost:$(GRAFANA_PORT)"
	@echo "  Prometheus:         http://localhost:$(PROMETHEUS_PORT)"
	@echo "  AlertManager:       http://localhost:$(ALERTMANAGER_PORT)"
	@echo "  Pushgateway:        http://localhost:$(PUSHGATEWAY_PORT)"
	@echo "🌐 Application URLs:"
	@echo "  UI App:             http://localhost:8090"
	@echo "  CSCA Service:       http://localhost:8081"
	@echo "  Document Signer:    http://localhost:8082"
	@echo "  Inspection System:  http://localhost:8083"
	@echo "  Passport Engine:    http://localhost:8084"
	@echo "  MDL Engine:         http://localhost:8085"
	@echo "  mDoc Engine:        http://localhost:8086"
	@echo "  DTC Engine:         http://localhost:8087"
	@echo "  PKD Service:        http://localhost:8088"
	@echo "💡 Tip: Access credentials with 'make k8s-get-passwords'"

.PHONY: k8s-port-forward-stop
k8s-port-forward-stop: ## Stop all Kubernetes port forwarding
	@echo "🛑 Stopping all port forwarding..."
	@pkill -f "kubectl port-forward" || echo "No port forwarding processes found"
	@echo "✅ Port forwarding stopped"

.PHONY: k8s-port-forward-status
k8s-port-forward-status: ## Check status of port forwarding
	@echo "📊 Checking port forwarding status..."
	@echo "Active kubectl port-forward processes:"
	@ps aux | grep "kubectl port-forward" | grep -v grep || echo "No active port forwarding found"
	@echo ""
	@echo "Port usage check:"
	@netstat -an | grep -E ':(3000|9090|9091|9093|8081|8082|8083|8084|8085|8086|8087|8088|8090)' | grep LISTEN || echo "No listeners found on monitored ports"

.PHONY: k8s-get-passwords
k8s-get-passwords: ## Get Grafana admin password and other credentials
	@echo "🔑 Retrieving credentials..."
	@echo ""
	@echo "📊 Grafana Admin Password:"
	@kubectl get secret --namespace marty-system grafana -o jsonpath="{.data.admin-password}" | base64 --decode || echo "Grafana password not found"
	@echo ""
	@echo ""
	@echo "🔍 Other available secrets:"
	@kubectl get secrets --all-namespaces | grep -v Opaque | head -10

.PHONY: k8s-dev-full
k8s-dev-full: k8s-setup k8s-deploy k8s-monitoring k8s-port-forward ## Complete development environment setup
	@echo "🎉 Full development environment ready!"
	@echo ""
	@echo "📊 Monitoring Stack:"
	@echo "  Grafana:            http://localhost:$(GRAFANA_PORT) (admin/[see k8s-get-passwords])"
	@echo "  Prometheus:         http://localhost:$(PROMETHEUS_PORT)"
	@echo "  AlertManager:       http://localhost:$(ALERTMANAGER_PORT)"
	@echo ""
	@echo "🌐 Application URLs:"
	@echo "  UI App:             http://localhost:8090"
	@echo "  CSCA Service:       http://localhost:8081"
	@echo "  Document Signer:    http://localhost:8082"
	@echo "  Inspection System:  http://localhost:8083"
	@echo "  Passport Engine:    http://localhost:8084"
	@echo "  MDL Engine:         http://localhost:8085"
	@echo "  mDoc Engine:        http://localhost:8086"
	@echo "  DTC Engine:         http://localhost:8087"
	@echo "  PKD Service:        http://localhost:8088"
	@echo ""
	@echo "💡 Useful commands:"
	@echo "  make k8s-get-passwords    # Get access credentials"
	@echo "  make k8s-port-forward-status  # Check port forwarding"
	@echo "  make k8s-port-forward-stop    # Stop port forwarding"
	@echo "  make k8s-logs            # View service logs"

# Deploy monitoring stack (Prometheus/Grafana)
k8s-monitoring:
	@echo "📊 Deploying monitoring stack..."
	@helm upgrade --install marty-monitoring helm/charts/monitoring \
		--namespace marty-system \
		--create-namespace \
		--wait --timeout=300s
	@echo "✅ Monitoring stack deployed!"
	@echo "🌐 Access monitoring:"
	@echo "  kubectl port-forward svc/marty-monitoring-grafana 3000:3000 -n marty-system"
	@echo "  kubectl port-forward svc/marty-monitoring-prometheus-server 9090:9090 -n marty-system"

# Start development with hot-reload using Skaffold
k8s-dev:
	@command -v skaffold >/dev/null 2>&1 || { echo "❌ skaffold is required. Installing..."; $(MAKE) k8s-install-skaffold; }
	@echo "🔥 Starting development with hot-reload..."
	@if [ ! -f skaffold.yaml ]; then \
		echo "❌ skaffold.yaml not found. Creating basic configuration..."; \
		$(MAKE) k8s-create-skaffold-config; \
	fi
	@skaffold dev --port-forward

# Create basic Skaffold configuration
k8s-create-skaffold-config:
	@echo "📝 Creating Skaffold configuration..."
	@echo "Creating basic skaffold.yaml file..."
	@echo "apiVersion: skaffold/v4beta11" > skaffold.yaml
	@echo "kind: Config" >> skaffold.yaml
	@echo "metadata:" >> skaffold.yaml
	@echo "  name: marty-dev" >> skaffold.yaml
	@echo "build:" >> skaffold.yaml
	@echo "  artifacts:" >> skaffold.yaml
	@echo "    - image: marty/ui-app" >> skaffold.yaml
	@echo "      docker:" >> skaffold.yaml
	@echo "        dockerfile: docker/ui-app.Dockerfile" >> skaffold.yaml
	@echo "    - image: marty/csca-service" >> skaffold.yaml
	@echo "      docker:" >> skaffold.yaml
	@echo "        dockerfile: docker/csca-service.Dockerfile" >> skaffold.yaml
	@echo "deploy:" >> skaffold.yaml
	@echo "  helm:" >> skaffold.yaml
	@echo "    releases:" >> skaffold.yaml
	@echo "      - name: ui-app" >> skaffold.yaml
	@echo "        chartPath: helm/charts/ui-app" >> skaffold.yaml
	@echo "        namespace: marty" >> skaffold.yaml
	@echo "portForward:" >> skaffold.yaml
	@echo "  - resourceType: service" >> skaffold.yaml
	@echo "    resourceName: ui-app" >> skaffold.yaml
	@echo "    namespace: marty" >> skaffold.yaml
	@echo "    port: 8090" >> skaffold.yaml
	@echo "✅ Skaffold configuration created"

# =============================================================================
# DEVELOPMENT ENVIRONMENT COMMANDS
# =============================================================================

# Complete development environment setup for manual testing (Docker-based)
dev-environment: dev-clean build
	@echo "🚀 Setting up complete Docker development environment..."
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
	@$(UV) run python scripts/generate_synthetic_data.py

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
# TRUST SERVICE TARGETS
# =============================================================================

# Trust Service Base Configuration
TRUST_SVC_BASE_URL := http://localhost:$(TRUST_SVC_PORT)

# Run all trust service tests
test-trust-svc: test-trust-svc-unit test-trust-svc-integration test-trust-svc-e2e
	@echo "✅ All trust service tests completed!"

# Run unit tests for trust service
test-trust-svc-unit:
	@echo "🧪 Running trust service unit tests..."
	$(UV) run pytest tests/trust_svc/unit/ -v --tb=short

# Run integration tests for trust service API endpoints
test-trust-svc-integration: test-trust-svc-api test-trust-svc-health
	@echo "✅ Trust service integration tests completed!"

# Run end-to-end tests for trust service workflows
test-trust-svc-e2e:
	@echo "🎬 Running trust service E2E tests..."
	$(UV) run python tests/trust_svc/e2e/test_trust_workflow.py

# Test trust service API endpoints with live service
test-trust-svc-api:
	@echo "🔍 Testing trust service API endpoints..."
	@echo "Checking if service is running..."
	@curl -s -f $(TRUST_SVC_BASE_URL)/api/v1/admin/status > /dev/null || (echo "❌ Service not running. Start with 'make trust-svc-start'" && exit 1)
	@echo "✓ Service is responding"
	@echo ""
	@echo "Testing core endpoints..."
	@curl -s $(TRUST_SVC_BASE_URL)/api/v1/admin/status | jq '.' > /dev/null && echo "✓ Status endpoint working" || echo "❌ Status endpoint failed"
	@curl -s $(TRUST_SVC_BASE_URL)/api/v1/admin/stats | jq '.' > /dev/null && echo "✓ Stats endpoint working" || echo "❌ Stats endpoint failed"
	@curl -s $(TRUST_SVC_BASE_URL)/metrics | grep -q "trust_" && echo "✓ Metrics endpoint working" || echo "❌ Metrics endpoint failed"
	@echo ""
	@echo "Testing API documentation..."
	@curl -s $(TRUST_SVC_BASE_URL)/docs > /dev/null && echo "✓ API docs available" || echo "❌ API docs failed"

# Test trust service health and status endpoints
test-trust-svc-health:
	@echo "💚 Testing trust service health endpoints..."
	@echo "Service URL: $(TRUST_SVC_BASE_URL)"
	@echo ""
	@echo "=== Health Check Details ==="
	@curl -s $(TRUST_SVC_BASE_URL)/api/v1/admin/status | jq '.' || echo "❌ Failed to get health details"
	@echo ""
	@echo "=== Trust Statistics ==="
	@curl -s $(TRUST_SVC_BASE_URL)/api/v1/admin/stats | jq '.' || echo "❌ Failed to get trust stats"

# Run trust service tests with Docker
test-trust-svc-docker:
	@echo "🐳 Running trust service tests with Docker..."
	docker-compose -f docker/docker-compose.trust-dev.yml up --build trust-svc

# Start trust service for testing
trust-svc-start:
	@echo "🚀 Starting trust service..."
	cd src && \
		$(UV) run uvicorn trust_svc.api:app --host 0.0.0.0 --port $(TRUST_SVC_PORT) --reload &
	@echo "Service PID: $$!"
	@echo "Waiting for service to start..."
	@sleep 5
	@echo "Service should be available at: $(TRUST_SVC_BASE_URL)"
	@echo "API Documentation: $(TRUST_SVC_BASE_URL)/docs"
	@echo "Metrics: $(TRUST_SVC_BASE_URL)/metrics"

# Start trust service with Docker
trust-svc-start-docker:
	@echo "🐳 Starting trust service with Docker..."
	docker-compose -f docker/docker-compose.trust-dev.yml up -d trust-svc
	@echo "Waiting for service to start..."
	@sleep 10
	@echo "Service should be available at: $(TRUST_SVC_BASE_URL)"

# Stop trust service
trust-svc-stop:
	@echo "🛑 Stopping trust service..."
	@pkill -f "uvicorn.*trust_svc" || true
	@docker-compose -f docker/docker-compose.trust-dev.yml down || true
	@echo "Trust service stopped"

# Check trust service status
trust-svc-status:
	@echo "📊 Trust service status:"
	@echo "Local service:"
	@curl -s $(TRUST_SVC_BASE_URL)/api/v1/admin/status 2>/dev/null && echo "✓ Running" || echo "❌ Not running"
	@echo "Docker service:"
	@docker-compose -f docker/docker-compose.trust-dev.yml ps trust-svc 2>/dev/null || echo "❌ Not running"

# View trust service logs
trust-svc-logs:
	@echo "📋 Trust service logs:"
	@echo "=== Docker logs ==="
	@docker-compose -f docker/docker-compose.trust-dev.yml logs --tail=50 trust-svc 2>/dev/null || echo "No Docker logs available"

# Run trust service development job
trust-svc-dev-job:
	@echo "🔧 Running trust service development job..."
	cd src && $(UV) run python -m trust_svc.dev_job --count 1000 --countries 10 --format table

# Load synthetic data into trust service
trust-svc-load-data:
	@echo "📊 Loading synthetic data into trust service..."
	cd src && $(UV) run python -m trust_svc.dev_job --count 5000 --countries 50 --format json

# Clean trust service test artifacts
trust-svc-clean:
	@echo "🧹 Cleaning trust service test artifacts..."
	@find src/trust_svc -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	@find tests/trust_svc -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	@find . -name "*.pyc" -path "*/trust_svc/*" -delete 2>/dev/null || true
	@find . -name ".pytest_cache" -type d -path "*/trust_svc/*" -exec rm -rf {} + 2>/dev/null || true
	@docker-compose -f docker/docker-compose.trust-dev.yml down -v 2>/dev/null || true
	@echo "✅ Trust service cleanup completed"

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
	@echo "  test-comprehensive - Run all tests including OpenID4VP"
	@echo "  test-presentations - Run all presentation-related tests"
	@echo "  test-unit          - Run unit tests"
	@echo "  test-integration   - Run integration tests"
	@echo "  test-e2e           - Run E2E tests (Kubernetes-based)"
	@echo "  test-e2e-k8s       - Run E2E tests with Kubernetes (explicit)"
	@echo "  test-e2e-k8s-existing - Run E2E tests with existing K8s cluster"
	@echo "  test-e2e-k8s-smoke - Run E2E smoke tests with Kubernetes"
	@echo "  test-e2e-k8s-monitoring - Run E2E tests with monitoring stack"
	@echo "  test-cert-validator - Run certificate validator tests"
	@echo ""
	@echo "🔐 OpenID4VP Integration Testing:"
	@echo "  test-openid4vp      - Run all OpenID4VP integration tests"
	@echo "  test-openid4vp-mdoc - Run mDoc OpenID4VP presentation tests"
	@echo "  test-openid4vp-mdl  - Run mDL OpenID4VP presentation tests"
	@echo "  test-openid4vp-setup - Setup OpenID4VP test environment"
	@echo "  test-openid4vp-quick - Run quick OpenID4VP smoke tests"
	@echo "  test-openid4vp-selective-disclosure - Test selective disclosure"
	@echo "  test-openid4vp-age-verification - Test age verification flows"
	@echo "  test-openid4vp-privacy - Test privacy-preserving presentations"
	@echo "  test-openid4vp-real-world - Test real-world scenarios"
	@echo "  test-openid4vp-collect - Collect OpenID4VP tests (no execution)"
	@echo ""
	@echo "🎯 Kubernetes E2E Testing Commands:"
	@echo "  test-e2e-k8s       - Run E2E tests with Kubernetes (recommended)"
	@echo "  test-e2e-k8s-existing - Use existing cluster (faster for development)"
	@echo "  test-e2e-k8s-smoke - Quick validation with Kubernetes"
	@echo "  test-e2e-k8s-monitoring - E2E tests with full monitoring stack"
	@echo "  test-e2e-clean     - Clean up E2E test environment"
	@echo ""
	@echo "⚠️  Legacy Commands (Deprecated - will be removed):"
	@echo "  test-e2e-docker-legacy - Docker-based E2E tests (deprecated)"
	@echo "  test-integration-docker-legacy - Docker-based integration tests (deprecated)"
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
	@echo "🎭 Playwright E2E Testing (Kubernetes-based):"
	@echo "  playwright-install    - Install Playwright browsers"
	@echo "  test-e2e-ui          - Run UI E2E tests (uses Kubernetes)"
	@echo "  test-e2e-smoke       - Run smoke E2E tests with Kubernetes"
	@echo "  test-e2e-ui-existing - Run E2E tests against existing service"
	@echo "  test-e2e-dashboard   - Run dashboard-specific E2E tests"
	@echo "  test-e2e-passport    - Run passport workflow E2E tests"
	@echo "  test-e2e-mdl         - Run MDL workflow E2E tests"
	@echo "  test-e2e-responsive  - Run responsive design E2E tests"
	@echo "  test-e2e-report      - Run E2E tests with HTML report (K8s)"
	@echo "  test-e2e-ui-integration - Run full-stack integration tests (K8s)"
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
	@echo "☸️  Kubernetes Development:"
	@echo "  k8s-setup          - Set up local Kubernetes development environment"
	@echo "  k8s-destroy        - Destroy local Kubernetes cluster"
	@echo "  k8s-status         - Check cluster and pod status"
	@echo "  k8s-deploy         - Deploy all services to Kubernetes"
	@echo "  k8s-undeploy       - Remove all services from Kubernetes"
	@echo "  k8s-restart        - Restart all services in Kubernetes"
	@echo "  k8s-logs           - Show logs from all services"
	@echo "  k8s-port-forward   - Set up port forwarding for development"
	@echo "  k8s-monitoring     - Deploy monitoring stack (Prometheus/Grafana)"
	@echo "  k8s-dev            - Start development with hot-reload (Skaffold)"
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
	@echo "🔐 Trust Services:"
	@echo "  test-trust-svc          - Run all trust service tests"
	@echo "  test-trust-svc-unit     - Run trust service unit tests"
	@echo "  test-trust-svc-integration - Run trust service integration tests"
	@echo "  test-trust-svc-e2e      - Run trust service E2E tests"
	@echo "  test-trust-svc-api      - Test API endpoints (requires running service)"
	@echo "  test-trust-svc-health   - Test health endpoints"
	@echo "  test-trust-svc-docker   - Run tests with Docker"
	@echo "  trust-svc-start         - Start trust service"
	@echo "  trust-svc-start-docker  - Start service with Docker"
	@echo "  trust-svc-stop          - Stop trust service"
	@echo "  trust-svc-status        - Check service status"
	@echo "  trust-svc-logs          - View service logs"
	@echo "  trust-svc-dev-job       - Run development job with synthetic data"
	@echo "  trust-svc-load-data     - Load large dataset for testing"
	@echo "  trust-svc-clean         - Clean test artifacts"
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
