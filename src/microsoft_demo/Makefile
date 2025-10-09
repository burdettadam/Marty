# Microsoft Authenticator Demo Makefile
# Consolidated operations for Microsoft demo environment
#
# This Makefile provides a DRY approach to managing the Microsoft Authenticator demo
# with support for Docker, Kubernetes, and VS Code integration.

# =============================================================================
# CONFIGURATION VARIABLES
# =============================================================================

# Project root path (relative to this Makefile)
PROJECT_ROOT := ../..

# Demo configuration
DEMO_NAME := microsoft-demo
NAMESPACE := marty-$(DEMO_NAME)
KIND_CLUSTER_NAME := marty-$(DEMO_NAME)

# Service configuration
ISSUER_PORT := 8000
VERIFIER_PORT := 8001

# Default URLs (will be overridden by environment)
ISSUER_BASE_URL ?= http://localhost:$(ISSUER_PORT)
VERIFIER_BASE_URL ?= http://localhost:$(VERIFIER_PORT)

# Docker compose configuration
DOCKER_COMPOSE_SIMPLE := docker compose -f config/docker-compose.demo-simple.yml
DOCKER_COMPOSE_FULL := docker compose -f config/docker-compose.demo-full.yml

# Environment files
ENV_FILE := config/.env.demo
ENV_TEMPLATE := config/.env.template

# Script directories
SCRIPTS_DIR := scripts
CONFIG_DIR := config
K8S_DIR := k8s
DOCS_DIR := docs

# Color output
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[0;33m
BLUE := \033[0;34m
PURPLE := \033[0;35m
CYAN := \033[0;36m
NC := \033[0m # No Color

# =============================================================================
# HELP SYSTEM
# =============================================================================

.PHONY: help
help: ## Show this help message
	@echo "$(CYAN)Microsoft Authenticator Demo Commands$(NC)"
	@echo "======================================"
	@echo ""
	@echo "$(YELLOW)🚀 Quick Start:$(NC)"
	@echo "  make setup          - Complete demo setup with Docker"
	@echo "  make setup-k8s      - Complete demo setup with Kubernetes"
	@echo "  make setup-vscode   - Setup with VS Code port forwarding"
	@echo ""
	@echo "$(YELLOW)🐳 Docker Commands:$(NC)"
	@echo "  docker-up            Start all demo services with Docker (full setup)"
	@echo "  docker-up-simple     Start demo services with Docker (simple setup for VS Code)"
	@echo "  docker-down          Stop all Docker services"
	@echo "  docker-restart       Restart Docker services"
	@echo "  docker-logs          Show Docker service logs"
	@echo ""
	@echo "$(YELLOW)☸️  Kubernetes Commands:$(NC)"
	@echo "  k8s-up               Complete Kubernetes setup"
	@echo "  k8s-cluster-create   Create Kind cluster for demo"
	@echo "  k8s-deploy           Deploy demo to Kubernetes"
	@echo "  k8s-port-forward     Setup port forwarding for Kubernetes services"
	@echo "  k8s-status           Show Kubernetes deployment status"
	@echo "  k8s-logs             Show Kubernetes pod logs"
	@echo "  k8s-cleanup          Cleanup Kubernetes resources"
	@echo ""
	@echo "$(YELLOW)🔧 Configuration:$(NC)"
	@echo "  setup-env            Setup environment configuration"
	@echo "  configure-urls       Configure custom URLs for issuer and verifier"
	@echo "  configure-tunnels    Alias for configure-urls (backward compatibility)"
	@echo "  show-config          Show current configuration"
	@echo ""
	@echo "$(YELLOW)🧪 Testing & Validation:$(NC)"
	@echo "  test-all             Run all tests"
	@echo "  test-endpoints       Test API endpoints"
	@echo "  test-issuer          Test issuer API specifically"
	@echo "  test-verifier        Test verifier API specifically"
	@echo "  test-workflow        Test complete credential workflow"
	@echo "  validate-setup       Validate that setup is correct"
	@echo "  status               Show overall demo status"
	@echo "  wait-for-services    Wait for services to be ready"
	@echo ""
	@echo "$(YELLOW)🧹 Cleanup:$(NC)"
	@echo "  clean                Stop and cleanup all resources"
	@echo "  docker-down          Stop Docker services"
	@echo "  k8s-cleanup          Cleanup Kubernetes resources"
	@echo ""
	@echo "$(YELLOW)📱 Usage Examples:$(NC)"
	@echo "  $(CYAN)# Setup with custom URLs$(NC)"
	@echo "  make configure-urls ISSUER_URL=https://abc-8000.devtunnels.ms VERIFIER_URL=https://def-8001.devtunnels.ms"
	@echo ""
	@echo "  $(CYAN)# Test specific endpoint$(NC)"
	@echo "  make test-issuer"
	@echo ""

# =============================================================================
# QUICK START COMMANDS
# =============================================================================

.PHONY: setup
setup: setup-env docker-up test-endpoints ## Complete demo setup with Docker (recommended)
	@echo "$(GREEN)✅ Microsoft demo setup complete!$(NC)"
	@$(MAKE) show-info

.PHONY: setup-k8s
setup-k8s: setup-env k8s-up test-endpoints ## Complete demo setup with Kubernetes
	@echo "$(GREEN)✅ Microsoft demo setup complete with Kubernetes!$(NC)"
	@$(MAKE) show-info

.PHONY: setup-vscode
setup-vscode: setup-env docker-up-simple ## Setup for VS Code port forwarding
	@echo "$(YELLOW)🌐 VS Code port forwarding setup required$(NC)"
	@echo ""
	@echo "$(CYAN)Next steps:$(NC)"
	@echo "1. In VS Code: Open Command Palette (Cmd+Shift+P)"
	@echo "2. Type: 'Ports: Focus on Ports View'"
	@echo "3. Forward ports $(ISSUER_PORT) and $(VERIFIER_PORT) as 'Public'"
	@echo "4. Update URLs: make configure-urls ISSUER_URL=<your-issuer-url> VERIFIER_URL=<your-verifier-url>"
	@echo "5. Restart: make restart-docker"

# =============================================================================
# DOCKER COMMANDS
# =============================================================================

.PHONY: docker-up
docker-up: ## Start all demo services with Docker (full setup)
	@echo "$(BLUE)🐳 Starting Microsoft demo services (full setup)...$(NC)"
	@cd $(CONFIG_DIR) && docker compose -f docker-compose.demo-full.yml --env-file .env.demo up -d
	@$(MAKE) wait-for-services

.PHONY: docker-up-simple
docker-up-simple: ## Start demo services with Docker (simple setup for VS Code)
	@echo "$(BLUE)🐳 Starting Microsoft demo services (simple setup)...$(NC)"
	@cd $(CONFIG_DIR) && docker compose -f docker-compose.demo-simple.yml --env-file .env.demo up -d
	@$(MAKE) wait-for-services

.PHONY: docker-down
docker-down: ## Stop all Docker services
	@echo "$(YELLOW)🛑 Stopping Docker services...$(NC)"
	@cd $(CONFIG_DIR) && docker compose -f docker-compose.demo-full.yml down || true
	@cd $(CONFIG_DIR) && docker compose -f docker-compose.demo-simple.yml down || true

.PHONY: docker-restart
docker-restart: docker-down docker-up ## Restart Docker services

.PHONY: docker-logs
docker-logs: ## Show Docker service logs
	@echo "$(BLUE)📋 Showing Docker service logs...$(NC)"
	@cd $(CONFIG_DIR) && docker compose -f docker-compose.demo-full.yml logs -f --tail=50

# =============================================================================
# KUBERNETES COMMANDS
# =============================================================================

.PHONY: k8s-up
k8s-up: k8s-cluster-create k8s-deploy k8s-port-forward ## Complete Kubernetes setup
	@echo "$(GREEN)✅ Kubernetes setup complete$(NC)"

.PHONY: k8s-cluster-create
k8s-cluster-create: ## Create Kind cluster for demo
	@echo "$(BLUE)☸️  Creating Kind cluster...$(NC)"
	@bash $(SCRIPTS_DIR)/k8s-cluster-create.sh

.PHONY: k8s-deploy
k8s-deploy: ## Deploy demo to Kubernetes (production-ready)
	@echo "$(BLUE)☸️  Deploying to Kubernetes (production setup)...$(NC)"
	@bash $(SCRIPTS_DIR)/k8s-deploy.sh

.PHONY: k8s-deploy-legacy
k8s-deploy-legacy: ## Deploy demo to Kubernetes (legacy manifest)
	@echo "$(BLUE)☸️  Deploying to Kubernetes (legacy setup)...$(NC)"
	@kubectl apply -f $(K8S_DIR)/demo.yaml

.PHONY: k8s-port-forward
k8s-port-forward: ## Setup port forwarding for Kubernetes services
	@echo "$(BLUE)🌐 Setting up port forwarding...$(NC)"
	@bash $(SCRIPTS_DIR)/k8s-port-forward.sh

.PHONY: k8s-status
k8s-status: ## Show Kubernetes deployment status
	@echo "$(BLUE)☸️  Kubernetes status:$(NC)"
	@kubectl get pods -n $(NAMESPACE) 2>/dev/null || echo "$(YELLOW)⚠️  Namespace $(NAMESPACE) not found$(NC)"
	@kubectl get services -n $(NAMESPACE) 2>/dev/null || echo "$(YELLOW)⚠️  No services found$(NC)"
	@echo ""
	@echo "$(BLUE)External Access:$(NC)"
	@echo "  Issuer API:    http://localhost:30000"
	@echo "  Verifier API:  http://localhost:30001"

.PHONY: k8s-logs
k8s-logs: ## Show Kubernetes pod logs
	@echo "$(BLUE)📋 Kubernetes pod logs:$(NC)"
	@kubectl logs -n $(NAMESPACE) -l app=microsoft-demo --tail=50 2>/dev/null || echo "$(YELLOW)⚠️  No pods found$(NC)"

.PHONY: k8s-cleanup
k8s-cleanup: ## Cleanup Kubernetes resources
	@echo "$(BLUE)🧹 Cleaning up Kubernetes resources...$(NC)"
	@kubectl delete -f $(K8S_DIR)/demo.yaml 2>/dev/null || echo "$(YELLOW)⚠️  Demo resources not found$(NC)"
	@kind delete cluster --name $(KIND_CLUSTER_NAME) 2>/dev/null || echo "$(YELLOW)⚠️  Kind cluster not found$(NC)"

# =============================================================================
# CONFIGURATION COMMANDS
# =============================================================================

.PHONY: setup-env
setup-env: ## Setup environment configuration
	@echo "$(BLUE)⚙️  Setting up environment...$(NC)"
	@bash $(SCRIPTS_DIR)/setup-env.sh

.PHONY: configure-urls
configure-urls: ## Configure custom URLs for issuer and verifier
	@echo "$(BLUE)🔧 Configuring URLs...$(NC)"
	@if [ -z "$(ISSUER_URL)" ] || [ -z "$(VERIFIER_URL)" ]; then \
		echo "$(RED)Error: Both ISSUER_URL and VERIFIER_URL are required$(NC)"; \
		echo "Usage: make configure-urls ISSUER_URL=https://xxx-8000.devtunnels.ms VERIFIER_URL=https://xxx-8001.devtunnels.ms"; \
		exit 1; \
	fi
	@bash $(SCRIPTS_DIR)/configure-urls.sh --issuer-url $(ISSUER_URL) --verifier-url $(VERIFIER_URL)

.PHONY: configure-tunnels
configure-tunnels: configure-urls ## Alias for configure-urls (backward compatibility)

.PHONY: show-config
show-config: ## Show current configuration
	@echo "$(BLUE)📋 Current Configuration:$(NC)"
	@echo "Issuer URL: $(ISSUER_BASE_URL)"
	@echo "Verifier URL: $(VERIFIER_BASE_URL)"
	@echo "Environment file: $(ENV_FILE)"
	@if [ -f "$(ENV_FILE)" ]; then \
		echo "$(GREEN)✅ Environment file exists$(NC)"; \
		echo ""; \
		echo "$(YELLOW)Environment variables:$(NC)"; \
		cat $(ENV_FILE) | grep -v "^#" | grep "=" || true; \
	else \
		echo "$(RED)❌ Environment file not found$(NC)"; \
	fi

# =============================================================================
# TESTING AND VALIDATION
# =============================================================================

.PHONY: test-all
test-all: test-endpoints test-workflow ## Run all tests

.PHONY: test-endpoints
test-endpoints: ## Test API endpoints
	@echo "$(BLUE)🧪 Testing API endpoints...$(NC)"
	@bash $(SCRIPTS_DIR)/test-endpoints.sh

.PHONY: test-issuer
test-issuer: ## Test issuer API specifically
	@echo "$(BLUE)🧪 Testing issuer API...$(NC)"
	@curl -f -s $(ISSUER_BASE_URL)/health > /dev/null && echo "$(GREEN)✅ Issuer API healthy$(NC)" || echo "$(RED)❌ Issuer API not responding$(NC)"
	@curl -f -s $(ISSUER_BASE_URL)/docs > /dev/null && echo "$(GREEN)✅ Issuer API docs available$(NC)" || echo "$(RED)❌ Issuer API docs not available$(NC)"

.PHONY: test-verifier
test-verifier: ## Test verifier API specifically
	@echo "$(BLUE)🧪 Testing verifier API...$(NC)"
	@curl -f -s $(VERIFIER_BASE_URL)/health > /dev/null && echo "$(GREEN)✅ Verifier API healthy$(NC)" || echo "$(RED)❌ Verifier API not responding$(NC)"
	@curl -f -s $(VERIFIER_BASE_URL)/docs > /dev/null && echo "$(GREEN)✅ Verifier API docs available$(NC)" || echo "$(RED)❌ Verifier API docs not available$(NC)"

.PHONY: test-workflow
test-workflow: ## Test complete credential workflow
	@echo "$(BLUE)🧪 Testing credential workflow...$(NC)"
	@bash $(SCRIPTS_DIR)/test-workflow.sh

.PHONY: validate-setup
validate-setup: ## Validate that setup is correct
	@echo "$(BLUE)✅ Validating setup...$(NC)"
	@bash $(SCRIPTS_DIR)/validate-setup.sh

.PHONY: status
status: ## Show overall demo status
	@echo "$(BLUE)📊 Microsoft Demo Status$(NC)"
	@echo "========================="
	@$(MAKE) show-config
	@echo ""
	@echo "$(YELLOW)Service Health:$(NC)"
	@$(MAKE) test-issuer 2>/dev/null || true
	@$(MAKE) test-verifier 2>/dev/null || true

# =============================================================================
# UTILITY COMMANDS
# =============================================================================

.PHONY: wait-for-services
wait-for-services: ## Wait for services to be ready
	@echo "$(YELLOW)⏳ Waiting for services to be ready...$(NC)"
	@bash $(SCRIPTS_DIR)/wait-for-services.sh

.PHONY: show-info
show-info: ## Show demo information and next steps
	@echo ""
	@echo "$(CYAN)🎉 Microsoft Authenticator Demo Ready!$(NC)"
	@echo "======================================"
	@echo ""
	@echo "$(YELLOW)📱 API Endpoints:$(NC)"
	@echo "  Issuer API:    $(ISSUER_BASE_URL)"
	@echo "  Verifier API:  $(VERIFIER_BASE_URL)"
	@echo ""
	@echo "$(YELLOW)📖 Documentation:$(NC)"
	@echo "  Issuer API docs:   $(ISSUER_BASE_URL)/docs"
	@echo "  Verifier API docs: $(VERIFIER_BASE_URL)/docs"
	@echo ""
	@echo "$(YELLOW)🧪 Test Commands:$(NC)"
	@echo "  make test-all       - Run all tests"
	@echo "  make test-workflow  - Test credential workflow"
	@echo "  make status         - Check demo status"
	@echo ""
	@echo "$(YELLOW)🔧 Management:$(NC)"
	@echo "  make status         - Check current status"
	@echo "  make docker-logs    - View service logs"
	@echo "  make clean          - Stop and cleanup"

.PHONY: open-docs
open-docs: ## Open API documentation in browser
	@echo "$(BLUE)📖 Opening API documentation...$(NC)"
	@open $(ISSUER_BASE_URL)/docs || true
	@open $(VERIFIER_BASE_URL)/docs || true

# =============================================================================
# CLEANUP COMMANDS
# =============================================================================

.PHONY: clean
clean: stop-all ## Stop services and cleanup (alias for stop-all)

.PHONY: stop-all
stop-all: docker-down k8s-cleanup ## Stop all services and cleanup
	@echo "$(GREEN)✅ All services stopped and cleaned up$(NC)"

.PHONY: clean-env
clean-env: ## Remove environment configuration
	@echo "$(YELLOW)🧹 Cleaning environment configuration...$(NC)"
	@rm -f $(ENV_FILE)

.PHONY: reset
reset: stop-all clean-env ## Complete reset of demo environment
	@echo "$(GREEN)✅ Demo environment reset$(NC)"

# =============================================================================
# INTERNAL HELPERS
# =============================================================================

# Check if required tools are available
.PHONY: check-prerequisites
check-prerequisites:
	@command -v docker >/dev/null 2>&1 || { echo "$(RED)❌ Docker is required but not installed$(NC)"; exit 1; }
	@(command -v docker-compose >/dev/null 2>&1 || docker compose version >/dev/null 2>&1) || { echo "$(RED)❌ Docker Compose is required but not installed$(NC)"; exit 1; }
	@echo "$(GREEN)✅ Prerequisites satisfied$(NC)"

# Make sure we're in the right directory
.PHONY: check-directory
check-directory:
	@if [ ! -f "issuer_api.py" ] || [ ! -f "verifier_api.py" ]; then \
		echo "$(RED)❌ Must be run from the microsoft_demo directory$(NC)"; \
		exit 1; \
	fi

# =============================================================================
# CLEANUP COMMANDS
# =============================================================================

.PHONY: clean
clean: docker-down k8s-cleanup ## Stop and cleanup all resources
	@echo "$(GREEN)✅ All demo resources cleaned up$(NC)"

# Default target
.DEFAULT_GOAL := help
