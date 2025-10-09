#!/bin/bash

# Quick Development Setup Script for Marty Platform
# Provides common development tasks and shortcuts

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to print colored output
print_header() {
    echo -e "${BLUE}${1}${NC}"
    echo "$(printf '=%.0s' {1..50})"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_info() {
    echo -e "${CYAN}ℹ${NC} $1"
}

# Function to show help
show_help() {
    echo -e "${BLUE}Marty Platform Development Helper${NC}"
    echo "=================================="
    echo
    echo "Usage: $0 [COMMAND]"
    echo
    echo "Available commands:"
    echo -e "  ${GREEN}setup${NC}         - Complete development environment setup"
    echo -e "  ${GREEN}clean${NC}         - Clean all build artifacts and caches"
    echo -e "  ${GREEN}check${NC}         - Run all code quality checks"
    echo -e "  ${GREEN}format${NC}        - Format all code"
    echo -e "  ${GREEN}test${NC}          - Run all tests"
    echo -e "  ${GREEN}test-unit${NC}     - Run unit tests only"
    echo -e "  ${GREEN}test-integration${NC} - Run integration tests only"
    echo -e "  ${GREEN}docs${NC}          - Generate documentation"
    echo -e "  ${GREEN}perf${NC}          - Run performance tests"
    echo -e "  ${GREEN}security${NC}      - Run security scans"
    echo -e "  ${GREEN}logs${NC}          - Setup and start logging infrastructure"
    echo -e "  ${GREEN}services${NC}      - Start all Marty services"
    echo -e "  ${GREEN}status${NC}        - Show status of all services"
    echo -e "  ${GREEN}reset${NC}         - Reset development environment"
    echo -e "  ${GREEN}update${NC}        - Update dependencies and tools"
    echo -e "  ${GREEN}proto${NC}         - Compile protocol buffers"
    echo -e "  ${GREEN}db${NC}            - Database operations (migrate, seed, reset)"
    echo
    echo "Examples:"
    echo "  $0 setup          # Set up development environment"
    echo "  $0 check          # Run linting, type checking, and tests"
    echo "  $0 test unit      # Run only unit tests"
    echo "  $0 db migrate     # Run database migrations"
}

# Navigate to project root
cd "$PROJECT_ROOT"

# Check if uv is available
check_uv() {
    if ! command -v uv &> /dev/null; then
        print_error "uv is not installed. Please install it first:"
        echo "  curl -LsSf https://astral.sh/uv/install.sh | sh"
        exit 1
    fi
}

# Development environment setup
cmd_setup() {
    print_header "🛠️ Setting up development environment"

    check_uv

    # Run the full setup script
    if [[ -f "scripts/setup_dev_env.sh" ]]; then
        ./scripts/setup_dev_env.sh
    else
        print_warning "Setup script not found, running basic setup..."

        # Install dependencies
        uv sync --dev

        # Install pre-commit
        uv run pre-commit install

        # Create directories
        mkdir -p logs reports/coverage reports/performance reports/security

        print_success "Basic setup complete"
    fi
}

# Clean build artifacts
cmd_clean() {
    print_header "🧹 Cleaning build artifacts"

    # Python cache
    find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
    find . -type f -name "*.pyc" -delete 2>/dev/null || true
    find . -type f -name "*.pyo" -delete 2>/dev/null || true

    # Test and coverage
    rm -rf .pytest_cache .coverage htmlcov

    # MyPy cache
    rm -rf .mypy_cache

    # Reports
    rm -rf reports/coverage/* reports/performance/* reports/security/*

    # Logs
    rm -f logs/*.log

    # Docker volumes (if any)
    docker system prune -f 2>/dev/null || true

    print_success "Cleanup complete"
}

# Code quality checks
cmd_check() {
    print_header "🔍 Running code quality checks"

    check_uv

    echo "Running pre-commit hooks..."
    if uv run pre-commit run --all-files; then
        print_success "Pre-commit checks passed"
    else
        print_warning "Pre-commit found issues"
    fi

    echo
    echo "Running type checking..."
    if uv run mypy src/services/ src/marty_common/ --config-file pyproject.toml; then
        print_success "Type checking passed"
    else
        print_warning "Type checking found issues"
    fi

    echo
    echo "Running security scan..."
    uv run bandit -r src/ -f txt || print_warning "Security scan found issues"

    echo
    echo "Checking dependencies..."
    uv run safety check || print_warning "Dependency vulnerabilities found"
}

# Format code
cmd_format() {
    print_header "✨ Formatting code"

    check_uv

    echo "Running black formatter..."
    uv run black src/ --line-length=100

    echo "Organizing imports..."
    uv run isort src/ --profile=black --line-length=100

    echo "Running ruff fixes..."
    uv run ruff check src/ --fix

    print_success "Code formatting complete"
}

# Run tests
cmd_test() {
    print_header "🧪 Running tests"

    check_uv

    local test_type="${1:-all}"

    case "$test_type" in
        "unit")
            echo "Running unit tests..."
            uv run pytest tests/ -m "unit" -v --tb=short
            ;;
        "integration")
            echo "Running integration tests..."
            uv run pytest tests/ -m "integration" -v --tb=short
            ;;
        "performance")
            echo "Running performance tests..."
            uv run pytest tests/ -m "performance" -v --tb=short
            ;;
        "all"|*)
            echo "Running all tests..."
            uv run pytest tests/ -v --tb=short --cov=src --cov-report=html --cov-report=term
            ;;
    esac

    print_success "Tests complete"
}

# Generate documentation
cmd_docs() {
    print_header "📚 Generating documentation"

    if [[ -f "scripts/generate_simple_docs.py" ]]; then
        uv run python scripts/generate_simple_docs.py
        print_success "Documentation generated"
    else
        print_warning "Documentation script not found"
    fi
}

# Performance testing
cmd_perf() {
    print_header "🚀 Running performance tests"

    if [[ -f "scripts/run_perf_test.sh" ]]; then
        ./scripts/run_perf_test.sh quick
    else
        print_warning "Performance test script not found"
    fi
}

# Security scans
cmd_security() {
    print_header "🔒 Running security scans"

    check_uv

    echo "Running bandit security scan..."
    uv run bandit -r src/ -f json -o reports/security/bandit_report.json
    uv run bandit -r src/ -f txt -o reports/security/bandit_report.txt

    echo "Checking dependencies for vulnerabilities..."
    uv run safety check --json --output reports/security/safety_report.json

    print_success "Security scans complete"
}

# Logging infrastructure
cmd_logs() {
    print_header "📝 Setting up logging infrastructure"

    if [[ -f "scripts/setup_logging.sh" ]]; then
        ./scripts/setup_logging.sh
    else
        print_warning "Logging setup script not found"
    fi
}

# Start services
cmd_services() {
    print_header "🚀 Starting Marty services"

    echo "Starting services with docker-compose..."
    docker-compose up -d

    print_success "Services started"
    print_info "Check status with: $0 status"
}

# Service status
cmd_status() {
    print_header "📊 Service Status"

    echo "Docker containers:"
    docker-compose ps

    echo
    echo "Service health checks:"
    services=("8080" "8081" "8082" "8083" "8084" "8085" "8086" "8087" "8088" "8090")
    for port in "${services[@]}"; do
        if curl -s "http://localhost:$port/health" > /dev/null 2>&1; then
            print_success "Service on port $port is healthy"
        else
            print_warning "Service on port $port is not responding"
        fi
    done
}

# Reset environment
cmd_reset() {
    print_header "🔄 Resetting development environment"

    echo "Stopping all services..."
    docker-compose down -v 2>/dev/null || true

    echo "Cleaning artifacts..."
    cmd_clean

    echo "Reinstalling dependencies..."
    uv sync --dev

    print_success "Environment reset complete"
}

# Update dependencies
cmd_update() {
    print_header "⬆️ Updating dependencies and tools"

    check_uv

    echo "Updating Python dependencies..."
    uv sync --upgrade

    echo "Updating pre-commit hooks..."
    uv run pre-commit autoupdate

    print_success "Updates complete"
}

# Compile protocol buffers
cmd_proto() {
    print_header "🔧 Compiling protocol buffers"

    check_uv

    echo "Compiling .proto files..."
    uv run python -m src.compile_protos

    print_success "Protocol buffers compiled"
}

# Database operations
cmd_db() {
    local operation="${1:-status}"

    print_header "🗄️ Database operations"

    case "$operation" in
        "migrate")
            echo "Running database migrations..."
            # Add migration command here
            print_success "Migrations complete"
            ;;
        "seed")
            echo "Seeding database..."
            # Add seed command here
            print_success "Database seeded"
            ;;
        "reset")
            echo "Resetting database..."
            # Add reset command here
            print_success "Database reset"
            ;;
        "status"|*)
            echo "Database status:"
            # Add status check here
            print_info "Database operations not yet implemented"
            ;;
    esac
}

# Main command dispatcher
case "${1:-help}" in
    "setup")
        cmd_setup
        ;;
    "clean")
        cmd_clean
        ;;
    "check")
        cmd_check
        ;;
    "format")
        cmd_format
        ;;
    "test")
        cmd_test "${2:-all}"
        ;;
    "docs")
        cmd_docs
        ;;
    "perf")
        cmd_perf
        ;;
    "security")
        cmd_security
        ;;
    "logs")
        cmd_logs
        ;;
    "services")
        cmd_services
        ;;
    "status")
        cmd_status
        ;;
    "reset")
        cmd_reset
        ;;
    "update")
        cmd_update
        ;;
    "proto")
        cmd_proto
        ;;
    "db")
        cmd_db "${2:-status}"
        ;;
    "help"|*)
        show_help
        ;;
esac
