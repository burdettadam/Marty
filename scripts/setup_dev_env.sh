#!/bin/bash

# Enhanced Development Environment Setup for Marty Platform
# Comprehensive development tooling installation and configuration

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

echo -e "${BLUE}🛠️ Setting up Enhanced Development Environment for Marty Platform${NC}"
echo "================================================================="

# Function to print status
print_status() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

# Check if uv is installed
if ! command -v uv &> /dev/null; then
    print_error "uv is not installed. Please install it first:"
    echo "  curl -LsSf https://astral.sh/uv/install.sh | sh"
    exit 1
fi

print_status "uv is available"

# Navigate to project root
cd "$PROJECT_ROOT"

echo
echo -e "${BLUE}📦 Installing development dependencies...${NC}"

# Install development dependencies
uv add --group dev \
    playwright>=1.48.0 \
    pytest-html>=4.1.1 \
    pytest-xdist>=3.6.1 \
    pytest-asyncio>=0.24.0 \
    pre-commit>=3.6.0 \
    black>=24.2.0 \
    isort>=5.13.2 \
    mypy>=1.8.0 \
    bandit>=1.7.5 \
    xenon>=0.9.1 \
    pydocstyle>=6.3.0 \
    safety>=3.0.0 \
    radon>=6.0.1 \
    types-requests>=2.31.0 \
    types-PyYAML>=6.0.0 \
    grpcio-testing>=1.75.0 \
    ruff>=0.13.2 \
    pyyaml>=6.0.3 \
    aiohttp>=3.12.15 \
    prometheus-client>=0.23.1

print_status "Installed development dependencies"

# Install additional development tools
echo
echo -e "${BLUE}🔧 Installing additional development tools...${NC}"

# Install structlog and pythonjsonlogger for logging
uv add structlog>=23.2.0 pythonjsonlogger>=2.0.7

print_status "Installed logging dependencies"

echo
echo -e "${BLUE}⚙️ Setting up pre-commit hooks...${NC}"

# Install pre-commit hooks
uv run pre-commit install
uv run pre-commit install --hook-type commit-msg
uv run pre-commit install --hook-type pre-push

print_status "Installed pre-commit hooks"

echo
echo -e "${BLUE}🎭 Setting up Playwright...${NC}"

# Install Playwright browsers
uv run playwright install

print_status "Installed Playwright browsers"

echo
echo -e "${BLUE}📁 Creating development directories...${NC}"

# Create necessary directories
mkdir -p logs
mkdir -p reports/coverage
mkdir -p reports/performance
mkdir -p reports/security
mkdir -p .vscode
mkdir -p .devcontainer

print_status "Created development directories"

echo
echo -e "${BLUE}🔍 Running initial code quality checks...${NC}"

# Run initial pre-commit on all files (but don't fail if there are issues)
echo "Running pre-commit on all files..."
if uv run pre-commit run --all-files; then
    print_status "Pre-commit checks passed"
else
    print_warning "Pre-commit found issues - these will be auto-fixed on commit"
fi

# Run type checking
echo "Running type checking..."
if uv run mypy src/services/ src/marty_common/ --config-file pyproject.toml --show-error-codes --pretty --color-output --error-summary; then
    print_status "Type checking passed"
else
    print_warning "Type checking found issues - review mypy output above"
fi

echo
echo -e "${BLUE}📊 Generating initial reports...${NC}"

# Generate complexity report
echo "Generating complexity report..."
uv run radon cc src/ --total-average --show-complexity > reports/complexity_report.txt
print_status "Generated complexity report"

# Generate security scan
echo "Running security scan..."
uv run bandit -r src/ -f json -o reports/security/bandit_report.json || true
uv run bandit -r src/ -f txt -o reports/security/bandit_report.txt || true
print_status "Generated security scan report"

# Run safety check
echo "Checking dependencies for vulnerabilities..."
uv run safety check --json --output reports/security/safety_report.json || true
print_status "Generated dependency vulnerability report"

echo
echo -e "${GREEN}🎉 Enhanced Development Environment Setup Complete!${NC}"
echo "=============================================="
echo
echo "Development tools installed:"
echo -e "  • ${GREEN}Pre-commit hooks${NC}: Automatic code quality checks on commit"
echo -e "  • ${GREEN}Ruff${NC}: Fast Python linter and formatter"
echo -e "  • ${GREEN}Black${NC}: Code formatter"
echo -e "  • ${GREEN}isort${NC}: Import sorter"
echo -e "  • ${GREEN}MyPy${NC}: Static type checker"
echo -e "  • ${GREEN}Bandit${NC}: Security linter"
echo -e "  • ${GREEN}Safety${NC}: Dependency vulnerability scanner"
echo -e "  • ${GREEN}Radon${NC}: Complexity analyzer"
echo -e "  • ${GREEN}Playwright${NC}: E2E testing framework"
echo
echo "Available development commands:"
echo -e "  • ${BLUE}make dev-setup${NC}: Complete development environment setup"
echo -e "  • ${BLUE}make quality-check${NC}: Run all code quality checks"
echo -e "  • ${BLUE}make format${NC}: Format code with black and isort"
echo -e "  • ${BLUE}make lint${NC}: Run linting with ruff"
echo -e "  • ${BLUE}make type-check${NC}: Run type checking with mypy"
echo -e "  • ${BLUE}make security${NC}: Run security checks"
echo -e "  • ${BLUE}make complexity${NC}: Analyze code complexity"
echo -e "  • ${BLUE}make pre-commit-run${NC}: Run pre-commit on all files"
echo
echo "Reports generated in:"
echo -e "  • ${PURPLE}reports/complexity_report.txt${NC}: Code complexity analysis"
echo -e "  • ${PURPLE}reports/security/${NC}: Security scan results"
echo
echo "Next steps:"
echo "  1. Review any linting issues in the output above"
echo "  2. Run 'make quality-check' to verify everything is working"
echo "  3. Start developing with automatic code quality checks!"
echo
print_status "Setup complete! Happy coding! 🚀"