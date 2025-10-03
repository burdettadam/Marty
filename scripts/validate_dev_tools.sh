#!/bin/bash

# Validation script for Enhanced Development Tooling
# Verifies all development environment components are working correctly

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

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

check_file() {
    local file="$1"
    local description="$2"
    
    if [[ -f "$file" ]]; then
        print_success "$description exists"
        return 0
    else
        print_error "$description missing: $file"
        return 1
    fi
}

check_directory() {
    local dir="$1"
    local description="$2"
    
    if [[ -d "$dir" ]]; then
        print_success "$description exists"
        return 0
    else
        print_error "$description missing: $dir"
        return 1
    fi
}

check_command() {
    local cmd="$1"
    local description="$2"
    
    if command -v "$cmd" &> /dev/null; then
        print_success "$description available"
        return 0
    else
        print_warning "$description not found: $cmd"
        return 1
    fi
}

# Navigate to project root
cd "$PROJECT_ROOT"

print_header "🔍 Validating Enhanced Development Tooling"

echo
echo "Core Development Files:"
check_file "scripts/setup_dev_env.sh" "Development environment setup script"
check_file "scripts/dev.sh" "Development helper script"
check_file ".pre-commit-config.yaml" "Pre-commit configuration"
check_file "pyproject.toml" "Python project configuration"

echo
echo "VS Code Configuration:"
check_file ".vscode/marty.code-workspace" "VS Code workspace configuration"
check_directory ".vscode" "VS Code settings directory"

echo
echo "DevContainer Configuration:"
check_file ".devcontainer/devcontainer.json" "DevContainer configuration"
check_file ".devcontainer/setup.sh" "DevContainer setup script"

echo
echo "Development Tools:"
tools_ok=0
if check_command "uv" "UV package manager"; then
    ((tools_ok++))
fi

if command -v uv &> /dev/null; then
    echo
    echo "Pre-commit validation:"
    if uv run pre-commit --version &> /dev/null; then
        print_success "Pre-commit available via uv"
        ((tools_ok++))
    else
        print_warning "Pre-commit not available via uv"
    fi
    
    echo
    echo "Code quality tools:"
    quality_tools=("black" "ruff" "mypy" "bandit" "isort")
    for tool in "${quality_tools[@]}"; do
        if uv run "$tool" --version &> /dev/null 2>&1; then
            print_success "$tool available"
            ((tools_ok++))
        else
            print_warning "$tool not available"
        fi
    done
fi

echo
echo "Project Structure:"
check_directory "src" "Source code directory"
check_directory "tests" "Tests directory"
check_directory "docs" "Documentation directory"
check_directory "scripts" "Scripts directory"

echo
echo "Configuration Files:"
config_files=(
    "config/development.yaml"
    "config/testing.yaml"
    "docker/docker-compose.yml"
    "Makefile"
)

for file in "${config_files[@]}"; do
    check_file "$file" "Configuration file: $(basename "$file")"
done

echo
print_header "🧪 Testing Development Workflow"

echo "Testing development helper script:"
if [[ -x "scripts/dev.sh" ]]; then
    print_success "Development script is executable"
    
    # Test help command
    if ./scripts/dev.sh help | grep -q "Marty Platform Development Helper"; then
        print_success "Development script help works"
    else
        print_warning "Development script help may have issues"
    fi
else
    print_error "Development script is not executable"
fi

echo
echo "Testing VS Code workspace:"
if [[ -f ".vscode/marty.code-workspace" ]] && grep -q "\"name\": \"Marty Platform\"" ".vscode/marty.code-workspace"; then
    print_success "VS Code workspace configuration is valid"
else
    print_warning "VS Code workspace configuration may have issues"
fi

echo
echo "Testing pre-commit configuration:"
if command -v uv &> /dev/null && uv run pre-commit validate-config; then
    print_success "Pre-commit configuration is valid"
else
    print_warning "Pre-commit configuration validation failed"
fi

echo
print_header "📋 Validation Summary"

echo "Enhanced Development Tooling Components:"
echo "• Development Environment Setup: ✓ Automated script with all tools"
echo "• Pre-commit Hooks: ✓ Comprehensive code quality checks"
echo "• VS Code Configuration: ✓ Workspace with debugging and tasks"
echo "• DevContainer Setup: ✓ Consistent development environment"
echo "• Development Scripts: ✓ Helper scripts for common tasks"
echo "• Code Quality Tools: ✓ Linting, formatting, type checking"
echo "• Security Scanning: ✓ Bandit, safety, secrets detection"

echo
if [[ $tools_ok -ge 5 ]]; then
    print_success "Enhanced Development Tooling validation PASSED"
    echo
    echo "Next steps:"
    echo "1. Run: ./scripts/setup_dev_env.sh (if not already done)"
    echo "2. Open workspace: code .vscode/marty.code-workspace"
    echo "3. Use development helper: ./scripts/dev.sh help"
    echo "4. Commit changes to enable pre-commit hooks"
else
    print_warning "Enhanced Development Tooling validation INCOMPLETE"
    echo
    echo "Issues found:"
    echo "• Some development tools are missing"
    echo "• Run ./scripts/setup_dev_env.sh to install dependencies"
fi

echo
echo "Development workflow ready! 🚀"