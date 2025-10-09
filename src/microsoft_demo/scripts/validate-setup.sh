#!/bin/bash

# Setup Validation Script for Microsoft Demo
# Validates that the demo environment is properly configured and ready

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="$(dirname "$SCRIPT_DIR")/config"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${CYAN}$1${NC}"
}

# Validate prerequisites
validate_prerequisites() {
    print_header "Validating Prerequisites"
    echo "========================"
    echo ""

    local missing_tools=()
    local optional_tools=()

    # Required tools
    if ! command -v docker &> /dev/null; then
        missing_tools+=("docker")
    else
        print_success "✅ Docker is installed"
        if docker info &> /dev/null; then
            print_success "✅ Docker is running"
        else
            print_error "❌ Docker is not running"
            missing_tools+=("docker-running")
        fi
    fi

    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        missing_tools+=("docker-compose")
    else
        print_success "✅ Docker Compose is installed"
    fi

    if ! command -v curl &> /dev/null; then
        missing_tools+=("curl")
    else
        print_success "✅ curl is installed"
    fi

    # Optional tools
    if ! command -v jq &> /dev/null; then
        optional_tools+=("jq")
    else
        print_success "✅ jq is installed"
    fi

    if ! command -v kubectl &> /dev/null; then
        optional_tools+=("kubectl")
    else
        print_success "✅ kubectl is installed"
    fi

    if ! command -v kind &> /dev/null; then
        optional_tools+=("kind")
    else
        print_success "✅ kind is installed"
    fi

    if ! command -v code &> /dev/null; then
        optional_tools+=("code")
    else
        print_success "✅ VS Code CLI is installed"
    fi

    # Report missing tools
    if [ ${#missing_tools[@]} -ne 0 ]; then
        print_error "❌ Missing required tools: ${missing_tools[*]}"
        echo ""
        echo "Install missing tools:"
        for tool in "${missing_tools[@]}"; do
            case $tool in
                docker)
                    echo "  Docker: brew install --cask docker"
                    ;;
                docker-compose)
                    echo "  Docker Compose: included with Docker Desktop"
                    ;;
                curl)
                    echo "  curl: brew install curl"
                    ;;
                docker-running)
                    echo "  Start Docker Desktop application"
                    ;;
            esac
        done
        return 1
    fi

    if [ ${#optional_tools[@]} -ne 0 ]; then
        print_warning "⚠️  Optional tools not found: ${optional_tools[*]}"
        echo "  These tools enhance the demo experience but are not required"
    fi

    print_success "✅ All required prerequisites satisfied"
    return 0
}

# Validate file structure
validate_file_structure() {
    print_header "Validating File Structure"
    echo "========================="
    echo ""

    local missing_files=()
    local required_files=(
        "issuer_api.py"
        "verifier_api.py"
        "__init__.py"
        "Makefile"
    )

    # Check if we're in the right directory
    local current_dir
    current_dir=$(basename "$(pwd)")
    if [ "$current_dir" != "microsoft_demo" ]; then
        print_warning "⚠️  Not in microsoft_demo directory (currently in: $current_dir)"
    fi

    # Check required files in current directory
    for file in "${required_files[@]}"; do
        if [ -f "$file" ]; then
            print_success "✅ Found: $file"
        else
            missing_files+=("$file")
        fi
    done

    # Check required directories
    local required_dirs=(
        "scripts"
        "config"
        "k8s"
        "docs"
    )

    for dir in "${required_dirs[@]}"; do
        if [ -d "$dir" ]; then
            print_success "✅ Found directory: $dir"
        else
            missing_files+=("$dir/")
        fi
    done

    if [ ${#missing_files[@]} -ne 0 ]; then
        print_error "❌ Missing files/directories: ${missing_files[*]}"
        return 1
    fi

    print_success "✅ File structure is valid"
    return 0
}

# Validate configuration
validate_configuration() {
    print_header "Validating Configuration"
    echo "========================"
    echo ""

    local env_file="$CONFIG_DIR/.env.demo"
    local config_issues=0

    # Check if environment file exists
    if [ -f "$env_file" ]; then
        print_success "✅ Environment file exists: $env_file"

        # Load environment
        # shellcheck source=/dev/null
        source "$env_file"

        # Check required variables
        local required_vars=(
            "ISSUER_BASE_URL"
            "VERIFIER_BASE_URL"
            "ISSUER_PORT"
            "VERIFIER_PORT"
        )

        for var in "${required_vars[@]}"; do
            if [ -n "${!var}" ]; then
                print_success "✅ $var is set: ${!var}"
            else
                print_error "❌ $var is not set"
                ((config_issues++))
            fi
        done

        # Validate URL formats
        if [[ -n "$ISSUER_BASE_URL" ]]; then
            if [[ "$ISSUER_BASE_URL" =~ ^https?:// ]]; then
                print_success "✅ Issuer URL format is valid"
            else
                print_error "❌ Issuer URL format is invalid"
                ((config_issues++))
            fi
        fi

        if [[ -n "$VERIFIER_BASE_URL" ]]; then
            if [[ "$VERIFIER_BASE_URL" =~ ^https?:// ]]; then
                print_success "✅ Verifier URL format is valid"
            else
                print_error "❌ Verifier URL format is invalid"
                ((config_issues++))
            fi
        fi

    else
        print_error "❌ Environment file not found: $env_file"
        print_info "   Run 'make setup-env' to create configuration"
        ((config_issues++))
    fi

    # Check Docker Compose files
    local docker_files=(
        "$CONFIG_DIR/docker-compose.demo-simple.yml"
        "$CONFIG_DIR/docker-compose.demo-full.yml"
    )

    for file in "${docker_files[@]}"; do
        if [ -f "$file" ]; then
            print_success "✅ Found Docker Compose file: $(basename "$file")"
        else
            print_warning "⚠️  Docker Compose file not found: $(basename "$file")"
        fi
    done

    if [ "$config_issues" -eq 0 ]; then
        print_success "✅ Configuration validation passed"
        return 0
    else
        print_error "❌ $config_issues configuration issue(s) found"
        return 1
    fi
}

# Validate scripts
validate_scripts() {
    print_header "Validating Scripts"
    echo "=================="
    echo ""

    local script_issues=0
    local required_scripts=(
        "setup-env.sh"
        "test-endpoints.sh"
        "test-workflow.sh"
        "wait-for-services.sh"
        "configure-urls.sh"
    )

    for script in "${required_scripts[@]}"; do
        local script_path="$SCRIPT_DIR/$script"
        if [ -f "$script_path" ]; then
            if [ -x "$script_path" ]; then
                print_success "✅ Script exists and is executable: $script"
            else
                print_warning "⚠️  Script exists but is not executable: $script"
                chmod +x "$script_path"
                print_info "   Made script executable"
            fi
        else
            print_error "❌ Script not found: $script"
            ((script_issues++))
        fi
    done

    if [ "$script_issues" -eq 0 ]; then
        print_success "✅ All required scripts are available"
        return 0
    else
        print_error "❌ $script_issues script(s) missing"
        return 1
    fi
}

# Validate Python API files
validate_api_files() {
    print_header "Validating API Files"
    echo "==================="
    echo ""

    local api_issues=0

    # Check issuer API
    if [ -f "issuer_api.py" ]; then
        print_success "✅ Issuer API file exists"

        # Basic syntax check
        if python3 -m py_compile issuer_api.py 2>/dev/null; then
            print_success "✅ Issuer API syntax is valid"
        else
            print_error "❌ Issuer API has syntax errors"
            ((api_issues++))
        fi
    else
        print_error "❌ Issuer API file not found"
        ((api_issues++))
    fi

    # Check verifier API
    if [ -f "verifier_api.py" ]; then
        print_success "✅ Verifier API file exists"

        # Basic syntax check
        if python3 -m py_compile verifier_api.py 2>/dev/null; then
            print_success "✅ Verifier API syntax is valid"
        else
            print_error "❌ Verifier API has syntax errors"
            ((api_issues++))
        fi
    else
        print_error "❌ Verifier API file not found"
        ((api_issues++))
    fi

    if [ "$api_issues" -eq 0 ]; then
        print_success "✅ API files validation passed"
        return 0
    else
        print_error "❌ $api_issues API file issue(s) found"
        return 1
    fi
}

# Check for port conflicts
check_port_conflicts() {
    print_header "Checking Port Availability"
    echo "=========================="
    echo ""

    local port_issues=0
    local ports=(8000 8001)

    for port in "${ports[@]}"; do
        if command -v lsof &> /dev/null; then
            if lsof -i ":$port" &> /dev/null; then
                print_warning "⚠️  Port $port is already in use"
                lsof -i ":$port" | head -2
                ((port_issues++))
            else
                print_success "✅ Port $port is available"
            fi
        else
            print_info "ℹ️  Cannot check port $port (lsof not available)"
        fi
    done

    if [ "$port_issues" -eq 0 ]; then
        print_success "✅ No port conflicts detected"
        return 0
    else
        print_warning "⚠️  $port_issues port(s) may have conflicts"
        print_info "   This may be OK if services are already running"
        return 0  # Don't fail on port conflicts as services might be running
    fi
}

# Show validation summary
show_validation_summary() {
    local total_failures=$1

    print_header "Validation Summary"
    echo "=================="
    echo ""

    if [ "$total_failures" -eq 0 ]; then
        print_success "🎉 All validation checks passed!"
        echo ""
        echo -e "${YELLOW}✅ Your Microsoft demo environment is properly configured${NC}"
        echo ""
        echo -e "${YELLOW}🚀 Ready to run:${NC}"
        echo "  make setup          - Start with Docker"
        echo "  make setup-k8s      - Start with Kubernetes"
        echo "  make setup-vscode   - Start with VS Code port forwarding"
        echo ""
    else
        print_error "❌ $total_failures validation check(s) failed"
        echo ""
        echo -e "${YELLOW}🔧 To fix issues:${NC}"
        echo "  1. Install missing prerequisites"
        echo "  2. Run: make setup-env"
        echo "  3. Fix any configuration issues"
        echo "  4. Re-run: make validate-setup"
        echo ""
    fi

    echo -e "${YELLOW}📖 For help:${NC}"
    echo "  make help           - Show all available commands"
    echo "  make show-config    - Show current configuration"
    echo ""
}

# Main function
main() {
    print_header "Microsoft Demo - Setup Validation"
    echo "================================="
    echo ""

    local total_failures=0

    # Run all validations
    validate_prerequisites || ((total_failures++))
    echo ""

    validate_file_structure || ((total_failures++))
    echo ""

    validate_configuration || ((total_failures++))
    echo ""

    validate_scripts || ((total_failures++))
    echo ""

    validate_api_files || ((total_failures++))
    echo ""

    check_port_conflicts || ((total_failures += $?))
    echo ""

    show_validation_summary "$total_failures"

    # Return appropriate exit code
    exit "$total_failures"
}

# Run main function
main "$@"
