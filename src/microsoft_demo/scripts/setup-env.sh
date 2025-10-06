#!/bin/bash

# Microsoft Demo Environment Setup Script
# Consolidates all setup functionality for the Microsoft Authenticator demo
#
# Usage: ./setup-env.sh [--docker|--k8s|--vscode]
#

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

# Function to print colored output
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

# Function to check prerequisites
check_prerequisites() {
    print_info "Checking prerequisites..."
    
    local missing_tools=()
    
    if ! command -v docker &> /dev/null; then
        missing_tools+=("docker")
    fi
    
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        missing_tools+=("docker-compose")
    fi
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        print_error "Missing required tools: ${missing_tools[*]}"
        echo "Please install the missing tools and try again."
        exit 1
    fi
    
    print_success "All prerequisites satisfied"
}

# Function to setup environment file
setup_environment() {
    print_info "Setting up environment configuration..."
    
    local env_file="$CONFIG_DIR/.env.demo"
    local env_template="$CONFIG_DIR/.env.template"
    
    # Create config directory if it doesn't exist
    mkdir -p "$CONFIG_DIR"
    
    # Create environment template if it doesn't exist
    if [ ! -f "$env_template" ]; then
        cat > "$env_template" << 'EOF'
# Microsoft Authenticator Demo Environment Configuration
# Copy this file to .env.demo and customize as needed

# API Configuration
ISSUER_BASE_URL=http://localhost:8000
VERIFIER_BASE_URL=http://localhost:8001
CREDENTIAL_ISSUER_DID=did:web:localhost%3A8000

# Service Ports
ISSUER_PORT=8000
VERIFIER_PORT=8001

# CORS Configuration
CORS_ORIGINS=http://localhost:3000,http://localhost:8000,http://localhost:8001

# Logging
LOG_LEVEL=INFO

# Database Configuration (for full setup)
POSTGRES_USER=martyuser
POSTGRES_PASSWORD=martypassword
POSTGRES_DB=martydb
POSTGRES_PORT=5433

# MinIO Configuration (for full setup)
MINIO_ROOT_USER=minioadmin
MINIO_ROOT_PASSWORD=minioadmin123
MINIO_PORT=9000
MINIO_CONSOLE_PORT=9001

# For VS Code port forwarding, update these URLs with your actual forwarded URLs:
# ISSUER_BASE_URL=https://your-port-8000.preview.app.github.dev
# VERIFIER_BASE_URL=https://your-port-8001.preview.app.github.dev
EOF
    fi
    
    # Copy template to env file if it doesn't exist
    if [ ! -f "$env_file" ]; then
        cp "$env_template" "$env_file"
        print_success "Created environment file: $env_file"
    else
        print_warning "Environment file already exists: $env_file"
    fi
    
    # Source the environment file
    if [ -f "$env_file" ]; then
        set -a  # automatically export all variables
        # shellcheck source=/dev/null
        source "$env_file"
        set +a
        print_success "Environment loaded from $env_file"
    fi
}

# Function to validate environment
validate_environment() {
    print_info "Validating environment configuration..."
    
    local required_vars=(
        "ISSUER_BASE_URL"
        "VERIFIER_BASE_URL"
        "ISSUER_PORT"
        "VERIFIER_PORT"
    )
    
    local missing_vars=()
    
    for var in "${required_vars[@]}"; do
        if [ -z "${!var}" ]; then
            missing_vars+=("$var")
        fi
    done
    
    if [ ${#missing_vars[@]} -ne 0 ]; then
        print_error "Missing required environment variables: ${missing_vars[*]}"
        print_info "Please check your environment file: $CONFIG_DIR/.env.demo"
        exit 1
    fi
    
    print_success "Environment validation passed"
}

# Function to show setup information
show_setup_info() {
    print_header "Microsoft Authenticator Demo Setup Complete!"
    echo "============================================="
    echo ""
    echo -e "${YELLOW}📱 Configuration:${NC}"
    echo "  Issuer API:    ${ISSUER_BASE_URL}"
    echo "  Verifier API:  ${VERIFIER_BASE_URL}"
    echo ""
    echo -e "${YELLOW}📁 File Locations:${NC}"
    echo "  Environment:   $CONFIG_DIR/.env.demo"
    echo "  Scripts:       $SCRIPT_DIR"
    echo "  Config:        $CONFIG_DIR"
    echo ""
    echo -e "${YELLOW}🔧 Next Steps:${NC}"
    echo "  1. Run: make setup          (for Docker)"
    echo "  2. Run: make setup-k8s      (for Kubernetes)"
    echo "  3. Run: make setup-vscode   (for VS Code port forwarding)"
    echo ""
}

# Main execution
main() {
    print_header "Microsoft Authenticator Demo Environment Setup"
    echo "==============================================="
    echo ""
    
    check_prerequisites
    setup_environment
    validate_environment
    show_setup_info
    
    print_success "Environment setup complete!"
}

# Run main function
main "$@"