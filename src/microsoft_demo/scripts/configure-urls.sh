#!/bin/bash

# URL Configuration Script for Microsoft Demo
# Updates environment and deployment configurations with custom URLs

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="$(dirname "$SCRIPT_DIR")/config"
NAMESPACE="marty-microsoft-demo"

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

# Parse command line arguments
parse_args() {
    ISSUER_URL=""
    VERIFIER_URL=""
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --issuer-url)
                ISSUER_URL="$2"
                shift 2
                ;;
            --verifier-url)
                VERIFIER_URL="$2"
                shift 2
                ;;
            --help|-h)
                show_usage
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    # Validate required parameters
    if [ -z "$ISSUER_URL" ] || [ -z "$VERIFIER_URL" ]; then
        print_error "Both --issuer-url and --verifier-url are required"
        show_usage
        exit 1
    fi
}

# Show usage information
show_usage() {
    echo "Usage: $0 --issuer-url <URL> --verifier-url <URL>"
    echo ""
    echo "Configure custom URLs for the Microsoft demo APIs"
    echo ""
    echo "Options:"
    echo "  --issuer-url <URL>     Set the issuer API URL"
    echo "  --verifier-url <URL>   Set the verifier API URL"
    echo "  --help, -h             Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 --issuer-url https://abc-8000.devtunnels.ms --verifier-url https://def-8001.devtunnels.ms"
    echo "  $0 --issuer-url https://port-8000.preview.app.github.dev --verifier-url https://port-8001.preview.app.github.dev"
}

# Validate URLs
validate_urls() {
    print_info "Validating URLs..."
    
    # Check URL format
    if [[ ! "$ISSUER_URL" =~ ^https?:// ]]; then
        print_error "Issuer URL must start with http:// or https://"
        exit 1
    fi
    
    if [[ ! "$VERIFIER_URL" =~ ^https?:// ]]; then
        print_error "Verifier URL must start with http:// or https://"
        exit 1
    fi
    
    # For Microsoft Authenticator, URLs should be HTTPS
    if [[ "$ISSUER_URL" =~ ^http:// ]] && [[ ! "$ISSUER_URL" =~ localhost ]]; then
        print_warning "Microsoft Authenticator requires HTTPS URLs. Your issuer URL should use HTTPS."
    fi
    
    if [[ "$VERIFIER_URL" =~ ^http:// ]] && [[ ! "$VERIFIER_URL" =~ localhost ]]; then
        print_warning "Microsoft Authenticator requires HTTPS URLs. Your verifier URL should use HTTPS."
    fi
    
    print_success "URLs validated"
}

# Update environment file
update_environment_file() {
    print_info "Updating environment configuration..."
    
    local env_file="$CONFIG_DIR/.env.demo"
    
    # Create config directory if it doesn't exist
    mkdir -p "$CONFIG_DIR"
    
    # Backup existing env file
    if [ -f "$env_file" ]; then
        cp "$env_file" "${env_file}.backup.$(date +%Y%m%d_%H%M%S)"
        print_info "Backed up existing environment file"
    fi
    
    # Update or create environment file
    {
        echo "# Microsoft Authenticator Demo Environment Configuration"
        echo "# Updated on $(date)"
        echo ""
        echo "# API Configuration"
        echo "ISSUER_BASE_URL=$ISSUER_URL"
        echo "VERIFIER_BASE_URL=$VERIFIER_URL"
        
        # Extract DID from issuer URL
        local issuer_host
        issuer_host=$(echo "$ISSUER_URL" | sed -E 's|^https?://([^/]+).*|\1|')
        # URL encode the colon if present
        issuer_host=$(echo "$issuer_host" | sed 's/:/%3A/g')
        echo "CREDENTIAL_ISSUER_DID=did:web:$issuer_host"
        
        echo ""
        echo "# Service Ports (for local development)"
        echo "ISSUER_PORT=8000"
        echo "VERIFIER_PORT=8001"
        echo ""
        echo "# CORS Configuration"
        echo "CORS_ORIGINS=$ISSUER_URL,$VERIFIER_URL,http://localhost:3000"
        echo ""
        echo "# Logging"
        echo "LOG_LEVEL=INFO"
        echo ""
        echo "# Database Configuration (for full setup)"
        echo "POSTGRES_USER=martyuser"
        echo "POSTGRES_PASSWORD=martypassword"
        echo "POSTGRES_DB=martydb"
        echo "POSTGRES_PORT=5433"
        echo ""
        echo "# MinIO Configuration (for full setup)"
        echo "MINIO_ROOT_USER=minioadmin"
        echo "MINIO_ROOT_PASSWORD=minioadmin123"
        echo "MINIO_PORT=9000"
        echo "MINIO_CONSOLE_PORT=9001"
    } > "$env_file"
    
    print_success "Environment file updated: $env_file"
}

# Update Kubernetes ConfigMap if applicable
update_k8s_config() {
    if command -v kubectl &> /dev/null && kubectl get namespace "$NAMESPACE" &> /dev/null; then
        print_info "Updating Kubernetes ConfigMap..."
        
        # Extract DID from issuer URL
        local issuer_host
        issuer_host=$(echo "$ISSUER_URL" | sed -E 's|^https?://([^/]+).*|\1|')
        issuer_host=$(echo "$issuer_host" | sed 's/:/%3A/g')
        
        # Update ConfigMap
        kubectl patch configmap microsoft-demo-config -n "$NAMESPACE" --patch="
data:
  ISSUER_BASE_URL: \"$ISSUER_URL\"
  VERIFIER_BASE_URL: \"$VERIFIER_URL\"
  CREDENTIAL_ISSUER_DID: \"did:web:$issuer_host\"
  CORS_ORIGINS: \"$ISSUER_URL,$VERIFIER_URL,http://localhost:3000\"
" 2>/dev/null && print_success "Kubernetes ConfigMap updated" || print_warning "Could not update Kubernetes ConfigMap (this is OK if not using K8s)"
        
        # Restart deployments to pick up new configuration
        if kubectl get deployment issuer-api-microsoft-demo -n "$NAMESPACE" &> /dev/null; then
            print_info "Restarting Kubernetes deployments..."
            kubectl rollout restart deployment/issuer-api-microsoft-demo -n "$NAMESPACE" 2>/dev/null || true
            kubectl rollout restart deployment/verifier-api-microsoft-demo -n "$NAMESPACE" 2>/dev/null || true
            print_success "Kubernetes deployments restarted"
        fi
    else
        print_info "Kubernetes not available or namespace not found - skipping K8s configuration"
    fi
}

# Test connectivity
test_connectivity() {
    print_info "Testing connectivity to configured URLs..."
    
    # Wait a moment for services to restart
    sleep 5
    
    # Test issuer URL
    if curl -f -s --max-time 10 "$ISSUER_URL/health" > /dev/null 2>&1; then
        print_success "Issuer API is accessible at $ISSUER_URL"
    else
        print_warning "Issuer API may not be ready yet at $ISSUER_URL"
    fi
    
    # Test verifier URL
    if curl -f -s --max-time 10 "$VERIFIER_URL/health" > /dev/null 2>&1; then
        print_success "Verifier API is accessible at $VERIFIER_URL"
    else
        print_warning "Verifier API may not be ready yet at $VERIFIER_URL"
    fi
}

# Show configuration summary
show_summary() {
    print_header "Configuration Summary"
    echo "===================="
    echo ""
    echo -e "${YELLOW}📱 API Endpoints:${NC}"
    echo "  Issuer API:    $ISSUER_URL"
    echo "  Verifier API:  $VERIFIER_URL"
    echo ""
    echo -e "${YELLOW}📖 Documentation:${NC}"
    echo "  Issuer docs:   $ISSUER_URL/docs"
    echo "  Verifier docs: $VERIFIER_URL/docs"
    echo ""
    echo -e "${YELLOW}🧪 Test URLs:${NC}"
    echo "  Issuer health: $ISSUER_URL/health"
    echo "  Verifier health: $VERIFIER_URL/health"
    echo ""
    echo -e "${YELLOW}🔧 Next Steps:${NC}"
    echo "  1. Test endpoints: make test-endpoints"
    echo "  2. Open documentation: make open-docs"
    echo "  3. Run workflow test: make test-workflow"
    echo ""
}

# Main function
main() {
    print_header "Microsoft Demo - URL Configuration"
    echo "=================================="
    echo ""
    
    parse_args "$@"
    validate_urls
    update_environment_file
    update_k8s_config
    test_connectivity
    show_summary
    
    print_success "URL configuration complete!"
}

# Run main function
main "$@"