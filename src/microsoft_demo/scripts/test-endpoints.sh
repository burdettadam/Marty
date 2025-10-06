#!/bin/bash

# Endpoint Testing Script for Microsoft Demo
# Tests API endpoints and basic functionality

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

# Load environment configuration
load_environment() {
    local tunnel_env_file="$CONFIG_DIR/.env.tunnel"
    local k8s_env_file="$CONFIG_DIR/.env.k8s"
    local env_file="$CONFIG_DIR/.env.demo"
    
    # Check for tunnel environment first (for development tunnels)
    if [ -f "$tunnel_env_file" ]; then
        # shellcheck source=/dev/null
        source "$tunnel_env_file"
        print_info "Development tunnel environment loaded from $tunnel_env_file"
        return 0
    fi
    
    # Check if Kubernetes cluster is running and use K8s config
    if kind get clusters 2>/dev/null | grep -q "marty-microsoft-demo"; then
        if [ -f "$k8s_env_file" ]; then
            # shellcheck source=/dev/null
            source "$k8s_env_file"
            print_info "Kubernetes cluster detected. Environment loaded from $k8s_env_file"
            return 0
        fi
    fi
    
    # Fall back to demo environment
    if [ -f "$env_file" ]; then
        # shellcheck source=/dev/null
        source "$env_file"
        print_info "Environment loaded from $env_file"
    else
        print_error "Environment file not found: $env_file"
        print_info "Please run 'make setup-env' first"
        exit 1
    fi
    
    # Set defaults if not provided
    ISSUER_BASE_URL=${ISSUER_BASE_URL:-http://localhost:8000}
    VERIFIER_BASE_URL=${VERIFIER_BASE_URL:-http://localhost:8001}
}

# Test basic connectivity
test_connectivity() {
    print_header "Testing Basic Connectivity"
    echo "=========================="
    echo ""
    
    local success_count=0
    local total_count=2
    
    # Test issuer API connectivity
    print_info "Testing Issuer API connectivity..."
    if curl -f -s --max-time 10 "$ISSUER_BASE_URL" > /dev/null 2>&1; then
        print_success "✅ Issuer API is reachable at $ISSUER_BASE_URL"
        ((success_count++))
    else
        print_error "❌ Issuer API is not reachable at $ISSUER_BASE_URL"
    fi
    
    # Test verifier API connectivity
    print_info "Testing Verifier API connectivity..."
    if curl -f -s --max-time 10 "$VERIFIER_BASE_URL" > /dev/null 2>&1; then
        print_success "✅ Verifier API is reachable at $VERIFIER_BASE_URL"
        ((success_count++))
    else
        print_error "❌ Verifier API is not reachable at $VERIFIER_BASE_URL"
    fi
    
    echo ""
    echo "Connectivity: $success_count/$total_count tests passed"
    return $((total_count - success_count))
}

# Test health endpoints
test_health_endpoints() {
    print_header "Testing Health Endpoints"
    echo "========================"
    echo ""
    
    local success_count=0
    local total_count=2
    
    # Test issuer health
    print_info "Testing Issuer API health endpoint..."
    local issuer_health
    issuer_health=$(curl -f -s --max-time 10 "$ISSUER_BASE_URL/health" 2>/dev/null || echo "ERROR")
    
    if [ "$issuer_health" != "ERROR" ]; then
        print_success "✅ Issuer API health check passed"
        echo "   Response: $issuer_health"
        ((success_count++))
    else
        print_error "❌ Issuer API health check failed"
    fi
    
    # Test verifier health
    print_info "Testing Verifier API health endpoint..."
    local verifier_health
    verifier_health=$(curl -f -s --max-time 10 "$VERIFIER_BASE_URL/health" 2>/dev/null || echo "ERROR")
    
    if [ "$verifier_health" != "ERROR" ]; then
        print_success "✅ Verifier API health check passed"
        echo "   Response: $verifier_health"
        ((success_count++))
    else
        print_error "❌ Verifier API health check failed"
    fi
    
    echo ""
    echo "Health checks: $success_count/$total_count tests passed"
    return $((total_count - success_count))
}

# Test API documentation endpoints
test_documentation() {
    print_header "Testing API Documentation"
    echo "========================="
    echo ""
    
    local success_count=0
    local total_count=2
    
    # Test issuer documentation
    print_info "Testing Issuer API documentation..."
    if curl -f -s --max-time 10 "$ISSUER_BASE_URL/docs" > /dev/null 2>&1; then
        print_success "✅ Issuer API documentation is available"
        echo "   URL: $ISSUER_BASE_URL/docs"
        ((success_count++))
    else
        print_error "❌ Issuer API documentation is not available"
    fi
    
    # Test verifier documentation
    print_info "Testing Verifier API documentation..."
    if curl -f -s --max-time 10 "$VERIFIER_BASE_URL/docs" > /dev/null 2>&1; then
        print_success "✅ Verifier API documentation is available"
        echo "   URL: $VERIFIER_BASE_URL/docs"
        ((success_count++))
    else
        print_error "❌ Verifier API documentation is not available"
    fi
    
    echo ""
    echo "Documentation: $success_count/$total_count tests passed"
    return $((total_count - success_count))
}

# Test basic API functionality
test_api_functionality() {
    print_header "Testing API Functionality"
    echo "========================="
    echo ""
    
    local success_count=0
    local total_count=0
    
    # Test issuer credential offer endpoint
    print_info "Testing Issuer API credential offer..."
    local offer_response
    offer_response=$(curl -f -s --max-time 10 -X POST "$ISSUER_BASE_URL/credential-offer" \
        -H "Content-Type: application/json" \
        -d '{"type":"EmployeeCredential","subject_data":{"name":"Test User","email":"test@example.com"}}' 2>/dev/null || echo "ERROR")
    
    ((total_count++))
    if [ "$offer_response" != "ERROR" ] && [ -n "$offer_response" ]; then
        print_success "✅ Issuer API credential offer endpoint working"
        echo "   Response length: ${#offer_response} characters"
        ((success_count++))
    else
        print_error "❌ Issuer API credential offer endpoint failed"
    fi
    
    # Test verifier presentation request endpoint
    print_info "Testing Verifier API presentation request..."
    local presentation_response
    presentation_response=$(curl -f -s --max-time 10 -X POST "$VERIFIER_BASE_URL/presentation-request" \
        -H "Content-Type: application/json" \
        -d '{"presentation_definition":{"id":"test_request","input_descriptors":[{"id":"employee_credential","schema":[{"uri":"EmployeeCredential"}]}]}}' 2>/dev/null || echo "ERROR")
    
    ((total_count++))
    if [ "$presentation_response" != "ERROR" ] && [ -n "$presentation_response" ]; then
        print_success "✅ Verifier API presentation request endpoint working"
        echo "   Response length: ${#presentation_response} characters"
        ((success_count++))
    else
        print_error "❌ Verifier API presentation request endpoint failed"
    fi
    
    echo ""
    echo "API functionality: $success_count/$total_count tests passed"
    return $((total_count - success_count))
}

# Test HTTPS requirements for Microsoft Authenticator
test_https_requirements() {
    print_header "Testing Microsoft Authenticator Requirements"
    echo "==========================================="
    echo ""
    
    local success_count=0
    local total_count=2
    
    # Check if URLs use HTTPS (required for Microsoft Authenticator)
    print_info "Checking HTTPS requirements..."
    
    if [[ "$ISSUER_BASE_URL" =~ ^https:// ]]; then
        print_success "✅ Issuer URL uses HTTPS (required for Microsoft Authenticator)"
        ((success_count++))
    elif [[ "$ISSUER_BASE_URL" =~ localhost ]]; then
        print_warning "⚠️  Issuer URL uses HTTP with localhost (OK for testing)"
        ((success_count++))
    else
        print_error "❌ Issuer URL must use HTTPS for Microsoft Authenticator"
    fi
    
    if [[ "$VERIFIER_BASE_URL" =~ ^https:// ]]; then
        print_success "✅ Verifier URL uses HTTPS (required for Microsoft Authenticator)"
        ((success_count++))
    elif [[ "$VERIFIER_BASE_URL" =~ localhost ]]; then
        print_warning "⚠️  Verifier URL uses HTTP with localhost (OK for testing)"
        ((success_count++))
    else
        print_error "❌ Verifier URL must use HTTPS for Microsoft Authenticator"
    fi
    
    echo ""
    echo "HTTPS requirements: $success_count/$total_count tests passed"
    return $((total_count - success_count))
}

# Show test summary
show_summary() {
    local total_failures=$1
    
    print_header "Test Summary"
    echo "============"
    echo ""
    
    if [ "$total_failures" -eq 0 ]; then
        print_success "🎉 All tests passed! Your Microsoft demo is ready."
        echo ""
        echo -e "${YELLOW}📱 Next steps for Microsoft Authenticator testing:${NC}"
        echo "  1. Open your mobile device's Microsoft Authenticator app"
        echo "  2. Use the app to scan QR codes from the demo"
        echo "  3. Test credential issuance: $ISSUER_BASE_URL"
        echo "  4. Test credential verification: $VERIFIER_BASE_URL"
    else
        print_error "❌ $total_failures test(s) failed. Please check the output above."
        echo ""
        echo -e "${YELLOW}🔧 Troubleshooting:${NC}"
        echo "  1. Ensure services are running: make status"
        echo "  2. Check service logs: make docker-logs (or make k8s-logs)"
        echo "  3. Verify configuration: make show-config"
        echo "  4. Restart services: make docker-restart (or make k8s-restart)"
    fi
    
    echo ""
    echo -e "${YELLOW}📖 Useful commands:${NC}"
    echo "  make status         - Check overall status"
    echo "  make test-workflow  - Test complete credential workflow"
    echo "  make open-docs      - Open API documentation"
    echo ""
}

# Main function
main() {
    print_header "Microsoft Demo - Endpoint Testing"
    echo "================================="
    echo ""
    
    load_environment
    
    local total_failures=0
    
    # Run all tests
    test_connectivity || ((total_failures += $?))
    echo ""
    
    test_health_endpoints || ((total_failures += $?))
    echo ""
    
    test_documentation || ((total_failures += $?))
    echo ""
    
    test_api_functionality || ((total_failures += $?))
    echo ""
    
    test_https_requirements || ((total_failures += $?))
    echo ""
    
    show_summary "$total_failures"
    
    # Return appropriate exit code
    exit "$total_failures"
}

# Run main function
main "$@"