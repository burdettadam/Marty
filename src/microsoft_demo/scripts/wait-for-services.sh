#!/bin/bash

# Service Waiting Script for Microsoft Demo
# Waits for services to be ready before proceeding

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="$(dirname "$SCRIPT_DIR")/config"

# Default timeouts (in seconds)
DEFAULT_TIMEOUT=120
HEALTH_CHECK_INTERVAL=5

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
    local env_file="$CONFIG_DIR/.env.demo"
    
    if [ -f "$env_file" ]; then
        # shellcheck source=/dev/null
        source "$env_file"
        print_info "Environment loaded"
    else
        print_warning "Environment file not found, using defaults"
    fi
    
    # Set defaults if not provided
    ISSUER_BASE_URL=${ISSUER_BASE_URL:-http://localhost:8000}
    VERIFIER_BASE_URL=${VERIFIER_BASE_URL:-http://localhost:8001}
}

# Wait for a single service to be ready
wait_for_service() {
    local service_name="$1"
    local service_url="$2"
    local timeout="${3:-$TIMEOUT}"
    
    print_info "Waiting for $service_name to be ready..."
    print_info "URL: $service_url"
    print_info "Timeout: ${timeout}s"
    
    local start_time
    start_time=$(date +%s)
    local end_time=$((start_time + timeout))
    
    while [ "$(date +%s)" -lt "$end_time" ]; do
        if curl -f -s --max-time 5 "$service_url/health" > /dev/null 2>&1; then
            local elapsed=$(($(date +%s) - start_time))
            print_success "✅ $service_name is ready (took ${elapsed}s)"
            return 0
        fi
        
        echo -n "."
        sleep "$HEALTH_CHECK_INTERVAL"
    done
    
    echo ""
    print_error "❌ $service_name failed to become ready within ${timeout}s"
    return 1
}

# Wait for all Microsoft demo services
wait_for_all_services() {
    print_header "Waiting for Microsoft Demo Services"
    echo "===================================="
    echo ""
    
    local total_failures=0
    
    # Wait for issuer API
    wait_for_service "Issuer API" "$ISSUER_BASE_URL" || ((total_failures++))
    echo ""
    
    # Wait for verifier API
    wait_for_service "Verifier API" "$VERIFIER_BASE_URL" || ((total_failures++))
    echo ""
    
    return "$total_failures"
}

# Check service versions and build info
check_service_info() {
    print_header "Service Information"
    echo "=================="
    echo ""
    
    # Check issuer API info
    print_info "Issuer API information:"
    local issuer_info
    issuer_info=$(curl -f -s --max-time 10 "$ISSUER_BASE_URL/" 2>/dev/null || echo "ERROR")
    
    if [ "$issuer_info" != "ERROR" ]; then
        if command -v jq &> /dev/null; then
            echo "$issuer_info" | jq -r '
                if .name then
                    "  Name: " + .name + "\n" +
                    "  Version: " + (.version // "N/A") + "\n" +
                    "  Status: " + (.status // "N/A")
                else
                    "  Response: " + (. | tostring | .[0:100] + "...")
                end
            ' 2>/dev/null || echo "  Raw response: ${issuer_info:0:100}..."
        else
            echo "  Response: ${issuer_info:0:100}..."
        fi
    else
        print_warning "  Could not retrieve issuer API information"
    fi
    
    echo ""
    
    # Check verifier API info
    print_info "Verifier API information:"
    local verifier_info
    verifier_info=$(curl -f -s --max-time 10 "$VERIFIER_BASE_URL/" 2>/dev/null || echo "ERROR")
    
    if [ "$verifier_info" != "ERROR" ]; then
        if command -v jq &> /dev/null; then
            echo "$verifier_info" | jq -r '
                if .name then
                    "  Name: " + .name + "\n" +
                    "  Version: " + (.version // "N/A") + "\n" +
                    "  Status: " + (.status // "N/A")
                else
                    "  Response: " + (. | tostring | .[0:100] + "...")
                end
            ' 2>/dev/null || echo "  Raw response: ${verifier_info:0:100}..."
        else
            echo "  Response: ${verifier_info:0:100}..."
        fi
    else
        print_warning "  Could not retrieve verifier API information"
    fi
    
    echo ""
}

# Show service endpoints
show_endpoints() {
    print_header "Service Endpoints"
    echo "================="
    echo ""
    
    echo -e "${YELLOW}📱 API Endpoints:${NC}"
    echo "  Issuer API:    $ISSUER_BASE_URL"
    echo "  Verifier API:  $VERIFIER_BASE_URL"
    echo ""
    
    echo -e "${YELLOW}📖 Documentation:${NC}"
    echo "  Issuer docs:   $ISSUER_BASE_URL/docs"
    echo "  Verifier docs: $VERIFIER_BASE_URL/docs"
    echo ""
    
    echo -e "${YELLOW}🔍 Health Checks:${NC}"
    echo "  Issuer health: $ISSUER_BASE_URL/health"
    echo "  Verifier health: $VERIFIER_BASE_URL/health"
    echo ""
    
    if curl -f -s --max-time 5 "$ISSUER_BASE_URL/demo" > /dev/null 2>&1; then
        echo -e "${YELLOW}🎮 Demo Interfaces:${NC}"
        echo "  Issuer demo:   $ISSUER_BASE_URL/demo"
    fi
    
    if curl -f -s --max-time 5 "$VERIFIER_BASE_URL/demo" > /dev/null 2>&1; then
        if [[ ! "$ISSUER_BASE_URL/demo" =~ demo ]]; then
            echo -e "${YELLOW}🎮 Demo Interfaces:${NC}"
        fi
        echo "  Verifier demo: $VERIFIER_BASE_URL/demo"
    fi
}

# Validate service health
validate_health() {
    print_header "Service Health Validation"
    echo "========================="
    echo ""
    
    local health_issues=0
    
    # Check issuer health
    print_info "Validating Issuer API health..."
    local issuer_health
    issuer_health=$(curl -f -s --max-time 10 "$ISSUER_BASE_URL/health" 2>/dev/null || echo "ERROR")
    
    if [ "$issuer_health" != "ERROR" ]; then
        print_success "✅ Issuer API is healthy"
        if command -v jq &> /dev/null && echo "$issuer_health" | jq -e . > /dev/null 2>&1; then
            echo "$issuer_health" | jq -r '
                if .status then
                    "  Status: " + (.status | tostring)
                else
                    "  Response: " + (. | tostring)
                end
            ' 2>/dev/null || echo "  Response: ${issuer_health}"
        else
            echo "  Response: ${issuer_health}"
        fi
    else
        print_error "❌ Issuer API health check failed"
        ((health_issues++))
    fi
    
    # Check verifier health
    print_info "Validating Verifier API health..."
    local verifier_health
    verifier_health=$(curl -f -s --max-time 10 "$VERIFIER_BASE_URL/health" 2>/dev/null || echo "ERROR")
    
    if [ "$verifier_health" != "ERROR" ]; then
        print_success "✅ Verifier API is healthy"
        if command -v jq &> /dev/null && echo "$verifier_health" | jq -e . > /dev/null 2>&1; then
            echo "$verifier_health" | jq -r '
                if .status then
                    "  Status: " + (.status | tostring)
                else
                    "  Response: " + (. | tostring)
                end
            ' 2>/dev/null || echo "  Response: ${verifier_health}"
        else
            echo "  Response: ${verifier_health}"
        fi
    else
        print_error "❌ Verifier API health check failed"
        ((health_issues++))
    fi
    
    echo ""
    if [ "$health_issues" -eq 0 ]; then
        print_success "✅ All services are healthy"
    else
        print_error "❌ $health_issues service(s) failed health checks"
    fi
    
    return "$health_issues"
}

# Show summary
show_summary() {
    local total_failures=$1
    
    print_header "Service Ready Summary"
    echo "===================="
    echo ""
    
    if [ "$total_failures" -eq 0 ]; then
        print_success "🎉 All Microsoft demo services are ready!"
        echo ""
        echo -e "${YELLOW}🚀 Next steps:${NC}"
        echo "  1. Test endpoints: make test-endpoints"
        echo "  2. Run workflow test: make test-workflow"
        echo "  3. Open demo interfaces in browser"
        echo "  4. Test with Microsoft Authenticator mobile app"
        echo ""
    else
        print_error "❌ Some services failed to become ready"
        echo ""
        echo -e "${YELLOW}🔧 Troubleshooting:${NC}"
        echo "  1. Check service logs: make docker-logs"
        echo "  2. Verify configuration: make show-config"
        echo "  3. Restart services: make docker-restart"
        echo ""
    fi
}

# Parse command line arguments
parse_args() {
    TIMEOUT="$DEFAULT_TIMEOUT"
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --timeout)
                TIMEOUT="$2"
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
}

# Show usage
show_usage() {
    echo "Usage: $0 [--timeout SECONDS] [--help]"
    echo ""
    echo "Wait for Microsoft demo services to be ready"
    echo ""
    echo "Options:"
    echo "  --timeout SECONDS  Maximum time to wait (default: $DEFAULT_TIMEOUT)"
    echo "  --help, -h         Show this help message"
}

# Main function
main() {
    print_header "Microsoft Demo - Service Readiness Check"
    echo "========================================"
    echo ""
    
    parse_args "$@"
    load_environment
    
    local total_failures=0
    
    # Wait for services
    wait_for_all_services || ((total_failures += $?))
    
    # If services are ready, get additional info
    if [ "$total_failures" -eq 0 ]; then
        check_service_info
        show_endpoints
        validate_health || ((total_failures += $?))
    fi
    
    show_summary "$total_failures"
    
    # Return appropriate exit code
    exit "$total_failures"
}

# Run main function
main "$@"