#!/bin/bash

# Workflow Testing Script for Microsoft Demo
# Tests the complete credential issuance and verification workflow

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
    local env_file="$CONFIG_DIR/.env.demo"

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

# Test credential offer creation
test_credential_offer() {
    print_header "Testing Credential Offer Creation"
    echo "================================="
    echo ""

    print_info "Creating credential offer..."

    local offer_data='{
        "credential_type": "MartyDigitalPassport",
        "subject_claims": {
            "given_name": "John",
            "family_name": "Doe",
            "birth_date": "1990-01-01",
            "nationality": "US",
            "passport_number": "TEST123456"
        }
    }'

    local offer_response
    offer_response=$(curl -f -s --max-time 30 -X POST "$ISSUER_BASE_URL/offer" \
        -H "Content-Type: application/json" \
        -d "$offer_data" 2>/dev/null || echo "ERROR")

    if [ "$offer_response" = "ERROR" ]; then
        print_error "❌ Failed to create credential offer"
        return 1
    fi

    print_success "✅ Credential offer created successfully"

    # Parse and display offer details
    if command -v jq &> /dev/null; then
        print_info "Offer details:"
        echo "$offer_response" | jq -r '
            if .credential_offer then
                "  Offer ID: " + (.credential_offer.credential_issuer // "N/A") + "\n" +
                "  Credentials: " + (.credential_offer.credentials | length | tostring)
            elif .qr_code_url then
                "  QR Code URL: " + .qr_code_url
            else
                "  Raw response: " + (. | tostring | .[0:100] + "...")
            end
        ' 2>/dev/null || echo "  Response: ${offer_response:0:200}..."
    else
        print_info "Offer response length: ${#offer_response} characters"
        echo "  (Install 'jq' for detailed response parsing)"
    fi

    # Save offer for potential verification test
    echo "$offer_response" > /tmp/microsoft_demo_offer.json

    return 0
}

# Test presentation request creation
test_presentation_request() {
    print_header "Testing Presentation Request Creation"
    echo "====================================="
    echo ""

    print_info "Creating presentation request..."

    local request_data='{
        "presentation_definition": {
            "id": "marty_passport_verification",
            "purpose": "Verify Marty Digital Passport",
            "input_descriptors": [
                {
                    "id": "marty_passport",
                    "name": "Marty Digital Passport",
                    "purpose": "Verify identity using Marty Digital Passport",
                    "schema": [
                        {
                            "uri": "MartyDigitalPassport"
                        }
                    ],
                    "constraints": {
                        "fields": [
                            {
                                "path": ["$.credentialSubject.given_name"],
                                "filter": {
                                    "type": "string"
                                }
                            }
                        ]
                    }
                }
            ]
        }
    }'

    local request_response
    request_response=$(curl -f -s --max-time 30 -X POST "$VERIFIER_BASE_URL/request" \
        -H "Content-Type: application/json" \
        -d "$request_data" 2>/dev/null || echo "ERROR")

    if [ "$request_response" = "ERROR" ]; then
        print_error "❌ Failed to create presentation request"
        return 1
    fi

    print_success "✅ Presentation request created successfully"

    # Parse and display request details
    if command -v jq &> /dev/null; then
        print_info "Request details:"
        echo "$request_response" | jq -r '
            if .presentation_request then
                "  Request ID: " + (.presentation_request.id // "N/A") + "\n" +
                "  Purpose: " + (.presentation_request.purpose // "N/A")
            elif .qr_code_url then
                "  QR Code URL: " + .qr_code_url
            else
                "  Raw response: " + (. | tostring | .[0:100] + "...")
            end
        ' 2>/dev/null || echo "  Response: ${request_response:0:200}..."
    else
        print_info "Request response length: ${#request_response} characters"
        echo "  (Install 'jq' for detailed response parsing)"
    fi

    return 0
}

# Test QR code generation
test_qr_code_generation() {
    print_header "Testing QR Code Generation"
    echo "=========================="
    echo ""

    local success_count=0
    local total_count=2

    # Test issuer QR code endpoint
    print_info "Testing issuer QR code generation..."
    local issuer_qr
    issuer_qr=$(curl -f -s --max-time 15 "$ISSUER_BASE_URL/qr?url=test" 2>/dev/null || echo "ERROR")

    if [ "$issuer_qr" != "ERROR" ] && [ -n "$issuer_qr" ]; then
        print_success "✅ Issuer QR code generation working"
        ((success_count++))
    else
        print_error "❌ Issuer QR code generation failed"
    fi

    # Test verifier QR code endpoint
    print_info "Testing verifier QR code generation..."
    local verifier_qr
    verifier_qr=$(curl -f -s --max-time 15 "$VERIFIER_BASE_URL/qr?url=test" 2>/dev/null || echo "ERROR")

    if [ "$verifier_qr" != "ERROR" ] && [ -n "$verifier_qr" ]; then
        print_success "✅ Verifier QR code generation working"
        ((success_count++))
    else
        print_error "❌ Verifier QR code generation failed"
    fi

    echo ""
    echo "QR code generation: $success_count/$total_count tests passed"
    return $((total_count - success_count))
}

# Test demo endpoints
test_demo_endpoints() {
    print_header "Testing Demo User Interface"
    echo "==========================="
    echo ""

    local success_count=0
    local total_count=2

    # Test issuer demo page
    print_info "Testing issuer demo page..."
    if curl -f -s --max-time 15 "$ISSUER_BASE_URL/demo" > /dev/null 2>&1; then
        print_success "✅ Issuer demo page accessible"
        echo "   URL: $ISSUER_BASE_URL/demo"
        ((success_count++))
    else
        print_warning "⚠️  Issuer demo page not accessible (may not be implemented)"
    fi

    # Test verifier demo page
    print_info "Testing verifier demo page..."
    if curl -f -s --max-time 15 "$VERIFIER_BASE_URL/demo" > /dev/null 2>&1; then
        print_success "✅ Verifier demo page accessible"
        echo "   URL: $VERIFIER_BASE_URL/demo"
        ((success_count++))
    else
        print_warning "⚠️  Verifier demo page not accessible (may not be implemented)"
    fi

    echo ""
    echo "Demo UI: $success_count/$total_count endpoints accessible"
    return 0  # Don't fail on demo endpoints as they may not be implemented
}

# Test Microsoft Authenticator compatibility
test_ms_authenticator_compatibility() {
    print_header "Testing Microsoft Authenticator Compatibility"
    echo "============================================="
    echo ""

    local issues=0

    # Check HTTPS requirement
    print_info "Checking HTTPS requirements..."
    if [[ "$ISSUER_BASE_URL" =~ ^https:// ]] || [[ "$ISSUER_BASE_URL" =~ localhost ]]; then
        print_success "✅ Issuer URL compatible with Microsoft Authenticator"
    else
        print_error "❌ Issuer URL must use HTTPS for Microsoft Authenticator"
        ((issues++))
    fi

    if [[ "$VERIFIER_BASE_URL" =~ ^https:// ]] || [[ "$VERIFIER_BASE_URL" =~ localhost ]]; then
        print_success "✅ Verifier URL compatible with Microsoft Authenticator"
    else
        print_error "❌ Verifier URL must use HTTPS for Microsoft Authenticator"
        ((issues++))
    fi

    # Check if URLs are accessible from mobile (rough check)
    print_info "Checking URL accessibility..."
    if [[ "$ISSUER_BASE_URL" =~ (localhost|127\.0\.0\.1) ]] && [[ ! "$ISSUER_BASE_URL" =~ (devtunnels|preview\.app\.github\.dev|ngrok) ]]; then
        print_warning "⚠️  Issuer URL uses localhost - may not be accessible from mobile device"
        print_info "   Consider using VS Code port forwarding or dev tunnels for mobile testing"
    fi

    if [[ "$VERIFIER_BASE_URL" =~ (localhost|127\.0\.0\.1) ]] && [[ ! "$VERIFIER_BASE_URL" =~ (devtunnels|preview\.app\.github\.dev|ngrok) ]]; then
        print_warning "⚠️  Verifier URL uses localhost - may not be accessible from mobile device"
        print_info "   Consider using VS Code port forwarding or dev tunnels for mobile testing"
    fi

    echo ""
    if [ "$issues" -eq 0 ]; then
        print_success "✅ Configuration is compatible with Microsoft Authenticator"
    else
        print_warning "⚠️  $issues compatibility issue(s) found"
    fi

    return "$issues"
}

# Show workflow summary and next steps
show_workflow_summary() {
    local total_failures=$1

    print_header "Workflow Test Summary"
    echo "===================="
    echo ""

    if [ "$total_failures" -eq 0 ]; then
        print_success "🎉 All workflow tests passed!"
        echo ""
        echo -e "${YELLOW}📱 Ready for Microsoft Authenticator testing:${NC}"
        echo ""
        echo "1. Credential Issuance:"
        echo "   - Open: $ISSUER_BASE_URL/demo"
        echo "   - Create a credential offer"
        echo "   - Scan QR code with Microsoft Authenticator"
        echo ""
        echo "2. Credential Verification:"
        echo "   - Open: $VERIFIER_BASE_URL/demo"
        echo "   - Create a presentation request"
        echo "   - Scan QR code with Microsoft Authenticator"
        echo "   - Present your credential"
        echo ""
    else
        print_error "❌ $total_failures workflow test(s) failed"
        echo ""
        echo -e "${YELLOW}🔧 Troubleshooting steps:${NC}"
        echo "1. Check service status: make status"
        echo "2. View service logs: make docker-logs"
        echo "3. Restart services: make docker-restart"
        echo "4. Verify configuration: make show-config"
        echo ""
    fi

    echo -e "${YELLOW}📖 Additional resources:${NC}"
    echo "  API Documentation:"
    echo "    - Issuer: $ISSUER_BASE_URL/docs"
    echo "    - Verifier: $VERIFIER_BASE_URL/docs"
    echo ""
    echo "  Useful commands:"
    echo "    - make test-endpoints  - Test basic connectivity"
    echo "    - make open-docs       - Open API documentation"
    echo "    - make status          - Check overall status"
    echo ""
}

# Main function
main() {
    print_header "Microsoft Demo - Workflow Testing"
    echo "================================="
    echo ""

    load_environment

    local total_failures=0

    # Run workflow tests
    test_credential_offer || ((total_failures++))
    echo ""

    test_presentation_request || ((total_failures++))
    echo ""

    test_qr_code_generation || ((total_failures += $?))
    echo ""

    test_demo_endpoints || ((total_failures += $?))
    echo ""

    test_ms_authenticator_compatibility || ((total_failures += $?))
    echo ""

    show_workflow_summary "$total_failures"

    # Cleanup temporary files
    rm -f /tmp/microsoft_demo_offer.json

    # Return appropriate exit code
    exit "$total_failures"
}

# Run main function
main "$@"
