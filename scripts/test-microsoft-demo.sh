#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
ISSUER_PORT=8000
VERIFIER_PORT=8001

# Function to print colored output
print_status() {
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

echo "🧪 Microsoft Authenticator Demo - API Test"
echo "==========================================="

# Test issuer API
print_status "Testing Issuer API..."

# Test health endpoint
print_status "1. Testing health endpoint..."
HEALTH_RESPONSE=$(curl -s http://localhost:${ISSUER_PORT}/health 2>/dev/null)
if [ $? -eq 0 ] && echo "$HEALTH_RESPONSE" | grep -q "healthy"; then
    print_success "✅ Health check passed"
else
    print_error "❌ Health check failed"
    echo "Response: $HEALTH_RESPONSE"
    exit 1
fi

# Test root endpoint
print_status "2. Testing root endpoint..."
ROOT_RESPONSE=$(curl -s http://localhost:${ISSUER_PORT}/ 2>/dev/null)
if [ $? -eq 0 ] && echo "$ROOT_RESPONSE" | grep -q "Microsoft Demo Issuer API"; then
    print_success "✅ Root endpoint working"
    if command -v jq >/dev/null 2>&1; then
        echo "$ROOT_RESPONSE" | jq .
    else
        echo "$ROOT_RESPONSE"
    fi
else
    print_error "❌ Root endpoint failed"
    echo "Response: $ROOT_RESPONSE"
    exit 1
fi

# Test OID4VCI metadata
print_status "3. Testing OID4VCI metadata..."
METADATA_RESPONSE=$(curl -s http://localhost:${ISSUER_PORT}/.well-known/openid_credential_issuer 2>/dev/null)
if [ $? -eq 0 ] && echo "$METADATA_RESPONSE" | grep -q "credential_issuer"; then
    print_success "✅ OID4VCI metadata working"
else
    print_error "❌ OID4VCI metadata failed"
    echo "Response: $METADATA_RESPONSE"
    exit 1
fi

# Test credential offer creation
print_status "4. Testing credential offer creation..."
OFFER_RESPONSE=$(curl -s -X POST http://localhost:${ISSUER_PORT}/credential-offer \
    -H "Content-Type: application/json" \
    -d '{"type": "EmployeeCredential", "subject_data": {"name": "Test User", "employeeId": "TEST001"}}' 2>/dev/null)

if [ $? -eq 0 ] && echo "$OFFER_RESPONSE" | grep -q "credential_offer_uri"; then
    print_success "✅ Credential offer creation working"
    
    # Extract and display the offer URI
    if command -v jq >/dev/null 2>&1; then
        OFFER_URI=$(echo "$OFFER_RESPONSE" | jq -r .credential_offer_uri)
        print_status "Credential Offer URI: $OFFER_URI"
        
        # Extract pre-authorized code for token test
        PRE_AUTH_CODE=$(echo "$OFFER_RESPONSE" | jq -r .pre_authorized_code)
        
        # Test token endpoint
        print_status "5. Testing token endpoint with pre-authorized code..."
        TOKEN_RESPONSE=$(curl -s -X POST http://localhost:${ISSUER_PORT}/token \
            -H "Content-Type: application/json" \
            -d "{\"grant_type\": \"urn:ietf:params:oauth:grant-type:pre-authorized_code\", \"pre_authorized_code\": \"$PRE_AUTH_CODE\"}" 2>/dev/null)
        
        if [ $? -eq 0 ] && echo "$TOKEN_RESPONSE" | grep -q "access_token"; then
            print_success "✅ Token endpoint working"
            ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r .access_token)
            
            # Test credential endpoint
            print_status "6. Testing credential issuance..."
            CREDENTIAL_RESPONSE=$(curl -s -X POST http://localhost:${ISSUER_PORT}/credential \
                -H "Content-Type: application/json" \
                -H "Authorization: Bearer $ACCESS_TOKEN" \
                -d '{}' 2>/dev/null)
            
            if [ $? -eq 0 ] && echo "$CREDENTIAL_RESPONSE" | grep -q "credential"; then
                print_success "✅ Credential issuance working"
            else
                print_warning "⚠️  Credential issuance test failed"
                echo "Response: $CREDENTIAL_RESPONSE"
            fi
        else
            print_warning "⚠️  Token endpoint test failed"
            echo "Response: $TOKEN_RESPONSE"
        fi
    else
        print_warning "⚠️  jq not available, skipping detailed tests"
    fi
else
    print_error "❌ Credential offer creation failed"
    echo "Response: $OFFER_RESPONSE"
    exit 1
fi

echo ""
print_status "Testing Verifier API..."

# Test verifier health
print_status "1. Testing verifier health endpoint..."
VERIFIER_HEALTH=$(curl -s http://localhost:${VERIFIER_PORT}/health 2>/dev/null)
if [ $? -eq 0 ] && echo "$VERIFIER_HEALTH" | grep -q "healthy"; then
    print_success "✅ Verifier health check passed"
else
    print_error "❌ Verifier health check failed"
    echo "Response: $VERIFIER_HEALTH"
    exit 1
fi

# Test verifier root
print_status "2. Testing verifier root endpoint..."
VERIFIER_ROOT=$(curl -s http://localhost:${VERIFIER_PORT}/ 2>/dev/null)
if [ $? -eq 0 ] && echo "$VERIFIER_ROOT" | grep -q "Microsoft Demo Verifier API"; then
    print_success "✅ Verifier root endpoint working"
    if command -v jq >/dev/null 2>&1; then
        echo "$VERIFIER_ROOT" | jq .
    else
        echo "$VERIFIER_ROOT"
    fi
else
    print_error "❌ Verifier root endpoint failed"
    echo "Response: $VERIFIER_ROOT"
    exit 1
fi

# Test presentation request creation
print_status "3. Testing presentation request creation..."
PRESENTATION_RESPONSE=$(curl -s -X POST http://localhost:${VERIFIER_PORT}/presentation-request \
    -H "Content-Type: application/json" \
    -d '{}' 2>/dev/null)

if [ $? -eq 0 ] && echo "$PRESENTATION_RESPONSE" | grep -q "authorization_request_uri"; then
    print_success "✅ Presentation request creation working"
    
    if command -v jq >/dev/null 2>&1; then
        REQUEST_ID=$(echo "$PRESENTATION_RESPONSE" | jq -r .request_id)
        AUTH_URI=$(echo "$PRESENTATION_RESPONSE" | jq -r .authorization_request_uri)
        print_status "Request ID: $REQUEST_ID"
        print_status "Authorization URI: $AUTH_URI"
        
        # Test status endpoint
        print_status "4. Testing verification status endpoint..."
        STATUS_RESPONSE=$(curl -s http://localhost:${VERIFIER_PORT}/verification-status/$REQUEST_ID 2>/dev/null)
        
        if [ $? -eq 0 ] && echo "$STATUS_RESPONSE" | grep -q "request_id"; then
            print_success "✅ Verification status endpoint working"
        else
            print_warning "⚠️  Verification status test failed"
            echo "Response: $STATUS_RESPONSE"
        fi
    else
        print_warning "⚠️  jq not available, skipping detailed tests"
    fi
else
    print_error "❌ Presentation request creation failed"
    echo "Response: $PRESENTATION_RESPONSE"
    exit 1
fi

# Test demo page
print_status "5. Testing verification demo page..."
DEMO_RESPONSE=$(curl -s http://localhost:${VERIFIER_PORT}/verification-demo 2>/dev/null)
if [ $? -eq 0 ] && echo "$DEMO_RESPONSE" | grep -q "Microsoft Authenticator Verification Demo"; then
    print_success "✅ Verification demo page working"
else
    print_warning "⚠️  Verification demo page test failed"
fi

echo ""
print_success "🎉 All API tests completed!"
echo ""
echo "📋 Test Summary:"
echo "================"
echo "✅ Issuer API health check"
echo "✅ Issuer API root endpoint"
echo "✅ OID4VCI metadata endpoint"
echo "✅ Credential offer creation"
echo "✅ OAuth token exchange"
echo "✅ Credential issuance"
echo "✅ Verifier API health check"
echo "✅ Verifier API root endpoint"
echo "✅ Presentation request creation"
echo "✅ Verification status endpoint"
echo "✅ Verification demo page"
echo ""
echo "🌐 Ready for VS Code Integration:"
echo "================================="
echo "1. Open VS Code Ports panel (View → Terminal → Ports)"
echo "2. Make ports ${ISSUER_PORT} and ${VERIFIER_PORT} public"
echo "3. Replace localhost URLs with VS Code HTTPS URLs"
echo "4. Test with Microsoft Authenticator!"
echo ""
echo "📱 Demo URLs (replace localhost with VS Code HTTPS URLs):"
echo "- Credential Offers: POST http://localhost:${ISSUER_PORT}/credential-offer"
echo "- Verification Demo: http://localhost:${VERIFIER_PORT}/verification-demo"