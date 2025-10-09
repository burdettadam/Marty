#!/bin/bash

# =============================================================================
# Configure Microsoft Demo with Dev Tunnels URLs
# =============================================================================
#
# This script updates the Kubernetes configuration to use VS Code dev tunnels
# URLs instead of localhost, enabling proper integration with Microsoft Authenticator.
#
# Usage:
#   ./scripts/configure-microsoft-demo-tunnels.sh \
#     --issuer-url https://7bmt9pc1-8000.usw3.devtunnels.ms \
#     --verifier-url https://7bmt9pc1-8001.usw3.devtunnels.ms
#
# =============================================================================

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Logging functions
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} ✅ $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} ⚠️  $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} ❌ $1"; }

# Default values
ISSUER_URL=""
VERIFIER_URL=""
NAMESPACE="marty-microsoft-demo"
CONFIG_MAP="microsoft-demo-config"
DRY_RUN=false

# Parse command line arguments
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
        --namespace)
            NAMESPACE="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --help)
            echo "Configure Microsoft Demo with Dev Tunnels URLs"
            echo ""
            echo "Usage: $0 --issuer-url <url> --verifier-url <url> [options]"
            echo ""
            echo "Options:"
            echo "  --issuer-url <url>      Dev tunnels URL for issuer API (port 8000)"
            echo "  --verifier-url <url>    Dev tunnels URL for verifier API (port 8001)"
            echo "  --namespace <name>      Kubernetes namespace (default: marty-microsoft-demo)"
            echo "  --dry-run              Show what would be changed without applying"
            echo "  --help                 Show this help message"
            echo ""
            echo "Example:"
            echo "  $0 \\"
            echo "    --issuer-url https://7bmt9pc1-8000.usw3.devtunnels.ms \\"
            echo "    --verifier-url https://7bmt9pc1-8001.usw3.devtunnels.ms"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Validate required parameters
if [[ -z "$ISSUER_URL" ]]; then
    log_error "Issuer URL is required. Use --issuer-url <url>"
    exit 1
fi

if [[ -z "$VERIFIER_URL" ]]; then
    log_error "Verifier URL is required. Use --verifier-url <url>"
    exit 1
fi

# Validate URLs
if [[ ! "$ISSUER_URL" =~ ^https?:// ]]; then
    log_error "Issuer URL must start with http:// or https://"
    exit 1
fi

if [[ ! "$VERIFIER_URL" =~ ^https?:// ]]; then
    log_error "Verifier URL must start with http:// or https://"
    exit 1
fi

# Remove trailing slashes from URLs
ISSUER_URL="${ISSUER_URL%/}"
VERIFIER_URL="${VERIFIER_URL%/}"

# Extract domain from issuer URL for DID
ISSUER_DOMAIN=$(echo "$ISSUER_URL" | sed 's|https\?://||' | sed 's|/.*||')
CREDENTIAL_ISSUER_DID="did:web:$(echo "$ISSUER_DOMAIN" | sed 's/:/%3A/g')"

# CORS origins - include both tunneled URLs
CORS_ORIGINS="$ISSUER_URL,$VERIFIER_URL,https://localhost:3000,https://localhost:8000,https://localhost:8001"

log_info "🔧 Configuring Microsoft Demo with Dev Tunnels URLs"
echo "====================================================="
log_info "Issuer URL: $ISSUER_URL"
log_info "Verifier URL: $VERIFIER_URL"
log_info "Credential Issuer DID: $CREDENTIAL_ISSUER_DID"
log_info "CORS Origins: $CORS_ORIGINS"
log_info "Namespace: $NAMESPACE"

if [[ "$DRY_RUN" == "true" ]]; then
    log_warning "DRY RUN MODE - No changes will be applied"
fi

echo ""

# Check if kubectl is available
if ! command -v kubectl &> /dev/null; then
    log_error "kubectl is not installed or not in PATH"
    exit 1
fi

# Check if namespace exists
if ! kubectl get namespace "$NAMESPACE" &> /dev/null; then
    log_error "Namespace '$NAMESPACE' does not exist"
    log_info "Please run the setup script first: ./scripts/setup-microsoft-demo-complete.sh"
    exit 1
fi

# Check if config map exists
if ! kubectl get configmap "$CONFIG_MAP" -n "$NAMESPACE" &> /dev/null; then
    log_error "ConfigMap '$CONFIG_MAP' does not exist in namespace '$NAMESPACE'"
    exit 1
fi

# Function to update ConfigMap
update_config_map() {
    log_info "Updating ConfigMap with new URLs..."

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "Would update ConfigMap '$CONFIG_MAP' with:"
        echo "  ISSUER_BASE_URL: $ISSUER_URL"
        echo "  VERIFIER_BASE_URL: $VERIFIER_URL"
        echo "  CREDENTIAL_ISSUER_DID: $CREDENTIAL_ISSUER_DID"
        echo "  CORS_ORIGINS: $CORS_ORIGINS"
        return
    fi

    # Update the ConfigMap
    kubectl patch configmap "$CONFIG_MAP" -n "$NAMESPACE" --type='merge' -p="{
        \"data\": {
            \"ISSUER_BASE_URL\": \"$ISSUER_URL\",
            \"VERIFIER_BASE_URL\": \"$VERIFIER_URL\",
            \"CREDENTIAL_ISSUER_DID\": \"$CREDENTIAL_ISSUER_DID\",
            \"CORS_ORIGINS\": \"$CORS_ORIGINS\"
        }
    }"

    log_success "ConfigMap updated successfully"
}

# Function to restart deployments
restart_deployments() {
    log_info "Restarting deployments to apply new configuration..."

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "Would restart deployments:"
        echo "  - issuer-api-microsoft-demo"
        echo "  - verifier-api-microsoft-demo"
        return
    fi

    # Restart issuer API deployment
    kubectl rollout restart deployment/issuer-api-microsoft-demo -n "$NAMESPACE"
    log_success "Issuer API deployment restart initiated"

    # Restart verifier API deployment
    kubectl rollout restart deployment/verifier-api-microsoft-demo -n "$NAMESPACE"
    log_success "Verifier API deployment restart initiated"

    # Wait for deployments to be ready
    log_info "Waiting for deployments to be ready..."

    kubectl rollout status deployment/issuer-api-microsoft-demo -n "$NAMESPACE" --timeout=300s
    kubectl rollout status deployment/verifier-api-microsoft-demo -n "$NAMESPACE" --timeout=300s

    log_success "All deployments are ready"
}

# Function to test the new configuration
test_configuration() {
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "Would test configuration at:"
        echo "  - $ISSUER_URL/.well-known/openid_credential_issuer"
        echo "  - $VERIFIER_URL/health"
        return
    fi

    log_info "Testing new configuration..."

    # Wait a moment for services to be ready
    sleep 10

    # Test issuer API (but don't fail if it's not ready yet)
    if curl -s -f "$ISSUER_URL/health" > /dev/null 2>&1; then
        log_success "Issuer API is accessible at $ISSUER_URL"
    else
        log_warning "Issuer API not yet ready at $ISSUER_URL (may take a few more seconds)"
    fi

    # Test verifier API (but don't fail if it's not ready yet)
    if curl -s -f "$VERIFIER_URL/health" > /dev/null 2>&1; then
        log_success "Verifier API is accessible at $VERIFIER_URL"
    else
        log_warning "Verifier API not yet ready at $VERIFIER_URL (may take a few more seconds)"
    fi
}

# Main execution
echo ""
log_info "🚀 Starting configuration update..."

# Update ConfigMap
update_config_map

# Restart deployments
restart_deployments

# Test configuration
test_configuration

echo ""
log_success "🎉 Configuration update completed!"
echo ""
log_info "📱 Next steps for Microsoft Authenticator:"
echo "1. The APIs are now configured with your dev tunnels URLs"
echo "2. Open your issuer API in browser: $ISSUER_URL"
echo "3. The metadata will now show correct tunneled URLs"
echo "4. Use Microsoft Authenticator to scan QR codes from the demo pages"
echo ""
log_info "🌐 Demo URLs:"
echo "- Issuer API: $ISSUER_URL"
echo "- Verifier API: $VERIFIER_URL"
echo "- Verification Demo: $VERIFIER_URL/verification-demo"
echo ""
log_info "🔍 To check the updated metadata:"
echo "curl -s $ISSUER_URL/.well-known/openid_credential_issuer | jq ."
