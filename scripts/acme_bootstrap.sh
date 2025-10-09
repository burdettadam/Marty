#!/bin/bash
#
# ACME Bootstrap Script for Marty Development Environment
#
# This script sets up ACME certificate management for local development using Pebble.
# It can also be configured to use Let's Encrypt staging for more realistic testing.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ACME_DATA_DIR="$PROJECT_ROOT/data/acme_certs"
DOCKER_COMPOSE_FILE="$PROJECT_ROOT/docker/docker-compose.pebble.yml"

# Configuration
ACME_SERVER="${ACME_SERVER:-pebble}"  # pebble, letsencrypt-staging, or custom URL
CONTACT_EMAIL="${CONTACT_EMAIL:-admin@marty.local}"
DOMAIN="${DOMAIN:-marty.local}"
SETUP_PEBBLE="${SETUP_PEBBLE:-true}"
SKIP_DNS_CHECK="${SKIP_DNS_CHECK:-false}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

usage() {
    cat << EOF
Usage: $0 [options]

Bootstrap ACME certificate management for Marty development.

Options:
    -s, --server SERVER     ACME server (pebble, letsencrypt-staging, or URL)
                           Default: pebble
    -e, --email EMAIL      Contact email for ACME account
                           Default: admin@marty.local
    -d, --domain DOMAIN    Domain name for certificates
                           Default: marty.local
    --no-pebble           Skip Pebble setup (useful for Let's Encrypt staging)
    --skip-dns-check      Skip DNS resolution check for domain
    -h, --help            Show this help message

Examples:
    # Set up with Pebble (development)
    $0

    # Set up with Let's Encrypt staging
    $0 --server letsencrypt-staging --email admin@example.com --domain example.com --no-pebble

    # Set up with custom domain
    $0 --domain my-service.local --email admin@my-service.local

Environment variables:
    ACME_SERVER      Same as --server
    CONTACT_EMAIL    Same as --email
    DOMAIN          Same as --domain
    SETUP_PEBBLE    Set to 'false' to skip Pebble setup
    SKIP_DNS_CHECK  Set to 'true' to skip DNS checks
EOF
}

check_dependencies() {
    local missing_deps=()

    # Check for required tools
    if ! command -v python3 &> /dev/null; then
        missing_deps+=("python3")
    fi

    if ! command -v docker &> /dev/null; then
        missing_deps+=("docker")
    fi

    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        missing_deps+=("docker-compose")
    fi

    if [ ${#missing_deps[@]} -ne 0 ]; then
        error "Missing required dependencies: ${missing_deps[*]}"
        error "Please install the missing dependencies and try again"
        exit 1
    fi

    success "All dependencies are available"
}

setup_directories() {
    log "Setting up ACME directories..."

    mkdir -p "$ACME_DATA_DIR"
    mkdir -p "$ACME_DATA_DIR/.well-known/acme-challenge"

    # Set appropriate permissions
    chmod 755 "$ACME_DATA_DIR"
    chmod 755 "$ACME_DATA_DIR/.well-known"
    chmod 755 "$ACME_DATA_DIR/.well-known/acme-challenge"

    success "Created ACME directories at $ACME_DATA_DIR"
}

create_pebble_docker_compose() {
    log "Creating Pebble Docker Compose configuration..."

    mkdir -p "$(dirname "$DOCKER_COMPOSE_FILE")"

    cat > "$DOCKER_COMPOSE_FILE" << 'EOF'
version: '3.8'

services:
  pebble:
    image: letsencrypt/pebble:latest
    container_name: marty-pebble
    ports:
      - "14000:14000"  # ACME directory
      - "15000:15000"  # Management interface
    environment:
      - PEBBLE_VA_NOSLEEP=1
      - PEBBLE_VA_ALWAYS_VALID=1  # Skip DNS validation for local development
      - PEBBLE_WFE_NONCEREJECT=0
    command: pebble -config /test/config/pebble-config.json -dnsserver 8.8.8.8:53
    volumes:
      - ./pebble-config.json:/test/config/pebble-config.json:ro
    networks:
      - acme-net

  pebble-challtestsrv:
    image: letsencrypt/pebble-challtestsrv:latest
    container_name: marty-pebble-challtestsrv
    ports:
      - "8055:8055"  # HTTP challenge server
    command: pebble-challtestsrv -defaultIPv6 "" -defaultIPv4 127.0.0.1
    networks:
      - acme-net

networks:
  acme-net:
    driver: bridge
EOF

    # Create Pebble configuration
    cat > "$(dirname "$DOCKER_COMPOSE_FILE")/pebble-config.json" << 'EOF'
{
  "pebble": {
    "listenAddress": "0.0.0.0:14000",
    "managementListenAddress": "0.0.0.0:15000",
    "certificate": "test/certs/localhost/cert.pem",
    "privateKey": "test/certs/localhost/key.pem",
    "httpPort": 5002,
    "tlsPort": 5001,
    "ocspResponderURL": "",
    "externalAccountBindingRequired": false
  }
}
EOF

    success "Created Pebble Docker Compose configuration"
}

start_pebble() {
    if [ "$SETUP_PEBBLE" != "true" ]; then
        log "Skipping Pebble setup as requested"
        return
    fi

    log "Starting Pebble ACME server..."

    cd "$(dirname "$DOCKER_COMPOSE_FILE")"

    if docker-compose -f "$(basename "$DOCKER_COMPOSE_FILE")" ps | grep -q "Up"; then
        warn "Pebble is already running"
    else
        docker-compose -f "$(basename "$DOCKER_COMPOSE_FILE")" up -d

        # Wait for Pebble to be ready
        log "Waiting for Pebble to start..."
        for i in {1..30}; do
            if curl -s -k https://localhost:14000/dir > /dev/null 2>&1; then
                success "Pebble is ready"
                break
            fi
            sleep 1
            if [ $i -eq 30 ]; then
                error "Pebble failed to start within 30 seconds"
                exit 1
            fi
        done
    fi
}

check_domain_resolution() {
    if [ "$SKIP_DNS_CHECK" = "true" ]; then
        log "Skipping DNS resolution check as requested"
        return
    fi

    log "Checking domain resolution for $DOMAIN..."

    if ! nslookup "$DOMAIN" > /dev/null 2>&1 && ! getent hosts "$DOMAIN" > /dev/null 2>&1; then
        warn "Domain $DOMAIN does not resolve to an IP address"
        warn "For local development, you may need to add it to your /etc/hosts file:"
        warn "  echo '127.0.0.1 $DOMAIN' | sudo tee -a /etc/hosts"

        if [ "$ACME_SERVER" = "pebble" ]; then
            warn "For Pebble, this is usually fine as it can be configured to skip validation"
        else
            error "Domain resolution is required for $ACME_SERVER"
            exit 1
        fi
    else
        success "Domain $DOMAIN resolves correctly"
    fi
}

create_acme_config() {
    log "Creating ACME configuration..."

    local config_file="$PROJECT_ROOT/config/acme.yaml"
    mkdir -p "$(dirname "$config_file")"

    cat > "$config_file" << EOF
# ACME Configuration for Marty
acme:
  enabled: true
  server: "$ACME_SERVER"
  contact_email: "$CONTACT_EMAIL"
  cert_storage_dir: "$ACME_DATA_DIR"

  # Domains to manage
  domains:
    - name: "$DOMAIN"
      key_path: "$ACME_DATA_DIR/$DOMAIN.key"
      cert_path: "$ACME_DATA_DIR/$DOMAIN.crt"
      challenge_type: "http-01"

  # Renewal settings
  renewal:
    days_before_expiry: 30
    check_interval_hours: 24

  # Development settings (for Pebble)
  development:
    skip_tls_verify: $( [ "$ACME_SERVER" = "pebble" ] && echo "true" || echo "false" )
    challenge_server_port: 8055
EOF

    success "Created ACME configuration at $config_file"
}

test_acme_client() {
    log "Testing ACME client functionality..."

    cd "$PROJECT_ROOT"

    # Create a simple test script
    cat > /tmp/test_acme.py << EOF
#!/usr/bin/env python3
import asyncio
import sys
import os
sys.path.insert(0, 'src')

from marty_common.acme_client import create_acme_client

async def test_acme():
    try:
        # Test ACME client initialization
        client = await create_acme_client(
            server="$ACME_SERVER",
            contact_email="$CONTACT_EMAIL",
            cert_storage_dir="$ACME_DATA_DIR"
        )

        print("✓ ACME client initialized successfully")

        # Test directory loading
        if client.directory:
            print("✓ ACME directory loaded successfully")
        else:
            print("✗ Failed to load ACME directory")
            return False

        # Test account
        if client.account_url:
            print(f"✓ ACME account ready: {client.account_url}")
        else:
            print("✗ ACME account not ready")
            return False

        await client.client.aclose()
        return True

    except Exception as e:
        print(f"✗ ACME test failed: {e}")
        return False

if __name__ == "__main__":
    success = asyncio.run(test_acme())
    sys.exit(0 if success else 1)
EOF

    if python3 /tmp/test_acme.py; then
        success "ACME client test passed"
    else
        error "ACME client test failed"
        warn "Check the logs above for details"
        exit 1
    fi

    rm -f /tmp/test_acme.py
}

show_next_steps() {
    success "ACME bootstrap completed successfully!"
    echo
    log "Next steps:"
    echo "  1. The ACME client is now configured and ready to use"
    echo "  2. Configuration file: $PROJECT_ROOT/config/acme.yaml"
    echo "  3. Certificate storage: $ACME_DATA_DIR"
    echo

    if [ "$ACME_SERVER" = "pebble" ]; then
        log "Pebble ACME server:"
        echo "  - Directory URL: https://localhost:14000/dir"
        echo "  - Management interface: https://localhost:15000"
        echo "  - Challenge test server: http://localhost:8055"
        echo
        log "To request a certificate:"
        echo "  cd $PROJECT_ROOT"
        echo "  python3 -c \""
        echo "import asyncio"
        echo "from src.marty_common.acme_client import create_acme_client"
        echo "async def main():"
        echo "    async with await create_acme_client('pebble', '$CONTACT_EMAIL') as client:"
        echo "        await client.request_certificate('$DOMAIN')"
        echo "asyncio.run(main())"
        echo "\""
    else
        log "ACME server: $ACME_SERVER"
        warn "Make sure your domain $DOMAIN is publicly accessible for HTTP-01 challenges"
    fi

    echo
    log "To stop Pebble (if running):"
    echo "  cd $(dirname "$DOCKER_COMPOSE_FILE")"
    echo "  docker-compose -f $(basename "$DOCKER_COMPOSE_FILE") down"
}

main() {
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -s|--server)
                ACME_SERVER="$2"
                shift 2
                ;;
            -e|--email)
                CONTACT_EMAIL="$2"
                shift 2
                ;;
            -d|--domain)
                DOMAIN="$2"
                shift 2
                ;;
            --no-pebble)
                SETUP_PEBBLE="false"
                shift
                ;;
            --skip-dns-check)
                SKIP_DNS_CHECK="true"
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done

    log "ACME Bootstrap for Marty Development Environment"
    log "=============================================="
    log "Server: $ACME_SERVER"
    log "Email: $CONTACT_EMAIL"
    log "Domain: $DOMAIN"
    log "Setup Pebble: $SETUP_PEBBLE"
    echo

    check_dependencies
    setup_directories

    if [ "$ACME_SERVER" = "pebble" ] && [ "$SETUP_PEBBLE" = "true" ]; then
        create_pebble_docker_compose
        start_pebble
    fi

    check_domain_resolution
    create_acme_config
    test_acme_client
    show_next_steps
}

# Run main function
main "$@"
