#!/bin/bash

# Kubernetes Port Forwarding Script for Microsoft Demo
# Sets up port forwarding for VS Code integration

set -e

# Configuration
NAMESPACE="marty-microsoft-demo"
ISSUER_PORT=8000
VERIFIER_PORT=8001

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

# Check if services are ready
wait_for_services() {
    print_info "Waiting for services to be ready..."
    
    print_info "Waiting for Issuer API..."
    kubectl wait --for=condition=ready pod -l app=issuer-api -n "$NAMESPACE" --timeout=180s
    
    print_info "Waiting for Verifier API..."
    kubectl wait --for=condition=ready pod -l app=verifier-api -n "$NAMESPACE" --timeout=180s
    
    print_success "All services are ready!"
}

# Kill existing port forwarding processes
cleanup_port_forwarding() {
    print_info "Cleaning up existing port forwarding..."
    
    # Kill any existing port forwarding for our ports
    pkill -f "kubectl port-forward.*${ISSUER_PORT}" || true
    pkill -f "kubectl port-forward.*${VERIFIER_PORT}" || true
    
    # Wait a moment for processes to cleanup
    sleep 2
}

# Start port forwarding
start_port_forwarding() {
    print_info "Starting port forwarding..."
    
    # Start issuer API port forwarding
    print_info "Setting up port forwarding for Issuer API (port ${ISSUER_PORT})..."
    kubectl port-forward -n "$NAMESPACE" service/issuer-api-microsoft-demo "${ISSUER_PORT}:${ISSUER_PORT}" &
    local issuer_pid=$!
    
    # Start verifier API port forwarding
    print_info "Setting up port forwarding for Verifier API (port ${VERIFIER_PORT})..."
    kubectl port-forward -n "$NAMESPACE" service/verifier-api-microsoft-demo "${VERIFIER_PORT}:${VERIFIER_PORT}" &
    local verifier_pid=$!
    
    # Wait a moment for port forwarding to start
    sleep 3
    
    # Check if port forwarding is working
    if ps -p $issuer_pid > /dev/null 2>&1; then
        print_success "Issuer API port forwarding started (PID: $issuer_pid)"
    else
        print_error "Failed to start Issuer API port forwarding"
    fi
    
    if ps -p $verifier_pid > /dev/null 2>&1; then
        print_success "Verifier API port forwarding started (PID: $verifier_pid)"
    else
        print_error "Failed to start Verifier API port forwarding"
    fi
}

# Test port forwarding
test_port_forwarding() {
    print_info "Testing port forwarding..."
    
    # Wait a moment for services to be available
    sleep 5
    
    # Test issuer API
    if curl -f -s "http://localhost:${ISSUER_PORT}/health" > /dev/null 2>&1; then
        print_success "Issuer API is accessible at http://localhost:${ISSUER_PORT}"
    else
        print_warning "Issuer API may not be ready yet at http://localhost:${ISSUER_PORT}"
    fi
    
    # Test verifier API
    if curl -f -s "http://localhost:${VERIFIER_PORT}/health" > /dev/null 2>&1; then
        print_success "Verifier API is accessible at http://localhost:${VERIFIER_PORT}"
    else
        print_warning "Verifier API may not be ready yet at http://localhost:${VERIFIER_PORT}"
    fi
}

# Show VS Code instructions
show_vscode_instructions() {
    print_header "VS Code Port Forwarding Setup"
    echo "============================="
    echo ""
    echo -e "${YELLOW}🌐 For VS Code integration:${NC}"
    echo ""
    echo "1. In VS Code, open Command Palette (Cmd+Shift+P or Ctrl+Shift+P)"
    echo "2. Type 'Ports: Focus on Ports View' and press Enter"
    echo "3. In the Ports panel, click 'Forward a Port'"
    echo "4. Add these ports with 'Public' visibility:"
    echo "   - Port ${ISSUER_PORT} (Issuer API)"
    echo "   - Port ${VERIFIER_PORT} (Verifier API)"
    echo ""
    echo "5. Copy the generated URLs from the Ports panel (they'll look like:"
    echo "   https://your-port-${ISSUER_PORT}.preview.app.github.dev"
    echo "   https://your-port-${VERIFIER_PORT}.preview.app.github.dev"
    echo ""
    echo "6. Update configuration with your URLs:"
    echo "   make configure-urls ISSUER_URL=<your-issuer-url> VERIFIER_URL=<your-verifier-url>"
    echo ""
    echo -e "${YELLOW}🔧 Alternative - kubectl direct forwarding:${NC}"
    echo "In separate terminals:"
    echo "  kubectl port-forward -n ${NAMESPACE} service/issuer-api-microsoft-demo ${ISSUER_PORT}:${ISSUER_PORT}"
    echo "  kubectl port-forward -n ${NAMESPACE} service/verifier-api-microsoft-demo ${VERIFIER_PORT}:${VERIFIER_PORT}"
    echo ""
}

# Show service status
show_status() {
    print_header "Service Status"
    echo "=============="
    echo ""
    kubectl get pods -n "$NAMESPACE" -o wide
    echo ""
    kubectl get services -n "$NAMESPACE"
    echo ""
}

# Main function
main() {
    print_header "Microsoft Demo - Port Forwarding Setup"
    echo "======================================="
    echo ""
    
    # Check if VS Code is available
    local vscode_available=false
    if command -v code &> /dev/null; then
        vscode_available=true
        print_info "VS Code CLI detected"
    else
        print_warning "VS Code CLI not found - manual port forwarding setup required"
    fi
    
    wait_for_services
    show_status
    cleanup_port_forwarding
    start_port_forwarding
    test_port_forwarding
    show_vscode_instructions
    
    echo ""
    print_success "Port forwarding setup complete!"
    echo ""
    echo -e "${YELLOW}💡 Pro tips:${NC}"
    echo "  - Keep this terminal open to maintain port forwarding"
    echo "  - Use Ctrl+C to stop port forwarding"
    echo "  - Monitor forwarded ports in VS Code's Ports panel"
    echo ""
    
    if [ "$vscode_available" = true ]; then
        read -p "Open VS Code now? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            print_info "Opening VS Code..."
            code ../..
        fi
    fi
    
    # Keep the script running to maintain port forwarding
    print_info "Port forwarding is active. Press Ctrl+C to stop."
    trap 'print_info "Stopping port forwarding..."; cleanup_port_forwarding; exit 0' INT
    
    # Keep running
    while true; do
        sleep 30
        # Check if port forwarding processes are still running
        if ! pgrep -f "kubectl port-forward.*${ISSUER_PORT}" > /dev/null; then
            print_warning "Issuer API port forwarding stopped, restarting..."
            kubectl port-forward -n "$NAMESPACE" service/issuer-api-microsoft-demo "${ISSUER_PORT}:${ISSUER_PORT}" &
        fi
        if ! pgrep -f "kubectl port-forward.*${VERIFIER_PORT}" > /dev/null; then
            print_warning "Verifier API port forwarding stopped, restarting..."
            kubectl port-forward -n "$NAMESPACE" service/verifier-api-microsoft-demo "${VERIFIER_PORT}:${VERIFIER_PORT}" &
        fi
    done
}

# Run main function
main "$@"