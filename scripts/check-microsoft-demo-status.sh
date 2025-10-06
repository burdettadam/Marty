#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
CLUSTER_NAME="marty-microsoft-demo"
NAMESPACE="marty-microsoft-demo"
ISSUER_PORT=8000
VERIFIER_PORT=8001
AUTO_FIX=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --fix)
            AUTO_FIX=true
            shift
            ;;
        --help)
            echo "Usage: $0 [--fix]"
            echo "  --fix  Automatically attempt to fix common issues"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

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

# Auto-fix functions
start_port_forwarding() {
    local service=$1
    local local_port=$2
    local remote_port=$3
    
    print_status "Starting port forwarding for ${service}..."
    kubectl port-forward -n ${NAMESPACE} service/${service} ${local_port}:${remote_port} >/dev/null 2>&1 &
    local pid=$!
    sleep 2
    
    if kill -0 $pid 2>/dev/null; then
        print_success "✅ Port forwarding started for ${service} (PID: $pid)"
        return 0
    else
        print_error "❌ Failed to start port forwarding for ${service}"
        return 1
    fi
}

restart_deployment() {
    local deployment=$1
    print_status "Restarting deployment ${deployment}..."
    kubectl rollout restart deployment/${deployment} -n ${NAMESPACE}
    kubectl rollout status deployment/${deployment} -n ${NAMESPACE} --timeout=60s
    if [ $? -eq 0 ]; then
        print_success "✅ Successfully restarted ${deployment}"
        return 0
    else
        print_error "❌ Failed to restart ${deployment}"
        return 1
    fi
}

echo "📊 Microsoft Authenticator Demo - Status Check"
echo "==============================================="

# Check if kind cluster exists
print_status "Checking kind cluster..."
if command -v kind >/dev/null 2>&1; then
    if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
        print_success "✅ Kind cluster '${CLUSTER_NAME}' exists"
        
        # Check if cluster is accessible
        if kubectl cluster-info --context kind-${CLUSTER_NAME} >/dev/null 2>&1; then
            print_success "✅ Cluster is accessible"
        else
            print_error "❌ Cluster exists but is not accessible"
        fi
    else
        print_error "❌ Kind cluster '${CLUSTER_NAME}' not found"
        echo "Run: ./scripts/setup-microsoft-demo-complete.sh"
        exit 1
    fi
else
    print_error "❌ kind command not found"
    exit 1
fi

# Check namespace
print_status "Checking namespace..."
if kubectl get namespace ${NAMESPACE} >/dev/null 2>&1; then
    print_success "✅ Namespace '${NAMESPACE}' exists"
else
    print_error "❌ Namespace '${NAMESPACE}' not found"
    echo "Run: ./scripts/setup-microsoft-demo-complete.sh"
    exit 1
fi

# Check deployments
print_status "Checking deployments..."
ISSUER_READY=$(kubectl get deployment issuer-api-microsoft-demo -n ${NAMESPACE} -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
VERIFIER_READY=$(kubectl get deployment verifier-api-microsoft-demo -n ${NAMESPACE} -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")

if [ "$ISSUER_READY" = "1" ]; then
    print_success "✅ Issuer API deployment ready"
else
    print_error "❌ Issuer API deployment not ready"
    if [ "$AUTO_FIX" = true ]; then
        restart_deployment "issuer-api-microsoft-demo"
        ISSUER_READY=$(kubectl get deployment issuer-api-microsoft-demo -n ${NAMESPACE} -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
    fi
fi

if [ "$VERIFIER_READY" = "1" ]; then
    print_success "✅ Verifier API deployment ready"
else
    print_error "❌ Verifier API deployment not ready"
    if [ "$AUTO_FIX" = true ]; then
        restart_deployment "verifier-api-microsoft-demo"
        VERIFIER_READY=$(kubectl get deployment verifier-api-microsoft-demo -n ${NAMESPACE} -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
    fi
fi

# Check pods
print_status "Pod status:"
kubectl get pods -n ${NAMESPACE} 2>/dev/null || print_error "Could not get pod status"

# Check port forwarding
print_status "Checking port forwarding..."
ISSUER_LOCAL=false
VERIFIER_LOCAL=false

if curl -s http://localhost:${ISSUER_PORT}/health >/dev/null 2>&1; then
    print_success "✅ Issuer API accessible on localhost:${ISSUER_PORT}"
    ISSUER_LOCAL=true
else
    print_warning "⚠️  Issuer API not accessible on localhost:${ISSUER_PORT}"
    if [ "$AUTO_FIX" = true ] && [ "$ISSUER_READY" = "1" ]; then
        # Kill any existing port forward for this port
        pkill -f "kubectl port-forward.*${ISSUER_PORT}:8000" 2>/dev/null
        sleep 1
        start_port_forwarding "issuer-api-microsoft-demo" "${ISSUER_PORT}" "8000"
        sleep 3
        if curl -s http://localhost:${ISSUER_PORT}/health >/dev/null 2>&1; then
            ISSUER_LOCAL=true
        fi
    fi
fi

if curl -s http://localhost:${VERIFIER_PORT}/health >/dev/null 2>&1; then
    print_success "✅ Verifier API accessible on localhost:${VERIFIER_PORT}"
    VERIFIER_LOCAL=true
else
    print_warning "⚠️  Verifier API not accessible on localhost:${VERIFIER_PORT}"
    if [ "$AUTO_FIX" = true ] && [ "$VERIFIER_READY" = "1" ]; then
        # Kill any existing port forward for this port
        pkill -f "kubectl port-forward.*${VERIFIER_PORT}:8001" 2>/dev/null
        sleep 1
        start_port_forwarding "verifier-api-microsoft-demo" "${VERIFIER_PORT}" "8001"
        sleep 3
        if curl -s http://localhost:${VERIFIER_PORT}/health >/dev/null 2>&1; then
            VERIFIER_LOCAL=true
        fi
    fi
fi

# Show running port forward processes
print_status "Port forwarding processes:"
if pgrep -f "kubectl port-forward.*${NAMESPACE}" >/dev/null 2>&1; then
    print_success "✅ Port forwarding processes are running:"
    ps aux | grep "kubectl port-forward.*${NAMESPACE}" | grep -v grep
else
    print_warning "⚠️  No port forwarding processes found"
    echo "To start port forwarding:"
    echo "  kubectl port-forward -n ${NAMESPACE} service/issuer-api-microsoft-demo ${ISSUER_PORT}:8000 &"
    echo "  kubectl port-forward -n ${NAMESPACE} service/verifier-api-microsoft-demo ${VERIFIER_PORT}:8001 &"
fi

echo ""
echo "📋 Summary:"
echo "==========="
echo "Cluster: $([ -n "$(kind get clusters 2>/dev/null | grep "^${CLUSTER_NAME}$")" ] && echo "✅" || echo "❌")"
echo "Namespace: $([ "$(kubectl get namespace ${NAMESPACE} 2>/dev/null)" ] && echo "✅" || echo "❌")"
echo "Issuer API: $([ "$ISSUER_READY" = "1" ] && echo "✅" || echo "❌") (K8s) | $([ "$ISSUER_LOCAL" = true ] && echo "✅" || echo "❌") (Local)"
echo "Verifier API: $([ "$VERIFIER_READY" = "1" ] && echo "✅" || echo "❌") (K8s) | $([ "$VERIFIER_LOCAL" = true ] && echo "✅" || echo "❌") (Local)"

echo ""
if [ "$ISSUER_LOCAL" = true ] && [ "$VERIFIER_LOCAL" = true ]; then
    print_success "🎉 Demo is fully operational!"
    echo ""
    echo "🌐 Next steps for VS Code:"
    echo "1. Open VS Code Ports panel (View → Terminal → Ports)"
    echo "2. Make ports ${ISSUER_PORT} and ${VERIFIER_PORT} public"
    echo "3. Use the generated HTTPS URLs with Microsoft Authenticator"
    echo ""
    echo "📱 Test endpoints:"
    echo "- Issuer API: http://localhost:${ISSUER_PORT}/"
    echo "- Verifier API: http://localhost:${VERIFIER_PORT}/"
    echo "- Verification Demo: http://localhost:${VERIFIER_PORT}/verification-demo"
elif [ "$ISSUER_READY" = "1" ] && [ "$VERIFIER_READY" = "1" ]; then
    print_warning "⚠️  APIs are running in K8s but port forwarding is not active"
    echo ""
    echo "To start port forwarding:"
    echo "  kubectl port-forward -n ${NAMESPACE} service/issuer-api-microsoft-demo ${ISSUER_PORT}:8000 &"
    echo "  kubectl port-forward -n ${NAMESPACE} service/verifier-api-microsoft-demo ${VERIFIER_PORT}:8001 &"
    echo ""
    echo "Or run with auto-fix:"
    echo "  $0 --fix"
else
    print_error "❌ Demo is not fully operational"
    echo ""
    echo "To fix issues, try:"
    echo "  $0 --fix"
    echo "  ./scripts/setup-microsoft-demo-complete.sh"
fi