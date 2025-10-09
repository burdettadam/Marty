#!/bin/bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
CLUSTER_NAME="marty-microsoft-demo"
NAMESPACE="marty-microsoft-demo"

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

echo "🧹 Microsoft Authenticator Demo - Cleanup"
echo "=========================================="

# Ask for confirmation
echo "This script will:"
echo "1. Stop any running port forwarding processes"
echo "2. Delete the Kubernetes namespace and all resources"
echo "3. Delete the kind cluster"
echo ""
read -p "Are you sure you want to proceed? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    print_status "Cleanup cancelled"
    exit 0
fi

# Stop port forwarding processes
print_status "Stopping port forwarding processes..."

# Kill processes by PID files if they exist
if [ -f /tmp/issuer-pf.pid ]; then
    PID=$(cat /tmp/issuer-pf.pid)
    if kill -0 $PID 2>/dev/null; then
        kill $PID
        print_success "Stopped issuer port forwarding (PID: $PID)"
    fi
    rm -f /tmp/issuer-pf.pid
fi

if [ -f /tmp/verifier-pf.pid ]; then
    PID=$(cat /tmp/verifier-pf.pid)
    if kill -0 $PID 2>/dev/null; then
        kill $PID
        print_success "Stopped verifier port forwarding (PID: $PID)"
    fi
    rm -f /tmp/verifier-pf.pid
fi

# Kill any kubectl port-forward processes for this demo
print_status "Killing any remaining port forwarding processes..."
pkill -f "kubectl port-forward.*${NAMESPACE}" 2>/dev/null || true
pkill -f "kubectl port-forward.*8000" 2>/dev/null || true
pkill -f "kubectl port-forward.*8001" 2>/dev/null || true

print_success "Port forwarding processes stopped"

# Delete Kubernetes resources
if command -v kubectl >/dev/null 2>&1; then
    print_status "Deleting Kubernetes resources..."

    # Check if namespace exists
    if kubectl get namespace ${NAMESPACE} >/dev/null 2>&1; then
        kubectl delete namespace ${NAMESPACE} --ignore-not-found=true
        print_success "Deleted namespace '${NAMESPACE}'"
    else
        print_status "Namespace '${NAMESPACE}' not found"
    fi
else
    print_warning "kubectl not found, skipping Kubernetes cleanup"
fi

# Delete kind cluster
if command -v kind >/dev/null 2>&1; then
    print_status "Deleting kind cluster..."

    # Check if cluster exists
    if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
        kind delete cluster --name ${CLUSTER_NAME}
        print_success "Deleted kind cluster '${CLUSTER_NAME}'"
    else
        print_status "Cluster '${CLUSTER_NAME}' not found"
    fi
else
    print_warning "kind not found, skipping cluster cleanup"
fi

# Clean up temporary files
print_status "Cleaning up temporary files..."
rm -f /tmp/kind-config.yaml
rm -f /tmp/issuer-pf.pid
rm -f /tmp/verifier-pf.pid

print_success "Temporary files cleaned up"

echo ""
print_success "🎉 Cleanup complete!"
echo ""
echo "The Microsoft Authenticator demo has been completely removed."
echo "To set it up again, run:"
echo "  ./scripts/setup-microsoft-demo-complete.sh"
echo ""
