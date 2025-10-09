#!/bin/bash

# Kubernetes Deployment Script for Microsoft Demo
# Prepares and deploys the production-ready Kubernetes manifests

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEMO_DIR="$(dirname "$SCRIPT_DIR")"
K8S_DIR="$DEMO_DIR/k8s"
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

# Function to check prerequisites
check_prerequisites() {
    print_header "Checking Prerequisites"
    echo "======================"
    echo ""

    # Check kubectl
    if ! command -v kubectl &> /dev/null; then
        print_error "kubectl is required but not installed"
        return 1
    fi
    print_success "kubectl is available"

    # Check kind (optional but recommended)
    if command -v kind &> /dev/null; then
        print_success "kind is available"
    else
        print_warning "kind not found - you'll need an existing Kubernetes cluster"
    fi

    # Check if API files exist
    if [[ ! -f "$DEMO_DIR/issuer_api.py" ]]; then
        print_error "issuer_api.py not found in $DEMO_DIR"
        return 1
    fi
    print_success "issuer_api.py found"

    if [[ ! -f "$DEMO_DIR/verifier_api.py" ]]; then
        print_error "verifier_api.py not found in $DEMO_DIR"
        return 1
    fi
    print_success "verifier_api.py found"

    echo ""
}

# Function to deploy to Kubernetes
deploy_to_kubernetes() {
    local namespace="marty-microsoft-demo"

    print_header "Deploying to Kubernetes"
    echo "======================="
    echo ""

    print_info "Creating namespace..."
    kubectl create namespace "$namespace" --dry-run=client -o yaml | kubectl apply -f -

    print_info "Applying main Kubernetes manifest..."
    # Apply the main manifest first
    kubectl apply -f "$K8S_DIR/production-demo.yaml"

    print_info "Creating ConfigMaps with API code..."
    # Create ConfigMaps directly from files (this will overwrite the stub ones from the manifest)
    kubectl create configmap issuer-api-code \
        --from-file=issuer_api.py="$DEMO_DIR/issuer_api.py" \
        --namespace="$namespace" \
        --dry-run=client -o yaml | kubectl apply -f -

    kubectl create configmap verifier-api-code \
        --from-file=verifier_api.py="$DEMO_DIR/verifier_api.py" \
        --namespace="$namespace" \
        --dry-run=client -o yaml | kubectl apply -f -

    print_info "Restarting deployments to pick up new code..."
    kubectl rollout restart deployment/issuer-api -n "$namespace"
    kubectl rollout restart deployment/verifier-api -n "$namespace"

    print_success "Kubernetes resources created/updated"

    print_info "Waiting for deployments to be ready..."

    print_info "Waiting for PostgreSQL to be ready..."
    kubectl wait --for=condition=Available deployment/postgres -n $namespace --timeout=300s || print_warning "PostgreSQL timeout"

    print_info "Waiting for MinIO to be ready..."
    kubectl wait --for=condition=Available deployment/minio -n $namespace --timeout=300s || print_warning "MinIO timeout"

    print_info "Waiting for Vault to be ready..."
    kubectl wait --for=condition=Available deployment/vault -n $namespace --timeout=300s || print_warning "Vault timeout"

    print_info "Waiting for Issuer API to be ready..."
    kubectl wait --for=condition=Available deployment/issuer-api -n $namespace --timeout=300s || print_warning "Issuer API timeout"

    print_info "Waiting for Verifier API to be ready..."
    kubectl wait --for=condition=Available deployment/verifier-api -n $namespace --timeout=300s || print_warning "Verifier API timeout"

    print_success "All services deployed successfully!"
    echo ""
}

# Function to show deployment status
show_status() {
    print_header "Deployment Status"
    echo "================="
    echo ""

    print_info "Namespace:"
    kubectl get namespace $NAMESPACE 2>/dev/null || print_warning "Namespace not found"
    echo ""

    print_info "Pods:"
    kubectl get pods -n $NAMESPACE -o wide 2>/dev/null || print_warning "No pods found"
    echo ""

    print_info "Services:"
    kubectl get services -n $NAMESPACE 2>/dev/null || print_warning "No services found"
    echo ""

    print_info "Persistent Volume Claims:"
    kubectl get pvc -n $NAMESPACE 2>/dev/null || print_warning "No PVCs found"
    echo ""

    print_info "External access:"
    local node_ip
    if command -v kind &> /dev/null && kind get clusters | grep -q marty-microsoft-demo; then
        node_ip="localhost"
    else
        node_ip=$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="ExternalIP")].address}' 2>/dev/null || echo "localhost")
        if [[ -z "$node_ip" || "$node_ip" == "null" ]]; then
            node_ip=$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}' 2>/dev/null || echo "localhost")
        fi
    fi

    echo "  Issuer API:    http://$node_ip:30000"
    echo "  Verifier API:  http://$node_ip:30001"
    echo "  Issuer Health: http://$node_ip:30000/health"
    echo "  Verifier Health: http://$node_ip:30001/health"
    echo "  Issuer Docs:   http://$node_ip:30000/docs"
    echo "  Verifier Docs: http://$node_ip:30001/docs"
    echo ""
}

# Main deployment function
main() {
    print_header "Microsoft Demo - Kubernetes Deployment"
    echo "======================================="
    echo ""

    # Check prerequisites
    if ! check_prerequisites; then
        print_error "Prerequisites check failed"
        exit 1
    fi

    # Deploy to Kubernetes
    if ! deploy_to_kubernetes; then
        print_error "Deployment failed"
        exit 1
    fi

    # Show status
    show_status

    print_success "Microsoft Demo deployment complete!"
    print_info "Access the APIs at the URLs shown above"
}

# Run main function
main "$@"
