#!/bin/bash

# Kubernetes Cluster Creation Script for Microsoft Demo
# Creates a Kind cluster optimized for the Microsoft Authenticator demo

set -e

# Configuration
CLUSTER_NAME="marty-microsoft-demo"
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

# Check prerequisites
check_prerequisites() {
    print_info "Checking Kubernetes prerequisites..."
    
    local missing_tools=()
    
    if ! command -v kubectl &> /dev/null; then
        missing_tools+=("kubectl")
    fi
    
    if ! command -v kind &> /dev/null; then
        missing_tools+=("kind")
    fi
    
    if ! command -v docker &> /dev/null; then
        missing_tools+=("docker")
    fi
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        print_error "Missing required tools: ${missing_tools[*]}"
        echo ""
        echo "Install missing tools:"
        for tool in "${missing_tools[@]}"; do
            case $tool in
                kubectl)
                    echo "  kubectl: brew install kubectl"
                    ;;
                kind)
                    echo "  kind: brew install kind"
                    ;;
                docker)
                    echo "  docker: brew install --cask docker"
                    ;;
            esac
        done
        exit 1
    fi
    
    # Check if Docker is running
    if ! docker info &> /dev/null; then
        print_error "Docker is not running. Please start Docker and try again."
        exit 1
    fi
    
    print_success "All prerequisites satisfied"
}

# Create Kind cluster configuration
create_cluster_config() {
    local config_file="/tmp/kind-config-${CLUSTER_NAME}.yaml"
    local script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local project_root="$(dirname "$(dirname "$script_dir")")"
    
    print_info "Creating Kind cluster configuration..." >&2
    
    cat > "$config_file" << EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: ${CLUSTER_NAME}
nodes:
- role: control-plane
  extraPortMappings:
  - containerPort: 30000
    hostPort: 30000
    protocol: TCP
  - containerPort: 30001
    hostPort: 30001
    protocol: TCP
  extraMounts:
  - hostPath: ${project_root}
    containerPath: /host/marty
    readOnly: false
    selinuxRelabel: false
    propagation: None
EOF
    
    print_success "Cluster configuration created at: $config_file" >&2
    echo "$config_file"
}

# Create Kind cluster
create_cluster() {
    print_info "Creating Kind cluster: $CLUSTER_NAME"
    
    # Check if cluster already exists
    if kind get clusters | grep -q "^${CLUSTER_NAME}$"; then
        print_warning "Cluster $CLUSTER_NAME already exists"
        read -p "Do you want to delete and recreate it? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            print_info "Deleting existing cluster..."
            kind delete cluster --name "$CLUSTER_NAME"
        else
            print_info "Using existing cluster"
            return 0
        fi
    fi
    
    local config_file
    config_file=$(create_cluster_config)
    
    print_info "Creating new Kind cluster..."
    kind create cluster --config "$config_file"
    
    # Clean up temporary config file
    rm -f "$config_file"
    
    print_success "Kind cluster created successfully"
}

# Configure kubectl context
configure_kubectl() {
    print_info "Configuring kubectl context..."
    
    # Set kubectl context
    kubectl cluster-info --context "kind-${CLUSTER_NAME}"
    kubectl config use-context "kind-${CLUSTER_NAME}"
    
    print_success "kubectl configured for cluster: $CLUSTER_NAME"
}

# Create namespace
create_namespace() {
    print_info "Creating namespace: $NAMESPACE"
    
    kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
    
    print_success "Namespace created: $NAMESPACE"
}

# Verify cluster
verify_cluster() {
    print_info "Verifying cluster setup..."
    
    # Wait for nodes to be ready
    print_info "Waiting for nodes to be ready..."
    kubectl wait --for=condition=Ready nodes --all --timeout=180s
    
    # Show cluster info
    print_info "Cluster information:"
    kubectl get nodes -o wide
    
    print_success "Cluster verification complete"
}

# Main function
main() {
    print_header "Microsoft Demo - Kubernetes Cluster Setup"
    echo "=========================================="
    echo ""
    
    check_prerequisites
    create_cluster
    configure_kubectl
    create_namespace
    verify_cluster
    
    echo ""
    print_success "Kubernetes cluster setup complete!"
    echo ""
    echo -e "${YELLOW}Next steps:${NC}"
    echo "  1. Deploy demo: make k8s-deploy"
    echo "  2. Set up port forwarding: make k8s-port-forward"
    echo "  3. Test endpoints: make test-endpoints"
}

# Run main function
main "$@"