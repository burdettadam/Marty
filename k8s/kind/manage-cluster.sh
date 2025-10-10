#!/bin/bash
set -euo pipefail

# Marty MMF Plugin - Kind Development Cluster Management
# Provides utilities for local Kubernetes development using Kind

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
KIND_CONFIG_DIR="${PROJECT_ROOT}/k8s/kind"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Kind is installed
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    if ! command -v kind &> /dev/null; then
        log_error "Kind is not installed. Please install Kind first:"
        log_info "  # macOS: brew install kind"
        log_info "  # Linux: curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.20.0/kind-linux-amd64"
        exit 1
    fi
    
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl is not installed. Please install kubectl first:"
        log_info "  # macOS: brew install kubectl"
        log_info "  # Linux: see https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/"
        exit 1
    fi
    
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed or not running. Please install and start Docker."
        exit 1
    fi
    
    log_success "All prerequisites are available"
}

# Create development cluster
create_cluster() {
    local cluster_name="${1:-marty-dev}"
    local config_file="${KIND_CONFIG_DIR}/cluster-config.yaml"
    
    if [ "$cluster_name" = "marty-ci" ]; then
        config_file="${KIND_CONFIG_DIR}/ci-config.yaml"
    fi
    
    log_info "Creating Kind cluster: $cluster_name"
    log_info "Using config: $config_file"
    
    if kind get clusters | grep -q "^${cluster_name}$"; then
        log_warning "Cluster $cluster_name already exists. Use 'recreate' to replace it."
        return 1
    fi
    
    kind create cluster --config="$config_file" --name="$cluster_name"
    
    # Wait for cluster to be ready
    log_info "Waiting for cluster to be ready..."
    kubectl wait --for=condition=Ready nodes --all --timeout=300s
    
    log_success "Cluster $cluster_name created successfully"
    
    # Display cluster info
    show_cluster_info "$cluster_name"
}

# Delete cluster
delete_cluster() {
    local cluster_name="${1:-marty-dev}"
    
    log_info "Deleting Kind cluster: $cluster_name"
    
    if ! kind get clusters | grep -q "^${cluster_name}$"; then
        log_warning "Cluster $cluster_name does not exist"
        return 1
    fi
    
    kind delete cluster --name="$cluster_name"
    log_success "Cluster $cluster_name deleted successfully"
}

# Recreate cluster
recreate_cluster() {
    local cluster_name="${1:-marty-dev}"
    
    log_info "Recreating Kind cluster: $cluster_name"
    
    if kind get clusters | grep -q "^${cluster_name}$"; then
        delete_cluster "$cluster_name"
    fi
    
    create_cluster "$cluster_name"
}

# Show cluster information
show_cluster_info() {
    local cluster_name="${1:-marty-dev}"
    
    if ! kind get clusters | grep -q "^${cluster_name}$"; then
        log_error "Cluster $cluster_name does not exist"
        return 1
    fi
    
    log_info "Cluster Information for: $cluster_name"
    echo "----------------------------------------"
    
    # Set kubectl context
    kubectl config use-context "kind-${cluster_name}"
    
    # Show nodes
    echo "📋 Nodes:"
    kubectl get nodes -o wide
    echo ""
    
    # Show system pods
    echo "🏗️  System Pods:"
    kubectl get pods -n kube-system --no-headers | wc -l | xargs echo "  Running:"
    echo ""
    
    # Show available resources
    echo "💾 Resources:"
    kubectl top nodes 2>/dev/null || echo "  Metrics not available (metrics-server not installed)"
    echo ""
    
    # Show cluster endpoint
    echo "🌐 Access:"
    local api_server=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
    echo "  API Server: $api_server"
    echo "  Context: kind-${cluster_name}"
    echo ""
    
    # Show port mappings for development cluster
    if [ "$cluster_name" = "marty-dev" ]; then
        echo "🔌 Port Mappings (Development):"
        echo "  MMF Framework:    http://localhost:8080"
        echo "  Plugin gRPC:      grpc://localhost:9090"
        echo "  Plugin REST:      http://localhost:8090"
        echo "  Prometheus:       http://localhost:9091"
        echo "  Grafana:          http://localhost:3000"
        echo "  Health Checks:    http://localhost:8081"
        echo ""
    fi
}

# List all Kind clusters
list_clusters() {
    log_info "Available Kind clusters:"
    
    if ! kind get clusters &>/dev/null; then
        echo "  No clusters found"
        return 0
    fi
    
    for cluster in $(kind get clusters); do
        local current_context=$(kubectl config current-context 2>/dev/null || echo "")
        local mark=""
        
        if [ "$current_context" = "kind-${cluster}" ]; then
            mark=" ${GREEN}(current)${NC}"
        fi
        
        echo -e "  📦 ${cluster}${mark}"
    done
}

# Load MMF plugin images into cluster
load_images() {
    local cluster_name="${1:-marty-dev}"
    
    log_info "Loading Marty MMF plugin images into cluster: $cluster_name"
    
    if ! kind get clusters | grep -q "^${cluster_name}$"; then
        log_error "Cluster $cluster_name does not exist"
        return 1
    fi
    
    # Build plugin image if it doesn't exist
    local image_name="marty-mmf-plugin:latest"
    
    if ! docker images | grep -q marty-mmf-plugin; then
        log_info "Building plugin image..."
        cd "$PROJECT_ROOT"
        docker build -t "$image_name" -f docker/mmf-plugin.Dockerfile .
    fi
    
    # Load image into Kind cluster
    log_info "Loading image into cluster..."
    kind load docker-image "$image_name" --name="$cluster_name"
    
    log_success "Images loaded successfully"
}

# Install cluster dependencies
install_dependencies() {
    local cluster_name="${1:-marty-dev}"
    
    log_info "Installing cluster dependencies for: $cluster_name"
    
    kubectl config use-context "kind-${cluster_name}"
    
    # Install metrics-server for resource monitoring
    log_info "Installing metrics-server..."
    kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml
    
    # Patch metrics-server for Kind compatibility
    kubectl patch deployment metrics-server -n kube-system --type='json' \
        -p='[{"op": "add", "path": "/spec/template/spec/containers/0/args/-", "value": "--kubelet-insecure-tls"}]'
    
    # Install ingress controller for plugin access
    log_info "Installing ingress-nginx..."
    kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/kind/deploy.yaml
    
    # Wait for ingress controller
    kubectl wait --namespace ingress-nginx \
        --for=condition=ready pod \
        --selector=app.kubernetes.io/component=controller \
        --timeout=90s
    
    log_success "Dependencies installed successfully"
}

# Main command handling
main() {
    case "${1:-}" in
        "create")
            check_prerequisites
            create_cluster "${2:-marty-dev}"
            ;;
        "delete")
            delete_cluster "${2:-marty-dev}"
            ;;
        "recreate")
            check_prerequisites
            recreate_cluster "${2:-marty-dev}"
            ;;
        "info")
            show_cluster_info "${2:-marty-dev}"
            ;;
        "list")
            list_clusters
            ;;
        "load-images")
            load_images "${2:-marty-dev}"
            ;;
        "install-deps")
            install_dependencies "${2:-marty-dev}"
            ;;
        "setup")
            check_prerequisites
            create_cluster "${2:-marty-dev}"
            install_dependencies "${2:-marty-dev}"
            load_images "${2:-marty-dev}"
            ;;
        "help"|"--help"|"-h"|"")
            echo "Marty MMF Plugin - Kind Cluster Management"
            echo ""
            echo "Usage: $0 <command> [cluster-name]"
            echo ""
            echo "Commands:"
            echo "  create [name]     Create a new Kind cluster (default: marty-dev)"
            echo "  delete [name]     Delete a Kind cluster"
            echo "  recreate [name]   Delete and recreate a cluster"
            echo "  info [name]       Show cluster information"
            echo "  list              List all Kind clusters"
            echo "  load-images [name] Load plugin images into cluster"
            echo "  install-deps [name] Install cluster dependencies"
            echo "  setup [name]      Full setup: create + dependencies + images"
            echo "  help              Show this help message"
            echo ""
            echo "Available cluster configurations:"
            echo "  marty-dev         Full development cluster with port mappings"
            echo "  marty-ci          Lightweight cluster for CI/CD testing"
            echo ""
            echo "Examples:"
            echo "  $0 setup                    # Create development cluster with everything"
            echo "  $0 create marty-ci          # Create CI cluster"
            echo "  $0 info marty-dev           # Show development cluster info"
            echo "  $0 load-images              # Load plugin images"
            ;;
        *)
            log_error "Unknown command: $1"
            echo "Use '$0 help' for usage information"
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"