#!/bin/bash
set -euo pipefail

# Marty MMF Plugin - Kubernetes Deployment Script
# Supports both Kind (local) and real Kubernetes clusters

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
MANIFESTS_DIR="${PROJECT_ROOT}/k8s/manifests"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
NAMESPACE="marty-mmf"
PLUGIN_NAME="marty-mmf-plugin"
IMAGE_NAME="marty-mmf-plugin:latest"

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

# Check if kubectl is available and cluster is accessible
check_cluster() {
    log_info "Checking cluster connectivity..."
    
    if ! kubectl cluster-info &>/dev/null; then
        log_error "Cannot connect to Kubernetes cluster"
        log_info "Please ensure kubectl is configured and cluster is accessible"
        exit 1
    fi
    
    local context=$(kubectl config current-context)
    local cluster_type="unknown"
    
    if [[ "$context" == *"kind"* ]]; then
        cluster_type="Kind (local development)"
    elif [[ "$context" == *"minikube"* ]]; then
        cluster_type="Minikube (local development)"
    else
        cluster_type="Real Kubernetes cluster"
    fi
    
    log_success "Connected to cluster: $context ($cluster_type)"
    
    # Show cluster info
    kubectl get nodes --no-headers | wc -l | xargs echo "  Nodes:"
    kubectl version --short 2>/dev/null || kubectl version --client
}

# Build and load plugin image
build_and_load_image() {
    local cluster_name="${1:-}"
    
    log_info "Building plugin image..."
    
    cd "$PROJECT_ROOT"
    
    # Build the image
    docker build -t "$IMAGE_NAME" -f docker/mmf-plugin.Dockerfile .
    
    # Load into Kind cluster if applicable
    local context=$(kubectl config current-context)
    if [[ "$context" == *"kind"* ]] && [ -n "$cluster_name" ]; then
        log_info "Loading image into Kind cluster: $cluster_name"
        kind load docker-image "$IMAGE_NAME" --name="$cluster_name"
    elif [[ "$context" == *"kind"* ]]; then
        # Try to detect Kind cluster name from context
        local kind_cluster=$(echo "$context" | sed 's/kind-//')
        log_info "Loading image into Kind cluster: $kind_cluster"
        kind load docker-image "$IMAGE_NAME" --name="$kind_cluster"
    fi
    
    log_success "Image built and loaded successfully"
}

# Apply Kubernetes manifests
apply_manifests() {
    local environment="${1:-development}"
    
    log_info "Applying Kubernetes manifests for environment: $environment"
    
    # Apply manifests in order
    local manifests=(
        "namespace.yaml"
        "rbac.yaml"
        "configmap.yaml"
        "deployment.yaml"
        "service.yaml"
        "ingress.yaml"
    )
    
    for manifest in "${manifests[@]}"; do
        local manifest_path="${MANIFESTS_DIR}/${manifest}"
        
        if [ ! -f "$manifest_path" ]; then
            log_warning "Manifest not found: $manifest"
            continue
        fi
        
        log_info "Applying: $manifest"
        
        # Environment-specific customizations
        if [ "$environment" = "production" ] && [ "$manifest" = "deployment.yaml" ]; then
            # Update image pull policy and environment for production
            kubectl apply -f "$manifest_path"
            kubectl patch deployment "$PLUGIN_NAME" -n "$NAMESPACE" \
                -p '{"spec":{"template":{"spec":{"containers":[{"name":"marty-plugin","env":[{"name":"MARTY_ENV","value":"production"}],"imagePullPolicy":"Always"}]}}}}'
        else
            kubectl apply -f "$manifest_path"
        fi
    done
    
    log_success "All manifests applied successfully"
}

# Wait for deployment to be ready
wait_for_deployment() {
    log_info "Waiting for deployment to be ready..."
    
    # Wait for deployment to be available
    kubectl wait --for=condition=available deployment/$PLUGIN_NAME -n $NAMESPACE --timeout=300s
    
    # Wait for pods to be ready
    kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=$PLUGIN_NAME -n $NAMESPACE --timeout=300s
    
    log_success "Deployment is ready"
}

# Show deployment status
show_status() {
    log_info "Deployment Status:"
    echo "-------------------"
    
    # Show namespace
    echo "📦 Namespace:"
    kubectl get namespace $NAMESPACE -o wide 2>/dev/null || echo "  Namespace not found"
    echo ""
    
    # Show deployment
    echo "🚀 Deployment:"
    kubectl get deployment $PLUGIN_NAME -n $NAMESPACE -o wide 2>/dev/null || echo "  Deployment not found"
    echo ""
    
    # Show pods
    echo "🎯 Pods:"
    kubectl get pods -l app.kubernetes.io/name=$PLUGIN_NAME -n $NAMESPACE -o wide 2>/dev/null || echo "  No pods found"
    echo ""
    
    # Show services
    echo "🌐 Services:"
    kubectl get services -n $NAMESPACE -o wide 2>/dev/null || echo "  No services found"
    echo ""
    
    # Show ingress
    echo "🔗 Ingress:"
    kubectl get ingress -n $NAMESPACE -o wide 2>/dev/null || echo "  No ingress found"
    echo ""
}

# Show access information
show_access_info() {
    local context=$(kubectl config current-context)
    
    log_info "Access Information:"
    echo "-------------------"
    
    if [[ "$context" == *"kind"* ]]; then
        echo "🏠 Kind Cluster Access:"
        echo "  Plugin HTTP:      http://localhost:30080"
        echo "  Plugin gRPC:      grpc://localhost:30090"
        echo "  Health Checks:    http://localhost:30081"
        echo "  Ingress (if set): http://marty-plugin.local"
        echo ""
        echo "💡 Add to /etc/hosts for ingress access:"
        echo "  127.0.0.1 marty-plugin.local marty-grpc.local"
    else
        echo "☁️  Cluster Service Access:"
        kubectl get service -n $NAMESPACE -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.type}{"\t"}{.status.loadBalancer.ingress[0].ip}{"\n"}{end}' 2>/dev/null || echo "  No services found"
    fi
    echo ""
    
    # Show logs access
    echo "📋 Logs:"
    echo "  kubectl logs -f deployment/$PLUGIN_NAME -n $NAMESPACE"
    echo "  kubectl logs -f -l app.kubernetes.io/name=$PLUGIN_NAME -n $NAMESPACE"
    echo ""
}

# Test plugin deployment
test_deployment() {
    log_info "Testing plugin deployment..."
    
    # Test if pods are running
    local pod_count=$(kubectl get pods -l app.kubernetes.io/name=$PLUGIN_NAME -n $NAMESPACE --no-headers 2>/dev/null | wc -l)
    
    if [ "$pod_count" -eq 0 ]; then
        log_error "No pods found for plugin"
        return 1
    fi
    
    log_info "Found $pod_count plugin pod(s)"
    
    # Test health endpoint
    local context=$(kubectl config current-context)
    if [[ "$context" == *"kind"* ]]; then
        log_info "Testing health endpoint..."
        if curl -f -s http://localhost:30081/health &>/dev/null; then
            log_success "Health endpoint responding"
        else
            log_warning "Health endpoint not responding (may still be starting up)"
        fi
    fi
    
    # Test plugin functionality
    log_info "Testing plugin functionality..."
    local pod_name=$(kubectl get pods -l app.kubernetes.io/name=$PLUGIN_NAME -n $NAMESPACE -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
    
    if [ -n "$pod_name" ]; then
        kubectl exec "$pod_name" -n $NAMESPACE -- python -c "
from src.mmf_plugin import MartyPlugin
try:
    plugin = MartyPlugin()
    services = plugin.get_services()
    print(f'✅ Plugin test successful - {len(services)} services available')
    for service in services:
        print(f'  - {service}')
except Exception as e:
    print(f'❌ Plugin test failed: {e}')
    exit(1)
" 2>/dev/null || log_warning "Plugin functionality test failed"
    fi
    
    log_success "Deployment test completed"
}

# Delete deployment
delete_deployment() {
    log_info "Deleting plugin deployment..."
    
    # Delete manifests in reverse order
    local manifests=(
        "ingress.yaml"
        "service.yaml"
        "deployment.yaml"
        "configmap.yaml"
        "rbac.yaml"
        "namespace.yaml"
    )
    
    for manifest in "${manifests[@]}"; do
        local manifest_path="${MANIFESTS_DIR}/${manifest}"
        
        if [ -f "$manifest_path" ]; then
            log_info "Deleting: $manifest"
            kubectl delete -f "$manifest_path" --ignore-not-found=true
        fi
    done
    
    log_success "Deployment deleted successfully"
}

# Main command handling
main() {
    case "${1:-}" in
        "deploy")
            check_cluster
            build_and_load_image "${3:-}"
            apply_manifests "${2:-development}"
            wait_for_deployment
            show_status
            show_access_info
            test_deployment
            ;;
        "build")
            build_and_load_image "${2:-}"
            ;;
        "apply")
            check_cluster
            apply_manifests "${2:-development}"
            ;;
        "status")
            check_cluster
            show_status
            show_access_info
            ;;
        "test")
            check_cluster
            test_deployment
            ;;
        "delete")
            check_cluster
            delete_deployment
            ;;
        "logs")
            check_cluster
            kubectl logs -f deployment/$PLUGIN_NAME -n $NAMESPACE
            ;;
        "help"|"--help"|"-h"|"")
            echo "Marty MMF Plugin - Kubernetes Deployment"
            echo ""
            echo "Usage: $0 <command> [environment] [cluster-name]"
            echo ""
            echo "Commands:"
            echo "  deploy [env] [cluster]    Full deployment: build + apply + test"
            echo "  build [cluster]           Build and load plugin image"
            echo "  apply [env]               Apply manifests only"
            echo "  status                    Show deployment status"
            echo "  test                      Test plugin deployment"
            echo "  delete                    Delete plugin deployment"
            echo "  logs                      Follow plugin logs"
            echo "  help                      Show this help message"
            echo ""
            echo "Environments:"
            echo "  development              Development configuration (default)"
            echo "  production               Production configuration"
            echo ""
            echo "Examples:"
            echo "  $0 deploy                           # Deploy to development"
            echo "  $0 deploy production                # Deploy to production"
            echo "  $0 deploy development marty-dev     # Deploy to Kind cluster"
            echo "  $0 status                           # Show current status"
            echo "  $0 test                             # Test deployment"
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