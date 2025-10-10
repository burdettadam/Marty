#!/bin/bash
set -euo pipefail

# Marty MMF Plugin - Development Workflow Script
# Streamlined development workflow for Kind and real K8s

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
DEFAULT_CLUSTER="marty-dev"
WATCH_PATHS=("src/" "config/" "docker/" "k8s/")

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

# Quick setup for new development
dev_setup() {
    local cluster_name="${1:-$DEFAULT_CLUSTER}"
    
    log_info "🚀 Setting up development environment..."
    
    # Check prerequisites
    for cmd in kind kubectl docker; do
        if ! command -v $cmd &> /dev/null; then
            log_error "$cmd not found. Please install it first."
            exit 1
        fi
    done
    
    # Create Kind cluster
    log_info "Creating Kind cluster: $cluster_name"
    "$SCRIPT_DIR/kind/manage-cluster.sh" setup "$cluster_name"
    
    # Deploy plugin
    log_info "Deploying plugin to cluster"
    "$SCRIPT_DIR/deploy.sh" deploy development "$cluster_name"
    
    # Run basic tests
    log_info "Running basic tests"
    "$SCRIPT_DIR/test.sh" basic
    
    log_success "Development environment ready!"
    echo ""
    echo "🔗 Access URLs:"
    echo "  Plugin HTTP:  http://localhost:30080"
    echo "  Health:       http://localhost:30081"
    echo "  Plugin gRPC:  grpc://localhost:30090"
    echo ""
    echo "📋 Useful commands:"
    echo "  $0 logs                    # Follow plugin logs"
    echo "  $0 test                    # Run tests"
    echo "  $0 rebuild                 # Rebuild and redeploy"
    echo "  $0 cleanup                 # Clean up environment"
}

# Quick rebuild and redeploy
rebuild() {
    local cluster_name="${1:-$DEFAULT_CLUSTER}"
    
    log_info "🔄 Rebuilding and redeploying plugin..."
    
    # Build new image
    "$SCRIPT_DIR/deploy.sh" build "$cluster_name"
    
    # Restart deployment
    kubectl rollout restart deployment/marty-mmf-plugin -n marty-mmf
    kubectl rollout status deployment/marty-mmf-plugin -n marty-mmf --timeout=300s
    
    # Quick health check
    log_info "Running health check..."
    if "$SCRIPT_DIR/test.sh" health; then
        log_success "Rebuild and redeploy successful!"
    else
        log_error "Health check failed after redeploy"
        return 1
    fi
}

# Live development with file watching
dev_watch() {
    if ! command -v fswatch &> /dev/null; then
        log_error "fswatch not found. Install with: brew install fswatch"
        exit 1
    fi
    
    local cluster_name="${1:-$DEFAULT_CLUSTER}"
    
    log_info "👀 Starting file watcher for live development..."
    log_info "Watching: ${WATCH_PATHS[*]}"
    
    # Initial deployment
    if ! kubectl get deployment marty-mmf-plugin -n marty-mmf &>/dev/null; then
        log_info "No existing deployment found, running initial setup..."
        rebuild "$cluster_name"
    fi
    
    # Watch for changes
    fswatch -o "${WATCH_PATHS[@]}" | while read -r; do
        echo ""
        log_info "🔄 Files changed, rebuilding..."
        if rebuild "$cluster_name"; then
            log_success "✅ Rebuild complete - ready for testing"
        else
            log_error "❌ Rebuild failed - check logs"
        fi
        echo "Watching for changes..."
    done
}

# Show logs
show_logs() {
    local follow="${1:-true}"
    
    if [ "$follow" = "true" ]; then
        log_info "📋 Following plugin logs (Ctrl+C to stop)..."
        kubectl logs -f deployment/marty-mmf-plugin -n marty-mmf
    else
        log_info "📋 Recent plugin logs:"
        kubectl logs deployment/marty-mmf-plugin -n marty-mmf --tail=50
    fi
}

# Development status
dev_status() {
    log_info "📊 Development Environment Status"
    echo "=================================="
    
    # Check cluster
    local context
    context=$(kubectl config current-context 2>/dev/null || echo "none")
    echo "🏗️  Cluster: $context"
    
    if [[ "$context" == *"kind"* ]]; then
        local cluster_name
        cluster_name=$(echo "$context" | sed 's/kind-//')
        echo "📦 Kind cluster: $cluster_name"
        
        # Check if cluster is running
        if kind get clusters | grep -q "^${cluster_name}$"; then
            echo "✅ Cluster is running"
        else
            echo "❌ Cluster not found"
            return 1
        fi
    fi
    
    echo ""
    
    # Check deployment
    if kubectl get deployment marty-mmf-plugin -n marty-mmf &>/dev/null; then
        echo "🚀 Plugin Deployment:"
        kubectl get deployment marty-mmf-plugin -n marty-mmf
        echo ""
        
        echo "🎯 Pods:"
        kubectl get pods -l app.kubernetes.io/name=marty-mmf-plugin -n marty-mmf
        echo ""
        
        # Quick health check
        if [ "$context" == *"kind"* ]; then
            echo "🔍 Health Check:"
            if curl -s -f http://localhost:30081/health &>/dev/null; then
                echo "✅ Health endpoint responding"
            else
                echo "❌ Health endpoint not responding"
            fi
        fi
    else
        echo "❌ Plugin deployment not found"
    fi
    
    echo ""
    echo "🔗 Access URLs (Kind):"
    echo "  Plugin:  http://localhost:30080"
    echo "  Health:  http://localhost:30081/health"
    echo "  Metrics: http://localhost:30081/metrics"
}

# Interactive development shell
dev_shell() {
    local pod_name
    pod_name=$(kubectl get pods -l app.kubernetes.io/name=marty-mmf-plugin -n marty-mmf -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
    
    if [ -z "$pod_name" ]; then
        log_error "No plugin pods found"
        return 1
    fi
    
    log_info "🐚 Starting shell in pod: $pod_name"
    kubectl exec -it "$pod_name" -n marty-mmf -- /bin/bash
}

# Plugin debugging
debug_plugin() {
    log_info "🔍 Debugging plugin deployment..."
    
    # Show deployment events
    echo "📋 Recent Deployment Events:"
    kubectl describe deployment marty-mmf-plugin -n marty-mmf | grep -A 20 "Events:" || echo "No events found"
    echo ""
    
    # Show pod events
    echo "📋 Pod Events:"
    kubectl describe pods -l app.kubernetes.io/name=marty-mmf-plugin -n marty-mmf | grep -A 20 "Events:" || echo "No events found"
    echo ""
    
    # Show logs from all pods
    echo "📋 Pod Logs:"
    local pods
    pods=$(kubectl get pods -l app.kubernetes.io/name=marty-mmf-plugin -n marty-mmf -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)
    
    for pod in $pods; do
        echo "--- Logs from $pod ---"
        kubectl logs "$pod" -n marty-mmf --tail=20
        echo ""
    done
    
    # Show configuration
    echo "📋 Configuration:"
    kubectl get configmap marty-plugin-config -n marty-mmf -o yaml 2>/dev/null || echo "ConfigMap not found"
}

# Cleanup development environment
cleanup() {
    local cluster_name="${1:-$DEFAULT_CLUSTER}"
    local full_cleanup="${2:-false}"
    
    log_info "🧹 Cleaning up development environment..."
    
    # Delete plugin deployment
    if kubectl get namespace marty-mmf &>/dev/null; then
        log_info "Deleting plugin deployment..."
        "$SCRIPT_DIR/deploy.sh" delete
    fi
    
    # Delete Kind cluster if requested
    if [ "$full_cleanup" = "true" ]; then
        log_info "Deleting Kind cluster: $cluster_name"
        "$SCRIPT_DIR/kind/manage-cluster.sh" delete "$cluster_name"
    fi
    
    log_success "Cleanup completed"
}

# Performance testing
perf_test() {
    log_info "🏃 Running performance tests..."
    
    # Check if plugin is deployed
    if ! kubectl get deployment marty-mmf-plugin -n marty-mmf &>/dev/null; then
        log_error "Plugin not deployed. Run 'dev_setup' first."
        return 1
    fi
    
    # Simple performance test using ab (if available)
    if command -v ab &> /dev/null; then
        log_info "Running Apache Bench test..."
        ab -n 100 -c 10 http://localhost:30081/health
    else
        log_warning "Apache Bench not available, using curl loop..."
        for i in {1..50}; do
            if curl -s -f http://localhost:30081/health &>/dev/null; then
                echo -n "✅"
            else
                echo -n "❌"
            fi
            [ $((i % 10)) -eq 0 ] && echo ""
        done
        echo ""
    fi
    
    log_success "Performance test completed"
}

# Main command handling
main() {
    case "${1:-}" in
        "setup")
            dev_setup "${2:-$DEFAULT_CLUSTER}"
            ;;
        "rebuild")
            rebuild "${2:-$DEFAULT_CLUSTER}"
            ;;
        "watch")
            dev_watch "${2:-$DEFAULT_CLUSTER}"
            ;;
        "logs")
            show_logs "${2:-true}"
            ;;
        "status")
            dev_status
            ;;
        "shell")
            dev_shell
            ;;
        "debug")
            debug_plugin
            ;;
        "test")
            "$SCRIPT_DIR/test.sh" "${2:-basic}"
            ;;
        "perf")
            perf_test
            ;;
        "cleanup")
            cleanup "${2:-$DEFAULT_CLUSTER}" "${3:-false}"
            ;;
        "help"|"--help"|"-h"|"")
            echo "Marty MMF Plugin - Development Workflow"
            echo ""
            echo "Usage: $0 <command> [options]"
            echo ""
            echo "Setup Commands:"
            echo "  setup [cluster]          Complete development setup"
            echo "  cleanup [cluster] [full] Clean up (full=true deletes cluster)"
            echo ""
            echo "Development Commands:"
            echo "  rebuild [cluster]        Rebuild and redeploy plugin"
            echo "  watch [cluster]          Live development with file watching"
            echo "  logs [follow]            Show plugin logs (follow=true/false)"
            echo "  shell                    Interactive shell in plugin pod"
            echo ""
            echo "Testing Commands:"
            echo "  test [type]              Run tests (basic/extended/e2e)"
            echo "  perf                     Run performance tests"
            echo "  debug                    Debug deployment issues"
            echo ""
            echo "Status Commands:"
            echo "  status                   Show development environment status"
            echo "  help                     Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0 setup                 # Full development setup"
            echo "  $0 watch                 # Live development mode"
            echo "  $0 test extended         # Run extended tests"
            echo "  $0 logs false            # Show recent logs without following"
            echo "  $0 cleanup marty-dev true # Full cleanup including cluster"
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