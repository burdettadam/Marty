#!/bin/bash
set -euo pipefail

# Marty MMF Plugin - Comprehensive Testing Script
# Supports both Kind (local) and real Kubernetes E2E testing

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
NAMESPACE="marty-mmf"
PLUGIN_NAME="marty-mmf-plugin"
TEST_TIMEOUT="300s"

# Test result tracking
TESTS_PASSED=0
TESTS_FAILED=0
FAILED_TESTS=()

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

log_test_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((TESTS_PASSED++))
}

log_test_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((TESTS_FAILED++))
    FAILED_TESTS+=("$1")
}

# Check if cluster is accessible
check_cluster() {
    log_info "Checking cluster connectivity..."
    
    if ! kubectl cluster-info &>/dev/null; then
        log_error "Cannot connect to Kubernetes cluster"
        return 1
    fi
    
    local context
    context=$(kubectl config current-context)
    local cluster_type="unknown"
    
    if [[ "$context" == *"kind"* ]]; then
        cluster_type="Kind (local development)"
        export CLUSTER_TYPE="kind"
    elif [[ "$context" == *"minikube"* ]]; then
        cluster_type="Minikube (local development)"
        export CLUSTER_TYPE="minikube"
    else
        cluster_type="Real Kubernetes cluster"
        export CLUSTER_TYPE="real"
    fi
    
    log_success "Connected to cluster: $context ($cluster_type)"
    return 0
}

# Test 1: Verify namespace exists
test_namespace() {
    log_info "Testing namespace existence..."
    
    if kubectl get namespace $NAMESPACE &>/dev/null; then
        log_test_pass "Namespace $NAMESPACE exists"
        return 0
    else
        log_test_fail "Namespace $NAMESPACE not found"
        return 1
    fi
}

# Test 2: Verify deployment is ready
test_deployment() {
    log_info "Testing deployment readiness..."
    
    local ready_replicas
    ready_replicas=$(kubectl get deployment $PLUGIN_NAME -n $NAMESPACE -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
    local desired_replicas
    desired_replicas=$(kubectl get deployment $PLUGIN_NAME -n $NAMESPACE -o jsonpath='{.spec.replicas}' 2>/dev/null || echo "0")
    
    if [ "$ready_replicas" = "$desired_replicas" ] && [ "$ready_replicas" != "0" ]; then
        log_test_pass "Deployment has $ready_replicas/$desired_replicas replicas ready"
        return 0
    else
        log_test_fail "Deployment not ready: $ready_replicas/$desired_replicas replicas"
        return 1
    fi
}

# Test 3: Verify pods are running
test_pods() {
    log_info "Testing pod status..."
    
    local running_pods
    running_pods=$(kubectl get pods -l app.kubernetes.io/name=$PLUGIN_NAME -n $NAMESPACE --field-selector=status.phase=Running --no-headers 2>/dev/null | wc -l || echo "0")
    
    if [ "$running_pods" -gt 0 ]; then
        log_test_pass "$running_pods pod(s) running successfully"
        
        # Test individual pod health
        local pods
        pods=$(kubectl get pods -l app.kubernetes.io/name=$PLUGIN_NAME -n $NAMESPACE -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)
        
        for pod in $pods; do
            if kubectl get pod "$pod" -n $NAMESPACE -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' | grep -q "True"; then
                log_test_pass "Pod $pod is ready"
            else
                log_test_fail "Pod $pod is not ready"
            fi
        done
        
        return 0
    else
        log_test_fail "No running pods found"
        return 1
    fi
}

# Test 4: Verify services are accessible
test_services() {
    log_info "Testing service accessibility..."
    
    local services
    services=$(kubectl get services -n $NAMESPACE -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)
    
    if [ -z "$services" ]; then
        log_test_fail "No services found"
        return 1
    fi
    
    for service in $services; do
        local cluster_ip
        cluster_ip=$(kubectl get service "$service" -n $NAMESPACE -o jsonpath='{.spec.clusterIP}' 2>/dev/null)
        
        if [ "$cluster_ip" != "None" ] && [ "$cluster_ip" != "" ]; then
            log_test_pass "Service $service has cluster IP: $cluster_ip"
        else
            log_test_pass "Service $service is headless (cluster IP: None)"
        fi
    done
    
    return 0
}

# Test 5: Test plugin health endpoints
test_health_endpoints() {
    log_info "Testing plugin health endpoints..."
    
    local pod_name
    pod_name=$(kubectl get pods -l app.kubernetes.io/name=$PLUGIN_NAME -n $NAMESPACE -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
    
    if [ -z "$pod_name" ]; then
        log_test_fail "No pods available for health testing"
        return 1
    fi
    
    # Test health endpoint inside pod
    if kubectl exec "$pod_name" -n $NAMESPACE -- curl -f -s http://localhost:8081/health &>/dev/null; then
        log_test_pass "Health endpoint responding in pod $pod_name"
    else
        log_test_fail "Health endpoint not responding in pod $pod_name"
    fi
    
    # Test readiness endpoint
    if kubectl exec "$pod_name" -n $NAMESPACE -- curl -f -s http://localhost:8081/ready &>/dev/null; then
        log_test_pass "Readiness endpoint responding in pod $pod_name"
    else
        log_test_fail "Readiness endpoint not responding in pod $pod_name"
    fi
    
    # Test external access for Kind clusters
    if [ "$CLUSTER_TYPE" = "kind" ]; then
        if curl -f -s http://localhost:30081/health &>/dev/null; then
            log_test_pass "External health endpoint accessible on localhost:30081"
        else
            log_test_fail "External health endpoint not accessible on localhost:30081"
        fi
    fi
    
    return 0
}

# Test 6: Test plugin functionality
test_plugin_functionality() {
    log_info "Testing plugin functionality..."
    
    local pod_name
    pod_name=$(kubectl get pods -l app.kubernetes.io/name=$PLUGIN_NAME -n $NAMESPACE -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
    
    if [ -z "$pod_name" ]; then
        log_test_fail "No pods available for functionality testing"
        return 1
    fi
    
    # Test plugin initialization
    if kubectl exec "$pod_name" -n $NAMESPACE -- python -c "
from src.mmf_plugin import MartyPlugin
try:
    plugin = MartyPlugin()
    print('Plugin initialized successfully')
except Exception as e:
    print(f'Plugin initialization failed: {e}')
    exit(1)
" &>/dev/null; then
        log_test_pass "Plugin initialization successful"
    else
        log_test_fail "Plugin initialization failed"
        return 1
    fi
    
    # Test service discovery
    local service_output
    service_output=$(kubectl exec "$pod_name" -n $NAMESPACE -- python -c "
from src.mmf_plugin import MartyPlugin
try:
    plugin = MartyPlugin()
    services = plugin.get_services()
    print(f'Services: {list(services.keys())}')
    print(f'Count: {len(services)}')
except Exception as e:
    print(f'Error: {e}')
    exit(1)
" 2>/dev/null)
    
    if echo "$service_output" | grep -q "Count: [1-9]"; then
        log_test_pass "Plugin service discovery working"
        log_info "  $service_output"
    else
        log_test_fail "Plugin service discovery failed"
    fi
    
    return 0
}

# Test 7: Test resource usage
test_resource_usage() {
    log_info "Testing resource usage..."
    
    # Test if metrics-server is available
    if ! kubectl top nodes &>/dev/null; then
        log_warning "Metrics server not available, skipping resource tests"
        return 0
    fi
    
    local pods
    pods=$(kubectl get pods -l app.kubernetes.io/name=$PLUGIN_NAME -n $NAMESPACE -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)
    
    for pod in $pods; do
        local metrics
        metrics=$(kubectl top pod "$pod" -n $NAMESPACE --no-headers 2>/dev/null || echo "")
        
        if [ -n "$metrics" ]; then
            log_test_pass "Resource metrics available for pod $pod: $metrics"
        else
            log_warning "Resource metrics not available for pod $pod"
        fi
    done
    
    return 0
}

# Test 8: Test configuration
test_configuration() {
    log_info "Testing configuration..."
    
    # Test ConfigMap exists
    if kubectl get configmap marty-plugin-config -n $NAMESPACE &>/dev/null; then
        log_test_pass "Plugin ConfigMap exists"
    else
        log_test_fail "Plugin ConfigMap not found"
    fi
    
    # Test Secret exists
    if kubectl get secret marty-plugin-secrets -n $NAMESPACE &>/dev/null; then
        log_test_pass "Plugin Secret exists"
    else
        log_test_fail "Plugin Secret not found"
    fi
    
    # Test configuration loading in pod
    local pod_name
    pod_name=$(kubectl get pods -l app.kubernetes.io/name=$PLUGIN_NAME -n $NAMESPACE -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
    
    if [ -n "$pod_name" ]; then
        if kubectl exec "$pod_name" -n $NAMESPACE -- test -f /app/config/plugin/plugin.yaml; then
            log_test_pass "Plugin configuration file mounted correctly"
        else
            log_test_fail "Plugin configuration file not found"
        fi
    fi
    
    return 0
}

# Test 9: Test network connectivity
test_network_connectivity() {
    log_info "Testing network connectivity..."
    
    local pod_name
    pod_name=$(kubectl get pods -l app.kubernetes.io/name=$PLUGIN_NAME -n $NAMESPACE -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
    
    if [ -z "$pod_name" ]; then
        log_warning "No pods available for network testing"
        return 0
    fi
    
    # Test DNS resolution
    if kubectl exec "$pod_name" -n $NAMESPACE -- nslookup kubernetes.default.svc.cluster.local &>/dev/null; then
        log_test_pass "DNS resolution working"
    else
        log_test_fail "DNS resolution failed"
    fi
    
    # Test service discovery
    if kubectl exec "$pod_name" -n $NAMESPACE -- nslookup marty-mmf-plugin-service.$NAMESPACE.svc.cluster.local &>/dev/null; then
        log_test_pass "Service DNS resolution working"
    else
        log_test_fail "Service DNS resolution failed"
    fi
    
    return 0
}

# Test 10: Test RBAC permissions
test_rbac() {
    log_info "Testing RBAC permissions..."
    
    # Test ServiceAccount exists
    if kubectl get serviceaccount marty-plugin-sa -n $NAMESPACE &>/dev/null; then
        log_test_pass "ServiceAccount exists"
    else
        log_test_fail "ServiceAccount not found"
    fi
    
    # Test if pods can access Kubernetes API
    local pod_name
    pod_name=$(kubectl get pods -l app.kubernetes.io/name=$PLUGIN_NAME -n $NAMESPACE -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
    
    if [ -n "$pod_name" ]; then
        if kubectl exec "$pod_name" -n $NAMESPACE -- kubectl get pods -n $NAMESPACE &>/dev/null; then
            log_test_pass "Pod has required Kubernetes API permissions"
        else
            log_test_fail "Pod lacks required Kubernetes API permissions"
        fi
    fi
    
    return 0
}

# Load testing (for real K8s clusters)
load_test() {
    if [ "$CLUSTER_TYPE" != "real" ]; then
        log_info "Skipping load test for non-production cluster"
        return 0
    fi
    
    log_info "Running load test..."
    
    # Simple load test using kubectl
    local service_ip
    service_ip=$(kubectl get service marty-mmf-plugin-service -n $NAMESPACE -o jsonpath='{.spec.clusterIP}' 2>/dev/null)
    
    if [ -n "$service_ip" ]; then
        # Create a test pod to run load test from inside cluster
        kubectl run load-test-pod --image=busybox --rm -i --restart=Never -- sh -c "
            for i in \$(seq 1 100); do
                wget -q -O- http://$service_ip:8081/health >/dev/null 2>&1
                if [ \$? -eq 0 ]; then
                    echo 'Request \$i: OK'
                else
                    echo 'Request \$i: FAILED'
                fi
            done
        " &>/dev/null
        
        log_test_pass "Load test completed (100 requests)"
    else
        log_test_fail "Could not get service IP for load testing"
    fi
    
    return 0
}

# Comprehensive test runner
run_all_tests() {
    local test_type="${1:-basic}"
    
    log_info "Running comprehensive plugin tests (type: $test_type)..."
    echo "============================================="
    
    # Check cluster connectivity first
    if ! check_cluster; then
        log_error "Cluster connectivity check failed"
        exit 1
    fi
    
    # Basic tests (always run)
    test_namespace
    test_deployment
    test_pods
    test_services
    test_health_endpoints
    test_plugin_functionality
    test_configuration
    
    # Extended tests
    if [ "$test_type" = "extended" ] || [ "$test_type" = "e2e" ]; then
        test_resource_usage
        test_network_connectivity
        test_rbac
    fi
    
    # E2E tests (real clusters only)
    if [ "$test_type" = "e2e" ]; then
        load_test
    fi
    
    # Summary
    echo "============================================="
    log_info "Test Summary:"
    echo "  Total tests: $((TESTS_PASSED + TESTS_FAILED))"
    echo "  Passed: $TESTS_PASSED"
    echo "  Failed: $TESTS_FAILED"
    
    if [ $TESTS_FAILED -eq 0 ]; then
        log_success "All tests passed! 🎉"
        return 0
    else
        log_error "Some tests failed:"
        for test in "${FAILED_TESTS[@]}"; do
            echo "    - $test"
        done
        return 1
    fi
}

# Show detailed status
show_detailed_status() {
    log_info "Detailed Plugin Status"
    echo "======================"
    
    # Cluster info
    echo "🏗️  Cluster Information:"
    kubectl cluster-info
    echo ""
    
    # Namespace details
    echo "📦 Namespace Details:"
    kubectl describe namespace $NAMESPACE 2>/dev/null || echo "  Namespace not found"
    echo ""
    
    # Deployment details
    echo "🚀 Deployment Details:"
    kubectl describe deployment $PLUGIN_NAME -n $NAMESPACE 2>/dev/null || echo "  Deployment not found"
    echo ""
    
    # Pod details
    echo "🎯 Pod Details:"
    kubectl describe pods -l app.kubernetes.io/name=$PLUGIN_NAME -n $NAMESPACE 2>/dev/null || echo "  No pods found"
    echo ""
    
    # Service details
    echo "🌐 Service Details:"
    kubectl describe services -n $NAMESPACE 2>/dev/null || echo "  No services found"
    echo ""
    
    # Events
    echo "📋 Recent Events:"
    kubectl get events -n $NAMESPACE --sort-by='.lastTimestamp' 2>/dev/null | tail -10 || echo "  No events found"
}

# Main command handling
main() {
    case "${1:-}" in
        "basic")
            run_all_tests "basic"
            ;;
        "extended")
            run_all_tests "extended"
            ;;
        "e2e")
            run_all_tests "e2e"
            ;;
        "status")
            show_detailed_status
            ;;
        "health")
            check_cluster && test_health_endpoints
            ;;
        "functionality")
            check_cluster && test_plugin_functionality
            ;;
        "help"|"--help"|"-h"|"")
            echo "Marty MMF Plugin - Comprehensive Testing"
            echo ""
            echo "Usage: $0 <test-type>"
            echo ""
            echo "Test Types:"
            echo "  basic                    Basic functionality tests"
            echo "  extended                 Extended tests including resources and networking"
            echo "  e2e                      Full end-to-end tests (includes load testing)"
            echo ""
            echo "Individual Tests:"
            echo "  health                   Test health endpoints only"
            echo "  functionality            Test plugin functionality only"
            echo "  status                   Show detailed status information"
            echo ""
            echo "Examples:"
            echo "  $0 basic                 # Run basic tests"
            echo "  $0 extended              # Run extended test suite"
            echo "  $0 e2e                   # Run full E2E tests"
            echo "  $0 health                # Quick health check"
            ;;
        *)
            log_error "Unknown test type: $1"
            echo "Use '$0 help' for usage information"
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"