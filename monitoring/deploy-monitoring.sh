#!/bin/bash

# Marty Monitoring Stack Deployment Script
# This script deploys the complete monitoring infrastructure for Marty services

set -euo pipefail

# Configuration
NAMESPACE="${NAMESPACE:-marty-monitoring}"
RELEASE_NAME="${RELEASE_NAME:-marty-monitoring}"
ENVIRONMENT="${ENVIRONMENT:-development}"
CHART_DIR="$(dirname "$0")/helm"

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

# Function to check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check if kubectl is available
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl is not installed or not in PATH"
        exit 1
    fi
    
    # Check if helm is available
    if ! command -v helm &> /dev/null; then
        log_error "helm is not installed or not in PATH"
        exit 1
    fi
    
    # Check kubectl connectivity
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster"
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

# Function to create namespace
create_namespace() {
    log_info "Creating namespace ${NAMESPACE}..."
    
    if kubectl get namespace "${NAMESPACE}" &> /dev/null; then
        log_warning "Namespace ${NAMESPACE} already exists"
    else
        kubectl create namespace "${NAMESPACE}"
        log_success "Created namespace ${NAMESPACE}"
    fi
    
    # Label namespace for monitoring
    kubectl label namespace "${NAMESPACE}" name="${NAMESPACE}" --overwrite
    kubectl label namespace "${NAMESPACE}" environment="${ENVIRONMENT}" --overwrite
    kubectl label namespace "${NAMESPACE}" app.kubernetes.io/part-of=marty-monitoring --overwrite
}

# Function to add Helm repositories
add_helm_repos() {
    log_info "Adding required Helm repositories..."
    
    helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
    helm repo add grafana https://grafana.github.io/helm-charts
    helm repo update
    
    log_success "Helm repositories updated"
}

# Function to validate chart
validate_chart() {
    log_info "Validating Helm chart..."
    
    if [ ! -f "${CHART_DIR}/Chart.yaml" ]; then
        log_error "Chart.yaml not found in ${CHART_DIR}"
        exit 1
    fi
    
    if [ ! -f "${CHART_DIR}/values.yaml" ]; then
        log_error "values.yaml not found in ${CHART_DIR}"
        exit 1
    fi
    
    # Lint the chart
    helm lint "${CHART_DIR}"
    
    log_success "Chart validation passed"
}

# Function to generate values file for environment
generate_values_file() {
    local values_file="/tmp/marty-monitoring-${ENVIRONMENT}.yaml"
    
    log_info "Generating values file for environment: ${ENVIRONMENT}"
    
    cat > "${values_file}" << EOF
global:
  environment: "${ENVIRONMENT}"
  cluster: "${CLUSTER_NAME:-marty-cluster}"
  region: "${AWS_REGION:-us-east-1}"
  storageClass: "${STORAGE_CLASS:-}"

# Environment-specific overrides
prometheus:
  server:
    ingress:
      enabled: ${PROMETHEUS_INGRESS_ENABLED:-false}
      hosts:
        - host: prometheus-${ENVIRONMENT}.${DOMAIN:-marty.local}
          paths:
            - path: /
              pathType: Prefix

grafana:
  adminPassword: "${GRAFANA_ADMIN_PASSWORD:-marty-admin-${ENVIRONMENT}}"
  ingress:
    enabled: ${GRAFANA_INGRESS_ENABLED:-false}
    hosts:
      - host: grafana-${ENVIRONMENT}.${DOMAIN:-marty.local}
        paths:
          - path: /
            pathType: Prefix

alertmanager:
  ingress:
    enabled: ${ALERTMANAGER_INGRESS_ENABLED:-false}
    hosts:
      - host: alertmanager-${ENVIRONMENT}.${DOMAIN:-marty.local}
        paths:
          - path: /
            pathType: Prefix
  config:
    global:
      smtp_smarthost: '${SMTP_HOST:-localhost:587}'
      smtp_from: '${SMTP_FROM:-alertmanager@marty.com}'
      smtp_auth_username: '${SMTP_USERNAME:-}'
      smtp_auth_password: '${SMTP_PASSWORD:-}'
EOF

    echo "${values_file}"
}

# Function to deploy monitoring stack
deploy_monitoring() {
    local values_file
    values_file=$(generate_values_file)
    
    log_info "Deploying monitoring stack to ${ENVIRONMENT} environment..."
    
    # Copy monitoring configuration files to chart
    if [ -d "../monitoring/prometheus" ]; then
        cp -r ../monitoring/prometheus "${CHART_DIR}/"
        log_info "Copied Prometheus configuration files"
    fi
    
    if [ -d "../monitoring/grafana" ]; then
        cp -r ../monitoring/grafana "${CHART_DIR}/"
        log_info "Copied Grafana configuration files"
    fi
    
    # Deploy with Helm
    helm upgrade --install "${RELEASE_NAME}" "${CHART_DIR}" \
        --namespace "${NAMESPACE}" \
        --values "${CHART_DIR}/values.yaml" \
        --values "${values_file}" \
        --set global.environment="${ENVIRONMENT}" \
        --timeout 10m \
        --wait
    
    log_success "Monitoring stack deployed successfully"
    
    # Clean up temporary values file
    rm -f "${values_file}"
}

# Function to verify deployment
verify_deployment() {
    log_info "Verifying deployment..."
    
    # Check pod status
    log_info "Checking pod status..."
    kubectl get pods -n "${NAMESPACE}" -l app.kubernetes.io/instance="${RELEASE_NAME}"
    
    # Wait for pods to be ready
    log_info "Waiting for pods to be ready..."
    kubectl wait --for=condition=ready pod -l app.kubernetes.io/instance="${RELEASE_NAME}" -n "${NAMESPACE}" --timeout=300s
    
    # Check services
    log_info "Checking services..."
    kubectl get services -n "${NAMESPACE}" -l app.kubernetes.io/instance="${RELEASE_NAME}"
    
    # Check ingresses if enabled
    if kubectl get ingresses -n "${NAMESPACE}" -l app.kubernetes.io/instance="${RELEASE_NAME}" &> /dev/null; then
        log_info "Checking ingresses..."
        kubectl get ingresses -n "${NAMESPACE}" -l app.kubernetes.io/instance="${RELEASE_NAME}"
    fi
    
    log_success "Deployment verification completed"
}

# Function to show access information
show_access_info() {
    log_info "Access Information:"
    echo
    
    # Prometheus
    local prometheus_port
    prometheus_port=$(kubectl get service "${RELEASE_NAME}-prometheus" -n "${NAMESPACE}" -o jsonpath='{.spec.ports[0].port}')
    echo -e "${BLUE}Prometheus:${NC}"
    echo "  Port forward: kubectl port-forward svc/${RELEASE_NAME}-prometheus ${prometheus_port}:${prometheus_port} -n ${NAMESPACE}"
    echo "  URL: http://localhost:${prometheus_port}"
    echo
    
    # Grafana
    local grafana_port
    grafana_port=$(kubectl get service "${RELEASE_NAME}-grafana" -n "${NAMESPACE}" -o jsonpath='{.spec.ports[0].port}')
    echo -e "${BLUE}Grafana:${NC}"
    echo "  Port forward: kubectl port-forward svc/${RELEASE_NAME}-grafana ${grafana_port}:${grafana_port} -n ${NAMESPACE}"
    echo "  URL: http://localhost:${grafana_port}"
    echo "  Username: admin"
    echo "  Password: ${GRAFANA_ADMIN_PASSWORD:-marty-admin-${ENVIRONMENT}}"
    echo
    
    # Alertmanager
    local alertmanager_port
    alertmanager_port=$(kubectl get service "${RELEASE_NAME}-alertmanager" -n "${NAMESPACE}" -o jsonpath='{.spec.ports[0].port}')
    echo -e "${BLUE}Alertmanager:${NC}"
    echo "  Port forward: kubectl port-forward svc/${RELEASE_NAME}-alertmanager ${alertmanager_port}:${alertmanager_port} -n ${NAMESPACE}"
    echo "  URL: http://localhost:${alertmanager_port}"
    echo
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "Options:"
    echo "  -e, --environment ENVIRONMENT    Set deployment environment (default: development)"
    echo "  -n, --namespace NAMESPACE        Set Kubernetes namespace (default: marty-monitoring)"
    echo "  -r, --release RELEASE_NAME       Set Helm release name (default: marty-monitoring)"
    echo "  -h, --help                       Show this help message"
    echo
    echo "Environment Variables:"
    echo "  GRAFANA_ADMIN_PASSWORD          Grafana admin password"
    echo "  PROMETHEUS_INGRESS_ENABLED      Enable Prometheus ingress (true/false)"
    echo "  GRAFANA_INGRESS_ENABLED         Enable Grafana ingress (true/false)"
    echo "  ALERTMANAGER_INGRESS_ENABLED    Enable Alertmanager ingress (true/false)"
    echo "  DOMAIN                          Base domain for ingresses"
    echo "  SMTP_HOST                       SMTP server for alerts"
    echo "  SMTP_FROM                       From address for alerts"
    echo "  SMTP_USERNAME                   SMTP username"
    echo "  SMTP_PASSWORD                   SMTP password"
    echo "  STORAGE_CLASS                   Kubernetes storage class"
    echo "  CLUSTER_NAME                    Cluster name for labeling"
    echo "  AWS_REGION                      AWS region for labeling"
    echo
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -e|--environment)
            ENVIRONMENT="$2"
            shift 2
            ;;
        -n|--namespace)
            NAMESPACE="$2"
            shift 2
            ;;
        -r|--release)
            RELEASE_NAME="$2"
            shift 2
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Main execution
main() {
    log_info "Starting Marty monitoring stack deployment"
    log_info "Environment: ${ENVIRONMENT}"
    log_info "Namespace: ${NAMESPACE}"
    log_info "Release: ${RELEASE_NAME}"
    echo
    
    check_prerequisites
    create_namespace
    add_helm_repos
    validate_chart
    deploy_monitoring
    verify_deployment
    show_access_info
    
    log_success "Monitoring stack deployment completed successfully!"
    log_info "Run 'helm status ${RELEASE_NAME} -n ${NAMESPACE}' to check deployment status"
}

# Run main function
main "$@"