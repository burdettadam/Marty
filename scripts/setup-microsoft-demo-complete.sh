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

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to cleanup on exit
cleanup() {
    print_status "Script completed."
}

# Set trap to cleanup on script exit
trap cleanup EXIT

echo "🚀 Microsoft Authenticator Demo - Complete Setup"
echo "================================================"
echo "This script will:"
echo "1. Check prerequisites"
echo "2. Create kind cluster with proper configuration"
echo "3. Deploy the Microsoft demo APIs"
echo "4. Set up port forwarding"
echo "5. Provide VS Code integration instructions"
echo ""

# Check prerequisites
print_status "Checking prerequisites..."

if ! command_exists kubectl; then
    print_error "kubectl is not installed. Please install kubectl first."
    echo "Visit: https://kubernetes.io/docs/tasks/tools/"
    exit 1
fi

if ! command_exists kind; then
    print_error "kind is not installed. Please install kind first."
    echo "Visit: https://kind.sigs.k8s.io/docs/user/quick-start/#installation"
    exit 1
fi

if ! command_exists docker; then
    print_error "Docker is not installed or not running. Please install and start Docker."
    exit 1
fi

# Check if Docker is running
if ! docker info >/dev/null 2>&1; then
    print_error "Docker is not running. Please start Docker and try again."
    exit 1
fi

print_success "All prerequisites are satisfied"

# Check if cluster already exists
if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
    print_warning "Cluster '${CLUSTER_NAME}' already exists."
    read -p "Do you want to delete and recreate it? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        print_status "Deleting existing cluster..."
        kind delete cluster --name "${CLUSTER_NAME}"
        print_success "Existing cluster deleted"
    else
        print_status "Using existing cluster"
    fi
fi

# Create kind cluster configuration
print_status "Creating kind cluster configuration..."
cat > /tmp/kind-config.yaml << EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: ${CLUSTER_NAME}
nodes:
- role: control-plane
  extraPortMappings:
  - containerPort: 30000
    hostPort: 31103
    protocol: TCP
  - containerPort: 30001
    hostPort: 31104
    protocol: TCP
EOF

# Create kind cluster if it doesn't exist
if ! kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
    print_status "Creating kind cluster '${CLUSTER_NAME}'..."
    kind create cluster --config /tmp/kind-config.yaml
    print_success "Kind cluster created successfully"
else
    print_status "Using existing kind cluster '${CLUSTER_NAME}'"
fi

# Set kubectl context
print_status "Setting kubectl context..."
kubectl cluster-info --context kind-${CLUSTER_NAME}

# Verify cluster is ready
print_status "Waiting for cluster to be ready..."
kubectl wait --for=condition=Ready nodes --all --timeout=300s

# Deploy the Microsoft demo
print_status "Deploying Microsoft demo to Kubernetes..."
kubectl apply -f k8s/microsoft-demo-simple.yaml

# Wait for deployments to be ready
print_status "Waiting for deployments to be ready..."
kubectl wait --for=condition=available deployment/issuer-api-microsoft-demo -n ${NAMESPACE} --timeout=300s
kubectl wait --for=condition=available deployment/verifier-api-microsoft-demo -n ${NAMESPACE} --timeout=300s

# Wait for pods to be ready
print_status "Waiting for pods to be ready..."
kubectl wait --for=condition=ready pod -l app=issuer-api -n ${NAMESPACE} --timeout=300s
kubectl wait --for=condition=ready pod -l app=verifier-api -n ${NAMESPACE} --timeout=300s

print_success "All deployments are ready!"

# Show pod status
print_status "Current pod status:"
kubectl get pods -n ${NAMESPACE}

# Test the APIs
print_status "Testing APIs..."
print_status "Testing Issuer API health:"
if kubectl exec -n ${NAMESPACE} deployment/issuer-api-microsoft-demo -- curl -f -s http://localhost:8000/health >/dev/null 2>&1; then
    print_success "Issuer API is healthy"
else
    print_warning "Issuer API health check failed"
fi

print_status "Testing Verifier API health:"
if kubectl exec -n ${NAMESPACE} deployment/verifier-api-microsoft-demo -- curl -f -s http://localhost:8001/health >/dev/null 2>&1; then
    print_success "Verifier API is healthy"
else
    print_warning "Verifier API health check failed"
fi

# Get NodePort access information
print_status "Getting NodePort access information..."
ISSUER_NODEPORT=$(kubectl get service issuer-api-microsoft-demo -n ${NAMESPACE} -o jsonpath='{.spec.ports[0].nodePort}')
VERIFIER_NODEPORT=$(kubectl get service verifier-api-microsoft-demo -n ${NAMESPACE} -o jsonpath='{.spec.ports[0].nodePort}')

print_success "Services are accessible via NodePort:"
print_success "Issuer API: http://localhost:${ISSUER_NODEPORT}"
print_success "Verifier API: http://localhost:${VERIFIER_NODEPORT}"

# Test NodePort connectivity
print_status "Testing NodePort connectivity..."
ISSUER_HEALTHY=false
VERIFIER_HEALTHY=false

for i in {1..20}; do
    if curl -f -s http://localhost:${ISSUER_NODEPORT}/health >/dev/null 2>&1; then
        ISSUER_HEALTHY=true
        break
    fi
    sleep 2
done

for i in {1..20}; do
    if curl -f -s http://localhost:${VERIFIER_NODEPORT}/health >/dev/null 2>&1; then
        VERIFIER_HEALTHY=true
        break
    fi
    sleep 2
done

if [ "$ISSUER_HEALTHY" = true ]; then
    print_success "Issuer API is accessible on http://localhost:${ISSUER_NODEPORT}"
else
    print_error "Issuer API is not accessible on http://localhost:${ISSUER_NODEPORT}"
fi

if [ "$VERIFIER_HEALTHY" = true ]; then
    print_success "Verifier API is accessible on http://localhost:${VERIFIER_NODEPORT}"
else
    print_error "Verifier API is not accessible on http://localhost:${VERIFIER_NODEPORT}"
fi

# Show API information
if [ "$ISSUER_HEALTHY" = true ]; then
    print_status "Issuer API Information:"
    curl -s http://localhost:${ISSUER_NODEPORT}/ | jq . 2>/dev/null || curl -s http://localhost:${ISSUER_NODEPORT}/
fi

if [ "$VERIFIER_HEALTHY" = true ]; then
    print_status "Verifier API Information:"
    curl -s http://localhost:${VERIFIER_NODEPORT}/ | jq . 2>/dev/null || curl -s http://localhost:${VERIFIER_NODEPORT}/
fi

# Test credential offer creation
if [ "$ISSUER_HEALTHY" = true ]; then
    print_status "Testing credential offer creation..."
    OFFER_RESPONSE=$(curl -s -X POST http://localhost:${ISSUER_NODEPORT}/credential-offer \
        -H "Content-Type: application/json" \
        -d '{"credential_type": "EmployeeCredential", "claims": {"given_name": "John", "family_name": "Doe", "employee_id": "EMP001"}}')
    
    if echo "$OFFER_RESPONSE" | jq . >/dev/null 2>&1; then
        print_success "✅ Credential offer created successfully!"
        echo "$OFFER_RESPONSE" | jq .
    else
        print_warning "Credential offer creation test failed"
        echo "$OFFER_RESPONSE"
    fi
fi

echo ""
echo "🎯 Setup Complete!"
echo "=================="
print_success "Microsoft Authenticator demo is now running!"
echo ""
echo "🌐 Access URLs:"
echo "==============="
echo "Issuer API Demo Page: http://localhost:${ISSUER_NODEPORT}/demo"
echo "Verifier API: http://localhost:${VERIFIER_NODEPORT}/"
echo ""
echo "📱 Microsoft Authenticator Integration:"
echo "======================================="
echo "1. 🖥️  Open the demo page: http://localhost:${ISSUER_NODEPORT}/demo"
echo "2. 🎫  Click 'Generate QR Code' to create a credential offer"
echo "3. 📱  Scan the QR code with Microsoft Authenticator"
echo "4. ✅  Complete the credential issuance flow"
echo ""
echo "🔑 Important API Endpoints:"
echo "=========================="
echo "Issuer API (http://localhost:${ISSUER_NODEPORT}):"
echo "  - Demo page: GET /demo"
echo "  - Root info: GET /"
echo "  - Create offer: POST /credential-offer"
echo "  - Generate QR: POST /generate-qr"
echo "  - Health check: GET /health"
echo ""
echo "Verifier API (http://localhost:${VERIFIER_NODEPORT}):"
echo "  - Root info: GET /"
echo "  - Health check: GET /health"
echo ""
echo "📊 Current Status:"
echo "=================="
echo "Cluster: ${CLUSTER_NAME} ✅"
echo "Namespace: ${NAMESPACE} ✅"
echo "Issuer API: http://localhost:${ISSUER_NODEPORT} $([ "$ISSUER_HEALTHY" = true ] && echo "✅" || echo "❌")"
echo "Verifier API: http://localhost:${VERIFIER_NODEPORT} $([ "$VERIFIER_HEALTHY" = true ] && echo "✅" || echo "❌")"
echo ""
echo "🛠️  Management Commands:"
echo "======================"
echo "To restart the APIs:"
echo "  kubectl rollout restart deployment/issuer-api-microsoft-demo -n ${NAMESPACE}"
echo "  kubectl rollout restart deployment/verifier-api-microsoft-demo -n ${NAMESPACE}"
echo ""
echo "To view logs:"
echo "  kubectl logs -f deployment/issuer-api-microsoft-demo -n ${NAMESPACE}"
echo "  kubectl logs -f deployment/verifier-api-microsoft-demo -n ${NAMESPACE}"
echo ""
echo "To delete the entire demo:"
echo "  kind delete cluster --name ${CLUSTER_NAME}"
echo ""
echo "✨ Ready to use! Open http://localhost:${ISSUER_NODEPORT}/demo to get started!"
wait