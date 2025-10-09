#!/bin/bash

# Microsoft Authenticator VS Code Port Forwarding Setup - Kubernetes Version
# Production-like demo using Kubernetes with VS Code port forwarding
#
# Prerequisites:
# - Kubernetes cluster running (Docker Desktop K8s, minikube, kind, etc.)
# - kubectl configured and connected to cluster
# - VS Code with port forwarding capability

set -e

echo "🚀 Microsoft Authenticator VS Code Port Forwarding Setup (Kubernetes)"
echo "========================================================================"
echo

# Check prerequisites
echo "🔍 Checking prerequisites..."

if ! command -v kubectl &> /dev/null; then
    echo "❌ kubectl not found. Please install kubectl first."
    echo "   See: https://kubernetes.io/docs/tasks/tools/"
    exit 1
fi

if ! kubectl cluster-info &> /dev/null; then
    echo "❌ No Kubernetes cluster found or kubectl not configured."
    echo "   Please ensure you have a running K8s cluster (Docker Desktop, minikube, etc.)"
    exit 1
fi

echo "✅ kubectl found and connected to cluster"

# Check if VS Code is available
if ! command -v code &> /dev/null; then
    echo "⚠️  VS Code 'code' command not found. Port forwarding instructions will be manual."
    VSCODE_AVAILABLE=false
else
    echo "✅ VS Code found"
    VSCODE_AVAILABLE=true
fi

echo

# Deploy to Kubernetes
echo "☸️  Deploying Microsoft demo to Kubernetes..."

cd ..

# Apply the Kubernetes manifests
kubectl apply -f k8s/microsoft-demo.yaml

echo "✅ Kubernetes manifests applied"
echo

# Wait for pods to be ready
echo "⏳ Waiting for services to be ready..."

# Wait for postgres to be ready
echo "   Waiting for PostgreSQL..."
kubectl wait --for=condition=ready pod -l app=postgres -n marty-microsoft-demo --timeout=180s

# Wait for APIs to be ready
echo "   Waiting for Issuer API..."
kubectl wait --for=condition=ready pod -l app=issuer-api -n marty-microsoft-demo --timeout=180s

echo "   Waiting for Verifier API..."
kubectl wait --for=condition=ready pod -l app=verifier-api -n marty-microsoft-demo --timeout=180s

echo "✅ All services are ready!"
echo

# Show service status
echo "📊 Service Status:"
kubectl get pods -n marty-microsoft-demo -o wide
echo

# Set up port forwarding instructions
echo "🌐 Setting up VS Code port forwarding:"
echo

if [ "$VSCODE_AVAILABLE" = true ]; then
    echo "1. Opening VS Code in this directory..."
    code .
    echo
fi

cat << 'EOF'
2. Set up port forwarding in VS Code:

   Method 1 - Using VS Code UI:
   a) Open Command Palette (Cmd+Shift+P or Ctrl+Shift+P)
   b) Type 'Ports: Focus on Ports View' and press Enter
   c) In the Ports panel, click 'Forward a Port'
   d) Add these ports with 'Public' visibility:
      - Port 8000 (for issuer-api-microsoft-demo)
      - Port 8001 (for verifier-api-microsoft-demo)

   Method 2 - Using kubectl directly:
   # In separate terminals:
   kubectl port-forward -n marty-microsoft-demo service/issuer-api-microsoft-demo 8000:8000
   kubectl port-forward -n marty-microsoft-demo service/verifier-api-microsoft-demo 8001:8001

3. Get your public URLs:
   - In VS Code Ports panel, copy the generated URLs (like https://abc123-8000.preview.app.github.dev)
   - Or use localhost URLs if using kubectl directly

4. Update configuration with your actual URLs:
   kubectl patch configmap microsoft-demo-config -n marty-microsoft-demo --patch='
   data:
     ISSUER_BASE_URL: "https://your-actual-issuer-url"
     VERIFIER_BASE_URL: "https://your-actual-verifier-url"
     CREDENTIAL_ISSUER_DID: "did:web:your-actual-issuer-domain"
     VERIFIER_DID: "did:web:your-actual-verifier-domain"'

5. Restart services to pick up new configuration:
   kubectl rollout restart deployment/issuer-api-microsoft-demo -n marty-microsoft-demo
   kubectl rollout restart deployment/verifier-api-microsoft-demo -n marty-microsoft-demo

EOF

echo "🧪 Testing your services:"
echo
echo "Once port forwarding is set up:"
echo "  curl https://your-actual-issuer-url/health"
echo "  curl https://your-actual-verifier-url/health"
echo
echo "📱 Create a credential for Microsoft Authenticator:"
echo "  curl -X POST https://your-actual-issuer-url/offer \\"
echo "    -H 'Content-Type: application/json' \\"
echo "    -d '{\"credential_type\":\"MartyDigitalPassport\",\"subject_claims\":{\"given_name\":\"John\",\"family_name\":\"Doe\"}}'"
echo
echo "🔍 Open verifier demo on mobile:"
echo "  https://your-actual-verifier-url/demo"
echo

echo "🎉 Kubernetes setup complete!"
echo
echo "💡 Useful commands:"
echo "  # View logs"
echo "  kubectl logs -f -l app=issuer-api -n marty-microsoft-demo"
echo "  kubectl logs -f -l app=verifier-api -n marty-microsoft-demo"
echo
echo "  # Check service status"
echo "  kubectl get pods -n marty-microsoft-demo"
echo
echo "  # Clean up when done"
echo "  kubectl delete namespace marty-microsoft-demo"
echo
echo "📖 Keep VS Code open with the Ports panel visible to monitor your forwarded ports."
