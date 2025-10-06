# Microsoft Authenticator Demo - Kubernetes Setup

This directory contains scripts for setting up a complete Microsoft Authenticator demo environment using Kubernetes and VS Code port forwarding.

## 🚀 Quick Start

### Complete Automated Setup
```bash
./scripts/setup-microsoft-demo-complete.sh
```

This single script will:
- ✅ Check all prerequisites (kubectl, kind, Docker)
- ✅ Create a kind cluster with proper host path mounts
- ✅ Deploy the Microsoft demo APIs to Kubernetes
- ✅ Set up port forwarding for both APIs
- ✅ Test all endpoints and provide VS Code integration instructions

### Check Status
```bash
./scripts/check-microsoft-demo-status.sh
```

### Cleanup
```bash
./scripts/cleanup-microsoft-demo.sh
```

## 📋 Prerequisites

The setup script will check for these automatically:

- **kubectl** - Kubernetes CLI tool
- **kind** - Kubernetes in Docker for local development
- **Docker** - Container runtime (must be running)
- **curl** (optional) - For testing endpoints
- **jq** (optional) - For pretty JSON output

### Installing Prerequisites

**kubectl:**
```bash
# macOS
brew install kubectl

# Linux
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
```

**kind:**
```bash
# macOS
brew install kind

# Linux
[ $(uname -m) = x86_64 ] && curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.20.0/kind-linux-amd64
chmod +x ./kind
sudo mv ./kind /usr/local/bin/kind
```

**Docker:**
- macOS: Download Docker Desktop from https://docker.com
- Linux: Follow instructions at https://docs.docker.com/engine/install/

## 🎯 What Gets Created

### Kubernetes Resources
- **Cluster**: `marty-microsoft-demo` (kind cluster)
- **Namespace**: `marty-microsoft-demo`
- **Deployments**: 
  - `issuer-api-microsoft-demo` (port 8000)
  - `verifier-api-microsoft-demo` (port 8001)
- **Services**: ClusterIP services for both APIs
- **ConfigMaps**: Configuration for demo environment

### Local Access
- **Port Forwarding**: 
  - Issuer API: `http://localhost:8000`
  - Verifier API: `http://localhost:8001`

## 🌐 VS Code Integration

After running the setup script:

1. **Open VS Code** in this workspace
2. **Open Ports Panel**: View → Terminal → Ports
3. **Make Ports Public**: 
   - Right-click on port 8000 → "Change Port Visibility" → "Public"
   - Right-click on port 8001 → "Change Port Visibility" → "Public"
4. **Get HTTPS URLs**: VS Code will generate URLs like:
   - `https://abcd1234-8000.app.github.dev/` (Issuer API)
   - `https://abcd1234-8001.app.github.dev/` (Verifier API)

## 📱 Microsoft Authenticator Testing

### Credential Issuance Flow

1. **Create Credential Offer**:
   ```bash
   curl -X POST https://your-issuer-url/credential-offer \
     -H "Content-Type: application/json" \
     -d '{
       "type": "EmployeeCredential",
       "subject_data": {
         "name": "John Doe",
         "employeeId": "EMP001",
         "department": "Engineering"
       }
     }'
   ```

2. **Use the returned `credential_offer_uri`** with Microsoft Authenticator
3. **The app will follow the OID4VCI flow** to obtain the credential

### Credential Verification Flow

1. **Visit Demo Page**: `https://your-verifier-url/verification-demo`
2. **Click "Start Verification"** to create a presentation request
3. **Use the generated authorization URI** with Microsoft Authenticator
4. **The app will present credentials** according to the presentation definition

## 🔧 API Endpoints

### Issuer API (`https://your-issuer-url/`)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | API information |
| `/health` | GET | Health check |
| `/.well-known/openid_credential_issuer` | GET | OID4VCI metadata |
| `/credential-offer` | POST | Create credential offer |
| `/token` | POST | OAuth token exchange |
| `/credential` | POST | Issue credential |

### Verifier API (`https://your-verifier-url/`)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | API information |
| `/health` | GET | Health check |
| `/verification-demo` | GET | Interactive demo page |
| `/presentation-request` | POST | Create verification request |
| `/presentation-response` | POST | Handle credential presentation |
| `/verification-status/{id}` | GET | Check verification status |

## 🛠️ Management Commands

### Restart APIs
```bash
kubectl rollout restart deployment/issuer-api-microsoft-demo -n marty-microsoft-demo
kubectl rollout restart deployment/verifier-api-microsoft-demo -n marty-microsoft-demo
```

### View Logs
```bash
kubectl logs -f deployment/issuer-api-microsoft-demo -n marty-microsoft-demo
kubectl logs -f deployment/verifier-api-microsoft-demo -n marty-microsoft-demo
```

### Scale APIs
```bash
kubectl scale deployment/issuer-api-microsoft-demo --replicas=2 -n marty-microsoft-demo
```

### Port Forward Manually
```bash
kubectl port-forward -n marty-microsoft-demo service/issuer-api-microsoft-demo 8000:8000 &
kubectl port-forward -n marty-microsoft-demo service/verifier-api-microsoft-demo 8001:8001 &
```

## 🚨 Troubleshooting

### Common Issues

**Port forwarding fails:**
```bash
# Check if ports are in use
lsof -i :8000
lsof -i :8001

# Kill existing processes
pkill -f "kubectl port-forward.*8000"
pkill -f "kubectl port-forward.*8001"
```

**APIs not starting:**
```bash
# Check pod status
kubectl get pods -n marty-microsoft-demo

# Check logs
kubectl logs -f deployment/issuer-api-microsoft-demo -n marty-microsoft-demo
```

**Cluster issues:**
```bash
# Recreate cluster
kind delete cluster --name marty-microsoft-demo
./scripts/setup-microsoft-demo-complete.sh
```

### Script Outputs

Each script provides colored output:
- 🔵 **[INFO]** - Informational messages
- 🟢 **[SUCCESS]** - Successful operations
- 🟡 **[WARNING]** - Warnings (non-fatal)
- 🔴 **[ERROR]** - Errors (may be fatal)

## 📁 File Structure

```
scripts/
├── setup-microsoft-demo-complete.sh    # Complete automated setup
├── check-microsoft-demo-status.sh      # Status checker
├── cleanup-microsoft-demo.sh           # Complete cleanup
└── README.md                          # This file

k8s/
└── microsoft-demo.yaml                 # Kubernetes manifests

src/microsoft_demo/
├── issuer_api.py                       # Standalone issuer API
├── verifier_api.py                     # Standalone verifier API
└── __init__.py                         # Package marker
```

## ⚠️ Important Notes

1. **HTTPS Required**: Microsoft Authenticator requires HTTPS URLs - use VS Code's public port forwarding
2. **Production vs Demo**: These are simplified demo APIs - use proper implementations for production
3. **Resource Usage**: The kind cluster uses local Docker resources
4. **Port Conflicts**: Ensure ports 8000 and 8001 are available locally
5. **VS Code**: The port forwarding integration assumes you're using VS Code with this workspace

## 🎉 Success Indicators

When everything is working correctly, you should see:
- ✅ Kind cluster created and accessible
- ✅ All pods in `Running` state with `1/1` ready
- ✅ Both APIs responding to health checks
- ✅ Port forwarding active on localhost:8000 and localhost:8001
- ✅ Credential offers and verification requests can be created
- ✅ VS Code shows ports 8000 and 8001 in the Ports panel