# Microsoft Authenticator Demo

A consolidated, DRY implementation of the Microsoft Authenticator integration demo for the Marty project. This directory contains all Microsoft demo-specific code, configuration, scripts, and documentation in one organized location.

## 🎯 Overview

The Microsoft Authenticator demo showcases end-to-end credential issuance and verification using Microsoft Authenticator app. This implementation supports:

- **OID4VCI (OpenID for Verifiable Credential Issuance)** - Issue credentials to Microsoft Authenticator
- **OID4VP (OpenID for Verifiable Presentations)** - Verify credentials from Microsoft Authenticator  
- **Multiple deployment options** - Docker, Kubernetes, VS Code port forwarding
- **HTTPS support** - Required for Microsoft Authenticator compatibility
- **Production-ready configuration** - With security, monitoring, and storage

## 🏗️ Directory Structure

```
src/microsoft_demo/
├── Makefile                          # Consolidated demo operations
├── README.md                         # This file
├── issuer_api.py                     # Standalone issuer API
├── verifier_api.py                   # Standalone verifier API
├── __init__.py                       # Python package marker
├── config/                           # Configuration files
│   ├── .env.template                 # Environment template
│   ├── docker-compose.demo-simple.yml  # Simple Docker setup
│   └── docker-compose.demo-full.yml    # Full Docker setup with services
├── scripts/                          # Automation scripts
│   ├── setup-env.sh                  # Environment setup
│   ├── k8s-cluster-create.sh         # Kubernetes cluster creation
│   ├── k8s-port-forward.sh           # Port forwarding for K8s
│   ├── configure-urls.sh             # URL configuration
│   ├── test-endpoints.sh             # API endpoint testing
│   ├── test-workflow.sh              # Workflow testing
│   ├── wait-for-services.sh          # Service readiness check
│   └── validate-setup.sh             # Setup validation
├── k8s/                              # Kubernetes manifests
│   └── demo.yaml                     # Complete K8s deployment
└── docs/                             # Documentation
    └── (additional documentation)
```

## 🚀 Quick Start

### Option 1: Docker Setup (Recommended for Development)

```bash
cd src/microsoft_demo
make setup
```

### Option 2: Kubernetes Setup (Recommended for Production-like Testing)

```bash
cd src/microsoft_demo  
make setup-k8s
```

### Option 3: VS Code Port Forwarding (Best for Mobile Testing)

```bash
cd src/microsoft_demo
make setup-vscode
```

## 📋 Prerequisites

### Required Tools

- **Docker** - For containerized deployment
- **Docker Compose** - For orchestrating services
- **curl** - For API testing

### Optional Tools (Enhanced Experience)

- **kubectl** - For Kubernetes operations
- **kind** - For local Kubernetes clusters  
- **jq** - For JSON parsing in scripts
- **VS Code** - For port forwarding integration

### Installation (macOS)

```bash
# Required tools
brew install --cask docker
brew install curl

# Optional tools  
brew install kubectl kind jq
brew install --cask visual-studio-code
```

## 🔧 Configuration

### Environment Setup

1. **Initialize environment**:
   ```bash
   make setup-env
   ```

2. **Customize configuration** (optional):
   ```bash
   cp config/.env.template config/.env.demo
   # Edit config/.env.demo with your settings
   ```

### URL Configuration

For external access (required for mobile testing):

```bash
make configure-urls \
  ISSUER_URL=https://your-issuer-url.com \
  VERIFIER_URL=https://your-verifier-url.com
```

## 📱 Deployment Options

### Docker - Simple Setup

**Best for:** Local development, quick testing

```bash
# Start services
make docker-up-simple

# Check status
make status

# Test endpoints
make test-endpoints
```

**Features:**
- Minimal dependencies
- Fast startup
- Local PostgreSQL
- HTTP endpoints (localhost only)

### Docker - Full Setup

**Best for:** Production-like testing, integration testing

```bash
# Start all services
make docker-up

# Check status  
make status

# Test complete workflow
make test-workflow
```

**Features:**
- Complete service stack
- PostgreSQL + MinIO + Vault
- Traefik reverse proxy
- HTTPS support
- Health checks

### Kubernetes Setup

**Best for:** Production environment, scalability testing

```bash
# Create cluster and deploy
make k8s-up

# Check status
make k8s-status

# View logs
make k8s-logs
```

**Features:**
- Kind cluster or existing K8s
- Production-ready manifests
- Service discovery
- Horizontal scaling
- Resource management

### VS Code Port Forwarding

**Best for:** Mobile device testing, remote development

```bash
# Start services for port forwarding
make setup-vscode

# Follow instructions to:
# 1. Forward ports 8000, 8001 as "Public" in VS Code
# 2. Configure URLs with your forwarded URLs
# 3. Test with mobile device
```

**Features:**
- Public HTTPS URLs
- Mobile device access
- Microsoft Authenticator compatible
- Easy setup with VS Code

## 🧪 Testing

### Quick Health Check

```bash
make test-endpoints
```

### Complete Workflow Test

```bash
make test-workflow
```

### API Testing

```bash
# Test issuer API
curl https://your-issuer-url/health

# Test verifier API  
curl https://your-verifier-url/health

# Create credential offer
curl -X POST https://your-issuer-url/offer \
  -H "Content-Type: application/json" \
  -d '{"credential_type":"MartyDigitalPassport","subject_claims":{"given_name":"John","family_name":"Doe"}}'
```

## 📱 Microsoft Authenticator Testing

### Prerequisites

- Microsoft Authenticator app installed on mobile device
- Public HTTPS URLs (use VS Code port forwarding or deployed environment)

### Credential Issuance Flow

1. **Open issuer demo**: `https://your-issuer-url/demo`
2. **Create credential offer** with test data
3. **Scan QR code** with Microsoft Authenticator
4. **Accept credential** in the app

### Credential Verification Flow

1. **Open verifier demo**: `https://your-verifier-url/demo`
2. **Create presentation request**
3. **Scan QR code** with Microsoft Authenticator  
4. **Present credential** from your wallet

## 🔧 Management Commands

### Status and Monitoring

```bash
make status              # Overall status
make show-config         # Current configuration
make validate-setup      # Validate environment
```

### Service Management

```bash
make docker-restart      # Restart Docker services
make k8s-restart         # Restart Kubernetes deployments  
make wait-for-services   # Wait for services to be ready
```

### Development

```bash
make docker-logs         # View Docker logs
make k8s-logs           # View Kubernetes logs
make open-docs          # Open API documentation
```

### Cleanup

```bash
make clean              # Stop and cleanup all
make docker-down        # Stop Docker services
make k8s-cleanup        # Cleanup Kubernetes resources
```

## 🌐 API Endpoints

### Issuer API (Port 8000)

- **Health**: `GET /health`
- **Documentation**: `GET /docs`
- **Root**: `GET /` - API information
- **Create Offer**: `POST /offer` - Create credential offer
- **QR Code**: `GET /qr` - Generate QR codes
- **Demo UI**: `GET /demo` - Demo interface (if implemented)

### Verifier API (Port 8001)

- **Health**: `GET /health`
- **Documentation**: `GET /docs`  
- **Root**: `GET /` - API information
- **Create Request**: `POST /request` - Create presentation request
- **QR Code**: `GET /qr` - Generate QR codes
- **Demo UI**: `GET /demo` - Demo interface (if implemented)

## 🔍 Troubleshooting

### Common Issues

**Services not starting:**
```bash
# Check prerequisites
make validate-setup

# Check Docker
docker info

# Check ports
lsof -i :8000
lsof -i :8001
```

**API not accessible:**
```bash
# Test connectivity
make test-endpoints

# Check configuration
make show-config

# Restart services
make docker-restart
```

**Microsoft Authenticator not working:**
- Ensure URLs are HTTPS (not HTTP)
- Verify URLs are accessible from mobile device
- Check QR code generation
- Confirm credential format compatibility

### Logs and Debugging

```bash
# Docker logs
make docker-logs

# Kubernetes logs  
make k8s-logs

# Service status
make status

# Detailed validation
make validate-setup
```

### Port Conflicts

```bash
# Check port usage
lsof -i :8000
lsof -i :8001

# Kill conflicting processes
pkill -f "port.*8000"
pkill -f "port.*8001"

# Restart services
make docker-restart
```

## 🚀 Advanced Usage

### Custom Environments

```bash
# Use custom environment file
cp config/.env.template config/.env.production
# Edit config/.env.production
make setup ENV_FILE=config/.env.production
```

### Development Mode

```bash
# Enable hot reload (Docker)
make docker-up-simple
# APIs will automatically reload on code changes

# Enable debug logging
make configure-urls LOG_LEVEL=DEBUG
```

### Production Deployment

```bash
# Full setup with all services
make docker-up

# Or Kubernetes for production
make k8s-up

# Configure proper HTTPS URLs
make configure-urls \
  ISSUER_URL=https://issuer.yourdomain.com \
  VERIFIER_URL=https://verifier.yourdomain.com
```

## 🤝 Integration with Main Project

This consolidated demo integrates with the main Marty project through:

### Main Makefile Integration

From the project root:

```bash
# Delegates to src/microsoft_demo/Makefile
make demo-microsoft                    # Kubernetes setup
make demo-microsoft-docker             # Docker setup  
make demo-microsoft-vscode             # VS Code setup
make demo-microsoft-status             # Status check
make demo-microsoft-test               # Run tests
make demo-microsoft-cleanup            # Cleanup
make demo-microsoft-configure-tunnels  # Configure URLs
make demo-microsoft-help               # Detailed help
```

### Shared Resources

The demo can optionally use shared project resources:

- **Database schemas** from `scripts/init-demo-db.sql`
- **Trust store** from `data/trust_store.json`
- **Common utilities** from `src/marty_common/`

## 📖 Additional Resources

### Documentation

- **API Documentation**: Available at `/docs` endpoint when services are running
- **OpenID4VC Specs**: [OpenID for Verifiable Credentials](https://openid.net/sg/openid4vc/)
- **Microsoft Authenticator**: [Microsoft Entra Verified ID](https://docs.microsoft.com/en-us/azure/active-directory/verifiable-credentials/)

### Related Commands

```bash
# From project root
make help                              # Show all commands
make demo-microsoft-help               # Show Microsoft demo help

# From microsoft_demo directory  
make help                              # Show detailed demo commands
```

### Scripts

All scripts are in `scripts/` and include:
- Comprehensive error handling
- Colored output for clarity
- Help documentation
- Validation and testing

## 🎉 Success Indicators

Your demo is working correctly when:

✅ All API endpoints return healthy status  
✅ QR codes are generated successfully  
✅ Microsoft Authenticator can scan QR codes  
✅ Credentials are issued and stored in the app  
✅ Credentials can be presented for verification  
✅ All workflow tests pass  

## 💡 Tips and Best Practices

- **Use VS Code port forwarding** for mobile testing
- **Test with HTTPS URLs** for Microsoft Authenticator compatibility  
- **Monitor logs** during development for debugging
- **Validate setup** before troubleshooting issues
- **Use the workflow tests** to verify end-to-end functionality
- **Keep configurations in version control** (except secrets)

## 🔄 Migration from Old Structure

This consolidated structure replaces the previous scattered approach:

**Old** → **New**
- `scripts/setup-microsoft-*.sh` → `src/microsoft_demo/scripts/`
- `docker/docker-compose.demo-microsoft*.yml` → `src/microsoft_demo/config/`  
- `k8s/microsoft-demo.yaml` → `src/microsoft_demo/k8s/demo.yaml`
- `.env.microsoft*` → `src/microsoft_demo/config/.env.*`

All main Makefile targets are preserved and delegate to the consolidated location.

---

**Happy testing with Microsoft Authenticator! 🎉**