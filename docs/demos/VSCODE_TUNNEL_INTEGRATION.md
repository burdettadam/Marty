# VS Code Port Forwarding Integration for Microsoft Authenticator Demo

## Overview
Updated the Microsoft Authenticator demo to use VS Code port forwarding for public access, enabling mobile device testing from anywhere with a simpler setup than tunnels.

## Changes Made

### 1. Docker Compose Updates
**File**: `docker/docker-compose.demo-microsoft-simple.yml`

- **Header**: Added VS Code port forwarding usage instructions
- **Environment Variables**: Made URLs configurable for forwarded port access
- **CORS**: Configured to allow forwarded domains
- **Services**: Maintained existing document-signer and inspection-system services
- **Dependencies**: Proper service dependencies and health checks

Key environment variables:
```
ISSUER_BASE_URL=${ISSUER_BASE_URL:-https://localhost:8000}
VERIFIER_BASE_URL=${VERIFIER_BASE_URL:-https://localhost:8001}
PORT_FORWARD_MODE=${PORT_FORWARD_MODE:-false}
CORS_ORIGINS=${CORS_ORIGINS:-*}
```

### 2. Documentation Updates
**File**: `docs/demos/microsoft_authenticator.md`

- **Architecture Diagram**: Updated to show VS Code port forwarding in the flow
- **Prerequisites**: Added VS Code port forwarding setup instructions
- **Quick Start**: Two-option setup (automated script vs manual)
- **Demo Walkthrough**: Updated all URLs to use forwarded port endpoints
- **Mobile Testing**: Added specific guidance for mobile device usage
- **Troubleshooting**: New VS Code port forwarding-specific troubleshooting section

### 3. Configuration Template
**File**: `.env.microsoft.portforward.example`

Complete environment template with:
- Database and MinIO configuration
- VS Code port forwarding URL placeholders
- Clear instructions for customization
- Step-by-step setup guide

### 4. Automated Setup Script
**File**: `scripts/setup-microsoft-portforward.sh`

Interactive script that:
- Validates VS Code availability
- Starts demo services
- Provides step-by-step port forwarding instructions
- Guides through environment configuration
- Shows exact commands to run

## Usage Instructions

### Quick Setup (Recommended)
1. Run setup script: `./scripts/setup-microsoft-portforward.sh`
2. In VS Code, open Ports panel and forward ports 8000 and 8001 as "Public"
3. Update `.env.microsoft` with your actual forwarded URLs
4. Restart demo: `docker-compose -f docker/docker-compose.demo-microsoft-simple.yml --env-file .env.microsoft down && up -d`

### Manual Setup
1. Copy `.env.microsoft.portforward.example` to `.env.microsoft`
2. Start services: `docker-compose -f docker/docker-compose.demo-microsoft-simple.yml up -d`
3. Set up port forwarding in VS Code
4. Update environment file with actual URLs and restart services

## Benefits

1. **Simpler Setup**: No need for named tunnels or CLI commands
2. **Visual Interface**: VS Code Ports panel provides easy management
3. **HTTPS by Default**: Port forwarding provides automatic HTTPS certificates
4. **Mobile Access**: Services accessible from any mobile device with internet
5. **No Background Processes**: Port forwarding integrated into VS Code workspace

## VS Code Port Forwarding Workflow

1. **Start Services**: Docker Compose starts local services on ports 8000/8001
2. **Forward Ports**: VS Code Ports panel forwards local ports to public URLs
3. **Mobile Access**: Microsoft Authenticator can reach public HTTPS endpoints
4. **Complete Flow**: Full OID4VCI → OID4VP cycle works across devices

## Port Forwarding vs Tunnel Comparison

| Feature | Port Forwarding | Tunnel |
|---------|----------------|--------|
| Setup Complexity | Low (GUI-based) | Medium (CLI-based) |
| Background Process | None (integrated) | Separate tunnel process |
| URL Format | `https://your-port-8000.preview.app.github.dev` | `https://8000-tunnel-name.githubpreview.dev` |
| Management | VS Code Ports panel | Terminal commands |
| Discoverability | Visual in VS Code | Command line output |

## Security Considerations

- Forwarded URLs are publicly accessible during demo session
- VS Code manages the forwarding securely through GitHub infrastructure
- Stop forwarding when demo is complete by removing ports from VS Code panel
- Environment variables contain URLs, not secrets
- All existing Marty security measures remain in place

## File Structure
```
Marty/
├── docker/docker-compose.demo-microsoft-simple.yml (updated)
├── docs/demos/microsoft_authenticator.md (updated)
├── scripts/setup-microsoft-portforward.sh (new)
├── .env.microsoft.portforward.example (new)
└── README.md (updated reference)
```

This implementation provides the simplest way to demo Microsoft Authenticator integration without complex network setup, making it ideal for development, testing, and demonstrations.