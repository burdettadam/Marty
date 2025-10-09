# Microsoft Authenticator Integration Demo with VS Code Tunnel

This demonstration showcases end-to-end interoperability between Marty's digital identity platform and Microsoft Authenticator, implementing the OpenID4VCI (OpenID for Verifiable Credential Issuance) and OpenID4VP (OpenID for Verifiable Presentations) standards. The demo uses VS Code tunnel to expose services publicly, enabling mobile device access from anywhere.

## Overview

Microsoft Authenticator uses Microsoft Entra Verified ID (previously Azure AD Verifiable Credentials) under the W3C VC Data Model and OIDC4VCI/OIDC4VP standards. This demo extends Marty's existing issuer to act as an OIDC Credential Issuer compliant with Microsoft Authenticator's expectations.

### Architecture with VS Code Tunnel

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│                 │    │                 │    │                 │
│  Microsoft      │    │   VS Code       │    │   Marty Demo    │
│  Authenticator  │◄──►│   Tunnel        │◄──►│   Environment   │
│  (Mobile)       │    │   (Public)      │    │   (Local)       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │                        │
                        ┌─────┴─────┐         ┌─────────┴─────────┐
                        │           │         │                   │
                   Port 8000   Port 8001    Issuer API     Verifier API
                   (Issuer)    (Verifier)   (OID4VCI)      (OID4VP)
                                                   │              │
                                                   ▼              ▼
                                            ┌─────────────────┐    ┌─────────────────┐
                                            │  Document       │    │  Inspection     │
                                            │  Signer         │    │  System         │
                                            │  (gRPC)         │    │  (gRPC)         │
                                            └─────────────────┘    └─────────────────┘
```

## Prerequisites

### System Requirements

- Docker and Docker Compose
- Python 3.9+
- VS Code with tunnel support
- Microsoft Authenticator app installed on a mobile device
- Internet connection for tunnel access

### VS Code Tunnel Setup

Microsoft Authenticator requires HTTPS endpoints accessible from the internet. VS Code tunnel provides a simple way to expose local services publicly:

1. **Install VS Code CLI** (if not already installed):

   ```bash
   # macOS
   brew install --cask visual-studio-code

   # Or download from https://code.visualstudio.com/
   ```

2. **Start VS Code Tunnel**:

   ```bash
   code tunnel --name marty-demo --accept-server-license-terms
   ```

   This will:
   - Create a public tunnel named "marty-demo"
   - Generate URLs like `https://8000-marty-demo.githubpreview.dev`
   - Automatically handle HTTPS certificates

3. **Note Your Tunnel URLs**:
   - Issuer API: `https://8000-YOUR_TUNNEL_NAME.githubpreview.dev`
   - Verifier API: `https://8001-YOUR_TUNNEL_NAME.githubpreview.dev`

   Replace `YOUR_TUNNEL_NAME` with your actual tunnel name.

## Quick Start with VS Code Tunnel

### Option A: Automated Setup (Recommended)

Use the provided setup script for easy configuration:

```bash
# Navigate to project root
cd /path/to/Marty

# Run the setup script
./scripts/setup-microsoft-portforward.sh
```

The script will:

- Start the demo services  
- Guide you through VS Code port forwarding setup
- Provide step-by-step instructions for configuration

### Option B: Manual Setup

### 1. Start Demo Services

First, start the demo environment:

```bash
# Navigate to project root
cd /path/to/Marty

# Start demo services
docker-compose -f docker/docker-compose.demo-microsoft-simple.yml up -d

# Verify services are running
docker-compose -f docker/docker-compose.demo-microsoft-simple.yml ps
```

### 2. Set Up Port Forwarding

In VS Code:

1. Open Command Palette (`Cmd+Shift+P`)
2. Type "Ports: Focus on Ports View"
3. Click "Forward a Port"
4. Add port `8000` with visibility "Public"
5. Add port `8001` with visibility "Public"
6. Copy the generated URLs from the Ports panel

### 3. Update Environment Configuration

Create/update `.env.microsoft` with your forwarded URLs:

```bash
# Database Configuration
POSTGRES_USER=martyuser
POSTGRES_PASSWORD=martypassword
POSTGRES_DB=martydb
POSTGRES_PORT=5433

# MinIO Configuration
MINIO_ROOT_USER=minioadmin
MINIO_ROOT_PASSWORD=minioadmin123
MINIO_PORT=9000
MINIO_CONSOLE_PORT=9001

# VS Code Port Forwarding Configuration
# Replace with your actual forwarded URLs from VS Code Ports panel
PORT_FORWARD_MODE=true
ISSUER_BASE_URL=https://your-port-8000.preview.app.github.dev
VERIFIER_BASE_URL=https://your-port-8001.preview.app.github.dev
CREDENTIAL_ISSUER_DID=did:web:your-port-8000.preview.app.github.dev
VERIFIER_DID=did:web:your-port-8001.preview.app.github.dev
CORS_ORIGINS=https://your-port-8000.preview.app.github.dev,https://your-port-8001.preview.app.github.dev

# Logging
LOG_LEVEL=INFO
```

### 4. Restart Services with New Configuration

```bash
# Restart with updated environment
docker-compose -f docker/docker-compose.demo-microsoft-simple.yml --env-file .env.microsoft down
docker-compose -f docker/docker-compose.demo-microsoft-simple.yml --env-file .env.microsoft up -d
```

### 5. Verify Services

Check that all services are accessible via port forwarding:

```bash
# Check issuer API locally
curl http://localhost:8000/health

# Check verifier API locally
curl http://localhost:8001/health

# Check issuer API via port forwarding (replace with your forwarded URL)
curl https://your-port-8000.preview.app.github.dev/health

# Check issuer metadata via port forwarding
curl https://your-port-8000.preview.app.github.dev/.well-known/openid-credential-issuer
```

## Demo Walkthrough

### Step 1: Issue a Verifiable Credential

1. **Create Credential Offer** (replace URLs with your forwarded port URLs):

   ```bash
   curl -X POST https://your-port-8000.preview.app.github.dev/offer \
     -H "Content-Type: application/json" \
     -d '{
       "credential_type": "MartyDigitalPassport",
       "subject_claims": {
         "given_name": "John",
         "family_name": "Doe",
         "nationality": "US",
         "date_of_birth": "1985-06-15",
         "passport_number": "P12345678",
         "issuing_country": "US",
         "expiry_date": "2030-06-15"
       }
     }'
   ```

2. **Scan QR Code**: The response includes a QR code in the `qr_code` field. Display this QR code and scan it with Microsoft Authenticator on your mobile device.

3. **Accept Credential**: In Microsoft Authenticator:
   - Tap "Add Credential"
   - Scan the QR code
   - Review the "Marty Digital Passport" details
   - Tap "Add" to store the credential

### Step 2: Verify the Credential

1. **Open Verifier Demo Page** (replace URL with your forwarded port URL):

   ```bash
   # On mobile device, navigate to:
   https://your-port-8001.preview.app.github.dev/demo
   ```

2. **Initiate Verification**:
   - Open the verifier demo page on your mobile browser
   - Click "Verify Credential"
   - A new QR code appears for verification

3. **Present Credential**: In Microsoft Authenticator:
   - Scan the verification QR code from the demo page
   - Select your "Marty Digital Passport"
   - Tap "Share" to present the credential

4. **View Results**: The demo page displays:
   - ✅ **Verified**: Signature valid, trust chain verified
   - 📋 **Details**: Credential subject information
   - 🔒 **Security**: Cryptographic verification results

### Mobile Testing Tips

- **Both issuer and verifier services are accessible from anywhere** via your VS Code port forwarding
- **Use the same mobile device** for Microsoft Authenticator and web browser
- **Keep VS Code open** with port forwarding active throughout the demo session
- **Check port forwarding status** in VS Code Ports panel if you encounter connectivity issues

## Expected Flow Sequence

| Step | Action | What Happens | Expected Result |
|------|--------|--------------|-----------------|
| 1 | User opens Microsoft Authenticator → "Add Credential" → "Scan QR" | Authenticator requests `openid-credential-offer://` URL | QR code displayed |
| 2 | Marty Issuer returns metadata from `/.well-known/openid-credential-issuer` | Authenticator verifies credential type & endpoints | Metadata validated |
| 3 | Authenticator calls `/token` with `grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code` | Marty issues access token | Bearer token received |
| 4 | Authenticator calls `/credential` with the token | Marty returns JWT-based VC in `jwt_vc_json` format | Credential stored |
| 5 | Later, Authenticator sends VC to Marty Verifier `/verify` endpoint (OID4VP) | Verifier validates signature and trust chain | Verification completed |
| 6 | Verification result displayed | Green "Verified by Marty" status | Success confirmation |

## API Endpoints

### Issuer API (Port 8000)

#### Metadata Discovery

```
GET /.well-known/openid-credential-issuer
```

Returns OpenID Credential Issuer metadata compatible with Microsoft Authenticator.

#### Create Credential Offer

```
POST /offer
Content-Type: application/json

{
  "credential_type": "MartyDigitalPassport",
  "subject_claims": {
    "given_name": "John",
    "family_name": "Doe",
    "nationality": "US"
  }
}
```

#### Token Exchange

```
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code&
pre-authorized_code=<code>
```

#### Credential Issuance

```
POST /credential
Authorization: Bearer <token>
Content-Type: application/json

{
  "format": "jwt_vc_json"
}
```

### Verifier API (Port 8001)

#### Create Verification Request

```
POST /verification-requests
Content-Type: application/json

{
  "presentation_definition": {
    "id": "marty_passport_verification",
    "input_descriptors": [...]
  },
  "client_id": "did:web:verifier.marty.local"
}
```

#### Handle Verification Response

```
POST /verification-response
Content-Type: application/x-www-form-urlencoded

vp_token=<presentation>&
presentation_submission=<submission>&
state=<state>
```

#### Direct Verification

```
POST /verify
Content-Type: application/json

{
  "vp_token": "<verifiable_presentation>",
  "presentation_submission": {...}
}
```

## Troubleshooting

### Common Issues

#### 1. VS Code Port Forwarding Issues

**Problem**: Cannot access services via forwarded port URLs.

**Solutions**:

- Verify ports are forwarded in VS Code Ports panel (View → Command Palette → "Ports: Focus on Ports View")
- Ensure port visibility is set to **"Public"** (not "Private")
- Check that the forwarded URLs in `.env.microsoft` match exactly what VS Code shows
- Test local access first: `curl http://localhost:8000/health`
- Restart port forwarding if needed (remove and re-add ports)

#### 2. QR Code Not Recognized

**Problem**: Microsoft Authenticator doesn't recognize the QR code.

**Solutions**:

- Ensure the QR code contains `openid-credential-offer://` URL scheme
- Verify the credential offer JSON is properly formatted
- Check that the issuer metadata endpoint is accessible via forwarded port
- Confirm the forwarded URLs are properly configured in environment variables

#### 3. HTTPS Required

**Problem**: Microsoft Authenticator requires HTTPS endpoints.

**Solutions**:

- VS Code port forwarding automatically provides HTTPS endpoints
- No additional SSL configuration needed with port forwarding
- For production, use proper SSL certificates on your domain

#### 4. Credential Not Appearing

**Problem**: Credential doesn't appear in Microsoft Authenticator after scanning.

**Solutions**:

- Check the `credentials_supported` in issuer metadata
- Verify the `jwt_vc_json` format is supported
- Ensure credential type matches what's declared in metadata
- Test the issuer metadata endpoint: `curl https://your-port-8000.preview.app.github.dev/.well-known/openid-credential-issuer`

#### 5. Verification Fails

**Problem**: Credential verification returns invalid results.

**Solutions**:

- Check signature validation in inspection system
- Verify trust chain configuration
- Ensure proper certificate management

### Debug Commands

```bash
# Check service logs
docker-compose -f docker/docker-compose.demo-microsoft-simple.yml logs issuer-api-microsoft
docker-compose -f docker/docker-compose.demo-microsoft-simple.yml logs verifier-api-microsoft

# Test issuer metadata
curl -v http://localhost:8000/.well-known/openid-credential-issuer | jq

# Test credential offer creation
curl -X POST http://localhost:8000/offer \
  -H "Content-Type: application/json" \
  -d '{"credential_type": "MartyDigitalPassport", "subject_claims": {"test": "data"}}' | jq

# Test verification endpoint
curl http://localhost:8001/presentation-definition/marty-passport | jq
```

### Network Debugging

```bash
# Check port accessibility
nc -zv localhost 8000
nc -zv localhost 8001

# Verify DNS resolution (if using custom domains)
nslookup issuer.marty.local
nslookup verifier.marty.local

# Test HTTPS connectivity (if using SSL)
openssl s_client -connect issuer.marty.local:443 -servername issuer.marty.local
```

## Security Considerations

### Production Deployment

1. **SSL/TLS**: Use proper SSL certificates, not self-signed
2. **Domain Validation**: Ensure proper domain verification for DID:web
3. **Secret Management**: Use proper secret management for signing keys
4. **Network Security**: Implement proper firewall and network policies
5. **Monitoring**: Set up comprehensive logging and monitoring

### Trust Management

1. **Certificate Validation**: Proper PKI certificate validation
2. **Revocation Checking**: Implement certificate revocation checking
3. **Trust Anchors**: Configure proper trust anchor certificates
4. **Key Rotation**: Implement key rotation policies

## Integration Testing

### Automated Tests

Run the integration test suite:

```bash
# Run Microsoft Authenticator compatibility tests
python -m pytest tests/integration/test_microsoft_authenticator.py -v

# Run OID4VCI flow tests
python -m pytest tests/integration/test_oidc4vci_flow.py -v

# Run OID4VP flow tests  
python -m pytest tests/integration/test_oidc4vp_flow.py -v
```

### Manual Test Scenarios

1. **Happy Path**: Complete issuance and verification
2. **Error Handling**: Invalid credentials, expired tokens
3. **Edge Cases**: Network failures, malformed requests
4. **Security Tests**: Invalid signatures, tampered credentials

## Performance Metrics

Expected performance benchmarks:

- **Credential Issuance**: < 2 seconds end-to-end
- **Verification**: < 1 second for signature validation
- **QR Code Generation**: < 500ms
- **Metadata Discovery**: < 100ms

## Compliance

This implementation follows these standards:

- **OpenID4VCI**: [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
- **OpenID4VP**: [OpenID for Verifiable Presentations](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
- **W3C VC Data Model**: [Verifiable Credentials Data Model](https://www.w3.org/TR/vc-data-model/)
- **Microsoft Entra**: [Microsoft Entra Verified ID](https://docs.microsoft.com/en-us/azure/active-directory/verifiable-credentials/)

## Next Steps

After successful demo completion:

1. **Production Deployment**: Deploy to production environment with proper SSL
2. **Custom Credentials**: Define custom credential types for your use case
3. **Integration**: Integrate with existing identity systems
4. **Monitoring**: Set up comprehensive monitoring and logging
5. **Scale Testing**: Perform load testing for production deployment

## Support

For issues and questions:

1. Check the troubleshooting section above
2. Review service logs for detailed error information
3. Consult the Marty documentation
4. Open GitHub issues for bugs or feature requests

---

**Demo Status**: ✅ Ready for testing with Microsoft Authenticator

**Last Updated**: October 2025
