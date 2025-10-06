"""
Standalone Microsoft Authenticator Demo Issuer API

This is a simplified implementation for demonstrating OID4VCI with Microsoft Authenticator.
It doesn't depend on gRPC services and provides a self-contained credential issuance flow.
"""

import os
import base64
import uuid
import qrcode
from io import BytesIO
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

app = FastAPI(title="Microsoft Demo Issuer API", version="1.0.0")

# Configure CORS for Microsoft Authenticator
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify allowed origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration
ISSUER_BASE_URL = os.getenv("ISSUER_BASE_URL", "https://localhost:8000")
CREDENTIAL_ISSUER_DID = os.getenv("CREDENTIAL_ISSUER_DID", "did:web:localhost%3A8000")

# In-memory storage for demo purposes
credential_offers: Dict[str, Dict[str, Any]] = {}
issued_credentials: Dict[str, Dict[str, Any]] = {}
issuance_requests: Dict[str, Dict[str, Any]] = {}


class CredentialRequest(BaseModel):
    type: str
    holder_did: Optional[str] = None
    subject_data: Dict[str, Any]


class TokenRequest(BaseModel):
    grant_type: str
    code: Optional[str] = None
    pre_authorized_code: Optional[str] = None


@app.get("/health")
async def health():
    """Health check endpoint for Kubernetes."""
    return {"status": "healthy", "service": "issuer-api"}


@app.get("/")
async def root():
    """Root endpoint with API information."""
    return {
        "name": "Microsoft Demo Issuer API",
        "version": "1.0.0",
        "issuer": CREDENTIAL_ISSUER_DID,
        "base_url": ISSUER_BASE_URL,
        "endpoints": {
            "metadata": "/.well-known/openid_credential_issuer",
            "token": "/token",
            "credential": "/credential",
            "offers": "/credential-offer",
            "demo": "/demo"
        },
        "status": "operational"
    }


@app.get("/demo")
async def credential_demo():
    """Interactive demo page for credential issuance with Microsoft Authenticator."""
    
    # Create verifier URL by replacing port 8000 with 8001
    verifier_url = ISSUER_BASE_URL.replace(":8000", ":8001")
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Microsoft Authenticator Credential Demo</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                max-width: 800px;
                margin: 0 auto;
                padding: 20px;
                background-color: #f5f5f5;
            }}
            .container {{
                background: white;
                padding: 30px;
                border-radius: 10px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }}
            h1 {{
                color: #0078d4;
                text-align: center;
                margin-bottom: 10px;
            }}
            .subtitle {{
                text-align: center;
                color: #666;
                margin-bottom: 30px;
            }}
            .step {{
                background: #f8f9fa;
                padding: 20px;
                margin: 20px 0;
                border-radius: 8px;
                border-left: 4px solid #0078d4;
            }}
            .step h3 {{
                margin-top: 0;
                color: #0078d4;
            }}
            .button {{
                background: #0078d4;
                color: white;
                border: none;
                padding: 12px 24px;
                border-radius: 5px;
                cursor: pointer;
                font-size: 16px;
                margin: 10px 0;
            }}
            .button:hover {{
                background: #106ebe;
            }}
            .qr-container {{
                text-align: center;
                margin: 20px 0;
                padding: 20px;
                background: white;
                border: 2px dashed #ddd;
                border-radius: 8px;
            }}
            .credential-offer {{
                background: #e7f3ff;
                padding: 15px;
                border-radius: 5px;
                margin: 15px 0;
                font-family: monospace;
                word-break: break-all;
                font-size: 12px;
            }}
            .status {{
                padding: 10px;
                border-radius: 5px;
                margin: 10px 0;
            }}
            .success {{ background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }}
            .info {{ background: #d1ecf1; color: #0c5460; border: 1px solid #bee5eb; }}
            .warning {{ background: #fff3cd; color: #856404; border: 1px solid #ffeaa7; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🆔 Microsoft Authenticator Demo</h1>
            <p class="subtitle">Issue and store verifiable credentials in Microsoft Authenticator</p>
            
            <div class="step">
                <h3>📱 Step 1: Ensure Microsoft Authenticator is Ready</h3>
                <p>Make sure you have Microsoft Authenticator installed on your mobile device and set up.</p>
            </div>
            
            <div class="step">
                <h3>🎫 Step 2: Create a Credential Offer</h3>
                <p>Click the button below to generate a credential offer for an Employee Credential:</p>
                <button onclick="createCredentialOffer()" class="button">Generate QR Code</button>
                <div id="offer-result"></div>
            </div>
            
            <div class="step">
                <h3>📱 Step 3: Scan QR Code with Microsoft Authenticator</h3>
                <p>Use Microsoft Authenticator to scan the QR code below:</p>
                <div id="qr-container" class="qr-container" style="display: none;">
                    <img id="qr-image" alt="Credential Offer QR Code" style="display:none; width:256px; height:256px;" />
                    <div id="manual-fallback" style="display:none;"></div>
                    <p id="qr-instructions" style="display:none;"><strong>Scan this QR code with Microsoft Authenticator</strong></p>
                </div>
            </div>
            
            <div class="step">
                <h3>✅ Step 4: Complete the Flow</h3>
                <p>Follow the prompts in Microsoft Authenticator to complete the credential issuance.</p>
                <p>Once complete, you can proceed to verification:</p>
                <a href="{verifier_url}/verification-demo" class="button" style="text-decoration: none; display: inline-block;">Go to Verification Demo</a>
            </div>
        </div>
        
        <script>
            const isMobile = /android|iphone|ipad|ipod/i.test(navigator.userAgent);
            let currentOffer = null;

            async function createCredentialOffer() {{
                try {{
                    // Use default demo values since this is the simplified demo
                    const credentialType = 'EmployeeCredential';
                    const holderName = 'Demo Employee';
                    const holderEmail = 'demo.employee@example.com';
                    const issuerName = 'Marty Document Services';
                    const format = 'microsoft'; // Default to Microsoft format
                    
                    const response = await fetch('/credential-offer', {{
                        method: 'POST',
                        headers: {{
                            'Content-Type': 'application/json',
                        }},
                        body: JSON.stringify({{
                            type: credentialType,
                            subject_data: {{
                                name: holderName,
                                email: holderEmail,
                                issuer: issuerName,
                                employeeId: 'EMP-' + Math.random().toString(36).substr(2, 9).toUpperCase(),
                                department: 'Technology',
                                position: 'Software Engineer'
                            }},
                            format: format
                        }}),
                    }});
                    if (!response.ok) {{
                        throw new Error('Failed to create credential offer');
                    }}
                    const offer = await response.json();
                    currentOffer = offer;
                    displayOffer(offer);
                    handleOfferDisplay(offer);
                }} catch (error) {{
                    document.getElementById('offer-result').innerHTML = `
                        <div class="status warning">
                            <strong>Error:</strong> ${{error.message}}
                        </div>
                    `;
                }}
            }}

            function displayOffer(offer) {{
                document.getElementById('offer-result').innerHTML = `
                    <div class="status success">
                        <strong>✅ Credential Offer Created!</strong><br>
                        Offer ID: <code>${{offer.offer_id}}</code>
                    </div>
                    <div class="credential-offer">
                        <strong>Credential Offer URI:</strong><br>
                        ${{offer.credential_offer_uri}}
                    </div>
                `;
            }}

            function handleOfferDisplay(offer) {{
                const qrContainer = document.getElementById('qr-container');
                const img = document.getElementById('qr-image');
                const manual = document.getElementById('manual-fallback');
                const qrInstructions = document.getElementById('qr-instructions');
                manual.innerHTML = '';

                if (offer.qr_code && !isMobile) {{
                    // Desktop: Show QR code
                    img.src = `data:image/png;base64,${{offer.qr_code}}`;
                    img.style.display = 'block';
                    qrInstructions.style.display = 'block';
                    manual.style.display = 'none';
                }} else {{
                    // Mobile: Show manual entry options
                    manual.style.display = 'block';
                    manual.innerHTML = getMobileInstructions(offer);
                    img.style.display = 'none';
                    qrInstructions.style.display = 'none';
                }}
                
                qrContainer.style.display = 'block';
            }}

            function getMobileInstructions(offer) {{
                return `
                    <div style="border: 2px dashed #ccc; padding: 16px; text-align: left;">
                        <h4>📱 Mobile Detected</h4>
                        <p>Choose your preferred credential format:</p>
                        <div style="margin: 10px 0; padding: 10px; background: #e3f2fd; border-radius: 5px;">
                            <strong>Microsoft Authenticator URI:</strong><br/>
                            <code style="font-size: 11px; word-break: break-all;">${{offer.credential_offer_uri}}</code><br/>
                            <button onclick="copyToClipboard('${{offer.credential_offer_uri}}')" class="button" style="padding:8px 12px; font-size:14px; margin:4px;">Copy Microsoft URI</button>
                        </div>
                        <p style="margin-top: 15px; font-size: 14px; color: #666;">
                            <strong>Instructions:</strong> Copy the URI, then open Microsoft Authenticator → '+' → 'Work or school account' → 'Scan QR code' → 'Enter code manually' and paste the URI.
                        </p>
                    </div>`;
            }}

            function getManualFallbackHtml(uri) {{
                return `
                    <div style="border: 2px dashed #ccc; padding: 16px; text-align: center;">
                        <h4>📱 Manual Setup Required</h4>
                        <p>Copy this credential offer URI to Microsoft Authenticator:</p>
                        <div style=\"background: #f8f9fa; padding: 10px; border-radius: 5px; font-family: monospace; word-break: break-all; font-size: 12px; margin: 10px 0;\">${{uri}}</div>
                        <button onclick=\"copyToClipboard('${{uri}}')\" style=\"background: #0078d4; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer;\">Copy to Clipboard</button>
                        <p style="margin-top: 10px; font-size: 14px; color: #666;">In Microsoft Authenticator: '+' → 'Work or school account' → 'Scan QR code' → 'Enter code manually'</p>
                    </div>`;
            }}

            function copyToClipboard(text, showAlert = true) {{
                navigator.clipboard.writeText(text).then(() => {{
                    if (showAlert) alert('Credential offer URI copied to clipboard!');
                }}).catch(() => {{
                    const textArea = document.createElement('textarea');
                    textArea.value = text;
                    document.body.appendChild(textArea);
                    textArea.select();
                    document.execCommand('copy');
                    document.body.removeChild(textArea);
                    if (showAlert) alert('Credential offer URI copied to clipboard!');
                }});
            }}
        </script>
    </body>
    </html>
    """
    
    return HTMLResponse(content=html_content)


@app.get("/.well-known/openid_credential_issuer")
async def openid_credential_issuer_metadata():
    """OpenID4VCI credential issuer metadata endpoint for Microsoft Authenticator."""
    return {
        "credential_issuer": ISSUER_BASE_URL,
        "credential_endpoint": f"{ISSUER_BASE_URL}/credential",
        "token_endpoint": f"{ISSUER_BASE_URL}/token",
        "authorization_endpoint": f"{ISSUER_BASE_URL}/authorize",
        "credentials_supported": [
            {
                "format": "jwt_vc_json",
                "types": ["VerifiableCredential", "EmployeeCredential"],
                "id": "EmployeeCredential",
                "display": [
                    {
                        "name": "Employee Credential",
                        "locale": "en-US",
                        "logo": {
                            "url": f"{ISSUER_BASE_URL}/static/logo.png"
                        },
                        "background_color": "#0066CC",
                        "text_color": "#FFFFFF"
                    }
                ],
                "credential_definition": {
                    "type": ["VerifiableCredential", "EmployeeCredential"]
                }
            }
        ],
        "display": [
            {
                "name": "Marty Document Services",
                "locale": "en-US",
                "logo": {
                    "url": f"{ISSUER_BASE_URL}/static/issuer-logo.png"
                }
            }
        ]
    }


@app.get("/authorize")
async def authorize():
    """OAuth 2.0 authorization endpoint (placeholder for demo)."""
    return {
        "credential_issuer": ISSUER_BASE_URL,
        "authorization_endpoint": f"{ISSUER_BASE_URL}/authorize",
        "message": "Authorization flow not implemented in this demo - using pre-authorized codes instead"
    }


@app.get("/issuance-requests/{request_id}")
async def get_issuance_request(request_id: str):
    """OpenID4VCI compliant authorization request endpoint for Microsoft Authenticator."""
    
    if request_id not in issuance_requests:
        raise HTTPException(status_code=404, detail="Issuance request not found")
    
    request_data = issuance_requests[request_id]
    offer_data = request_data["offer_data"]
    
    # Return proper OpenID4VCI Authorization Request format
    # This follows the OpenID for Verifiable Credential Issuance specification
    return {
        "client_id": CREDENTIAL_ISSUER_DID,
        "client_id_scheme": "did",
        "response_type": "code",
        "redirect_uri": f"{ISSUER_BASE_URL}/issuance-callback",
        "scope": "openid",
        "state": request_id,
        "nonce": str(uuid.uuid4()),
        "code_challenge": "dummy_code_challenge_for_demo",
        "code_challenge_method": "S256",
        "client_metadata": {
            "vp_formats": {
                "jwt_vp": {
                    "alg": ["ES256"]
                },
                "ldp_vp": {
                    "proof_type": ["Ed25519Signature2018"]
                }
            },
            "client_name": "Marty Document Services",
            "logo_uri": f"{ISSUER_BASE_URL}/static/logo.png",
            "client_purpose": "To issue verifiable employee credentials"
        },
        "presentation_definition": {
            "id": str(uuid.uuid4()),
            "input_descriptors": [],
            "purpose": "No presentation required for issuance"
        },
        "authorization_details": [
            {
                "type": "openid_credential",
                "credential_configuration_id": offer_data["subject_data"].get("type", "EmployeeCredential"),
                "format": "vc+sd-jwt",
                "credential_definition": {
                    "type": [
                        "VerifiableCredential",
                        offer_data["subject_data"].get("type", "EmployeeCredential")
                    ],
                    "credentialSubject": {
                        "given_name": offer_data["subject_data"].get("name", "Demo User").split()[0],
                        "family_name": offer_data["subject_data"].get("name", "Demo User").split()[-1] if " " in offer_data["subject_data"].get("name", "Demo User") else "",
                        "email": offer_data["subject_data"].get("email", "demo@example.com"),
                        "jobTitle": offer_data["subject_data"].get("position", "Software Engineer"),
                        "department": offer_data["subject_data"].get("department", "Technology"),
                        "employeeId": offer_data["subject_data"].get("employeeId", f"EMP-{str(uuid.uuid4())[:8].upper()}")
                    }
                }
            }
        ]
    }


@app.post("/api/issuer/issuanceCallback")
async def issuance_callback_v2(callback_data: dict):  # noqa: ARG001
    """Handle callbacks from Microsoft Authenticator during issuance (v2 endpoint)."""
    return {"status": "received"}


@app.post("/issuance-callback")
async def issuance_callback(callback_data: dict):  # noqa: ARG001
    """Handle callbacks from Microsoft Authenticator during issuance."""
    return {"status": "received"}


@app.post("/credential-offer")
async def create_credential_offer(request: CredentialRequest):
    """Create a credential offer with Microsoft Authenticator compatibility."""
    offer_id = str(uuid.uuid4())
    
    # Create the credential offer data
    offer_data = {
        "offer_id": offer_id,
        "credential_issuer": CREDENTIAL_ISSUER_DID,
        "credential_configuration_ids": [request.type],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": f"pre_auth_{offer_id}",
                "user_pin_required": False
            }
        },
        "subject_data": request.subject_data,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": datetime.now(timezone.utc).replace(hour=23, minute=59, second=59).isoformat()
    }
    
    # Store the offer
    credential_offers[offer_id] = offer_data
    
    # Create corresponding issuance request for Microsoft format compatibility
    issuance_requests[offer_id] = {
        "offer_data": offer_data,
        "request_id": offer_id,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    
    # Determine format to generate
    format_type = getattr(request, 'format', 'microsoft')  # Default to Microsoft format
    
    # Generate URIs based on requested format
    result = {"offer_id": offer_id}
    
    # Use Microsoft Entra ID format for Microsoft Authenticator compatibility
    microsoft_uri = f"openid-vc://?request_uri={ISSUER_BASE_URL}/issuance-requests/{offer_id}"
    result["credential_offer_uri"] = microsoft_uri
    
    # Also create a standard OpenID4VCI format for compatibility
    standard_uri = f"openid-credential-offer://?credential_offer_uri={ISSUER_BASE_URL}/offers/{offer_id}"
    result["openid4vci_uri"] = standard_uri
    
    # Microsoft format requires a request_uri endpoint that returns the issuance request
    # The /issuance-requests/{offer_id} endpoint will return the Microsoft-compatible request
    
    # Generate QR code for the Microsoft-compatible URI
    primary_uri = result.get("credential_offer_uri")  # This is the Microsoft format URI
    if primary_uri:
        try:
            # Create QR code
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(primary_uri)
            qr.make(fit=True)
            
            # Generate QR code image
            qr_image = qr.make_image(fill_color="black", back_color="white")
            
            # Convert to base64
            img_buffer = BytesIO()
            qr_image.save(img_buffer, 'PNG')
            img_buffer.seek(0)
            qr_base64 = base64.b64encode(img_buffer.getvalue()).decode()
            
            result["qr_code"] = qr_base64
            result["qr_size"] = str(len(qr_base64))
            
        except Exception as e:  # noqa: BLE001
            print(f"QR code generation error: {e}")
            result["qr_error"] = str(e)
    
    return result


@app.get("/offers/{offer_id}")
async def get_credential_offer(offer_id: str):
    """Get a specific credential offer by ID (OpenID4VCI standard endpoint)."""
    if offer_id not in credential_offers:
        raise HTTPException(status_code=404, detail="Credential offer not found")
    
    return credential_offers[offer_id]


@app.post("/token")
async def token_endpoint(request: TokenRequest):
    """OAuth 2.0 token endpoint for pre-authorized code flow."""
    
    if request.grant_type != "urn:ietf:params:oauth:grant-type:pre-authorized_code":
        raise HTTPException(
            status_code=400,
            detail="unsupported_grant_type"
        )
    
    if not request.pre_authorized_code:
        raise HTTPException(
            status_code=400,
            detail="invalid_request"
        )
    
    # Find the corresponding offer
    offer_id = None
    for oid, offer_data in credential_offers.items():
        if offer_data["pre_authorized_code"] == request.pre_authorized_code:
            offer_id = oid
            break
    
    if not offer_id:
        raise HTTPException(
            status_code=400,
            detail="invalid_grant"
        )
    
    # Generate access token
    access_token = str(uuid.uuid4())
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": 3600,
        "c_nonce": str(uuid.uuid4()),
        "c_nonce_expires_in": 3600
    }


@app.post("/credential")
async def credential_endpoint(request: Request):
    """Credential endpoint for issuing verifiable credentials."""
    
    # In a real implementation, verify the access token
    # For demo purposes, we'll proceed without strict verification
    
    try:
        data = await request.json()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail="invalid_request") from exc
    
    credential_format = data.get("format", "jwt_vc_json")
    types = data.get("types", ["VerifiableCredential"])
    
    # Generate a mock credential
    credential_id = str(uuid.uuid4())
    
    # Find the original credential request (simplified lookup)
    credential_request = None
    for offer_data in credential_offers.values():
        if offer_data["status"] == "pending":
            credential_request = offer_data["credential_request"]
            offer_data["status"] = "completed"
            break
    
    if not credential_request:
        # Generate default data if no pending request found
        credential_request = {
            "type": "EmployeeCredential",
            "subject_data": {
                "employeeId": "EMP-DEMO123",
                "name": "Demo Employee",
                "department": "Technology",
                "position": "Software Engineer"
            }
        }
    
    # Create the verifiable credential
    credential = {
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://www.w3.org/2018/credentials/examples/v1"
        ],
        "id": f"did:example:{uuid.uuid4()}",
        "type": types,
        "issuer": {
            "id": CREDENTIAL_ISSUER_DID,
            "name": "Marty Document Services"
        },
        "issuanceDate": datetime.now(timezone.utc).isoformat(),
        "credentialSubject": {
            "id": f"did:example:{uuid.uuid4()}",
            **credential_request["subject_data"]
        }
    }
    
    # Store the issued credential
    issued_credentials[credential_id] = {
        "credential": credential,
        "format": credential_format,
        "issued_at": datetime.now(timezone.utc).isoformat()
    }
    
    return {
        "credential": credential,
        "format": credential_format
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)