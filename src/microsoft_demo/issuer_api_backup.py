"""
Standalone Microsoft Authenticator Demo Issuer API

This is a simplified implementation for demonstrating OID4VCI with Microsoft Authenticator.
It doesn't depend on gRPC services and provides a self-contained credential issuance flow.
"""

import json
import uuid
import os
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse
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


class CredentialRequest(BaseModel):
    type: str
    holder_did: Optional[str] = None
    subject_data: Dict[str, Any]


class TokenRequest(BaseModel):
    grant_type: str
    code: Optional[str] = None
    pre_authorized_code: Optional[str] = None


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
                <button class="button" onclick="createCredentialOffer()">Create Employee Credential Offer</button>
                <div id="offer-result"></div>
            </div>
            
            <div class="step">
                <h3>📱 Step 3: Scan QR Code with Microsoft Authenticator</h3>
                <p>Use Microsoft Authenticator to scan the QR code below:</p>
                <div id="qr-container" class="qr-container" style="display: none;">
                    <div id="qr-code"></div>
                    <p>Scan this QR code with Microsoft Authenticator</p>
                </div>
            </div>
            
            <div class="step">
                <h3>✅ Step 4: Complete the Flow</h3>
                <p>Follow the prompts in Microsoft Authenticator to complete the credential issuance.</p>
                <p>Once complete, you can proceed to verification:</p>
                <a href="{ISSUER_BASE_URL.replace(':8000', ':8001')}/verification-demo" class="button" style="text-decoration: none; display: inline-block;">Go to Verification Demo</a>
            </div>
        </div>
        
        <script src="https://cdn.jsdelivr.net/npm/qrcode@1.5.3/build/qrcode.min.js"></script>
        <script>
            let currentOffer = null;
            
            async function createCredentialOffer() {{
                try {{
                    const response = await fetch('/credential-offer', {{
                        method: 'POST',
                        headers: {{
                            'Content-Type': 'application/json'
                        }},
                        body: JSON.stringify({{
                            type: 'EmployeeCredential',
                            subject_data: {{
                                employeeId: 'EMP-' + Math.random().toString(36).substr(2, 9).toUpperCase(),
                                name: 'Demo Employee',
                                department: 'Technology',
                                position: 'Software Engineer',
                                issueDate: new Date().toISOString().split('T')[0]
                            }}
                        }})
                    }});
                    
                    if (!response.ok) {{
                        throw new Error('Failed to create credential offer');
                    }}
                    
                    const offer = await response.json();
                    currentOffer = offer;
                    
                    displayOffer(offer);
                    generateQRCode(offer.credential_offer_uri);
                    
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
            
            function generateQRCode(uri) {{
                const qrContainer = document.getElementById('qr-container');
                const qrCodeDiv = document.getElementById('qr-code');
                
                // Clear previous QR code
                qrCodeDiv.innerHTML = '';
                
                // Generate new QR code
                QRCode.toCanvas(qrCodeDiv, uri, {{
                    width: 256,
                    margin: 2,
                    color: {{
                        dark: '#0078d4',
                        light: '#ffffff'
                    }}
                }}, function (error) {{
                    if (error) {{
                        qrCodeDiv.innerHTML = '<p style="color: red;">Error generating QR code: ' + error + '</p>';
                    } else {{
                        qrContainer.style.display = 'block';
                    }}
                }});
            }}
        </script>
    </body>
    </html>
    """
    
    return HTMLResponse(content=html_content)d
import os
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse
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


@app.get("/.well-known/openid_credential_issuer")
async def credential_issuer_metadata():
    """OpenID for Verifiable Credentials Issuer metadata."""
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


@app.post("/credential-offer")
async def create_credential_offer(request: CredentialRequest):
    """Create a credential offer for pre-authorized flow."""
    
    # Generate offer ID and pre-authorized code
    offer_id = str(uuid.uuid4())
    pre_auth_code = str(uuid.uuid4())
    
    # Create credential offer
    offer = {
        "credential_issuer": ISSUER_BASE_URL,
        "credentials": [
            {
                "format": "jwt_vc_json",
                "types": ["VerifiableCredential", "EmployeeCredential"]
            }
        ],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": pre_auth_code,
                "user_pin_required": False
            }
        }
    }
    
    # Store offer details
    credential_offers[offer_id] = {
        "offer": offer,
        "pre_auth_code": pre_auth_code,
        "credential_type": request.type,
        "subject_data": request.subject_data,
        "holder_did": request.holder_did,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    
    # Generate credential offer URI for Microsoft Authenticator
    offer_uri = f"openid-credential-offer://?credential_offer={json.dumps(offer)}"
    
    return {
        "offer_id": offer_id,
        "credential_offer_uri": offer_uri,
        "credential_offer": offer,
        "pre_authorized_code": pre_auth_code
    }


@app.post("/token")
async def token_endpoint(request: TokenRequest):
    """OAuth 2.0 token endpoint for credential issuance."""
    
    if request.grant_type != "urn:ietf:params:oauth:grant-type:pre-authorized_code":
        raise HTTPException(
            status_code=400,
            detail="unsupported_grant_type"
        )
    
    # Find the credential offer by pre-authorized code
    offer_data = None
    for offer_id, data in credential_offers.items():
        if data["pre_auth_code"] == request.pre_authorized_code:
            offer_data = data
            break
    
    if not offer_data:
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
        "c_nonce_expires_in": 300
    }


@app.post("/credential")
async def credential_endpoint(request: Request):
    """Credential endpoint for issuing verifiable credentials."""
    
    # Get the authorization header
    auth_header = request.headers.get("authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="invalid_token"
        )
    
    access_token = auth_header[7:]  # Remove "Bearer " prefix
    
    # In a real implementation, validate the access token
    # For demo purposes, we'll generate a mock credential
    
    # Create a simple JWT VC JSON credential
    credential_id = str(uuid.uuid4())
    issued_at = datetime.now(timezone.utc)
    expires_at = issued_at + timedelta(days=365)
    
    credential = {
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://www.w3.org/2018/credentials/examples/v1"
        ],
        "id": f"urn:uuid:{credential_id}",
        "type": ["VerifiableCredential", "EmployeeCredential"],
        "issuer": {
            "id": CREDENTIAL_ISSUER_DID,
            "name": "Marty Document Services"
        },
        "issuanceDate": issued_at.isoformat(),
        "expirationDate": expires_at.isoformat(),
        "credentialSubject": {
            "id": f"did:example:{uuid.uuid4()}",
            "type": "Employee",
            "name": "John Doe",
            "jobTitle": "Software Developer",
            "department": "Engineering",
            "employeeId": "EMP001",
            "email": "john.doe@example.com"
        }
    }
    
    # Store issued credential
    issued_credentials[credential_id] = {
        "credential": credential,
        "access_token": access_token,
        "issued_at": issued_at.isoformat()
    }
    
    return {
        "format": "jwt_vc_json",
        "credential": credential
    }


@app.get("/credentials/{credential_id}")
async def get_credential(credential_id: str):
    """Retrieve an issued credential by ID."""
    
    if credential_id not in issued_credentials:
        raise HTTPException(
            status_code=404,
            detail="credential_not_found"
        )
    
    return issued_credentials[credential_id]["credential"]


@app.get("/")
async def root():
    """Root endpoint with issuer information."""
    return {
        "name": "Microsoft Demo Issuer API",
        "version": "1.0.0",
        "issuer": CREDENTIAL_ISSUER_DID,
        "base_url": ISSUER_BASE_URL,
        "endpoints": {
            "metadata": "/.well-known/openid_credential_issuer",
            "token": "/token",
            "credential": "/credential",
            "offers": "/credential-offer"
        },
        "status": "operational"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)