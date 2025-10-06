"""
Standalone Microsoft Authenticator Demo Verifier API

This is a simplified implementation for demonstrating OID4VP with Microsoft Authenticator.
It provides a self-contained verification flow for JWT VC JSON credentials.
"""

import json
import uuid
import os
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional, List

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse
from pydantic import BaseModel

app = FastAPI(title="Microsoft Demo Verifier API", version="1.0.0")

# Configure CORS for Microsoft Authenticator
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify allowed origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration
VERIFIER_BASE_URL = os.getenv("VERIFIER_BASE_URL", "https://localhost:8001")
ISSUER_BASE_URL = os.getenv("ISSUER_BASE_URL", "https://localhost:8000")

# In-memory storage for demo purposes
verification_requests: Dict[str, Dict[str, Any]] = {}
verification_results: Dict[str, Dict[str, Any]] = {}


class PresentationRequest(BaseModel):
    presentation_definition: Optional[Dict[str, Any]] = None
    challenge: Optional[str] = None
    domain: Optional[str] = None


class PresentationSubmission(BaseModel):
    vp_token: str
    presentation_submission: Dict[str, Any]
    state: Optional[str] = None


@app.get("/health")
async def health():
    """Health check endpoint for Kubernetes."""
    return {"status": "healthy", "service": "verifier-api"}


@app.post("/presentation-request")
async def create_presentation_request(request: PresentationRequest):
    """Create a presentation request for OID4VP flow."""
    
    # Generate request ID and challenge
    request_id = str(uuid.uuid4())
    challenge = request.challenge or str(uuid.uuid4())
    
    # Default presentation definition for employee credentials
    if not request.presentation_definition:
        presentation_definition = {
            "id": "employee_credential_presentation",
            "purpose": "Verify employee credentials",
            "input_descriptors": [
                {
                    "id": "employee_credential",
                    "name": "Employee Credential",
                    "purpose": "Verify employment status",
                    "constraints": {
                        "fields": [
                            {
                                "path": ["$.type"],
                                "filter": {
                                    "type": "array",
                                    "contains": {
                                        "const": "EmployeeCredential"
                                    }
                                }
                            },
                            {
                                "path": ["$.credentialSubject.employeeId"],
                                "filter": {
                                    "type": "string"
                                }
                            }
                        ]
                    }
                }
            ]
        }
    else:
        presentation_definition = request.presentation_definition
    
    # Store verification request
    verification_requests[request_id] = {
        "presentation_definition": presentation_definition,
        "challenge": challenge,
        "domain": request.domain or VERIFIER_BASE_URL,
        "status": "pending",
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    
    # Generate authorization request URI for Microsoft Authenticator
    auth_request = {
        "client_id": VERIFIER_BASE_URL,
        "response_type": "vp_token",
        "response_mode": "direct_post",
        "presentation_definition": presentation_definition,
        "nonce": challenge,
        "state": request_id,
        "redirect_uri": f"{VERIFIER_BASE_URL}/presentation-response"
    }
    
    # Create the OpenID4VP authorization request URI
    from urllib.parse import urlencode
    params = {
        "client_id": auth_request["client_id"],
        "response_type": auth_request["response_type"],
        "response_mode": auth_request["response_mode"],
        "presentation_definition": json.dumps(auth_request["presentation_definition"]),
        "nonce": auth_request["nonce"],
        "state": auth_request["state"],
        "redirect_uri": auth_request["redirect_uri"]
    }
    
    auth_request_uri = f"openid4vp://authorize?{urlencode(params)}"
    
    return {
        "request_id": request_id,
        "authorization_request_uri": auth_request_uri,
        "authorization_request": auth_request,
        "challenge": challenge,
        "status_endpoint": f"{VERIFIER_BASE_URL}/verification-status/{request_id}"
    }


@app.post("/presentation-response")
async def handle_presentation_response(request: Request):
    """Handle presentation response from Microsoft Authenticator."""
    
    # Parse form data or JSON body
    content_type = request.headers.get("content-type", "")
    
    if "application/x-www-form-urlencoded" in content_type:
        form_data = await request.form()
        data = dict(form_data)
    else:
        data = await request.json()
    
    state = data.get("state")
    vp_token = data.get("vp_token")
    presentation_submission = data.get("presentation_submission")
    
    # Ensure state is a string
    if not isinstance(state, str) or state not in verification_requests:
        raise HTTPException(
            status_code=400,
            detail="invalid_request"
        )
    
    if not vp_token:
        raise HTTPException(
            status_code=400,
            detail="missing_vp_token"
        )
    
    # In a real implementation, verify the VP token signature and content
    # For demo purposes, we'll assume it's valid and extract basic info
    
    try:
        # Simple parsing assuming it's a JWT VC JSON format
        verification_result = {
            "status": "valid",
            "vp_token": vp_token,
            "presentation_submission": presentation_submission,
            "verified_at": datetime.now(timezone.utc).isoformat(),
            "credential_data": "Mock credential data extracted from VP token"
        }
        
        # Update verification request status
        verification_requests[state]["status"] = "completed"
        verification_requests[state]["completed_at"] = datetime.now(timezone.utc).isoformat()
        
        # Store verification result
        verification_results[state] = verification_result
        
        return JSONResponse(
            status_code=200,
            content={"status": "success", "message": "Presentation verified successfully"}
        )
        
    except Exception as e:
        verification_result = {
            "status": "invalid",
            "error": str(e),
            "verified_at": datetime.now(timezone.utc).isoformat()
        }
        
        verification_requests[state]["status"] = "failed"
        verification_results[state] = verification_result
        
        raise HTTPException(
            status_code=400,
            detail="invalid_presentation"
        )


@app.get("/verification-status/{request_id}")
async def get_verification_status(request_id: str):
    """Get the status of a verification request."""
    
    if request_id not in verification_requests:
        raise HTTPException(
            status_code=404,
            detail="request_not_found"
        )
    
    request_data = verification_requests[request_id]
    response = {
        "request_id": request_id,
        "status": request_data["status"],
        "created_at": request_data["created_at"]
    }
    
    if request_id in verification_results:
        response["verification_result"] = verification_results[request_id]
    
    if "completed_at" in request_data:
        response["completed_at"] = request_data["completed_at"]
    
    return response


@app.get("/verification-demo")
async def verification_demo():
    """Interactive HTML demo page for testing verification with QR codes."""
    
    # Use the correct issuer URL from environment variable
    issuer_url = ISSUER_BASE_URL
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Microsoft Authenticator Verification Demo</title>
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
            .button.secondary {{
                background: #6c757d;
            }}
            .button.secondary:hover {{
                background: #545b62;
            }}
            .qr-container {{
                text-align: center;
                margin: 20px 0;
                padding: 20px;
                background: white;
                border: 2px dashed #ddd;
                border-radius: 8px;
            }}
            .verification-uri {{
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
            .pending {{ background: #fff3cd; color: #856404; border: 1px solid #ffeaa7; }}
            .completed {{ background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔍 Microsoft Authenticator Verification Demo</h1>
            <p class="subtitle">Verify credentials stored in Microsoft Authenticator</p>
            
            <div class="step">
                <h3>📱 Step 1: Ensure You Have a Credential</h3>
                <p>You need a verifiable credential stored in Microsoft Authenticator before verification.</p>
                <p>If you don't have one yet, issue a credential first:</p>
                <a href="{issuer_url}/demo" class="button" style="text-decoration: none; display: inline-block;">Go to Credential Issuance Demo</a>
            </div>
            
            <div class="step">
                <h3>🔐 Step 2: Start Verification Request</h3>
                <p>Click the button below to create a verification request for Employee Credentials:</p>
                <button class="button" onclick="startVerification()">Start Verification Request</button>
                <div id="verification-result"></div>
            </div>
            
            <div class="step" id="qr-step" style="display: none;">
                <h3>📱 Step 3: Scan QR Code with Microsoft Authenticator</h3>
                <p>Use Microsoft Authenticator to scan the QR code below to present your credential:</p>
                <div id="qr-container" class="qr-container">
                    <div id="qr-code"></div>
                    <p><strong>Scan this QR code with Microsoft Authenticator</strong></p>
                </div>
            </div>
            
            <div class="step" id="status-step" style="display: none;">
                <h3>✅ Step 4: Check Verification Status</h3>
                <p>Monitor the verification status:</p>
                <button class="button secondary" onclick="checkStatus()">Check Status</button>
                <div id="status-result"></div>
            </div>
        </div>
        
        <script src="https://cdn.jsdelivr.net/npm/qrcode@1.5.3/build/qrcode.min.js"></script>
        <script>
            let currentRequestId = null;
            
            async function startVerification() {{
                try {{
                    const response = await fetch('/presentation-request', {{
                        method: 'POST',
                        headers: {{ 'Content-Type': 'application/json' }},
                        body: JSON.stringify({{
                            challenge: 'demo-challenge-' + Math.random().toString(36).substr(2, 9)
                        }})
                    }});
                    
                    if (!response.ok) {{
                        throw new Error('Failed to create verification request');
                    }}
                    
                    const data = await response.json();
                    currentRequestId = data.request_id;
                    
                    displayVerificationRequest(data);
                    generateQRCode(data.authorization_request_uri);
                    
                    // Show additional steps
                    document.getElementById('qr-step').style.display = 'block';
                    document.getElementById('status-step').style.display = 'block';
                    
                }} catch (error) {{
                    document.getElementById('verification-result').innerHTML = `
                        <div class="status warning">
                            <strong>Error:</strong> ${{error.message}}
                        </div>
                    `;
                }}
            }}
            
            function displayVerificationRequest(data) {{
                document.getElementById('verification-result').innerHTML = `
                    <div class="status success">
                        <strong>✅ Verification Request Created!</strong><br>
                        Request ID: <code>${{data.request_id}}</code>
                    </div>
                    <div class="verification-uri">
                        <strong>Verification URI:</strong><br>
                        ${{data.authorization_request_uri}}
                    </div>
                `;
            }}
            
            function generateQRCode(uri) {{
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
                    }}
                }});
            }}
            
            async function checkStatus() {{
                if (!currentRequestId) {{
                    alert('No verification request active');
                    return;
                }}
                
                try {{
                    const response = await fetch(`/verification-status/${{currentRequestId}}`);
                    const data = await response.json();
                    
                    let statusClass = 'info';
                    let statusIcon = '🔄';
                    
                    if (data.status === 'completed') {{
                        statusClass = 'completed';
                        statusIcon = '✅';
                    }} else if (data.status === 'pending') {{
                        statusClass = 'pending';
                        statusIcon = '⏳';
                    }}
                    
                    document.getElementById('status-result').innerHTML = `
                        <div class="status ${{statusClass}}">
                            <strong>${{statusIcon}} Status: ${{data.status.toUpperCase()}}</strong>
                        </div>
                        <div style="background: #f8f9fa; padding: 15px; border-radius: 5px; margin-top: 10px;">
                            <strong>Full Response:</strong>
                            <pre style="margin: 10px 0; font-size: 12px; overflow-x: auto;">${{JSON.stringify(data, null, 2)}}</pre>
                        </div>
                    `;
                    
                }} catch (error) {{
                    document.getElementById('status-result').innerHTML = `
                        <div class="status warning">
                            <strong>Error:</strong> ${{error.message}}
                        </div>
                    `;
                }}
            }}
        </script>
    </body>
    </html>
    """
    
    return HTMLResponse(content=html_content)


@app.get("/")
async def root():
    """Root endpoint with verifier information."""
    return {
        "name": "Microsoft Demo Verifier API",
        "version": "1.0.0",
        "verifier": VERIFIER_BASE_URL,
        "endpoints": {
            "presentation_request": "/presentation-request",
            "presentation_response": "/presentation-response",
            "status": "/verification-status/{request_id}",
            "demo": "/verification-demo"
        },
        "status": "operational"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)