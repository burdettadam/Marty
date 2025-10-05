"""
Marty Demo UI Application
A minimal FastAPI + Jinja2 web interface for demonstrating the Marty platform capabilities.

Features:
- Issue credentials (Passport, MDL, mDoc)
- View logs and traces via Jaeger integration
- Verify presentations
- Monitor system health
- Demo data management
"""

from fastapi import FastAPI, Request, Form, HTTPException, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import httpx
import json
import logging
import os
from datetime import datetime, date
from typing import Dict, List, Optional, Any
from pathlib import Path

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
ISSUER_API_ADDR = os.getenv('UI_ISSUER_API_ADDR', 'http://issuer-api-demo:8000')
PASSPORT_ENGINE_ADDR = os.getenv('UI_PASSPORT_ENGINE_ADDR', 'passport-engine-demo:8084')
INSPECTION_SYSTEM_ADDR = os.getenv('UI_INSPECTION_SYSTEM_ADDR', 'inspection-system-demo:8083')
MDL_ENGINE_ADDR = os.getenv('UI_MDL_ENGINE_ADDR', 'mdl-engine-demo:8085')
MDOC_ENGINE_ADDR = os.getenv('UI_MDOC_ENGINE_ADDR', 'mdoc-engine-demo:8086')
TRUST_ANCHOR_ADDR = os.getenv('UI_TRUST_ANCHOR_ADDR', 'trust-anchor-demo:8080')
JAEGER_ADDR = os.getenv('UI_JAEGER_ADDR', 'http://jaeger-demo:16686')
GRAFANA_ADDR = os.getenv('UI_GRAFANA_ADDR', 'http://grafana-demo:3000')

UI_TITLE = os.getenv('UI_TITLE', 'Marty Demo Console')
UI_ENVIRONMENT = os.getenv('UI_ENVIRONMENT', 'demo')
ENABLE_MOCK_DATA = os.getenv('UI_ENABLE_MOCK_DATA', 'true').lower() == 'true'

# FastAPI app
app = FastAPI(
    title="Marty Demo UI",
    description="Web interface for the Marty platform demo environment",
    version="1.0.0"
)

# Templates and static files
templates_dir = Path(__file__).parent / "templates"
static_dir = Path(__file__).parent / "static"

# Create directories if they don't exist
templates_dir.mkdir(exist_ok=True)
static_dir.mkdir(exist_ok=True)

templates = Jinja2Templates(directory=str(templates_dir))

# Mount static files
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

# HTTP client for API calls
async def get_http_client():
    return httpx.AsyncClient(timeout=30.0)

# Template context helper
def get_base_context(request: Request) -> Dict[str, Any]:
    return {
        "request": request,
        "ui_title": UI_TITLE,
        "ui_environment": UI_ENVIRONMENT,
        "jaeger_url": JAEGER_ADDR,
        "grafana_url": GRAFANA_ADDR,
        "current_time": datetime.now().isoformat(),
        "demo_mode": ENABLE_MOCK_DATA
    }

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """Home page with system overview."""
    context = get_base_context(request)
    
    # Get system health status
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            # Check issuer API health
            try:
                response = await client.get(f"{ISSUER_API_ADDR}/health")
                context["issuer_api_status"] = "healthy" if response.status_code == 200 else "unhealthy"
            except:
                context["issuer_api_status"] = "unavailable"
            
            # Add more health checks as needed
            context["services_status"] = {
                "issuer_api": context["issuer_api_status"],
                "passport_engine": "healthy",  # Could add actual health checks
                "mdl_engine": "healthy",
                "mdoc_engine": "healthy",
                "inspection_system": "healthy"
            }
    except Exception as e:
        logger.error(f"Error checking system health: {e}")
        context["services_status"] = {}
    
    return templates.TemplateResponse("home.html", context)

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

@app.get("/issue", response_class=HTMLResponse)
async def issue_credential_form(request: Request):
    """Show credential issuance form."""
    context = get_base_context(request)
    context.update({
        "credential_types": [
            {"value": "PassportCredential", "label": "Passport Credential"},
            {"value": "MDLCredential", "label": "Mobile Driver's License"},
            {"value": "mDocCredential", "label": "Mobile Document"},
        ],
        "countries": ["USA", "CAN", "GBR", "AUS", "DEU", "FRA", "JPN"],
        "states": ["California", "Texas", "New York", "Florida", "Nevada", "Illinois"]
    })
    
    return templates.TemplateResponse("issue_credential.html", context)

@app.post("/issue", response_class=HTMLResponse)
async def issue_credential(
    request: Request,
    credential_type: str = Form(...),
    subject_id: str = Form(...),
    holder_name: str = Form(...),
    birth_date: str = Form(...),
    document_number: str = Form(None),
    issuing_country: str = Form(None),
    issuing_state: str = Form(None),
    license_class: str = Form(None)
):
    """Process credential issuance."""
    context = get_base_context(request)
    
    try:
        # Build credential request based on type
        base_claims = {
            "holder_name": holder_name,
            "birth_date": birth_date
        }
        
        if credential_type == "PassportCredential":
            base_claims.update({
                "document_number": document_number,
                "issuing_country": issuing_country
            })
        elif credential_type == "MDLCredential":
            base_claims.update({
                "license_number": document_number,
                "issuing_state": issuing_state,
                "license_class": license_class
            })
        
        credential_request = {
            "subject_id": subject_id,
            "credential_type": credential_type,
            "base_claims": base_claims,
            "selective_disclosures": {
                "address": "Demo Address for selective disclosure",
                "phone": "+1-555-DEMO"
            }
        }
        
        # Call issuer API
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{ISSUER_API_ADDR}/v1/credentials/offer",
                json=credential_request
            )
            
            if response.status_code in [200, 201]:
                credential_data = response.json()
                context.update({
                    "success": True,
                    "credential_data": json.dumps(credential_data, indent=2),
                    "credential_id": credential_data.get("credential_id", "N/A")
                })
            else:
                context.update({
                    "error": f"Failed to issue credential: {response.status_code}",
                    "error_details": response.text
                })
                
    except Exception as e:
        logger.error(f"Error issuing credential: {e}")
        context.update({
            "error": f"Error issuing credential: {str(e)}"
        })
    
    return templates.TemplateResponse("issue_result.html", context)

@app.get("/verify", response_class=HTMLResponse)
async def verify_presentation_form(request: Request):
    """Show presentation verification form."""
    context = get_base_context(request)
    return templates.TemplateResponse("verify_presentation.html", context)

@app.post("/verify", response_class=HTMLResponse)
async def verify_presentation(
    request: Request,
    presentation_data: str = Form(...),
    verification_policy: str = Form("standard")
):
    """Process presentation verification."""
    context = get_base_context(request)
    
    try:
        # Parse presentation data
        try:
            presentation = json.loads(presentation_data)
        except json.JSONDecodeError:
            context["error"] = "Invalid JSON format in presentation data"
            return templates.TemplateResponse("verify_result.html", context)
        
        # For demo purposes, simulate verification
        # In a real implementation, this would call the inspection system
        verification_result = {
            "verified": True,
            "verification_time": datetime.now().isoformat(),
            "policy_applied": verification_policy,
            "checks": {
                "signature_valid": True,
                "not_expired": True,
                "issuer_trusted": True,
                "revocation_status": "not_revoked"
            },
            "credential_info": {
                "type": presentation.get("type", ["VerifiablePresentation"]),
                "holder": presentation.get("holder", "Unknown"),
                "credentials_count": len(presentation.get("verifiableCredential", []))
            }
        }
        
        context.update({
            "verification_result": verification_result,
            "presentation_summary": json.dumps(presentation, indent=2)[:500] + "..."
        })
        
    except Exception as e:
        logger.error(f"Error verifying presentation: {e}")
        context["error"] = f"Error verifying presentation: {str(e)}"
    
    return templates.TemplateResponse("verify_result.html", context)

@app.get("/traces", response_class=HTMLResponse)
async def view_traces(request: Request):
    """View traces via Jaeger integration."""
    context = get_base_context(request)
    
    # For demo, we'll embed Jaeger in an iframe
    context["jaeger_embed_url"] = f"{JAEGER_ADDR}/search"
    
    return templates.TemplateResponse("traces.html", context)

@app.get("/metrics", response_class=HTMLResponse)
async def view_metrics(request: Request):
    """View metrics via Grafana integration."""
    context = get_base_context(request)
    
    # For demo, we'll embed Grafana in an iframe
    context["grafana_embed_url"] = f"{GRAFANA_ADDR}/d/marty-demo/marty-demo-dashboard"
    
    return templates.TemplateResponse("metrics.html", context)

@app.get("/demo-data", response_class=HTMLResponse)
async def demo_data_management(request: Request):
    """Demo data management interface."""
    context = get_base_context(request)
    
    # Sample demo data for display
    context["sample_data"] = {
        "passports": [
            {"document_number": "P123456789", "country": "USA", "holder": "John Doe"},
            {"document_number": "P987654321", "country": "CAN", "holder": "Jane Smith"}
        ],
        "mdls": [
            {"license_number": "DL123456789", "state": "California", "holder": "John Doe"},
            {"license_number": "DL987654321", "state": "Texas", "holder": "Jane Smith"}
        ],
        "credentials_issued": [
            {"id": "cred-001", "type": "PassportCredential", "subject": "demo-user-001"},
            {"id": "cred-002", "type": "MDLCredential", "subject": "demo-user-002"}
        ]
    }
    
    return templates.TemplateResponse("demo_data.html", context)

@app.get("/api/status")
async def api_status():
    """API endpoint for system status."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            services = {}
            
            # Check each service
            service_endpoints = {
                "issuer_api": f"{ISSUER_API_ADDR}/health",
                "jaeger": f"{JAEGER_ADDR}/api/services",
                "grafana": f"{GRAFANA_ADDR}/api/health"
            }
            
            for service, endpoint in service_endpoints.items():
                try:
                    response = await client.get(endpoint)
                    services[service] = {
                        "status": "healthy" if response.status_code < 400 else "unhealthy",
                        "response_time_ms": response.elapsed.total_seconds() * 1000
                    }
                except Exception as e:
                    services[service] = {
                        "status": "unavailable",
                        "error": str(e)
                    }
            
            return {
                "overall_status": "healthy" if all(s.get("status") == "healthy" for s in services.values()) else "degraded",
                "services": services,
                "timestamp": datetime.now().isoformat()
            }
            
    except Exception as e:
        return {"error": str(e), "timestamp": datetime.now().isoformat()}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)