"""
OpenWallet Foundation mDoc/mDL Verifier Service

This service integrates with the Multipaz SDK to verify mDoc and mDL credentials
using OpenID4VP and ISO 18013-5 presentation protocols.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import asyncpg
import httpx
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Configure logging early so it's available for import errors
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Enhanced demo features
try:
    from age_verification import AgeVerificationEngine
    from certificate_monitor import MDLCertificateMonitor
    from offline_verification import OfflineQREngine
    from policy_engine import PolicyBasedDisclosureEngine

    ENHANCED_FEATURES_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Enhanced features not available: {e}")
    ENHANCED_FEATURES_AVAILABLE = False

# Configuration from environment
DATABASE_URL = f"postgresql://{os.getenv('POSTGRES_USER')}:{os.getenv('POSTGRES_PASSWORD')}@{os.getenv('POSTGRES_HOST')}:{os.getenv('POSTGRES_PORT')}/{os.getenv('POSTGRES_DB')}"
MULTIPAZ_SDK_VERSION = os.getenv("MULTIPAZ_SDK_VERSION", "0.94.0")
PRESENTATION_PROTOCOLS = os.getenv("PRESENTATION_PROTOCOLS", "openid4vp,iso18013-5").split(",")
SUPPORTED_CLAIMS = os.getenv(
    "SUPPORTED_CLAIMS", "given_name,family_name,birth_date,license_number,driving_privileges"
).split(",")

# FastAPI app
app = FastAPI(
    title="OpenWallet Foundation mDoc/mDL Verifier",
    description="Demo verifier service using Multipaz SDK for mDoc/mDL verification",
    version="1.0.0",
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Demo only - restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Pydantic models
class PresentationDefinition(BaseModel):
    id: str = Field(..., description="Presentation definition ID")
    name: str = Field(..., description="Human readable name")
    purpose: str = Field(..., description="Purpose of the verification")
    input_descriptors: list[dict[str, Any]] = Field(..., description="Input descriptors")


class CreatePresentationRequestModel(BaseModel):
    verifier_id: str = Field(..., description="Verifier identifier")
    presentation_definition_id: str = Field(..., description="Presentation definition to use")
    callback_url: str | None = Field(default=None, description="Callback URL for async responses")


class PresentationRequestResponse(BaseModel):
    request_id: str
    presentation_uri: str
    qr_code: str
    status: str
    expires_at: str


class VerifyPresentationRequest(BaseModel):
    request_id: str = Field(..., description="Presentation request ID")
    presentation_submission: dict[str, Any] = Field(..., description="Presentation submission")
    vp_token: str = Field(..., description="Verifiable presentation token")


class VerificationResult(BaseModel):
    request_id: str
    status: str  # VALID, INVALID, EXPIRED
    verified_claims: dict[str, Any] | None = None
    errors: list[str] | None = None
    trust_level: str | None = None


# Database connection pool
db_pool: asyncpg.Pool | None = None

# Initialize demo data
verification_sessions = {}
credential_requests = {}

# Initialize enhanced engines (global variables)
age_verification_engine = None
offline_qr_engine = None
certificate_monitor = None
policy_engine = None


@app.on_event("startup")
async def startup():
    """Initialize database connection pool and load presentation definitions"""
    global db_pool, age_verification_engine, offline_qr_engine, certificate_monitor, policy_engine

    logger.info(f"Starting OpenWallet Foundation Verifier Service")
    logger.info(f"Multipaz SDK Version: {MULTIPAZ_SDK_VERSION}")
    logger.info(f"Supported Protocols: {PRESENTATION_PROTOCOLS}")

    # Create database connection pool
    db_pool = await asyncpg.create_pool(DATABASE_URL)

    # Initialize enhanced features if available
    if ENHANCED_FEATURES_AVAILABLE:
        try:
            age_verification_engine = AgeVerificationEngine()
            offline_qr_engine = OfflineQREngine()
            certificate_monitor = MDLCertificateMonitor()
            policy_engine = PolicyBasedDisclosureEngine()
            logger.info("Enhanced features initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize enhanced features: {e}")

    # Load presentation definitions
    await load_presentation_definitions()


@app.on_event("shutdown")
async def shutdown():
    """Close database connections"""
    global db_pool
    if db_pool:
        await db_pool.close()


async def get_db_connection():
    """Get database connection from pool"""
    if not db_pool:
        raise HTTPException(status_code=500, detail="Database pool not initialized")
    async with db_pool.acquire() as connection:
        yield connection


# Multipaz SDK Integration (Mock implementation for demo)
class MultipazVerifierSDK:
    """
    Mock implementation of Multipaz SDK verifier integration.
    In a real implementation, this would use the actual Multipaz Kotlin/Java libraries.
    """

    @staticmethod
    async def verify_mdoc(
        mdoc_data: str, trusted_issuers: list[str], required_claims: list[str]
    ) -> dict[str, Any]:
        """Verify an mDoc using Multipaz SDK"""

        # Mock verification - in reality this would use actual Multipaz SDK
        verification_result = {
            "valid": True,
            "trust_level": "HIGH",
            "issuer_verified": True,
            "signature_valid": True,
            "not_expired": True,
            "claims": {
                "given_name": "Alice",
                "family_name": "Smith",
                "birth_date": "1990-05-15",
                "license_number": "DL123456789",
                "driving_privileges": ["C"],
                "issuing_authority": "Demo DMV",
            },
            "multipaz_metadata": {
                "sdk_version": MULTIPAZ_SDK_VERSION,
                "verification_time": datetime.now(timezone.utc).isoformat(),
                "cryptographic_suite": "ES256",
            },
        }

        return verification_result

    @staticmethod
    async def create_openid4vp_request(
        presentation_definition: dict[str, Any], callback_url: str | None = None
    ) -> dict[str, Any]:
        """Create OpenID4VP presentation request"""

        request_id = str(uuid.uuid4())

        # Mock OpenID4VP request
        openid4vp_request = {
            "client_id": "demo_verifier",
            "response_type": "vp_token",
            "response_mode": "direct_post",
            "presentation_definition": presentation_definition,
            "nonce": str(uuid.uuid4()),
            "state": request_id,
        }

        if callback_url:
            openid4vp_request["redirect_uri"] = callback_url

        # Generate presentation URI
        presentation_uri = f"openid4vp://request?request_uri=https://verifier.demo.local/api/presentation/request/{request_id}"

        return {
            "request_id": request_id,
            "presentation_uri": presentation_uri,
            "openid4vp_request": openid4vp_request,
        }

    @staticmethod
    async def generate_qr_code(presentation_uri: str) -> str:
        """Generate QR code for presentation request"""
        # Mock QR code generation
        return f"data:image/png;base64,mock_qr_code_for_presentation_{uuid.uuid4()}"

    @staticmethod
    async def establish_iso18013_session(device_engagement: dict[str, Any]) -> dict[str, Any]:
        """Establish ISO 18013-5 proximity session"""

        session_id = str(uuid.uuid4())

        # Mock session establishment
        session_data = {
            "session_id": session_id,
            "transport": "BLE",
            "encryption_key": f"mock_session_key_{uuid.uuid4()}",
            "reader_engagement": {
                "version": "1.0",
                "reader_key": f"mock_reader_key_{uuid.uuid4()}",
            },
        }

        return session_data


# Predefined presentation definitions
PRESENTATION_DEFINITIONS = {}


async def load_presentation_definitions():
    """Load presentation definitions for different verification scenarios"""
    global PRESENTATION_DEFINITIONS

    PRESENTATION_DEFINITIONS = {
        "age_verification": {
            "id": "age_verification",
            "name": "Age Verification",
            "purpose": "Verify age for restricted venue access",
            "input_descriptors": [
                {
                    "id": "age_over_21",
                    "format": {"mso_mdoc": {"alg": ["ES256", "ES384", "ES512"]}},
                    "constraints": {
                        "fields": [
                            {
                                "path": ["$.birth_date"],
                                "purpose": "Age verification",
                                "intent_to_retain": False,
                            },
                            {
                                "path": ["$.portrait"],
                                "purpose": "Identity verification",
                                "intent_to_retain": False,
                            },
                        ]
                    },
                }
            ],
        },
        "driving_license_verification": {
            "id": "driving_license_verification",
            "name": "Driving License Verification",
            "purpose": "Verify driving privileges and identity",
            "input_descriptors": [
                {
                    "id": "mdl_verification",
                    "format": {"mso_mdoc": {"alg": ["ES256", "ES384", "ES512"]}},
                    "constraints": {
                        "fields": [
                            {"path": ["$.license_number"], "purpose": "License verification"},
                            {
                                "path": ["$.driving_privileges"],
                                "purpose": "Driving privileges verification",
                            },
                            {
                                "path": ["$.given_name", "$.family_name"],
                                "purpose": "Identity verification",
                            },
                            {"path": ["$.expiry_date"], "purpose": "Validity verification"},
                        ]
                    },
                }
            ],
        },
        "identity_verification": {
            "id": "identity_verification",
            "name": "Basic Identity Verification",
            "purpose": "Verify basic identity information",
            "input_descriptors": [
                {
                    "id": "identity_check",
                    "format": {"mso_mdoc": {"alg": ["ES256", "ES384", "ES512"]}},
                    "constraints": {
                        "fields": [
                            {
                                "path": ["$.given_name", "$.family_name"],
                                "purpose": "Name verification",
                            },
                            {"path": ["$.birth_date"], "purpose": "Birth date verification"},
                        ]
                    },
                }
            ],
        },
    }

    logger.info(f"Loaded {len(PRESENTATION_DEFINITIONS)} presentation definitions")


# API Endpoints


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "verifier",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0",
        "enhanced_features": {
            "age_verification": age_verification_engine is not None,
            "offline_qr": offline_qr_engine is not None,
            "certificate_monitoring": certificate_monitor is not None,
            "policy_based_disclosure": policy_engine is not None,
        },
        "features_available": ENHANCED_FEATURES_AVAILABLE,
    }


@app.post("/age-verification/request")
async def create_age_verification_request(request: dict[str, Any]):
    """Create an age verification request with enhanced privacy protection."""
    if not age_verification_engine:
        raise HTTPException(status_code=503, detail="Enhanced age verification not available")

    try:
        use_case = request.get("use_case", "alcohol_purchase")
        verifier_id = request.get("verifier_id", "demo_verifier")
        purpose = request.get("purpose")

        verification_request = age_verification_engine.create_age_verification_request(
            use_case=use_case, verifier_id=verifier_id, purpose=purpose
        )

        # Store request for later verification
        request_id = verification_request["request_id"]
        verification_sessions[request_id] = {
            "request": verification_request,
            "status": "pending",
            "created_at": datetime.utcnow().isoformat(),
        }

        return {
            "success": True,
            "verification_request": verification_request,
            "qr_code_data": f"age_verify:{request_id}",
            "expires_at": verification_request["expires_at"],
        }

    except Exception as e:
        logger.exception("Age verification request failed: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/age-verification/verify")
async def verify_age_presentation(verification: dict[str, Any]):
    """Verify age presentation with enhanced privacy protection."""
    if not age_verification_engine:
        raise HTTPException(status_code=503, detail="Enhanced age verification not available")

    try:
        request_id = verification.get("request_id")
        presentation = verification.get("presentation", {})

        if request_id not in verification_sessions:
            raise HTTPException(status_code=404, detail="Verification request not found")

        session = verification_sessions[request_id]
        verification_request = session["request"]

        # Perform age verification
        result = age_verification_engine.verify_age_presentation(
            presentation=presentation, verification_request=verification_request
        )

        # Generate privacy report
        privacy_report = age_verification_engine.get_privacy_report(result)

        # Update session
        session["status"] = "verified" if result["verified"] else "failed"
        session["result"] = result
        session["privacy_report"] = privacy_report
        session["completed_at"] = datetime.utcnow().isoformat()

        return {
            "verification_result": result,
            "privacy_report": privacy_report,
            "session_info": {
                "request_id": request_id,
                "status": session["status"],
                "completed_at": session["completed_at"],
            },
        }

    except Exception as e:
        logger.exception("Age verification failed: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/age-verification/use-cases")
async def get_age_verification_use_cases():
    """Get supported age verification use cases."""
    if not age_verification_engine:
        raise HTTPException(status_code=503, detail="Enhanced age verification not available")

    return age_verification_engine.get_supported_use_cases()


@app.post("/offline-qr/create")
async def create_offline_qr(request: dict[str, Any]):
    """Create an offline-verifiable QR code."""
    if not offline_qr_engine:
        raise HTTPException(status_code=503, detail="Offline QR functionality not available")

    try:
        mdl_data = request.get("mdl_data", {})
        verification_requirements = request.get("verification_requirements")
        expires_in_minutes = request.get("expires_in_minutes", 30)

        qr_result = offline_qr_engine.create_offline_qr(
            mdl_data=mdl_data,
            verification_requirements=verification_requirements,
            expires_in_minutes=expires_in_minutes,
        )

        return {"success": True, "offline_qr": qr_result}

    except Exception as e:
        logger.exception("Offline QR creation failed: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/offline-qr/verify")
async def verify_offline_qr(verification: dict[str, Any]):
    """Verify an offline QR code without network connectivity."""
    if not offline_qr_engine:
        raise HTTPException(status_code=503, detail="Offline QR functionality not available")

    try:
        qr_data = verification.get("qr_data")
        verification_context = verification.get("verification_context", {})

        if not qr_data:
            raise HTTPException(status_code=400, detail="QR data is required")

        result = offline_qr_engine.verify_offline_qr(
            qr_data=qr_data, verification_context=verification_context
        )

        return {
            "verification_result": result,
            "offline_capabilities": offline_qr_engine.get_offline_capabilities(),
        }

    except Exception as e:
        logger.exception("Offline QR verification failed: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/certificates/dashboard")
async def get_certificate_dashboard():
    """Get mDL certificate lifecycle dashboard."""
    if not certificate_monitor:
        raise HTTPException(status_code=503, detail="Certificate monitoring not available")

    try:
        dashboard = certificate_monitor.get_expiry_dashboard()
        return dashboard

    except Exception as e:
        logger.exception("Certificate dashboard failed: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/certificates/{cert_id}")
async def get_certificate_details(cert_id: str):
    """Get detailed information about a specific certificate."""
    if not certificate_monitor:
        raise HTTPException(status_code=503, detail="Certificate monitoring not available")

    try:
        details = certificate_monitor.get_certificate_details(cert_id)
        return details

    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.exception("Certificate details failed: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/certificates/{cert_id}/renew")
async def simulate_certificate_renewal(cert_id: str):
    """Simulate certificate renewal process."""
    if not certificate_monitor:
        raise HTTPException(status_code=503, detail="Certificate monitoring not available")

    try:
        renewal_result = certificate_monitor.simulate_certificate_renewal(cert_id)
        return renewal_result

    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.exception("Certificate renewal failed: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/policy/evaluate")
async def evaluate_disclosure_policy(evaluation_request: dict[str, Any]):
    """Evaluate disclosure policy for a presentation request."""
    if not policy_engine:
        raise HTTPException(status_code=503, detail="Policy engine not available")

    try:
        presentation_request = evaluation_request.get("presentation_request", {})
        available_attributes = evaluation_request.get("available_attributes", {})
        context = evaluation_request.get("context", {})

        evaluation_result = policy_engine.evaluate_disclosure_policy(
            presentation_request=presentation_request,
            available_attributes=available_attributes,
            context=context,
        )

        return evaluation_result

    except Exception as e:
        logger.exception("Policy evaluation failed: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/policy/summary")
async def get_policy_summary():
    """Get summary of all disclosure policies."""
    if not policy_engine:
        raise HTTPException(status_code=503, detail="Policy engine not available")

    return policy_engine.get_policy_summary()


@app.get("/ready")
async def readiness_check():
    """Readiness check endpoint"""
    try:
        async with db_pool.acquire() as conn:
            await conn.fetchval("SELECT 1")
        return {
            "status": "ready",
            "database": "connected",
            "presentation_definitions": len(PRESENTATION_DEFINITIONS),
        }
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Service not ready: {str(e)}")


@app.get("/api/presentation/definitions")
async def list_presentation_definitions():
    """List available presentation definitions"""
    return {
        "definitions": [
            {"id": pd["id"], "name": pd["name"], "purpose": pd["purpose"]}
            for pd in PRESENTATION_DEFINITIONS.values()
        ]
    }


@app.get("/api/presentation/definitions/{definition_id}")
async def get_presentation_definition(definition_id: str):
    """Get a specific presentation definition"""
    if definition_id not in PRESENTATION_DEFINITIONS:
        raise HTTPException(status_code=404, detail="Presentation definition not found")

    return PRESENTATION_DEFINITIONS[definition_id]


@app.post("/api/presentation/request", response_model=PresentationRequestResponse)
async def create_presentation_request(
    request: CreatePresentationRequestModel, conn=Depends(get_db_connection)
):
    """Create a new presentation request"""

    # Validate presentation definition exists
    if request.presentation_definition_id not in PRESENTATION_DEFINITIONS:
        raise HTTPException(status_code=400, detail="Invalid presentation definition ID")

    presentation_definition = PRESENTATION_DEFINITIONS[request.presentation_definition_id]

    try:
        # Create OpenID4VP request using Multipaz SDK
        openid4vp_data = await MultipazVerifierSDK.create_openid4vp_request(
            presentation_definition=presentation_definition, callback_url=request.callback_url
        )

        # Generate QR code
        qr_code = await MultipazVerifierSDK.generate_qr_code(openid4vp_data["presentation_uri"])

        # Store presentation session in database
        await conn.execute(
            """
            INSERT INTO sessions.presentation_sessions (
                session_id, verifier_id, status, protocol,
                presentation_definition, created_at
            ) VALUES ($1, $2, $3, $4, $5, $6)
            """,
            openid4vp_data["request_id"],
            request.verifier_id,
            "INITIATED",
            "openid4vp",
            json.dumps(presentation_definition),
            datetime.now(timezone.utc),
        )

        # Calculate expiry time (15 minutes from now)
        expires_at = datetime.now(timezone.utc).replace(
            minute=datetime.now(timezone.utc).minute + 15
        )

        return PresentationRequestResponse(
            request_id=openid4vp_data["request_id"],
            presentation_uri=openid4vp_data["presentation_uri"],
            qr_code=qr_code,
            status="INITIATED",
            expires_at=expires_at.isoformat(),
        )

    except Exception as e:
        logger.error(f"Error creating presentation request: {str(e)}")
        raise HTTPException(
            status_code=500, detail=f"Failed to create presentation request: {str(e)}"
        )


@app.get("/api/presentation/request/{request_id}")
async def get_presentation_request(request_id: str, conn=Depends(get_db_connection)):
    """Get presentation request details (for OpenID4VP request_uri)"""

    session = await conn.fetchrow(
        "SELECT * FROM sessions.presentation_sessions WHERE session_id = $1", request_id
    )

    if not session:
        raise HTTPException(status_code=404, detail="Presentation request not found")

    return {
        "client_id": "demo_verifier",
        "response_type": "vp_token",
        "response_mode": "direct_post",
        "presentation_definition": json.loads(session["presentation_definition"]),
        "nonce": str(uuid.uuid4()),
        "state": request_id,
    }


@app.post("/api/presentation/verify", response_model=VerificationResult)
async def verify_presentation(request: VerifyPresentationRequest, conn=Depends(get_db_connection)):
    """Verify a presentation submission"""

    # Get presentation session
    session = await conn.fetchrow(
        "SELECT * FROM sessions.presentation_sessions WHERE session_id = $1", request.request_id
    )

    if not session:
        raise HTTPException(status_code=404, detail="Presentation request not found")

    if session["status"] != "INITIATED":
        raise HTTPException(status_code=400, detail="Presentation request already processed")

    try:
        # Verify the presentation using Multipaz SDK
        verification_result = await MultipazVerifierSDK.verify_mdoc(
            mdoc_data=request.vp_token,
            trusted_issuers=["demo_issuer"],
            required_claims=SUPPORTED_CLAIMS,
        )

        # Determine verification status
        status = "VALID" if verification_result["valid"] else "INVALID"

        # Update session with results
        await conn.execute(
            """
            UPDATE sessions.presentation_sessions
            SET status = $1, updated_at = $2, presentation_submission = $3
            WHERE session_id = $4
            """,
            status,
            datetime.now(timezone.utc),
            json.dumps(request.presentation_submission),
            request.request_id,
        )

        return VerificationResult(
            request_id=request.request_id,
            status=status,
            verified_claims=(
                verification_result.get("claims") if verification_result["valid"] else None
            ),
            errors=(
                verification_result.get("errors", []) if not verification_result["valid"] else None
            ),
            trust_level=verification_result.get("trust_level"),
        )

    except Exception as e:
        logger.error(f"Error verifying presentation: {str(e)}")

        # Update session with error status
        await conn.execute(
            """
            UPDATE sessions.presentation_sessions
            SET status = $1, updated_at = $2
            WHERE session_id = $3
            """,
            "ERROR",
            datetime.now(timezone.utc),
            request.request_id,
        )

        raise HTTPException(status_code=500, detail=f"Verification failed: {str(e)}")


@app.get("/api/presentation/status/{request_id}")
async def get_presentation_status(request_id: str, conn=Depends(get_db_connection)):
    """Get presentation request status"""

    session = await conn.fetchrow(
        "SELECT session_id, status, created_at, updated_at FROM sessions.presentation_sessions WHERE session_id = $1",
        request_id,
    )

    if not session:
        raise HTTPException(status_code=404, detail="Presentation request not found")

    return dict(session)


@app.post("/api/proximity/session")
async def establish_proximity_session(
    device_engagement: dict[str, Any], conn=Depends(get_db_connection)
):
    """Establish ISO 18013-5 proximity presentation session"""

    try:
        # Establish session using Multipaz SDK
        session_data = await MultipazVerifierSDK.establish_iso18013_session(device_engagement)

        # Store session
        await conn.execute(
            """
            INSERT INTO sessions.presentation_sessions (
                session_id, verifier_id, status, protocol,
                device_engagement, created_at
            ) VALUES ($1, $2, $3, $4, $5, $6)
            """,
            session_data["session_id"],
            "proximity_verifier",
            "ESTABLISHED",
            "iso18013-5",
            json.dumps(device_engagement),
            datetime.now(timezone.utc),
        )

        return session_data

    except Exception as e:
        logger.error(f"Error establishing proximity session: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to establish session: {str(e)}")


@app.get("/api/demo/scenarios")
async def list_demo_scenarios():
    """List available demo scenarios"""
    scenarios = [
        {
            "id": "age_restricted_venue",
            "name": "Age Restricted Venue",
            "description": "21+ venue access verification",
            "presentation_definition_id": "age_verification",
            "use_case": "A customer wants to enter a 21+ venue and needs to prove their age",
        },
        {
            "id": "car_rental",
            "name": "Car Rental",
            "description": "Driving license verification for car rental",
            "presentation_definition_id": "driving_license_verification",
            "use_case": "A customer wants to rent a car and needs to prove they have a valid driving license",
        },
        {
            "id": "account_opening",
            "name": "Account Opening",
            "description": "Basic identity verification for account opening",
            "presentation_definition_id": "identity_verification",
            "use_case": "A customer wants to open a bank account and needs to verify their identity",
        },
    ]

    return {"scenarios": scenarios}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8081)
