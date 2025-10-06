"""
OpenWallet Foundation mDoc/mDL Wallet Service

This service integrates with the Multipaz SDK to provide wallet functionality
for mDoc and mDL credentials, including storage, presentation, and management.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import httpx
import asyncpg

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration from environment
DATABASE_URL = f"postgresql://{os.getenv('POSTGRES_USER')}:{os.getenv('POSTGRES_PASSWORD')}@{os.getenv('POSTGRES_HOST')}:{os.getenv('POSTGRES_PORT')}/{os.getenv('POSTGRES_DB')}"
MULTIPAZ_SDK_VERSION = os.getenv('MULTIPAZ_SDK_VERSION', '0.94.0')
ISSUER_BASE_URL = os.getenv('ISSUER_BASE_URL', 'http://issuer-service:8080')
VERIFIER_BASE_URL = os.getenv('VERIFIER_BASE_URL', 'http://verifier-service:8081')

# FastAPI app
app = FastAPI(
    title="OpenWallet Foundation mDoc/mDL Wallet",
    description="Demo wallet service using Multipaz SDK for mDoc/mDL management",
    version="1.0.0"
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
class WalletCredential(BaseModel):
    credential_id: str
    document_type: str
    status: str
    display_name: str
    issuer: str
    issued_at: str
    expires_at: Optional[str] = None
    claims: Dict[str, Any]

class ImportCredentialRequest(BaseModel):
    credential_offer_uri: Optional[str] = Field(default=None, description="OpenID4VCI credential offer URI")
    credential_data: Optional[str] = Field(default=None, description="Raw credential data")
    import_method: str = Field(default="openid4vci", description="Import method: openid4vci, qr_code, or direct")

class PresentationRequest(BaseModel):
    presentation_uri: str = Field(..., description="OpenID4VP presentation URI")
    user_consent: bool = Field(default=True, description="User consent for presentation")
    selective_disclosure: Optional[Dict[str, bool]] = Field(default=None, description="Selective disclosure preferences")

class ProximityPresentationRequest(BaseModel):
    verifier_engagement: Dict[str, Any] = Field(..., description="Verifier device engagement")
    requested_claims: List[str] = Field(..., description="Claims requested by verifier")
    user_consent: bool = Field(default=True, description="User consent for presentation")

class WalletStatus(BaseModel):
    wallet_id: str
    user_id: str
    status: str
    credentials_count: int
    last_activity: str
    secure_area_status: str

# Database connection pool
db_pool: Optional[asyncpg.Pool] = None

@app.on_event("startup")
async def startup():
    """Initialize database connection pool and wallet storage"""
    global db_pool
    
    logger.info(f"Starting OpenWallet Foundation Wallet Service")
    logger.info(f"Multipaz SDK Version: {MULTIPAZ_SDK_VERSION}")
    
    # Create database connection pool
    db_pool = await asyncpg.create_pool(DATABASE_URL)
    
    # Initialize secure storage
    await initialize_secure_storage()

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
class MultipazWalletSDK:
    """
    Mock implementation of Multipaz SDK wallet integration.
    In a real implementation, this would use the actual Multipaz Kotlin/Java libraries.
    """
    
    @staticmethod
    async def initialize_secure_area() -> Dict[str, Any]:
        """Initialize secure area for credential storage"""
        return {
            "secure_area_id": str(uuid.uuid4()),
            "status": "initialized",
            "encryption_enabled": True,
            "hardware_backed": False,  # Mock - would be true on real devices
            "biometric_enabled": True
        }
    
    @staticmethod
    async def store_credential(
        credential_data: Dict[str, Any],
        user_consent: bool = True
    ) -> str:
        """Store credential in secure area"""
        if not user_consent:
            raise ValueError("User consent required for credential storage")
        
        credential_id = str(uuid.uuid4())
        
        # Mock secure storage
        logger.info(f"Storing credential {credential_id} in secure area")
        
        return credential_id
    
    @staticmethod
    async def retrieve_credential(credential_id: str) -> Dict[str, Any]:
        """Retrieve credential from secure area"""
        
        # Mock credential retrieval
        mock_credential = {
            "credential_id": credential_id,
            "format": "mso_mdoc",
            "doctype": "org.iso.18013.5.1.mDL",
            "claims": {
                "given_name": "Alice",
                "family_name": "Smith",
                "birth_date": "1990-05-15",
                "license_number": "DL123456789"
            },
            "issuer": "Demo DMV",
            "issued_at": "2024-01-01T00:00:00Z",
            "expires_at": "2034-01-01T00:00:00Z"
        }
        
        return mock_credential
    
    @staticmethod
    async def create_presentation(
        credential_ids: List[str],
        presentation_definition: Dict[str, Any],
        nonce: str
    ) -> Dict[str, Any]:
        """Create presentation for credentials"""
        
        # Mock presentation creation
        presentation = {
            "format": "mso_mdoc",
            "vp_token": f"mock_vp_token_{uuid.uuid4()}",
            "presentation_submission": {
                "id": str(uuid.uuid4()),
                "definition_id": presentation_definition.get("id"),
                "descriptor_map": [
                    {
                        "id": "credential_1",
                        "format": "mso_mdoc",
                        "path": "$"
                    }
                ]
            },
            "device_signature": f"mock_device_signature_{uuid.uuid4()}"
        }
        
        return presentation
    
    @staticmethod
    async def establish_proximity_session(
        verifier_engagement: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Establish proximity presentation session"""
        
        session_data = {
            "session_id": str(uuid.uuid4()),
            "transport": "BLE",
            "device_engagement": {
                "version": "1.0",
                "device_key": f"mock_device_key_{uuid.uuid4()}"
            },
            "session_key": f"mock_session_key_{uuid.uuid4()}"
        }
        
        return session_data
    
    @staticmethod
    async def import_credential_from_offer(
        credential_offer_uri: str
    ) -> Dict[str, Any]:
        """Import credential from OpenID4VCI offer"""
        
        # Mock credential import
        imported_credential = {
            "credential_id": str(uuid.uuid4()),
            "format": "mso_mdoc",
            "doctype": "org.iso.18013.5.1.mDL",
            "issuer": "Demo Issuer",
            "status": "ACTIVE",
            "claims": {
                "given_name": "Bob",
                "family_name": "Johnson",
                "birth_date": "1985-08-22",
                "license_number": "DL987654321"
            }
        }
        
        return imported_credential

async def initialize_secure_storage():
    """Initialize secure storage for wallet"""
    try:
        secure_area_info = await MultipazWalletSDK.initialize_secure_area()
        logger.info(f"Secure area initialized: {secure_area_info}")
    except Exception as e:
        logger.error(f"Failed to initialize secure area: {str(e)}")

# API Endpoints

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "openwallet-wallet", "version": "1.0.0"}

@app.get("/ready")
async def readiness_check():
    """Readiness check endpoint"""
    try:
        async with db_pool.acquire() as conn:
            await conn.fetchval("SELECT 1")
        return {"status": "ready", "database": "connected", "secure_area": "initialized"}
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Service not ready: {str(e)}")

@app.get("/api/wallet/{user_id}/status", response_model=WalletStatus)
async def get_wallet_status(
    user_id: str,
    conn = Depends(get_db_connection)
):
    """Get wallet status for a user"""
    
    # Count user's credentials
    mdoc_count = await conn.fetchval(
        "SELECT COUNT(*) FROM credentials.mdocs WHERE user_id = $1 AND status = 'ISSUED'",
        user_id
    )
    
    mdl_count = await conn.fetchval(
        "SELECT COUNT(*) FROM credentials.mdls WHERE user_id = $1 AND status = 'ISSUED'",
        user_id
    )
    
    total_credentials = mdoc_count + mdl_count
    
    return WalletStatus(
        wallet_id=f"wallet_{user_id}",
        user_id=user_id,
        status="ACTIVE",
        credentials_count=total_credentials,
        last_activity=datetime.now(timezone.utc).isoformat(),
        secure_area_status="INITIALIZED"
    )

@app.get("/api/wallet/{user_id}/credentials")
async def list_wallet_credentials(
    user_id: str,
    conn = Depends(get_db_connection)
):
    """List all credentials in user's wallet"""
    
    # Get mDocs
    mdocs = await conn.fetch(
        """
        SELECT mdoc_id as credential_id, document_type, status,
               issuing_authority as issuer, created_at as issued_at,
               credential_data, multipaz_data
        FROM credentials.mdocs 
        WHERE user_id = $1 AND status = 'ISSUED'
        """,
        user_id
    )
    
    # Get mDLs
    mdls = await conn.fetch(
        """
        SELECT mdl_id as credential_id, 'MOBILE_DRIVING_LICENSE' as document_type, 
               status, 'Demo DMV' as issuer, created_at as issued_at,
               personal_data as credential_data, multipaz_data
        FROM credentials.mdls 
        WHERE user_id = $1 AND status = 'ISSUED'
        """,
        user_id
    )
    
    credentials = []
    
    # Process mDocs
    for mdoc in mdocs:
        credential_data = json.loads(mdoc["credential_data"]) if mdoc["credential_data"] else {}
        credentials.append(WalletCredential(
            credential_id=mdoc["credential_id"],
            document_type=mdoc["document_type"],
            status=mdoc["status"],
            display_name=f"{credential_data.get('given_name', 'Unknown')} {credential_data.get('family_name', 'User')} - {mdoc['document_type']}",
            issuer=mdoc["issuer"],
            issued_at=mdoc["issued_at"].isoformat(),
            claims=credential_data
        ))
    
    # Process mDLs
    for mdl in mdls:
        personal_data = json.loads(mdl["credential_data"]) if mdl["credential_data"] else {}
        credentials.append(WalletCredential(
            credential_id=mdl["credential_id"],
            document_type=mdl["document_type"],
            status=mdl["status"],
            display_name=f"{personal_data.get('given_name', 'Unknown')} {personal_data.get('family_name', 'User')} - Mobile Driving License",
            issuer=mdl["issuer"],
            issued_at=mdl["issued_at"].isoformat(),
            claims=personal_data
        ))
    
    return {"credentials": credentials}

@app.get("/api/wallet/credentials/{credential_id}")
async def get_credential_details(
    credential_id: str,
    conn = Depends(get_db_connection)
):
    """Get detailed information about a specific credential"""
    
    try:
        # Retrieve credential from secure area
        credential_data = await MultipazWalletSDK.retrieve_credential(credential_id)
        
        return {
            "credential_id": credential_id,
            "details": credential_data,
            "storage_type": "secure_area",
            "last_accessed": datetime.now(timezone.utc).isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error retrieving credential {credential_id}: {str(e)}")
        raise HTTPException(status_code=404, detail="Credential not found")

@app.post("/api/wallet/{user_id}/import")
async def import_credential(
    user_id: str,
    request: ImportCredentialRequest,
    conn = Depends(get_db_connection)
):
    """Import a credential into the wallet"""
    
    try:
        if request.import_method == "openid4vci" and request.credential_offer_uri:
            # Import from OpenID4VCI credential offer
            credential_data = await MultipazWalletSDK.import_credential_from_offer(
                request.credential_offer_uri
            )
        elif request.import_method == "direct" and request.credential_data:
            # Direct import of credential data
            credential_data = json.loads(request.credential_data)
        else:
            raise HTTPException(status_code=400, detail="Invalid import method or missing data")
        
        # Store credential in secure area
        credential_id = await MultipazWalletSDK.store_credential(
            credential_data=credential_data,
            user_consent=True
        )
        
        # Store metadata in database (for demo purposes)
        if credential_data.get("doctype") == "org.iso.18013.5.1.mDL":
            await conn.execute(
                """
                INSERT INTO credentials.mdls (
                    mdl_id, license_number, user_id, status,
                    personal_data, multipaz_data, created_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7)
                """,
                credential_id,
                credential_data["claims"].get("license_number", f"IMPORTED_{uuid.uuid4().hex[:8]}"),
                user_id,
                "ISSUED",
                json.dumps(credential_data["claims"]),
                json.dumps(credential_data),
                datetime.now(timezone.utc)
            )
        else:
            await conn.execute(
                """
                INSERT INTO credentials.mdocs (
                    mdoc_id, user_id, document_type, document_number, status,
                    credential_data, multipaz_data, created_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                """,
                credential_id,
                user_id,
                "IMPORTED_DOCUMENT",
                credential_data["claims"].get("document_number", f"IMPORTED_{uuid.uuid4().hex[:8]}"),
                "ISSUED",
                json.dumps(credential_data["claims"]),
                json.dumps(credential_data),
                datetime.now(timezone.utc)
            )
        
        return {
            "credential_id": credential_id,
            "status": "imported",
            "message": "Credential successfully imported into wallet"
        }
        
    except Exception as e:
        logger.error(f"Error importing credential for user {user_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to import credential: {str(e)}")

@app.post("/api/wallet/presentation/openid4vp")
async def create_openid4vp_presentation(
    request: PresentationRequest
):
    """Create presentation for OpenID4VP request"""
    
    try:
        # Parse presentation URI to get request parameters
        # In a real implementation, this would properly parse the URI
        presentation_id = str(uuid.uuid4())
        
        # Mock presentation definition
        presentation_definition = {
            "id": "demo_request",
            "input_descriptors": [
                {
                    "id": "credential_1",
                    "format": {"mso_mdoc": {"alg": ["ES256"]}}
                }
            ]
        }
        
        # Get relevant credentials for presentation
        credential_ids = ["demo_credential_1"]  # Mock selection
        
        # Create presentation using Multipaz SDK
        presentation = await MultipazWalletSDK.create_presentation(
            credential_ids=credential_ids,
            presentation_definition=presentation_definition,
            nonce=str(uuid.uuid4())
        )
        
        return {
            "presentation_id": presentation_id,
            "vp_token": presentation["vp_token"],
            "presentation_submission": presentation["presentation_submission"],
            "status": "created"
        }
        
    except Exception as e:
        logger.error(f"Error creating OpenID4VP presentation: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to create presentation: {str(e)}")

@app.post("/api/wallet/presentation/proximity")
async def create_proximity_presentation(
    request: ProximityPresentationRequest
):
    """Create presentation for proximity (ISO 18013-5) verification"""
    
    try:
        # Establish proximity session
        session_data = await MultipazWalletSDK.establish_proximity_session(
            verifier_engagement=request.verifier_engagement
        )
        
        # Get credentials with requested claims
        credential_ids = ["demo_credential_1"]  # Mock selection based on requested claims
        
        # Create presentation definition based on requested claims
        presentation_definition = {
            "id": "proximity_request",
            "input_descriptors": [
                {
                    "id": "proximity_credential",
                    "constraints": {
                        "fields": [
                            {"path": [f"$.{claim}"]} for claim in request.requested_claims
                        ]
                    }
                }
            ]
        }
        
        # Create presentation
        presentation = await MultipazWalletSDK.create_presentation(
            credential_ids=credential_ids,
            presentation_definition=presentation_definition,
            nonce=session_data["session_id"]
        )
        
        return {
            "session_id": session_data["session_id"],
            "presentation": presentation,
            "transport": "BLE",
            "status": "ready_to_present"
        }
        
    except Exception as e:
        logger.error(f"Error creating proximity presentation: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to create proximity presentation: {str(e)}")

@app.delete("/api/wallet/credentials/{credential_id}")
async def delete_credential(
    credential_id: str,
    conn = Depends(get_db_connection)
):
    """Delete a credential from the wallet"""
    
    try:
        # Delete from database (in real implementation, would also delete from secure area)
        mdoc_deleted = await conn.execute(
            "DELETE FROM credentials.mdocs WHERE mdoc_id = $1",
            credential_id
        )
        
        mdl_deleted = await conn.execute(
            "DELETE FROM credentials.mdls WHERE mdl_id = $1",
            credential_id
        )
        
        if mdoc_deleted == "DELETE 0" and mdl_deleted == "DELETE 0":
            raise HTTPException(status_code=404, detail="Credential not found")
        
        return {
            "credential_id": credential_id,
            "status": "deleted",
            "message": "Credential successfully removed from wallet"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting credential {credential_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to delete credential: {str(e)}")

@app.get("/api/wallet/demo/provision/{user_id}")
async def provision_demo_credentials(
    user_id: str
):
    """Provision demo credentials for a user (demo/testing only)"""
    
    try:
        # Create demo credential requests
        async with httpx.AsyncClient() as client:
            # Create mDL
            mdl_response = await client.post(
                f"{ISSUER_BASE_URL}/api/credentials/mdl",
                json={
                    "user_id": user_id,
                    "license_number": f"DL{uuid.uuid4().hex[:9].upper()}",
                    "person_info": {
                        "given_name": "Demo",
                        "family_name": "User",
                        "birth_date": "1990-01-01",
                        "nationality": "US"
                    },
                    "driving_privileges": {
                        "license_class": "C"
                    }
                }
            )
            
            # Create mDoc
            mdoc_response = await client.post(
                f"{ISSUER_BASE_URL}/api/credentials/mdoc",
                json={
                    "user_id": user_id,
                    "document_type": "ID_CARD",
                    "person_info": {
                        "given_name": "Demo",
                        "family_name": "User",
                        "birth_date": "1990-01-01",
                        "nationality": "US"
                    }
                }
            )
        
        return {
            "status": "provisioned",
            "credentials": [
                {"type": "mDL", "response": mdl_response.json() if mdl_response.status_code == 200 else None},
                {"type": "mDoc", "response": mdoc_response.json() if mdoc_response.status_code == 200 else None}
            ],
            "message": f"Demo credentials provisioned for user {user_id}"
        }
        
    except Exception as e:
        logger.error(f"Error provisioning demo credentials for user {user_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to provision demo credentials: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8082)