"""
OpenWallet Foundation mDoc/mDL Issuer Service

This service integrates with the Multipaz SDK to issue mDoc and mDL credentials
following ISO 18013-5 standards.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import asyncpg
import httpx
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration from environment
DATABASE_URL = f"postgresql://{os.getenv('POSTGRES_USER')}:{os.getenv('POSTGRES_PASSWORD')}@{os.getenv('POSTGRES_HOST')}:{os.getenv('POSTGRES_PORT')}/{os.getenv('POSTGRES_DB')}"
MULTIPAZ_SDK_VERSION = os.getenv("MULTIPAZ_SDK_VERSION", "0.94.0")
CREDENTIAL_FORMAT = os.getenv("CREDENTIAL_FORMAT", "mso_mdoc")
MDL_DOCTYPE = os.getenv("MDL_DOCTYPE", "org.iso.18013.5.1.mDL")

# FastAPI app
app = FastAPI(
    title="OpenWallet Foundation mDoc/mDL Issuer",
    description="Demo issuer service using Multipaz SDK for mDoc/mDL credentials",
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
class PersonInfo(BaseModel):
    given_name: str = Field(..., description="Given name")
    family_name: str = Field(..., description="Family name")
    birth_date: str = Field(..., description="Birth date in YYYY-MM-DD format")
    nationality: str = Field(default="US", description="Nationality code")
    gender: str | None = Field(default=None, description="Gender")
    place_of_birth: str | None = Field(default=None, description="Place of birth")


class DrivingPrivileges(BaseModel):
    license_class: str = Field(default="C", description="License class")
    restrictions: list[str] | None = Field(default=None, description="License restrictions")
    endorsements: list[str] | None = Field(default=None, description="License endorsements")


class CreateMDocRequest(BaseModel):
    user_id: str = Field(..., description="User identifier")
    document_type: str = Field(default="DRIVER_LICENSE", description="Document type")
    person_info: PersonInfo
    document_number: str | None = Field(default=None, description="Document number")
    issuing_authority: str = Field(default="Demo DMV", description="Issuing authority")
    issue_date: str | None = Field(default=None, description="Issue date in YYYY-MM-DD format")
    expiry_date: str | None = Field(default=None, description="Expiry date in YYYY-MM-DD format")


class CreateMDLRequest(CreateMDocRequest):
    license_number: str = Field(..., description="License number")
    driving_privileges: DrivingPrivileges = Field(default_factory=DrivingPrivileges)


class CredentialResponse(BaseModel):
    credential_id: str
    status: str
    document_type: str
    created_at: str
    multipaz_data: dict[str, Any] | None = None
    qr_code: str | None = None


# Database connection pool
db_pool: asyncpg.Pool | None = None


@app.on_event("startup")
async def startup():
    """Initialize database connection pool and setup demo data"""
    global db_pool

    logger.info(f"Starting OpenWallet Foundation Issuer Service")
    logger.info(f"Multipaz SDK Version: {MULTIPAZ_SDK_VERSION}")
    logger.info(f"Credential Format: {CREDENTIAL_FORMAT}")

    # Create database connection pool
    db_pool = await asyncpg.create_pool(DATABASE_URL)

    # Setup demo data if enabled
    if os.getenv("AUTO_PROVISION_SAMPLE_DATA", "false").lower() == "true":
        await setup_demo_data()


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
class MultipazSDK:
    """
    Mock implementation of Multipaz SDK integration.
    In a real implementation, this would use the actual Multipaz Kotlin/Java libraries
    via JNI or a REST API wrapper.
    """

    @staticmethod
    async def create_mdoc(
        doctype: str, claims: dict[str, Any], issuer_key: str, validity_period: timedelta
    ) -> dict[str, Any]:
        """Create an mDoc using Multipaz SDK"""

        # Mock mDoc creation - in reality this would use actual Multipaz SDK
        mock_mdoc = {
            "version": "1.0",
            "docType": doctype,
            "issuerSigned": {
                "nameSpaces": {"org.iso.18013.5.1": claims},
                "issuerAuth": {"signature": f"mock_signature_{uuid.uuid4()}", "algorithm": "ES256"},
            },
            "deviceSigned": {"deviceAuth": {"deviceSignature": f"mock_device_sig_{uuid.uuid4()}"}},
            "multipaz_metadata": {
                "sdk_version": MULTIPAZ_SDK_VERSION,
                "format": CREDENTIAL_FORMAT,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "validity_period_days": validity_period.days,
            },
        }

        return mock_mdoc

    @staticmethod
    async def generate_qr_code(mdoc_data: dict[str, Any]) -> str:
        """Generate QR code for offline presentation"""
        # Mock QR code generation
        qr_payload = {
            "mdoc_engagement": {
                "version": "1.0",
                "originInfos": [{"cat": 1, "typ": 1}],  # QR code  # Device engagement
                "deviceKey": f"mock_device_key_{uuid.uuid4()}",
            }
        }

        # In reality, this would generate an actual QR code image
        return f"data:image/png;base64,mock_qr_code_data_{uuid.uuid4()}"


async def setup_demo_data():
    """Setup sample demo data"""
    logger.info("Setting up demo data...")

    sample_users = [
        {
            "user_id": "demo-user-1",
            "given_name": "Alice",
            "family_name": "Smith",
            "birth_date": "1990-05-15",
            "license_number": "DL123456789",
        },
        {
            "user_id": "demo-user-2",
            "given_name": "Bob",
            "family_name": "Johnson",
            "birth_date": "1985-08-22",
            "license_number": "DL987654321",
        },
    ]

    async with db_pool.acquire() as conn:
        for user in sample_users:
            # Check if user already exists
            existing = await conn.fetchrow(
                "SELECT user_id FROM demo.sample_users WHERE user_id = $1", user["user_id"]
            )

            if not existing:
                await conn.execute(
                    """
                    INSERT INTO demo.sample_users (user_id, given_name, family_name, birth_date, nationality)
                    VALUES ($1, $2, $3, $4, 'US')
                    """,
                    user["user_id"],
                    user["given_name"],
                    user["family_name"],
                    user["birth_date"],
                )
                logger.info(f"Created demo user: {user['user_id']}")


# API Endpoints


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "openwallet-issuer", "version": "1.0.0"}


@app.get("/ready")
async def readiness_check():
    """Readiness check endpoint"""
    try:
        async with db_pool.acquire() as conn:
            await conn.fetchval("SELECT 1")
        return {"status": "ready", "database": "connected"}
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Service not ready: {str(e)}")


@app.get("/api/demo/users")
async def list_demo_users(conn=Depends(get_db_connection)):
    """List available demo users"""
    users = await conn.fetch("SELECT * FROM demo.sample_users")
    return [dict(user) for user in users]


@app.post("/api/credentials/mdoc", response_model=CredentialResponse)
async def create_mdoc(request: CreateMDocRequest, conn=Depends(get_db_connection)):
    """Create a new mDoc credential"""

    credential_id = str(uuid.uuid4())
    document_number = request.document_number or f"DOC{uuid.uuid4().hex[:8].upper()}"
    issue_date = request.issue_date or datetime.now(timezone.utc).date().isoformat()
    expiry_date = (
        request.expiry_date
        or (datetime.now(timezone.utc) + timedelta(days=365 * 10)).date().isoformat()
    )

    # Prepare claims for mDoc
    claims = {
        "given_name": request.person_info.given_name,
        "family_name": request.person_info.family_name,
        "birth_date": request.person_info.birth_date,
        "document_number": document_number,
        "issuing_authority": request.issuing_authority,
        "issue_date": issue_date,
        "expiry_date": expiry_date,
        "nationality": request.person_info.nationality,
    }

    if request.person_info.gender:
        claims["gender"] = request.person_info.gender
    if request.person_info.place_of_birth:
        claims["place_of_birth"] = request.person_info.place_of_birth

    # Create mDoc using Multipaz SDK
    try:
        multipaz_data = await MultipazSDK.create_mdoc(
            doctype=(
                "org.iso.18013.5.1"
                if request.document_type == "DRIVER_LICENSE"
                else "org.example.identity"
            ),
            claims=claims,
            issuer_key="demo_issuer_key",
            validity_period=timedelta(days=365 * 10),
        )

        # Generate QR code for offline presentation
        qr_code = await MultipazSDK.generate_qr_code(multipaz_data)

        # Store in database
        await conn.execute(
            """
            INSERT INTO credentials.mdocs (
                mdoc_id, user_id, document_type, document_number, status,
                issuing_authority, credential_data, multipaz_data, created_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            """,
            credential_id,
            request.user_id,
            request.document_type,
            document_number,
            "ISSUED",
            request.issuing_authority,
            json.dumps(claims),
            json.dumps(multipaz_data),
            datetime.now(timezone.utc),
        )

        return CredentialResponse(
            credential_id=credential_id,
            status="ISSUED",
            document_type=request.document_type,
            created_at=datetime.now(timezone.utc).isoformat(),
            multipaz_data=multipaz_data,
            qr_code=qr_code,
        )

    except Exception as e:
        logger.error(f"Error creating mDoc: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to create mDoc: {str(e)}")


@app.post("/api/credentials/mdl", response_model=CredentialResponse)
async def create_mdl(request: CreateMDLRequest, conn=Depends(get_db_connection)):
    """Create a new mDL (Mobile Driving License) credential"""

    credential_id = str(uuid.uuid4())
    issue_date = request.issue_date or datetime.now(timezone.utc).date().isoformat()
    expiry_date = (
        request.expiry_date
        or (datetime.now(timezone.utc) + timedelta(days=365 * 5)).date().isoformat()
    )

    # Check if license number already exists
    existing = await conn.fetchrow(
        "SELECT mdl_id FROM credentials.mdls WHERE license_number = $1", request.license_number
    )
    if existing:
        raise HTTPException(status_code=409, detail="License number already exists")

    # Prepare claims for mDL
    claims = {
        "given_name": request.person_info.given_name,
        "family_name": request.person_info.family_name,
        "birth_date": request.person_info.birth_date,
        "license_number": request.license_number,
        "license_class": request.driving_privileges.license_class,
        "issuing_authority": request.issuing_authority,
        "issue_date": issue_date,
        "expiry_date": expiry_date,
        "nationality": request.person_info.nationality,
    }

    if request.person_info.gender:
        claims["gender"] = request.person_info.gender
    if request.driving_privileges.restrictions:
        claims["restrictions"] = request.driving_privileges.restrictions
    if request.driving_privileges.endorsements:
        claims["endorsements"] = request.driving_privileges.endorsements

    # Create mDL using Multipaz SDK
    try:
        multipaz_data = await MultipazSDK.create_mdoc(
            doctype=MDL_DOCTYPE,
            claims=claims,
            issuer_key="demo_issuer_key",
            validity_period=timedelta(days=365 * 5),
        )

        # Generate QR code for offline presentation
        qr_code = await MultipazSDK.generate_qr_code(multipaz_data)

        # Store in database
        await conn.execute(
            """
            INSERT INTO credentials.mdls (
                mdl_id, license_number, user_id, status,
                license_class, driving_privileges, personal_data, multipaz_data, created_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            """,
            credential_id,
            request.license_number,
            request.user_id,
            "ISSUED",
            request.driving_privileges.license_class,
            json.dumps(request.driving_privileges.dict()),
            json.dumps(
                {
                    "given_name": request.person_info.given_name,
                    "family_name": request.person_info.family_name,
                    "birth_date": request.person_info.birth_date,
                    "nationality": request.person_info.nationality,
                    "gender": request.person_info.gender,
                    "place_of_birth": request.person_info.place_of_birth,
                }
            ),
            json.dumps(multipaz_data),
            datetime.now(timezone.utc),
        )

        return CredentialResponse(
            credential_id=credential_id,
            status="ISSUED",
            document_type="MOBILE_DRIVING_LICENSE",
            created_at=datetime.now(timezone.utc).isoformat(),
            multipaz_data=multipaz_data,
            qr_code=qr_code,
        )

    except Exception as e:
        logger.error(f"Error creating mDL: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to create mDL: {str(e)}")


@app.get("/api/credentials/{credential_id}")
async def get_credential(credential_id: str, conn=Depends(get_db_connection)):
    """Get a credential by ID"""

    # Try mDoc first
    credential = await conn.fetchrow(
        "SELECT * FROM credentials.mdocs WHERE mdoc_id = $1", credential_id
    )

    if not credential:
        # Try mDL
        credential = await conn.fetchrow(
            "SELECT * FROM credentials.mdls WHERE mdl_id = $1", credential_id
        )

    if not credential:
        raise HTTPException(status_code=404, detail="Credential not found")

    return dict(credential)


@app.get("/api/credentials/user/{user_id}")
async def get_user_credentials(user_id: str, conn=Depends(get_db_connection)):
    """Get all credentials for a user"""

    mdocs = await conn.fetch(
        "SELECT mdoc_id, document_type, status, created_at FROM credentials.mdocs WHERE user_id = $1",
        user_id,
    )

    mdls = await conn.fetch(
        "SELECT mdl_id as credential_id, 'MOBILE_DRIVING_LICENSE' as document_type, status, created_at FROM credentials.mdls WHERE user_id = $1",
        user_id,
    )

    credentials = []
    credentials.extend([dict(mdoc) for mdoc in mdocs])
    credentials.extend([dict(mdl) for mdl in mdls])

    return credentials


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8080)
