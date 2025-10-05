"""OID4VCI Issuer API - FastAPI REST facade for Document Signer gRPC service."""

from __future__ import annotations

import json
import logging
from typing import Any

import grpc
from fastapi import FastAPI, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from src.proto.v1 import document_signer_pb2, document_signer_pb2_grpc

logger = logging.getLogger(__name__)

app = FastAPI(
    title="OID4VCI Issuer API",
    description="OpenID for Verifiable Credential Issuance - REST API facade",
    version="1.0.0"
)

# gRPC client setup
GRPC_DOCUMENT_SIGNER_ADDRESS = "localhost:50051"  # This should come from config
channel: grpc.Channel | None = None
document_signer_stub: document_signer_pb2_grpc.DocumentSignerStub | None = None


def get_grpc_client() -> document_signer_pb2_grpc.DocumentSignerStub:
    """Get or create the gRPC client."""
    global channel, document_signer_stub
    
    if document_signer_stub is None:
        channel = grpc.insecure_channel(GRPC_DOCUMENT_SIGNER_ADDRESS)
        document_signer_stub = document_signer_pb2_grpc.DocumentSignerStub(channel)
    
    return document_signer_stub


# Pydantic models for OID4VCI
class CredentialOfferRequest(BaseModel):
    """Request to create a credential offer."""
    subject_id: str = Field(..., description="Subject identifier for the credential")
    credential_type: str = Field(default="VerifiableCredential", description="Type of credential to issue")
    base_claims: dict[str, Any] = Field(..., description="Base claims for the credential")
    selective_disclosures: dict[str, Any] = Field(..., description="Claims available for selective disclosure")
    metadata: dict[str, Any] | None = Field(default=None, description="Additional metadata")


class TokenRequest(BaseModel):
    """Token request for OID4VCI."""
    grant_type: str = Field(..., description="Grant type (pre-authorized_code)")
    pre_authorized_code: str = Field(alias="pre-authorized_code", description="Pre-authorized code")
    wallet_attestation: dict[str, Any] | None = Field(default=None, description="Wallet attestation")


class CredentialRequest(BaseModel):
    """Credential request for OID4VCI."""
    format: str = Field(default="sd-jwt", description="Credential format")
    disclose_claims: list[str] = Field(default_factory=list, description="Claims to disclose")
    audience: str | None = Field(default=None, description="Intended audience")
    nonce: str | None = Field(default=None, description="Nonce for proof of possession")
    wallet_attestation: dict[str, Any] | None = Field(default=None, description="Wallet attestation")


@app.get("/.well-known/openid-credential-issuer")
async def openid_credential_issuer_metadata() -> dict[str, Any]:
    """Return OpenID Credential Issuer metadata."""
    return {
        "credential_issuer": "https://issuer.example.com",  # Should come from config
        "authorization_servers": ["https://issuer.example.com"],
        "credential_endpoint": "/credential",
        "token_endpoint": "/token",
        "credentials_supported": [
            {
                "format": "sd-jwt",
                "credential_definition": {
                    "type": ["VerifiableCredential"],
                    "credentialSubject": {
                        "given_name": {"display": [{"name": "Given Name", "locale": "en"}]},
                        "family_name": {"display": [{"name": "Family Name", "locale": "en"}]},
                        "email": {"display": [{"name": "Email", "locale": "en"}]},
                        "birthdate": {"display": [{"name": "Date of Birth", "locale": "en"}]}
                    }
                },
                "display": [
                    {
                        "name": "Verifiable Credential",
                        "locale": "en",
                        "background_color": "#12107c",
                        "text_color": "#FFFFFF"
                    }
                ]
            }
        ],
        "display": [
            {
                "name": "Example Issuer",
                "locale": "en",
                "logo": {
                    "url": "https://issuer.example.com/logo.png",
                    "alt_text": "Example Issuer Logo"
                }
            }
        ]
    }


@app.post("/credential-offer")
async def create_credential_offer(request: CredentialOfferRequest) -> dict[str, Any]:
    """Create a credential offer."""
    try:
        client = get_grpc_client()
        
        grpc_request = document_signer_pb2.CreateCredentialOfferRequest(
            subject_id=request.subject_id,
            credential_type=request.credential_type,
            base_claims_json=json.dumps(request.base_claims),
            selective_disclosures_json=json.dumps(request.selective_disclosures),
            metadata_json=json.dumps(request.metadata) if request.metadata else ""
        )
        
        response = await client.CreateCredentialOffer(grpc_request)
        
        if response.error and response.error.code != 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to create credential offer: {response.error.message}"
            )
        
        return {
            "offer_id": response.offer_id,
            "credential_offer": json.loads(response.credential_offer),
            "pre_authorized_code": response.pre_authorized_code,
            "expires_in": response.expires_in
        }
        
    except grpc.RpcError as e:
        logger.exception("gRPC error creating credential offer")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Service error: {e.details()}"
        ) from e
    except Exception as e:
        logger.exception("Unexpected error creating credential offer")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        ) from e


@app.post("/token")
async def token_endpoint(request: TokenRequest) -> dict[str, Any]:
    """Token endpoint for OID4VCI flow."""
    if request.grant_type != "urn:ietf:params:oauth:grant-type:pre-authorized_code":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported grant type"
        )
    
    try:
        client = get_grpc_client()
        
        grpc_request = document_signer_pb2.RedeemPreAuthorizedCodeRequest(
            pre_authorized_code=request.pre_authorized_code,
            wallet_attestation=json.dumps(request.wallet_attestation) if request.wallet_attestation else ""
        )
        
        response = await client.RedeemPreAuthorizedCode(grpc_request)
        
        if response.error and response.error.code != 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to redeem code: {response.error.message}"
            )
        
        return {
            "access_token": response.access_token,
            "token_type": "Bearer",
            "expires_in": response.expires_in,
            "c_nonce": response.c_nonce
        }
        
    except grpc.RpcError as e:
        logger.exception("gRPC error redeeming pre-authorized code")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Service error: {e.details()}"
        ) from e
    except Exception as e:
        logger.exception("Unexpected error redeeming pre-authorized code")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        ) from e


@app.post("/credential")
async def credential_endpoint(
    request: CredentialRequest,
    authorization: str = None  # Should be extracted from header
) -> dict[str, Any]:
    """Credential endpoint for OID4VCI flow."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid authorization header"
        )
    
    access_token = authorization[7:]  # Remove "Bearer " prefix
    
    try:
        client = get_grpc_client()
        
        grpc_request = document_signer_pb2.IssueSdJwtCredentialRequest(
            access_token=access_token,
            disclose_claims=request.disclose_claims,
            audience=request.audience or "",
            nonce=request.nonce or "",
            wallet_attestation=json.dumps(request.wallet_attestation) if request.wallet_attestation else ""
        )
        
        response = await client.IssueSdJwtCredential(grpc_request)
        
        if response.error and response.error.code != 0:
            if response.error.code == 6:  # TOKEN_INVALID
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid or expired access token"
                )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to issue credential: {response.error.message}"
            )
        
        return {
            "credential": response.credential,
            "disclosures": response.disclosures,
            "format": response.format,
            "credential_id": response.credential_id,
            "expires_in": response.expires_in,
            "sd_jwt_location": response.sd_jwt_location,
            "disclosures_location": response.disclosures_location,
            "issuer": response.issuer,
            "credential_type": response.credential_type,
            "subject_id": response.subject_id
        }
        
    except grpc.RpcError as e:
        logger.exception("gRPC error issuing credential")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Service error: {e.details()}"
        ) from e
    except Exception as e:
        logger.exception("Unexpected error issuing credential")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        ) from e


@app.get("/health")
async def health_check() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)