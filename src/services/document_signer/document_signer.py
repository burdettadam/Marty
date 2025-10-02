"""Document Signer service with SD-JWT VC issuance support - Refactored."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

import grpc
from cryptography.hazmat.primitives import hashes

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from marty_common.grpc_types import (
        DatabaseManager,
        GrpcServicerContext,
        ProtoMessage,
        ServiceDependencies,
    )

from marty_common.infrastructure import OutboxRepository
from marty_common.validation import RequestValidationError, validate_request
from marty_common.validation.schemas.document_signer import (
    CreateCredentialOfferRequestSchema,
    GetCredentialOfferRequestSchema,
    IssueSdJwtCredentialRequestSchema,
    RedeemPreAuthorizedCodeRequestSchema,
    SignDocumentRequestSchema,
)
from marty_common.vc import SdJwtConfig
from proto import (
    csca_service_pb2,
    csca_service_pb2_grpc,
    document_signer_pb2,
    document_signer_pb2_grpc,
)

# Import our refactored modules (using dummy imports for now to avoid protobuf issues)
try:
    from .certificate_manager import CertificateManager
    from .sd_jwt_manager import SdJwtManager
    from .storage_manager import StorageManager
    from .utils import build_event_payload, seconds_until
except ImportError:
    # Fallback for when imports fail during development
    CertificateManager = None  # type: ignore[attr-defined]
    SdJwtManager = None  # type: ignore[attr-defined]
    StorageManager = None  # type: ignore[attr-defined]

    def build_event_payload(
        document_id: str,
        payload_hash: bytes,
        storage_key: str,
        signing_key_id: str,
    ) -> dict[str, Any]:
        return {
            "document_id": document_id,
            "hash_algo": "SHA256",
            "hash": payload_hash.hex(),
            "signature_location": storage_key,
            "signer": signing_key_id,
        }

    def seconds_until(moment: datetime) -> int:
        now = datetime.now(timezone.utc)
        delta = max(moment - now, timedelta(0))
        return int(delta.total_seconds())


class DocumentSigner(document_signer_pb2_grpc.DocumentSignerServicer):
    """Document signer using secure key vault, storage, and event bus."""

    def __init__(
        self,
        channels: dict[str, grpc.Channel] | None = None,
        dependencies: ServiceDependencies | None = None,
    ) -> None:
        if dependencies is None:
            msg = "DocumentSigner requires service dependencies"
            raise ValueError(msg)

        self.logger = logging.getLogger(__name__)
        self.channels = channels or {}
        self._database: DatabaseManager = dependencies.database
        self._key_vault = dependencies.key_vault
        self._object_storage = dependencies.object_storage

        service_config = dependencies.runtime_config.get_service("document_signer")
        self._signing_key_id = service_config.get("signing_key_id", "document-signer-default")
        self._signing_algorithm = service_config.get("signing_algorithm", "rsa2048")

        # SD-JWT configuration
        sd_jwt_settings = service_config.get("sd_jwt", {}) or {}
        issuer = sd_jwt_settings.get("issuer")
        self._sd_jwt_enabled = bool(issuer)

        if self._sd_jwt_enabled:
            self._setup_sd_jwt_components(sd_jwt_settings)
        else:
            self.logger.info("SD-JWT issuance disabled; issuer configuration missing")
            self._sd_jwt_manager = None
            self._certificate_manager = None
            self._storage_manager = None

    def _setup_sd_jwt_components(self, sd_jwt_settings: dict[str, Any]) -> None:
        """Initialize SD-JWT related components."""
        # Certificate management
        signing_key_id = sd_jwt_settings.get("signing_key_id", "document-signer-cert")
        vault_algorithm = sd_jwt_settings.get("vault_signing_algorithm", "ecdsa-p256")
        certificate_ids = sd_jwt_settings.get(
            "x5c_certificate_ids",
            [sd_jwt_settings.get("certificate_id", "document-signer-cert")],
        )

        if CertificateManager:
            self._certificate_manager = CertificateManager(
                database=self._database,
                key_vault=self._key_vault,
                signing_key_id=signing_key_id,
                vault_algorithm=vault_algorithm,
                certificate_ids=certificate_ids,
            )

        # Storage management
        storage_prefix = sd_jwt_settings.get("storage_prefix", "sd-jwt")
        if StorageManager:
            self._storage_manager = StorageManager(
                object_storage=self._object_storage,
                storage_prefix=storage_prefix,
            )

        # SD-JWT configuration and manager
        credential_ttl_seconds = int(sd_jwt_settings.get("credential_ttl_seconds", 60 * 60 * 24))
        offer_ttl = timedelta(seconds=int(sd_jwt_settings.get("offer_ttl_seconds", 600)))
        token_ttl = timedelta(seconds=int(sd_jwt_settings.get("token_ttl_seconds", 600)))
        default_credential_type = sd_jwt_settings.get(
            "default_credential_type", "VerifiableCredential"
        )

        sd_jwt_config = SdJwtConfig(
            issuer=sd_jwt_settings.get("issuer"),
            signing_key_id=signing_key_id,
            signing_algorithm=sd_jwt_settings.get("signing_algorithm", "ES256"),
            kid=sd_jwt_settings.get("kid"),
            default_expiry=timedelta(seconds=credential_ttl_seconds),
            audience=sd_jwt_settings.get("default_audience"),
        )

        if SdJwtManager and self._certificate_manager:
            self._sd_jwt_manager = SdJwtManager(
                database=self._database,
                key_vault=self._key_vault,
                object_storage=self._object_storage,
                certificate_chain_provider=self._certificate_manager.get_certificate_chain,
                config=sd_jwt_config,
                offer_ttl=offer_ttl,
                token_ttl=token_ttl,
                default_credential_type=default_credential_type,
            )

    def _error(
        self,
        code: int,
        message: str,
        *,
        details: dict[str, str] | None = None,
    ) -> document_signer_pb2.ApiError:
        """Create a standardized API error response."""
        detail_payload = {key: str(value) for key, value in (details or {}).items()}
        return document_signer_pb2.ApiError(code=code, message=message, details=detail_payload)

    # ------------------------------------------------------------------
    # Document signing endpoint
    # ------------------------------------------------------------------
    async def SignDocument(
        self,
        request: ProtoMessage,  # document_signer_pb2.SignRequest
        context: GrpcServicerContext,  # grpc.ServicerContext
    ) -> ProtoMessage:  # document_signer_pb2.SignResponse
        try:
            payload = validate_request(SignDocumentRequestSchema, request)
        except RequestValidationError as exc:
            error = self._error(
                document_signer_pb2.DOCUMENT_SIGNER_ERROR_INVALID_ARGUMENT,
                str(exc),
                details=exc.details_map(),
            )
            return document_signer_pb2.SignResponse(
                success=False, error_message=error.message, error=error
            )

        document_id = payload.document_id
        document_bytes = payload.document_content

        try:
            await self._key_vault.ensure_key(self._signing_key_id, self._signing_algorithm)
            signature = await self._key_vault.sign(
                self._signing_key_id,
                document_bytes,
                self._signing_algorithm,
            )

            digest = hashes.Hash(hashes.SHA256())
            digest.update(document_bytes)
            payload_hash = digest.finalize()

            # Store signature using storage manager if available, otherwise use direct storage
            if self._storage_manager:
                storage_key = await self._storage_manager.store_signature(
                    document_id, signature, int(datetime.now(timezone.utc).timestamp())
                )
            else:
                storage_key = (
                    f"signatures/{document_id}-"
                    f"{int(datetime.now(timezone.utc).timestamp())}.sig"
                )
                await self._object_storage.put_object(storage_key, signature)

            await self._sync_csca_certificate()

            event_payload = build_event_payload(
                document_id, payload_hash, storage_key, self._signing_key_id
            )

            async def handler(session: AsyncSession) -> None:
                outbox = OutboxRepository(session)
                await outbox.enqueue(
                    topic="credential.issued",
                    payload=json.dumps(event_payload).encode("utf-8"),
                    key=document_id.encode("utf-8"),
                )

            await self._database.run_within_transaction(handler)

            signature_info = document_signer_pb2.SignatureInfo(
                signature_date=datetime.now(timezone.utc).isoformat(),
                signer_id=self._signing_key_id,
                signature=signature,
            )
            return document_signer_pb2.SignResponse(success=True, signature_info=signature_info)
        except Exception as exc:  # pylint: disable=broad-except
            self.logger.exception("Failed to sign document %s", document_id)
            error = self._error(
                document_signer_pb2.DOCUMENT_SIGNER_ERROR_SIGNING_FAILED,
                str(exc),
            )
            return document_signer_pb2.SignResponse(
                success=False, error_message=error.message, error=error
            )

    # ------------------------------------------------------------------
    # SD-JWT gRPC endpoints
    # ------------------------------------------------------------------
    async def CreateCredentialOffer(
        self,
        request: ProtoMessage,  # document_signer_pb2.CreateCredentialOfferRequest
        context: GrpcServicerContext,  # grpc.ServicerContext
    ) -> ProtoMessage:  # document_signer_pb2.CreateCredentialOfferResponse
        if not self._sd_jwt_enabled or not self._sd_jwt_manager:
            error = self._error(
                document_signer_pb2.DOCUMENT_SIGNER_ERROR_NOT_CONFIGURED,
                "SD-JWT issuance is not configured",
            )
            return document_signer_pb2.CreateCredentialOfferResponse(error=error)

        try:
            payload = validate_request(CreateCredentialOfferRequestSchema, request)
        except RequestValidationError as exc:
            error = self._error(
                document_signer_pb2.DOCUMENT_SIGNER_ERROR_INVALID_ARGUMENT,
                str(exc),
                details=exc.details_map(),
            )
            return document_signer_pb2.CreateCredentialOfferResponse(error=error)

        try:
            if self._certificate_manager:
                await self._certificate_manager.ensure_document_signer_certificate()

            (
                offer_id,
                offer_dict,
                pre_authorized_code,
                expires_in,
            ) = await self._sd_jwt_manager.create_credential_offer(
                subject_id=payload.subject_id,
                credential_type=payload.credential_type,
                base_claims=payload.base_claims,
                selective_disclosures=payload.selective_disclosures,
                metadata=payload.metadata,
            )
        except Exception as exc:  # pylint: disable=broad-except
            self.logger.exception("Failed to create credential offer for %s", payload.subject_id)
            error = self._error(
                document_signer_pb2.DOCUMENT_SIGNER_ERROR_SIGNING_FAILED,
                str(exc),
            )
            return document_signer_pb2.CreateCredentialOfferResponse(error=error)

        return document_signer_pb2.CreateCredentialOfferResponse(
            offer_id=offer_id,
            credential_offer=json.dumps(offer_dict),
            pre_authorized_code=pre_authorized_code,
            expires_in=expires_in,
        )

    async def GetCredentialOffer(
        self,
        request: ProtoMessage,  # document_signer_pb2.GetCredentialOfferRequest
        context: GrpcServicerContext,  # grpc.ServicerContext
    ) -> ProtoMessage:  # document_signer_pb2.GetCredentialOfferResponse
        if not self._sd_jwt_enabled or not self._sd_jwt_manager:
            error = self._error(
                document_signer_pb2.DOCUMENT_SIGNER_ERROR_NOT_CONFIGURED,
                "SD-JWT issuance is not configured",
            )
            return document_signer_pb2.GetCredentialOfferResponse(error=error)

        try:
            payload = validate_request(GetCredentialOfferRequestSchema, request)
        except RequestValidationError as exc:
            error = self._error(
                document_signer_pb2.DOCUMENT_SIGNER_ERROR_INVALID_ARGUMENT,
                str(exc),
                details=exc.details_map(),
            )
            return document_signer_pb2.GetCredentialOfferResponse(error=error)

        result = await self._sd_jwt_manager.get_credential_offer(payload.offer_id)
        if result is None:
            error = self._error(
                document_signer_pb2.DOCUMENT_SIGNER_ERROR_OFFER_NOT_FOUND,
                "Credential offer not found",
                details={"offer_id": payload.offer_id},
            )
            return document_signer_pb2.GetCredentialOfferResponse(error=error)

        offer_dict, expires_in, pre_auth_code = result
        return document_signer_pb2.GetCredentialOfferResponse(
            credential_offer=json.dumps(offer_dict),
            expires_in=expires_in,
            pre_authorized_code=pre_auth_code,
        )

    async def RedeemPreAuthorizedCode(
        self,
        request: ProtoMessage,  # document_signer_pb2.RedeemPreAuthorizedCodeRequest
        context: GrpcServicerContext,  # grpc.ServicerContext
    ) -> ProtoMessage:  # document_signer_pb2.RedeemPreAuthorizedCodeResponse
        if not self._sd_jwt_enabled or not self._sd_jwt_manager:
            error = self._error(
                document_signer_pb2.DOCUMENT_SIGNER_ERROR_NOT_CONFIGURED,
                "SD-JWT issuance is not configured",
            )
            return document_signer_pb2.RedeemPreAuthorizedCodeResponse(error=error)

        try:
            payload = validate_request(RedeemPreAuthorizedCodeRequestSchema, request)
        except RequestValidationError as exc:
            error = self._error(
                document_signer_pb2.DOCUMENT_SIGNER_ERROR_INVALID_ARGUMENT,
                str(exc),
                details=exc.details_map(),
            )
            return document_signer_pb2.RedeemPreAuthorizedCodeResponse(error=error)

        result = await self._sd_jwt_manager.redeem_pre_authorized_code(
            payload.pre_authorized_code,
            payload.wallet_attestation,
        )

        if result is None:
            error = self._error(
                document_signer_pb2.DOCUMENT_SIGNER_ERROR_OFFER_NOT_FOUND,
                "Unknown or expired pre-authorized code",
                details={"pre_authorized_code": payload.pre_authorized_code},
            )
            return document_signer_pb2.RedeemPreAuthorizedCodeResponse(error=error)

        offer_id, access_token, expires_in, c_nonce = result
        return document_signer_pb2.RedeemPreAuthorizedCodeResponse(
            offer_id=offer_id,
            access_token=access_token,
            expires_in=expires_in,
            c_nonce=c_nonce,
        )

    async def IssueSdJwtCredential(
        self,
        request: ProtoMessage,  # document_signer_pb2.IssueSdJwtCredentialRequest
        context: GrpcServicerContext,  # grpc.ServicerContext
    ) -> ProtoMessage:  # document_signer_pb2.IssueSdJwtCredentialResponse
        if not self._sd_jwt_enabled or not self._sd_jwt_manager:
            error = self._error(
                document_signer_pb2.DOCUMENT_SIGNER_ERROR_NOT_CONFIGURED,
                "SD-JWT issuance is not configured",
            )
            return document_signer_pb2.IssueSdJwtCredentialResponse(error=error)

        try:
            payload = validate_request(IssueSdJwtCredentialRequestSchema, request)
        except RequestValidationError as exc:
            error = self._error(
                document_signer_pb2.DOCUMENT_SIGNER_ERROR_INVALID_ARGUMENT,
                str(exc),
                details=exc.details_map(),
            )
            return document_signer_pb2.IssueSdJwtCredentialResponse(error=error)

        try:
            if self._certificate_manager:
                await self._certificate_manager.ensure_document_signer_certificate()
                await self._certificate_manager.refresh_certificate_cache()

            result = await self._sd_jwt_manager.issue_sd_jwt_credential(
                access_token=payload.access_token,
                disclose_claims=payload.disclose_claims,
                audience=payload.audience,
                nonce=payload.nonce,
                wallet_attestation=payload.wallet_attestation,
            )

            if result is None:
                error = self._error(
                    document_signer_pb2.DOCUMENT_SIGNER_ERROR_TOKEN_INVALID,
                    "Invalid or expired access token",
                    details={"access_token": payload.access_token},
                )
                return document_signer_pb2.IssueSdJwtCredentialResponse(error=error)

            (
                token,
                disclosures,
                credential_id,
                expires_in,
                format_type,
                sd_jwt_location,
                disclosures_location,
                issuer,
                credential_type,
                subject_id,
            ) = result

        except Exception as exc:  # pylint: disable=broad-except
            self.logger.exception("Failed to issue SD-JWT credential")
            error = self._error(
                document_signer_pb2.DOCUMENT_SIGNER_ERROR_SIGNING_FAILED,
                str(exc),
            )
            return document_signer_pb2.IssueSdJwtCredentialResponse(error=error)

        return document_signer_pb2.IssueSdJwtCredentialResponse(
            credential=token,
            disclosures=list(disclosures),
            credential_id=credential_id,
            expires_in=expires_in,
            format=format_type,
            sd_jwt_location=sd_jwt_location,
            disclosures_location=disclosures_location,
            issuer=issuer,
            credential_type=credential_type,
            subject_id=subject_id,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    async def _sync_csca_certificate(self) -> None:
        """Sync CSCA certificate from CSCA service."""
        channel = self.channels.get("csca_service")
        if not channel:
            self.logger.debug("CSCA channel unavailable; skipping certificate sync")
            return

        stub = csca_service_pb2_grpc.CscaServiceStub(channel)
        try:
            response = await stub.GetCscaData(csca_service_pb2.CscaRequest(id="document-signer"))
        except grpc.RpcError as rpc_err:
            self.logger.exception("Failed to fetch CSCA data: %s", rpc_err.details())
            return

        pem_data = response.data

        async def handler(session) -> None:
            from marty_common.infrastructure import CertificateRepository

            repo = CertificateRepository(session)
            await repo.upsert("document-signer-csca", "CSCA", pem_data)

        await self._database.run_within_transaction(handler)


__all__ = ["DocumentSigner"]
