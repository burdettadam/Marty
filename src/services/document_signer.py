"""Document Signer service with SD-JWT VC issuance support."""

from __future__ import annotations

import json
import logging
import secrets
from datetime import datetime, timedelta, timezone

import grpc
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from marty_common.infrastructure import (
    CertificateRepository,
    KeyVaultClient,
    ObjectStorageClient,
    OutboxRepository,
)
from marty_common.vc import (
    CredentialOffer,
    CredentialOfferGrant,
    CredentialOfferGrantPreAuthorizedCode,
    SdJwtConfig,
    SdJwtIssuanceInput,
    SdJwtIssuer,
)
from proto import (
    csca_service_pb2,
    csca_service_pb2_grpc,
    document_signer_pb2,
    document_signer_pb2_grpc,
)
from src.marty_common.crypto.document_signer_certificate import (
    DOCUMENT_SIGNER_CERT_ID,
    load_or_create_document_signer_certificate,
)
from src.marty_common.infrastructure.repositories import (
    CredentialLedgerRepository,
    OidcSessionRepository,
    SdJwtCredentialRepository,
)


def _seconds_until(moment: datetime) -> int:
    """Return the number of whole seconds from now until ``moment`` (>=0)."""

    now = datetime.now(timezone.utc)
    delta = max(moment - now, timedelta(0))
    return int(delta.total_seconds())


class DocumentSigner(document_signer_pb2_grpc.DocumentSignerServicer):
    """Document signer using secure key vault, storage, and event bus."""

    def __init__(self, channels=None, dependencies=None) -> None:
        if dependencies is None:
            msg = "DocumentSigner requires service dependencies"
            raise ValueError(msg)
        self.logger = logging.getLogger(__name__)
        self.channels = channels or {}
        self._database = dependencies.database
        self._key_vault: KeyVaultClient = dependencies.key_vault
        self._object_storage: ObjectStorageClient = dependencies.object_storage
        service_config = dependencies.runtime_config.get_service("document_signer")
        self._signing_key_id = service_config.get("signing_key_id", "document-signer-default")
        self._signing_algorithm = service_config.get("signing_algorithm", "rsa2048")

        sd_jwt_settings = service_config.get("sd_jwt", {}) or {}
        issuer = sd_jwt_settings.get("issuer")
        self._sd_jwt_enabled = bool(issuer)
        self._sd_jwt_signing_key_id = sd_jwt_settings.get("signing_key_id", DOCUMENT_SIGNER_CERT_ID)
        self._sd_jwt_vault_algorithm = sd_jwt_settings.get("vault_signing_algorithm", "ecdsa-p256")
        self._sd_jwt_certificate_ids = sd_jwt_settings.get(
            "x5c_certificate_ids",
            [sd_jwt_settings.get("certificate_id", DOCUMENT_SIGNER_CERT_ID)],
        )
        credential_ttl_seconds = int(sd_jwt_settings.get("credential_ttl_seconds", 60 * 60 * 24))
        self._sd_jwt_offer_ttl = timedelta(seconds=int(sd_jwt_settings.get("offer_ttl_seconds", 600)))
        self._sd_jwt_token_ttl = timedelta(seconds=int(sd_jwt_settings.get("token_ttl_seconds", 600)))
        self._sd_jwt_storage_prefix = sd_jwt_settings.get("storage_prefix", "sd-jwt").rstrip("/")
        self._sd_jwt_default_type = sd_jwt_settings.get("default_credential_type", "VerifiableCredential")

        self._sd_jwt_issuer: SdJwtIssuer | None = None
        if self._sd_jwt_enabled:
            self._sd_jwt_config = SdJwtConfig(
                issuer=issuer,
                signing_key_id=self._sd_jwt_signing_key_id,
                signing_algorithm=sd_jwt_settings.get("signing_algorithm", "ES256"),
                kid=sd_jwt_settings.get("kid"),
                default_expiry=timedelta(seconds=credential_ttl_seconds),
                audience=sd_jwt_settings.get("default_audience"),
            )
            self._sd_jwt_issuer = SdJwtIssuer(
                self._key_vault,
                self._certificate_chain_provider,
                self._sd_jwt_config,
            )
        else:
            self.logger.info("SD-JWT issuance disabled; issuer configuration missing")

        self._cached_certificate_chain: list[x509.Certificate] = []
        self.logger.info("Document Signer service initialized with secure key vault")

    # ------------------------------------------------------------------
    # Existing signing endpoint
    # ------------------------------------------------------------------
    async def SignDocument(self, request, context):  # noqa: N802
        document_id = request.document_id or ""
        payload = request.document_content

        if not document_id:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "document_id is required")
            return document_signer_pb2.SignResponse(success=False, error_message="document_id missing")

        if not payload:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "document_content is required")
            return document_signer_pb2.SignResponse(success=False, error_message="document_content missing")

        try:
            await self._key_vault.ensure_key(self._signing_key_id, self._signing_algorithm)
            signature = await self._key_vault.sign(
                self._signing_key_id, payload, self._signing_algorithm
            )

            digest = hashes.Hash(hashes.SHA256())
            digest.update(payload)
            payload_hash = digest.finalize()

            storage_key = f"signatures/{document_id}-{int(datetime.now(timezone.utc).timestamp())}.sig"
            await self._object_storage.put_object(storage_key, signature)

            await self._sync_csca_certificate()

            event_payload = self._build_event_payload(document_id, payload_hash, storage_key)

            async def handler(session):
                outbox = OutboxRepository(session)
                await outbox.enqueue(
                    topic="credential.issued",
                    payload=event_payload,
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
            await context.abort(grpc.StatusCode.INTERNAL, str(exc))
            return document_signer_pb2.SignResponse(success=False, error_message=str(exc))

    # ------------------------------------------------------------------
    # SD-JWT gRPC endpoints
    # ------------------------------------------------------------------
    async def CreateCredentialOffer(self, request, context):  # noqa: N802
        if not self._sd_jwt_enabled or self._sd_jwt_issuer is None:
            await context.abort(grpc.StatusCode.UNIMPLEMENTED, "SD-JWT issuance is not configured")
            return document_signer_pb2.CreateCredentialOfferResponse()

        subject_id = (request.subject_id or "").strip()
        if not subject_id:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "subject_id is required")
            return document_signer_pb2.CreateCredentialOfferResponse()

        try:
            base_claims = json.loads(request.base_claims_json or "{}")
            selective_disclosures = json.loads(request.selective_disclosures_json or "{}")
            metadata = json.loads(request.metadata_json) if request.metadata_json else None
        except json.JSONDecodeError as exc:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, f"Invalid JSON payload: {exc}")
            return document_signer_pb2.CreateCredentialOfferResponse()

        if not isinstance(base_claims, dict) or not isinstance(selective_disclosures, dict):
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "claims must be JSON objects")
            return document_signer_pb2.CreateCredentialOfferResponse()

        credential_type = (request.credential_type or self._sd_jwt_default_type).strip() or self._sd_jwt_default_type
        now = datetime.now(timezone.utc)
        expires_at = now + self._sd_jwt_offer_ttl
        offer_id = secrets.token_urlsafe(16)
        pre_authorized_code = secrets.token_urlsafe(24)

        credentials_entry = {
            "format": "vc+sd-jwt",
            "types": [credential_type],
        }
        configuration_ids = None
        if metadata and isinstance(metadata, dict):
            configuration_ids = metadata.get("credential_configuration_ids")
            if configuration_ids is not None and not isinstance(configuration_ids, list):
                configuration_ids = None

        offer = CredentialOffer(
            credential_issuer=self._sd_jwt_config.issuer,
            credentials=[credentials_entry],
            grants=CredentialOfferGrant(
                pre_authorized_code=CredentialOfferGrantPreAuthorizedCode(
                    pre_authorized_code=pre_authorized_code,
                    user_pin_required=False,
                )
            ),
            credential_configuration_ids=configuration_ids,
            session_id=offer_id,
        )
        offer_dict = offer.to_dict()

        await self._key_vault.ensure_key(self._sd_jwt_signing_key_id, self._sd_jwt_vault_algorithm)
        await self._ensure_document_signer_certificate()

        async def handler(session):
            repo = OidcSessionRepository(session)
            await repo.create_offer(
                offer_id=offer_id,
                subject_id=subject_id,
                credential_type=credential_type,
                base_claims=base_claims,
                selective_disclosures=selective_disclosures,
                offer_payload=offer_dict,
                pre_authorized_code=pre_authorized_code,
                expires_at=expires_at,
                metadata=metadata,
            )

        await self._database.run_within_transaction(handler)

        return document_signer_pb2.CreateCredentialOfferResponse(
            offer_id=offer_id,
            credential_offer=json.dumps(offer_dict),
            pre_authorized_code=pre_authorized_code,
            expires_in=_seconds_until(expires_at),
        )

    async def GetCredentialOffer(self, request, context):  # noqa: N802
        if not self._sd_jwt_enabled or self._sd_jwt_issuer is None:
            await context.abort(grpc.StatusCode.UNIMPLEMENTED, "SD-JWT issuance is not configured")
            return document_signer_pb2.GetCredentialOfferResponse()

        offer_id = (request.offer_id or "").strip()
        if not offer_id:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "offer_id is required")
            return document_signer_pb2.GetCredentialOfferResponse()

        async def handler(session):
            repo = OidcSessionRepository(session)
            return await repo.get_by_offer_id(offer_id)

        record = await self._database.run_within_transaction(handler)
        if record is None:
            await context.abort(grpc.StatusCode.NOT_FOUND, "offer not found")
            return document_signer_pb2.GetCredentialOfferResponse()

        expires_in = _seconds_until(record.pre_authorized_code_expires_at)
        pre_auth_code = ""
        metadata = record.extra_metadata or {}
        internal = metadata.get("_internal", {}) if isinstance(metadata, dict) else {}
        if isinstance(internal, dict):
            pre_auth_code = internal.get("pre_authorized_code", "")

        return document_signer_pb2.GetCredentialOfferResponse(
            credential_offer=json.dumps(record.offer_payload or {}),
            expires_in=expires_in,
            pre_authorized_code=pre_auth_code,
        )

    async def RedeemPreAuthorizedCode(self, request, context):  # noqa: N802
        if not self._sd_jwt_enabled or self._sd_jwt_issuer is None:
            await context.abort(grpc.StatusCode.UNIMPLEMENTED, "SD-JWT issuance is not configured")
            return document_signer_pb2.RedeemPreAuthorizedCodeResponse()

        code = (request.pre_authorized_code or "").strip()
        if not code:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "pre_authorized_code is required")
            return document_signer_pb2.RedeemPreAuthorizedCodeResponse()

        try:
            wallet_attestation = json.loads(request.wallet_attestation) if request.wallet_attestation else None
        except json.JSONDecodeError as exc:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, f"Invalid wallet attestation: {exc}")
            return document_signer_pb2.RedeemPreAuthorizedCodeResponse()

        now = datetime.now(timezone.utc)
        access_token = secrets.token_urlsafe(32)
        c_nonce = secrets.token_urlsafe(16)
        token_expires_at = now + self._sd_jwt_token_ttl

        async def handler(session):
            repo = OidcSessionRepository(session)
            record = await repo.get_by_pre_authorized_code(code)
            return record

        record = await self._database.run_within_transaction(handler)
        if record is None:
            await context.abort(grpc.StatusCode.NOT_FOUND, "Unknown pre-authorized code")
            return document_signer_pb2.RedeemPreAuthorizedCodeResponse()

        if record.pre_authorized_code_expires_at < now:
            await context.abort(grpc.StatusCode.PERMISSION_DENIED, "Pre-authorized code expired")
            return document_signer_pb2.RedeemPreAuthorizedCodeResponse()

        async def update_handler(session):
            repo = OidcSessionRepository(session)
            refreshed = await repo.get_by_offer_id(record.offer_id)
            if refreshed is None:
                return False
            await repo.attach_access_token(
                refreshed,
                access_token=access_token,
                expires_at=token_expires_at,
                nonce=c_nonce,
                wallet_attestation=wallet_attestation,
            )
            return True

        updated = await self._database.run_within_transaction(update_handler)
        if not updated:
            await context.abort(grpc.StatusCode.NOT_FOUND, "Offer vanished")
            return document_signer_pb2.RedeemPreAuthorizedCodeResponse()

        return document_signer_pb2.RedeemPreAuthorizedCodeResponse(
            offer_id=record.offer_id,
            access_token=access_token,
            expires_in=_seconds_until(token_expires_at),
            c_nonce=c_nonce,
        )

    async def IssueSdJwtCredential(self, request, context):  # noqa: N802
        if not self._sd_jwt_enabled or self._sd_jwt_issuer is None:
            await context.abort(grpc.StatusCode.UNIMPLEMENTED, "SD-JWT issuance is not configured")
            return document_signer_pb2.IssueSdJwtCredentialResponse()

        access_token = (request.access_token or "").strip()
        if not access_token:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "access_token is required")
            return document_signer_pb2.IssueSdJwtCredentialResponse()

        try:
            wallet_attestation = json.loads(request.wallet_attestation) if request.wallet_attestation else None
        except json.JSONDecodeError as exc:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, f"Invalid wallet attestation: {exc}")
            return document_signer_pb2.IssueSdJwtCredentialResponse()

        now = datetime.now(timezone.utc)

        async def load_session(session):
            repo = OidcSessionRepository(session)
            return await repo.get_by_access_token(access_token)

        session_record = await self._database.run_within_transaction(load_session)
        if session_record is None:
            await context.abort(grpc.StatusCode.PERMISSION_DENIED, "Unknown access_token")
            return document_signer_pb2.IssueSdJwtCredentialResponse()

        if session_record.access_token_expires_at is None or session_record.access_token_expires_at < now:
            await context.abort(grpc.StatusCode.PERMISSION_DENIED, "access_token expired")
            return document_signer_pb2.IssueSdJwtCredentialResponse()

        if session_record.nonce and request.nonce and request.nonce != session_record.nonce:
            await context.abort(grpc.StatusCode.PERMISSION_DENIED, "nonce mismatch")
            return document_signer_pb2.IssueSdJwtCredentialResponse()

        disclose_claims = list(request.disclose_claims) or list(session_record.selective_disclosures.keys())
        disclosures_map = {
            key: value
            for key, value in session_record.selective_disclosures.items()
            if key in disclose_claims
        }

        issuance_input = SdJwtIssuanceInput(
            subject_id=session_record.subject_id,
            credential_type=session_record.credential_type,
            base_claims=session_record.base_claims,
            selective_disclosures=disclosures_map,
            audience=request.audience or None,
            nonce=request.nonce or session_record.nonce,
            additional_payload=(session_record.offer_payload or {}).get("vc", {}),
        )

        await self._ensure_document_signer_certificate()
        await self._refresh_certificate_cache()

        issuance_result = await self._sd_jwt_issuer.issue(issuance_input)
        sd_jwt_key, disclosures_key = await self._store_sd_jwt_artifacts(
            issuance_result.credential_id,
            issuance_result.token,
            issuance_result.disclosures,
        )

        event_payload = {
            "credential_id": issuance_result.credential_id,
            "credential_type": session_record.credential_type,
            "format": "vc+sd-jwt",
            "subject_id": session_record.subject_id,
            "issuer": issuance_result.issuer,
            "payload_location": sd_jwt_key,
            "disclosures_location": disclosures_key,
            "expires_at": issuance_result.expires_at.isoformat(),
        }

        async def persist(session):
            sd_repo = SdJwtCredentialRepository(session)
            await sd_repo.create(
                credential_id=issuance_result.credential_id,
                subject_id=session_record.subject_id,
                credential_type=session_record.credential_type,
                issuer=issuance_result.issuer,
                audience=issuance_result.audience,
                sd_jwt_location=sd_jwt_key,
                disclosures_location=disclosures_key,
                expires_at=issuance_result.expires_at,
                metadata=session_record.metadata,
                wallet_attestation=wallet_attestation,
            )

            sessions = OidcSessionRepository(session)
            refreshed = await sessions.get_by_offer_id(session_record.offer_id)
            if refreshed:
                await sessions.mark_issued(refreshed)

            ledger = CredentialLedgerRepository(session)
            await ledger.upsert_entry(
                credential_id=issuance_result.credential_id,
                credential_type=session_record.credential_type,
                status="ISSUED",
                metadata={
                    "issuer": issuance_result.issuer,
                    "subject_id": session_record.subject_id,
                    "payload_location": sd_jwt_key,
                    "disclosures_location": disclosures_key,
                },
                topic="vc.issued",
                offset=None,
            )

            outbox = OutboxRepository(session)
            await outbox.enqueue(
                topic="vc.issued",
                payload=json.dumps(event_payload).encode("utf-8"),
                key=issuance_result.credential_id.encode("utf-8"),
            )

        await self._database.run_within_transaction(persist)

        return document_signer_pb2.IssueSdJwtCredentialResponse(
            credential=issuance_result.token,
            disclosures=list(issuance_result.disclosures),
            credential_id=issuance_result.credential_id,
            expires_in=_seconds_until(issuance_result.expires_at),
            format="vc+sd-jwt",
            sd_jwt_location=sd_jwt_key,
            disclosures_location=disclosures_key,
            issuer=issuance_result.issuer,
            credential_type=session_record.credential_type,
            subject_id=session_record.subject_id,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _certificate_chain_provider(self) -> list[x509.Certificate]:
        return list(self._cached_certificate_chain)

    async def _ensure_document_signer_certificate(self) -> None:
        async def handler(session):
            await load_or_create_document_signer_certificate(
                session,
                self._key_vault,
                signing_algorithm=self._sd_jwt_vault_algorithm,
                key_id=self._sd_jwt_signing_key_id,
            )

        await self._database.run_within_transaction(handler)

    async def _refresh_certificate_cache(self) -> None:
        async def handler(session):
            repo = CertificateRepository(session)
            chain: list[x509.Certificate] = []
            for cert_id in self._sd_jwt_certificate_ids:
                if not cert_id:
                    continue
                record = await repo.get(cert_id)
                if record is None or not record.pem:
                    continue
                try:
                    chain.append(x509.load_pem_x509_certificate(record.pem.encode("utf-8")))
                except ValueError:
                    self.logger.warning("Failed to parse certificate %s for x5c chain", cert_id)
            return chain

        self._cached_certificate_chain = await self._database.run_within_transaction(handler)
        if not self._cached_certificate_chain:
            self.logger.warning("No certificates available for SD-JWT x5c header")

    async def _store_sd_jwt_artifacts(
        self,
        credential_id: str,
        token: str,
        disclosures: list[str],
    ) -> tuple[str, str]:
        base_path = f"{self._sd_jwt_storage_prefix}/{credential_id}"
        token_key = f"{base_path}.sdjwt"
        disclosures_key = f"{base_path}-disclosures.json"

        await self._object_storage.put_object(
            token_key,
            token.encode("utf-8"),
            content_type="application/sd-jwt",
        )
        disclosures_payload = json.dumps({"disclosures": disclosures}).encode("utf-8")
        await self._object_storage.put_object(
            disclosures_key,
            disclosures_payload,
            content_type="application/json",
        )
        return token_key, disclosures_key

    def _build_event_payload(self, document_id: str, payload_hash: bytes, storage_key: str) -> bytes:
        data = {
            "document_id": document_id,
            "hash_algo": "SHA256",
            "hash": payload_hash.hex(),
            "signature_location": storage_key,
            "signer": self._signing_key_id,
        }
        return json.dumps(data).encode("utf-8")

    async def _sync_csca_certificate(self) -> None:
        channel = self.channels.get("csca_service")
        if not channel:
            self.logger.debug("CSCA channel unavailable; skipping certificate sync")
            return

        stub = csca_service_pb2_grpc.CscaServiceStub(channel)
        try:
            response = await stub.GetCscaData(csca_service_pb2.CscaRequest(id="document-signer"))
        except grpc.RpcError as rpc_err:
            self.logger.error("Failed to fetch CSCA data: %s", rpc_err.details())
            return

        pem_data = response.data

        async def handler(session):
            repo = CertificateRepository(session)
            await repo.upsert("document-signer-csca", "CSCA", pem_data)

        await self._database.run_within_transaction(handler)


__all__ = ["DocumentSigner"]
