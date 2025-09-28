import json
import logging
from datetime import datetime, timezone

import grpc
from cryptography.hazmat.primitives import hashes

from marty_common.infrastructure import (
    CertificateRepository,
    EventBusMessage,
    EventBusProvider,
    KeyVaultClient,
    ObjectStorageClient,
)
from proto import (
    csca_service_pb2,
    csca_service_pb2_grpc,
    document_signer_pb2,
    document_signer_pb2_grpc,
)


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
        self._event_bus: EventBusProvider = dependencies.event_bus
        self._object_storage: ObjectStorageClient = dependencies.object_storage
        self._signing_key_id = "document-signer-default"
        self._signing_algorithm = "rsa2048"
        self.logger.info("Document Signer service initialized with secure key vault")

    async def SignDocument(self, request, context):
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

            message = EventBusMessage(
                topic="credential.issued",
                payload=self._build_event_payload(document_id, payload_hash, storage_key),
            )
            await self._event_bus.publish(message)

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
