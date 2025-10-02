"""Digital Travel Credential engine using externalized storage."""

from __future__ import annotations

import hashlib
import io
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from marty_common.grpc_types import (
        GrpcServicerContext,
        ProtoMessage,
        ServiceDependencies,
    )

import cbor2
import grpc
import qrcode
from cryptography import x509

from marty_common.infrastructure import (
    CertificateRepository,
    DigitalTravelCredentialRepository,
    KeyVaultClient,
    ObjectStorageClient,
    OutboxRepository,
)
from proto import document_signer_pb2, document_signer_pb2_grpc, dtc_engine_pb2, dtc_engine_pb2_grpc
from src.marty_common.crypto.document_signer_certificate import (
    DOCUMENT_SIGNER_KEY_ID,
    load_or_create_document_signer_certificate,
)
from src.marty_common.crypto.dtc_verifier import DTCVerifier


class DTCEngineServicer(dtc_engine_pb2_grpc.DTCEngineServicer):
    """Service responsible for issuing, signing, and managing DTCs."""

    def __init__(
        self,
        channels: dict[str, Any] | None = None,
        dependencies: ServiceDependencies | None = None,
    ) -> None:
        if dependencies is None:
            msg = "DTCEngineServicer requires service dependencies"
            raise ValueError(msg)
        self.logger = logging.getLogger(__name__)
        self.channels = channels or {}
        self._database = dependencies.database
        self._object_storage: ObjectStorageClient = dependencies.object_storage
        self._key_vault: KeyVaultClient = dependencies.key_vault
        service_config = dependencies.runtime_config.get_service("dtc_engine")
        self._signing_key_id = service_config.get("signing_key_id", DOCUMENT_SIGNER_KEY_ID)
        self._signing_algorithm = service_config.get("signing_algorithm", "rsa2048")

    # ------------------------------------------------------------------
    # gRPC endpoints
    # ------------------------------------------------------------------
    async def CreateDTC(
        self,
        request: Any,
        context: GrpcServicerContext,
    ) -> Any:
        dtc_id = f"DTC{uuid.uuid4().hex[:12].upper()}"
        self.logger.info("Issuing DTC %s for passport %s", dtc_id, request.passport_number)

        dtc_payload = self._build_dtc_payload(dtc_id, request)
        dtc_payload["data_group_hashes"] = self._build_compact_payload(dtc_payload)[
            "dataGroupHashes"
        ]
        payload_key = f"dtc/{dtc_id}.json"
        await self._object_storage.put_object(
            payload_key, json.dumps(dtc_payload).encode("utf-8"), "application/json"
        )

        async def handler(session) -> None:
            repo = DigitalTravelCredentialRepository(session)
            await repo.create(
                dtc_id=dtc_id,
                passport_number=request.passport_number,
                dtc_type=dtc_engine_pb2.DTCType.Name(request.dtc_type),
                access_control=dtc_engine_pb2.AccessControl.Name(request.access_control),
                details=dtc_payload,
                payload_location=payload_key,
                signature=None,
            )

            await self._publish_event(
                "dtc.issued",
                {
                    "dtc_id": dtc_id,
                    "passport_number": request.passport_number,
                    "payload_location": payload_key,
                },
                session=session,
                key=dtc_id,
            )

        await self._database.run_within_transaction(handler)

        return dtc_engine_pb2.CreateDTCResponse(dtc_id=dtc_id, status="SUCCESS", error_message="")

    async def GetDTC(
        self,
        request: Any,
        context: GrpcServicerContext,
    ) -> Any:
        record = await self._load_record(request.dtc_id)
        if record is None:
            return dtc_engine_pb2.DTCResponse(
                status="NOT_FOUND",
                error_message=f"DTC with ID {request.dtc_id} not found",
            )

        dtc_payload = await self._load_payload(record.payload_location)

        access_hash = dtc_payload.get("access_key_hash")
        if access_hash and not self._validate_access_key(request.access_key, access_hash):
            return dtc_engine_pb2.DTCResponse(
                status="ACCESS_DENIED", error_message="Invalid access key provided"
            )

        response = self._build_dtc_response(record.details or {}, record.signature)
        response.status = "REVOKED" if record.status == "REVOKED" else "SUCCESS"
        return response

    async def SignDTC(
        self,
        request: ProtoMessage,
        context: GrpcServicerContext,
    ) -> ProtoMessage:
        record = await self._load_record(request.dtc_id)
        if record is None:
            return dtc_engine_pb2.SignDTCResponse(
                success=False,
                error_message=f"DTC with ID {request.dtc_id} not found",
            )
        if record.status == "REVOKED":
            return dtc_engine_pb2.SignDTCResponse(
                success=False,
                error_message="Cannot sign a revoked DTC",
            )

        dtc_payload = await self._load_payload(record.payload_location)
        cbor_payload = self._to_cbor_payload(dtc_payload)

        signer_stub = self._document_signer_stub()
        if signer_stub is None:
            await context.abort(grpc.StatusCode.UNAVAILABLE, "Document signer channel unavailable")
            return dtc_engine_pb2.SignDTCResponse(success=False, error_message="Signer unavailable")

        try:
            sign_response = await signer_stub.SignDocument(
                document_signer_pb2.SignRequest(
                    document_id=request.dtc_id,
                    document_content=cbor_payload,
                )
            )
        except grpc.RpcError as rpc_err:
            self.logger.exception("Signer RPC error: %s", rpc_err.details())
            await context.abort(rpc_err.code(), rpc_err.details())
            return dtc_engine_pb2.SignDTCResponse(success=False, error_message=rpc_err.details())

        if not sign_response.success:
            return dtc_engine_pb2.SignDTCResponse(
                success=False,
                error_message=sign_response.error_message,
            )

        signature_info = {
            "signature_date": sign_response.signature_info.signature_date,
            "signer_id": sign_response.signature_info.signer_id,
        }
        signature_bytes = sign_response.signature_info.signature

        async def handler(session) -> bool:
            repo = DigitalTravelCredentialRepository(session)
            stored = await repo.get(request.dtc_id)
            if stored is None:
                return False
            details = stored.details or {}
            details["signature_info"] = signature_info
            stored.details = details
            stored.signature = signature_bytes
            stored.updated_at = datetime.now(timezone.utc)

            await self._publish_event(
                "dtc.signed",
                {
                    "dtc_id": request.dtc_id,
                    "signature_date": signature_info["signature_date"],
                    "signer_id": signature_info["signer_id"],
                },
                session=session,
                key=request.dtc_id,
            )
            return True

        updated = await self._database.run_within_transaction(handler)
        if not updated:
            return dtc_engine_pb2.SignDTCResponse(
                success=False,
                error_message=f"DTC with ID {request.dtc_id} not found",
            )

        return dtc_engine_pb2.SignDTCResponse(
            success=True,
            signature_info=dtc_engine_pb2.SignatureInfo(
                signature_date=signature_info["signature_date"],
                signer_id=signature_info["signer_id"],
                signature=signature_bytes,
                is_valid=True,
            ),
        )

    async def RevokeDTC(self, request, context):
        reason = request.reason or "unspecified"

        async def handler(session) -> None:
            repo = DigitalTravelCredentialRepository(session)
            await repo.mark_revoked(request.dtc_id, reason)
            await self._publish_event(
                "dtc.revoked",
                {"dtc_id": request.dtc_id, "reason": reason},
                session=session,
                key=request.dtc_id,
            )

        await self._database.run_within_transaction(handler)

        return dtc_engine_pb2.RevokeDTCResponse(success=True, status="REVOKED")

    async def GenerateDTCQRCode(
        self,
        request: ProtoMessage,
        context: GrpcServicerContext,
    ) -> ProtoMessage:
        record = await self._load_record(request.dtc_id)
        if record is None:
            return dtc_engine_pb2.DTCQRCodeResponse(
                success=False,
                error_message=f"DTC with ID {request.dtc_id} not found",
            )

        qr_content = json.dumps({"dtc_id": request.dtc_id, "status": record.status})
        qr_img = qrcode.make(qr_content)
        buffer = io.BytesIO()
        qr_img.save(buffer, format="PNG")
        return dtc_engine_pb2.DTCQRCodeResponse(success=True, qr_code_png=buffer.getvalue())

    async def TransferDTCToDevice(self, request, context):
        record = await self._load_record(request.dtc_id)
        if record is None:
            return dtc_engine_pb2.TransferDTCResponse(
                success=False,
                error_message=f"DTC with ID {request.dtc_id} not found",
            )

        return dtc_engine_pb2.TransferDTCResponse(
            success=True,
            payload_location=record.payload_location,
        )

    async def VerifyDTC(
        self,
        request: ProtoMessage,
        context: GrpcServicerContext,
    ) -> ProtoMessage:
        record = await self._load_record(request.dtc_id)
        if record is None:
            return dtc_engine_pb2.VerifyDTCResponse(
                success=False,
                error_message=f"DTC with ID {request.dtc_id} not found",
                verification_result=dtc_engine_pb2.INVALID,
            )

        dtc_payload = await self._load_payload(record.payload_location)
        if record.signature is None:
            return dtc_engine_pb2.VerifyDTCResponse(
                success=False,
                error_message="DTC is not signed",
                verification_result=dtc_engine_pb2.NOT_SIGNED,
            )

        if dtc_payload.get("access_key_hash") and not self._validate_access_key(
            request.access_key, dtc_payload.get("access_key_hash", "")
        ):
            return dtc_engine_pb2.VerifyDTCResponse(
                success=False,
                error_message="Access key invalid",
                verification_result=dtc_engine_pb2.ACCESS_DENIED,
            )

        compact_payload = self._build_compact_payload(dtc_payload)
        trust_anchors = await self._load_trust_anchors()
        verifier = DTCVerifier(trust_anchors)

        integrity_result = verifier.verify_data_group_hashes(
            compact_payload, dtc_payload.get("data_groups", [])
        )

        async def _load_certificate(session):
            return await load_or_create_document_signer_certificate(
                session,
                self._key_vault,
                signing_algorithm=self._signing_algorithm,
                key_id=self._signing_key_id,
            )

        certificate = await self._database.run_within_transaction(_load_certificate)
        signature_result = verifier.verify_signature(compact_payload, record.signature, certificate)
        chain_result = verifier.validate_certificate_chain(certificate, [])

        verification_checks = []
        verification_checks.append(
            dtc_engine_pb2.VerificationCheck(
                check_name="data_group_hashes",
                passed=integrity_result.is_valid,
                details="; ".join(integrity_result.mismatches) or "hashes match",
            )
        )
        verification_checks.append(
            dtc_engine_pb2.VerificationCheck(
                check_name="signature",
                passed=signature_result.is_valid,
                details=signature_result.error or signature_result.certificate_subject,
            )
        )
        verification_checks.append(
            dtc_engine_pb2.VerificationCheck(
                check_name="certificate_chain",
                passed=chain_result.is_valid,
                details=(
                    chain_result.error_summary
                    if chain_result.errors
                    else (
                        chain_result.trust_anchor.subject.rfc4514_string()
                        if chain_result.trust_anchor
                        else "trusted"
                    )
                ),
            )
        )

        if record.status == "REVOKED":
            verification_checks.append(
                dtc_engine_pb2.VerificationCheck(
                    check_name="revocation",
                    passed=False,
                    details=record.revocation_reason or "DTC is revoked",
                )
            )

        if request.check_passport_link:
            linked = (
                bool(record.passport_number) and record.passport_number == request.passport_number
            )
            verification_checks.append(
                dtc_engine_pb2.VerificationCheck(
                    check_name="passport_link",
                    passed=linked,
                    details="link verified" if linked else "passport number mismatch",
                )
            )

        overall_valid = all(check.passed for check in verification_checks)

        if not overall_valid and any(
            check.check_name == "signature" and not check.passed for check in verification_checks
        ):
            result_enum = dtc_engine_pb2.INVALID_SIGNATURE
        elif not overall_valid and any(
            check.check_name == "revocation" and not check.passed for check in verification_checks
        ):
            result_enum = dtc_engine_pb2.REVOKED
        else:
            result_enum = dtc_engine_pb2.VALID if overall_valid else dtc_engine_pb2.INVALID

        dtc_response = self._build_dtc_response(dtc_payload, record.signature)

        return dtc_engine_pb2.VerifyDTCResponse(
            success=overall_valid,
            is_valid=overall_valid,
            verification_results=verification_checks,
            dtc_data=dtc_response,
            verification_result=result_enum,
            error_message=""
            if overall_valid
            else "; ".join(check.details for check in verification_checks if not check.passed),
        )

    async def LinkDTCToPassport(self, request, context):
        async def handler(session) -> bool:
            repo = DigitalTravelCredentialRepository(session)
            stored = await repo.get(request.dtc_id)
            if stored is None:
                return False
            details = stored.details or {}
            details["passport_link_status"] = "LINKED"
            stored.details = details
            stored.updated_at = datetime.now(timezone.utc)
            return True

        updated = await self._database.run_within_transaction(handler)
        if not updated:
            return dtc_engine_pb2.LinkDTCResponse(
                success=False,
                error_message=f"DTC with ID {request.dtc_id} not found",
            )
        return dtc_engine_pb2.LinkDTCResponse(success=True)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    async def _load_record(self, dtc_id: str):
        async def handler(session):
            repo = DigitalTravelCredentialRepository(session)
            return await repo.get(dtc_id)

        return await self._database.run_within_transaction(handler)

    async def _load_payload(self, storage_key: str) -> dict[str, Any]:
        raw = await self._object_storage.get_object(storage_key)
        return json.loads(raw.decode("utf-8"))

    def _document_signer_stub(self):
        channel = self.channels.get("document_signer")
        if channel is None:
            return None
        return document_signer_pb2_grpc.DocumentSignerStub(channel)

    async def _load_trust_anchors(self) -> list[x509.Certificate]:
        async def handler(session):
            repo = CertificateRepository(session)
            records = await repo.list_by_type("CSCA")
            anchors: list[x509.Certificate] = []
            for record in records:
                if not record.pem:
                    continue
                try:
                    anchors.append(x509.load_pem_x509_certificate(record.pem.encode("utf-8")))
                except ValueError:
                    self.logger.warning(
                        "Failed to parse CSCA certificate %s", record.certificate_id
                    )
            return anchors

        try:
            return await self._database.run_within_transaction(handler)
        except Exception:  # pylint: disable=broad-except
            self.logger.exception("Unable to load CSCA trust anchors for DTC verification")
            return []

    async def _publish_event(
        self,
        topic: str,
        payload: dict[str, Any],
        *,
        session=None,
        key: str | None = None,
    ) -> None:
        serialized = json.dumps(payload).encode("utf-8")

        async def handler(db_session) -> None:
            outbox = OutboxRepository(db_session)
            await outbox.enqueue(
                topic=topic,
                payload=serialized,
                key=key.encode("utf-8") if key else None,
            )

        if session is None:
            await self._database.run_within_transaction(handler)
        else:
            await handler(session)

    def _build_dtc_payload(self, dtc_id: str, request) -> dict[str, Any]:
        valid_from = request.dtc_valid_from or request.issue_date
        valid_until = request.dtc_valid_until or request.expiry_date
        return {
            "dtc_id": dtc_id,
            "passport_number": request.passport_number,
            "issuing_authority": request.issuing_authority,
            "issue_date": request.issue_date,
            "expiry_date": request.expiry_date,
            "personal_details": {
                "first_name": request.personal_details.first_name,
                "last_name": request.personal_details.last_name,
                "date_of_birth": request.personal_details.date_of_birth,
                "gender": request.personal_details.gender,
                "nationality": request.personal_details.nationality,
                "place_of_birth": request.personal_details.place_of_birth,
                "portrait": request.personal_details.portrait.hex(),
                "signature": request.personal_details.signature.hex(),
                "other_names": list(request.personal_details.other_names),
            },
            "data_groups": [
                {
                    "dg_number": dg.dg_number,
                    "data": dg.data.hex(),
                    "data_type": dg.data_type,
                }
                for dg in request.data_groups
            ],
            "dtc_type": dtc_engine_pb2.DTCType.Name(request.dtc_type),
            "access_control": dtc_engine_pb2.AccessControl.Name(request.access_control),
            "access_key_hash": self._hash_access_key(request.access_key)
            if request.access_key
            else None,
            "dtc_valid_from": valid_from,
            "dtc_valid_until": valid_until,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "passport_link_status": "NOT_LINKED",
        }

    def _build_dtc_response(self, payload: dict[str, Any], signature: bytes | None):
        personal = payload.get("personal_details", {})
        personal_details = dtc_engine_pb2.PersonalDetails(
            first_name=personal.get("first_name", ""),
            last_name=personal.get("last_name", ""),
            date_of_birth=personal.get("date_of_birth", ""),
            gender=personal.get("gender", ""),
            nationality=personal.get("nationality", ""),
            place_of_birth=personal.get("place_of_birth", ""),
            portrait=bytes.fromhex(personal.get("portrait", ""))
            if personal.get("portrait")
            else b"",
            signature=bytes.fromhex(personal.get("signature", ""))
            if personal.get("signature")
            else b"",
            other_names=personal.get("other_names", []),
        )

        data_groups = [
            dtc_engine_pb2.DataGroup(
                dg_number=item.get("dg_number", 0),
                data=bytes.fromhex(item.get("data", "")) if item.get("data") else b"",
                data_type=item.get("data_type", ""),
            )
            for item in payload.get("data_groups", [])
        ]

        signature_info_payload = payload.get("signature_info") or {}
        signature_info = dtc_engine_pb2.SignatureInfo(
            signature_date=signature_info_payload.get("signature_date", ""),
            signer_id=signature_info_payload.get("signer_id", ""),
            signature=signature or b"",
            is_valid=bool(signature),
        )

        return dtc_engine_pb2.DTCResponse(
            dtc_id=payload.get("dtc_id", ""),
            passport_number=payload.get("passport_number", ""),
            issue_date=payload.get("issue_date", ""),
            expiry_date=payload.get("expiry_date", ""),
            personal_details=personal_details,
            data_groups=data_groups,
            signature_info=signature_info,
            status="SUCCESS",
        )

    def _build_compact_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        hashes_map = payload.get("data_group_hashes")
        if not hashes_map:
            hashes_map = {
                str(item.get("dg_number")): self._hash_data(
                    bytes.fromhex(item.get("data", "")) if item.get("data") else b""
                )
                for item in payload.get("data_groups", [])
            }

        return {
            "id": payload.get("dtc_id"),
            "type": payload.get("dtc_type"),
            "passportNumber": payload.get("passport_number"),
            "issuer": payload.get("issuing_authority"),
            "issuanceDate": payload.get("issue_date"),
            "expiryDate": payload.get("expiry_date"),
            "validFrom": payload.get("dtc_valid_from"),
            "validUntil": payload.get("dtc_valid_until"),
            "holder": payload.get("personal_details", {}),
            "dataGroupHashes": hashes_map,
        }

    def _to_cbor_payload(self, payload: dict[str, Any]) -> bytes:
        compact = self._build_compact_payload(payload)
        return cbor2.dumps(compact)

    @staticmethod
    def _hash_access_key(access_key: str) -> str:
        return hashlib.sha256(access_key.encode("utf-8")).hexdigest()

    @staticmethod
    def _validate_access_key(provided_key: str, stored_hash: str) -> bool:
        if not provided_key:
            return False
        return hashlib.sha256(provided_key.encode("utf-8")).hexdigest() == stored_hash

    @staticmethod
    def _hash_data(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()
