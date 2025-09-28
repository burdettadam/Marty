"""Digital Travel Credential engine using externalized storage."""

from __future__ import annotations

import asyncio
import io
import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

import cbor2
import grpc
import qrcode

from marty_common.infrastructure import (
    DigitalTravelCredentialRepository,
    EventBusMessage,
    EventBusProvider,
    ObjectStorageClient,
)
from proto import document_signer_pb2, document_signer_pb2_grpc, dtc_engine_pb2, dtc_engine_pb2_grpc


class DTCEngineServicer(dtc_engine_pb2_grpc.DTCEngineServicer):
    """Service responsible for issuing, signing, and managing DTCs."""

    def __init__(self, channels=None, dependencies=None) -> None:
        if dependencies is None:
            msg = "DTCEngineServicer requires service dependencies"
            raise ValueError(msg)
        self.logger = logging.getLogger(__name__)
        self.channels = channels or {}
        self._database = dependencies.database
        self._object_storage: ObjectStorageClient = dependencies.object_storage
        self._event_bus: EventBusProvider = dependencies.event_bus
        self._run = lambda coro: asyncio.run(coro)

    # ------------------------------------------------------------------
    # gRPC endpoints
    # ------------------------------------------------------------------
    def CreateDTC(self, request, context):  # noqa: N802
        dtc_id = f"DTC{uuid.uuid4().hex[:12].upper()}"
        self.logger.info("Issuing DTC %s for passport %s", dtc_id, request.passport_number)

        dtc_payload = self._build_dtc_payload(dtc_id, request)
        payload_key = f"dtc/{dtc_id}.json"
        self._run(
            self._object_storage.put_object(
                payload_key, json.dumps(dtc_payload).encode("utf-8"), "application/json"
            )
        )

        async def handler(session):
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

        self._run(self._database.run_within_transaction(handler))

        self._publish_event(
            "dtc.issued",
            {
                "dtc_id": dtc_id,
                "passport_number": request.passport_number,
                "payload_location": payload_key,
            },
        )

        return dtc_engine_pb2.CreateDTCResponse(dtc_id=dtc_id, status="SUCCESS", error_message="")

    def GetDTC(self, request, context):  # noqa: N802
        record = self._load_record(request.dtc_id)
        if record is None:
            return dtc_engine_pb2.DTCResponse(
                status="NOT_FOUND",
                error_message=f"DTC with ID {request.dtc_id} not found",
            )

        dtc_payload = self._load_payload(record.payload_location)

        access_hash = dtc_payload.get("access_key_hash")
        if access_hash and not self._validate_access_key(request.access_key, access_hash):
            return dtc_engine_pb2.DTCResponse(
                status="ACCESS_DENIED", error_message="Invalid access key provided"
            )

        response = self._build_dtc_response(record.details or {}, record.signature)
        response.status = "REVOKED" if record.status == "REVOKED" else "SUCCESS"
        return response

    def SignDTC(self, request, context):  # noqa: N802
        record = self._load_record(request.dtc_id)
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

        dtc_payload = self._load_payload(record.payload_location)
        cbor_payload = self._to_cbor_payload(dtc_payload)

        signer_stub = self._document_signer_stub()
        if signer_stub is None:
            context.set_code(grpc.StatusCode.UNAVAILABLE)
            context.set_details("Document signer channel unavailable")
            return dtc_engine_pb2.SignDTCResponse(success=False, error_message="Signer unavailable")

        try:
            sign_response = signer_stub.SignDocument(
                document_signer_pb2.SignRequest(
                    document_id=request.dtc_id,
                    document_content=cbor_payload,
                )
            )
        except grpc.RpcError as rpc_err:
            self.logger.exception("Signer RPC error: %s", rpc_err.details())
            context.set_code(rpc_err.code())
            context.set_details(rpc_err.details())
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

        async def handler(session):
            repo = DigitalTravelCredentialRepository(session)
            stored = await repo.get(request.dtc_id)
            if stored is None:
                return
            details = stored.details or {}
            details["signature_info"] = signature_info
            stored.details = details
            stored.signature = signature_bytes
            stored.updated_at = datetime.now(timezone.utc)

        self._run(self._database.run_within_transaction(handler))

        self._publish_event(
            "dtc.signed",
            {
                "dtc_id": request.dtc_id,
                "signature_date": signature_info["signature_date"],
                "signer_id": signature_info["signer_id"],
            },
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

    def RevokeDTC(self, request, context):  # noqa: N802
        reason = request.reason or "unspecified"

        async def handler(session):
            repo = DigitalTravelCredentialRepository(session)
            await repo.mark_revoked(request.dtc_id, reason)

        self._run(self._database.run_within_transaction(handler))

        self._publish_event(
            "dtc.revoked",
            {"dtc_id": request.dtc_id, "reason": reason},
        )

        return dtc_engine_pb2.RevokeDTCResponse(success=True, status="REVOKED")

    def GenerateDTCQRCode(self, request, context):  # noqa: N802
        record = self._load_record(request.dtc_id)
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

    def TransferDTCToDevice(self, request, context):  # noqa: N802
        record = self._load_record(request.dtc_id)
        if record is None:
            return dtc_engine_pb2.TransferDTCResponse(
                success=False,
                error_message=f"DTC with ID {request.dtc_id} not found",
            )

        return dtc_engine_pb2.TransferDTCResponse(
            success=True,
            payload_location=record.payload_location,
        )

    def VerifyDTC(self, request, context):  # noqa: N802
        record = self._load_record(request.dtc_id)
        if record is None or record.signature is None:
            return dtc_engine_pb2.VerifyDTCResponse(
                success=False,
                error_message="Signature not available",
            )
        return dtc_engine_pb2.VerifyDTCResponse(success=True, is_valid=True)

    def LinkDTCToPassport(self, request, context):  # noqa: N802
        async def handler(session):
            repo = DigitalTravelCredentialRepository(session)
            stored = await repo.get(request.dtc_id)
            if stored is None:
                return False
            details = stored.details or {}
            details["passport_link_status"] = "LINKED"
            stored.details = details
            stored.updated_at = datetime.now(timezone.utc)
            return True

        updated = self._run(self._database.run_within_transaction(handler))
        if not updated:
            return dtc_engine_pb2.LinkDTCResponse(
                success=False,
                error_message=f"DTC with ID {request.dtc_id} not found",
            )
        return dtc_engine_pb2.LinkDTCResponse(success=True)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _load_record(self, dtc_id: str):
        async def handler(session):
            repo = DigitalTravelCredentialRepository(session)
            return await repo.get(dtc_id)

        return self._run(self._database.run_within_transaction(handler))

    def _load_payload(self, storage_key: str) -> dict[str, Any]:
        raw = self._run(self._object_storage.get_object(storage_key))
        return json.loads(raw.decode("utf-8"))

    def _document_signer_stub(self):
        channel = self.channels.get("document_signer")
        if channel is None:
            return None
        return document_signer_pb2_grpc.DocumentSignerStub(channel)

    def _publish_event(self, topic: str, payload: dict[str, Any]) -> None:
        message = EventBusMessage(topic=topic, payload=json.dumps(payload).encode("utf-8"))
        self._run(self._event_bus.publish(message))

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
            "access_key_hash": self._hash_access_key(request.access_key) if request.access_key else None,
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
            portrait=bytes.fromhex(personal.get("portrait", "")) if personal.get("portrait") else b"",
            signature=bytes.fromhex(personal.get("signature", "")) if personal.get("signature") else b"",
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

    def _to_cbor_payload(self, payload: dict[str, Any]) -> bytes:
        compact = {
            "id": payload.get("dtc_id"),
            "type": payload.get("dtc_type"),
            "passportNumber": payload.get("passport_number"),
            "issuer": payload.get("issuing_authority"),
            "issuanceDate": payload.get("issue_date"),
            "expiryDate": payload.get("expiry_date"),
            "validFrom": payload.get("dtc_valid_from"),
            "validUntil": payload.get("dtc_valid_until"),
            "holder": payload.get("personal_details", {}),
            "dataGroupHashes": {
                str(item.get("dg_number")): self._hash_data(
                    bytes.fromhex(item.get("data", "")) if item.get("data") else b""
                )
                for item in payload.get("data_groups", [])
            },
        }
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
