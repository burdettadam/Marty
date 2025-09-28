"""Passport engine using external storage and asynchronous dependencies."""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

import grpc

from marty_common.infrastructure import (
    EventBusMessage,
    EventBusProvider,
    ObjectStorageClient,
    PassportRepository,
)
from marty_common.models.passport import DataGroupType, ICaoPassport
from proto import (
    document_signer_pb2,
    document_signer_pb2_grpc,
    passport_engine_pb2,
    passport_engine_pb2_grpc,
)


class PassportEngine(passport_engine_pb2_grpc.PassportEngineServicer):
    """Generates passports and persists artifacts asynchronously."""

    def __init__(self, channels=None, dependencies=None) -> None:
        if dependencies is None:
            msg = "PassportEngine requires service dependencies"
            raise ValueError(msg)
        self.logger = logging.getLogger(__name__)
        self.channels = channels or {}
        self._object_storage: ObjectStorageClient = dependencies.object_storage
        self._event_bus: EventBusProvider = dependencies.event_bus
        self._database = dependencies.database
        self.passport_status: dict[str, str] = {}

    def _run(self, coroutine):
        return asyncio.run(coroutine)

    def _document_signer_stub(self) -> Optional[document_signer_pb2_grpc.DocumentSignerStub]:
        channel = self.channels.get("document_signer")
        if channel is None:
            self.logger.warning("Document signer channel unavailable")
            return None
        return document_signer_pb2_grpc.DocumentSignerStub(channel)

    def _generate_passport_data(self, passport_number: str) -> ICaoPassport:
        now = datetime.now(timezone.utc)
        issue_date = now.date().isoformat()
        expiry_date = now.replace(year=now.year + 10).date().isoformat()
        data_groups = {
            DataGroupType.DG1.value: f"MRZ-DATA-{passport_number}",
            DataGroupType.DG2.value: f"PHOTO-DATA-{passport_number}",
            DataGroupType.DG3.value: f"FINGERPRINT-DATA-{passport_number}",
            DataGroupType.DG4.value: f"IRIS-DATA-{passport_number}",
        }
        return ICaoPassport(
            passport_number=passport_number,
            issue_date=issue_date,
            expiry_date=expiry_date,
            data_groups=data_groups,
            sod="",
        )

    def _sign_passport_data(
        self, passport_data: ICaoPassport
    ) -> tuple[Optional[bytes], Optional[dict[str, str]]]:
        stub = self._document_signer_stub()
        if stub is None:
            return None, None

        passport_dict = passport_data.model_dump()
        passport_dict.pop("sod", None)
        payload = json.dumps(passport_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")

        try:
            response = stub.SignDocument(
                document_signer_pb2.SignRequest(
                    document_id=passport_data.passport_number,
                    document_content=payload,
                )
            )
        except grpc.RpcError as rpc_err:
            self.logger.error("Document signer RPC failure: %s", rpc_err.details())
            return None, None

        if not response.success:
            self.logger.error("Document signer returned error: %s", response.error_message)
            return None, None

        signature_info = {
            "signature_date": response.signature_info.signature_date,
            "signer_id": response.signature_info.signer_id,
        }
        return response.signature_info.signature, signature_info

    def _persist_payload(
        self,
        passport_number: str,
        passport_payload: dict[str, Any],
        signature: bytes | None,
    ) -> str:
        if signature:
            passport_payload["sod"] = signature.hex()
        serialized = json.dumps(passport_payload, indent=2).encode("utf-8")
        object_key = f"passports/{passport_number}.json"
        self._run(
            self._object_storage.put_object(object_key, serialized, "application/json")
        )
        return object_key

    def _persist_metadata(
        self,
        passport_number: str,
        storage_key: str,
        status: str,
        details: dict[str, Any],
        signature: bytes | None,
    ) -> None:
        async def handler(session):
            repo = PassportRepository(session)
            await repo.upsert(
                passport_number=passport_number,
                payload_location=storage_key,
                status=status,
                details=details,
                signature=signature,
            )

        self._run(self._database.run_within_transaction(handler))

    def _publish_event(
        self,
        passport_number: str,
        storage_key: str,
        status: str,
        signature_info: Optional[dict[str, str]],
    ) -> None:
        payload: dict[str, Any] = {
            "passport_number": passport_number,
            "storage_key": storage_key,
            "status": status,
            "issued_at": datetime.now(timezone.utc).isoformat(),
        }
        if signature_info:
            payload["signature_info"] = signature_info
        message = EventBusMessage(
            topic="passport.issued",
            payload=json.dumps(payload).encode("utf-8"),
        )
        self._run(self._event_bus.publish(message))

    def ProcessPassport(self, request, context):  # noqa: N802 - gRPC naming
        passport_number = request.passport_number or f"P{uuid.uuid4().hex[:8].upper()}"
        self.logger.info("Processing passport %s", passport_number)

        passport_data = self._generate_passport_data(passport_number)
        signature, signature_info = self._sign_passport_data(passport_data)
        passport_details = passport_data.model_dump()
        passport_details["sod"] = signature.hex() if signature else ""
        status = "ISSUED" if signature else "PENDING_SIGNATURE"

        try:
            storage_key = self._persist_payload(passport_number, dict(passport_details), signature)
            self._persist_metadata(
                passport_number,
                storage_key,
                status,
                passport_details,
                signature,
            )
            self._publish_event(passport_number, storage_key, status, signature_info)
            grpc_status = "SUCCESS"
            self.passport_status[passport_number] = status
        except Exception as exc:  # pylint: disable=broad-except
            self.logger.exception("Failed to persist passport %s", passport_number)
            context.set_details(str(exc))
            context.set_code(grpc.StatusCode.INTERNAL)
            self.passport_status[passport_number] = "ERROR"
            try:
                self._persist_metadata(passport_number, "", "ERROR", passport_details, signature)
            except Exception:  # pylint: disable=broad-except
                self.logger.warning("Failed to record error state for passport %s", passport_number)
            grpc_status = "ERROR"

        return passport_engine_pb2.PassportResponse(status=grpc_status)
