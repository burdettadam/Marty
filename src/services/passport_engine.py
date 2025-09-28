"""Passport engine that persists artifacts in object storage and emits events."""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

import grpc

from marty_common.infrastructure import EventBusMessage, EventBusProvider, ObjectStorageClient
from marty_common.models.passport import DataGroupType, ICaoPassport
from proto import (
    document_signer_pb2,
    document_signer_pb2_grpc,
    passport_engine_pb2,
    passport_engine_pb2_grpc,
)


class PassportEngine(passport_engine_pb2_grpc.PassportEngineServicer):
    """Generates passports using externalized services."""

    def __init__(self, channels=None, dependencies=None) -> None:
        if dependencies is None:
            msg = "PassportEngine requires service dependencies"
            raise ValueError(msg)
        self.logger = logging.getLogger(__name__)
        self.channels = channels or {}
        self._object_storage: ObjectStorageClient = dependencies.object_storage
        self._event_bus: EventBusProvider = dependencies.event_bus
        self.passport_status: dict[str, str] = {}

    def _run(self, coroutine):
        return asyncio.run(coroutine)

    def _generate_passport_data(self, passport_number: str) -> ICaoPassport:
        issue_date = datetime.now(timezone.utc).date().isoformat()
        expiry_date = datetime.now(timezone.utc).replace(year=datetime.now(timezone.utc).year + 10).date().isoformat()
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

    def _sign_passport_data(self, passport_data: ICaoPassport) -> Optional[bytes]:
        passport_dict = passport_data.to_dict()
        passport_dict.pop("sod", None)
        payload = json.dumps(passport_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")

        channel = self.channels.get("document_signer")
        if not channel:
            self.logger.error("Document signer channel unavailable")
            return None

        stub = document_signer_pb2_grpc.DocumentSignerStub(channel)
        try:
            response = stub.SignDocument(
                document_signer_pb2.SignRequest(
                    document_id=passport_data.passport_number,
                    document_content=payload,
                )
            )
        except grpc.RpcError as rpc_err:
            self.logger.error("Document signer RPC failure: %s", rpc_err.details())
            return None

        if not response.success:
            self.logger.error("Document signer returned error: %s", response.error_message)
            return None

        return response.signature_info.signature

    def _persist_passport(self, passport_number: str, passport_data: ICaoPassport, signature: bytes | None) -> str:
        passport_dict = passport_data.to_dict()
        if signature:
            passport_dict["sod"] = signature.hex()
        serialized = json.dumps(passport_dict, indent=2).encode("utf-8")
        object_key = f"passports/{passport_number}.json"
        self._run(self._object_storage.put_object(object_key, serialized, "application/json"))
        return object_key

    def _publish_event(self, passport_number: str, storage_key: str, signature: bytes | None) -> None:
        payload = json.dumps(
            {
                "passport_number": passport_number,
                "storage_key": storage_key,
                "signature_hex": signature.hex() if signature else "",
                "issued_at": datetime.now(timezone.utc).isoformat(),
            }
        ).encode("utf-8")
        message = EventBusMessage(topic="passport.issued", payload=payload)
        self._run(self._event_bus.publish(message))

    def ProcessPassport(self, request, context):  # noqa: N802 - gRPC naming
        passport_number = request.passport_number or f"P{uuid.uuid4().hex[:8].upper()}"
        self.logger.info("Processing passport %s", passport_number)

        passport_data = self._generate_passport_data(passport_number)
        signature = self._sign_passport_data(passport_data)
        passport_data.sod = signature.hex() if signature else ""

        try:
            storage_key = self._persist_passport(passport_number, passport_data, signature)
            self._publish_event(passport_number, storage_key, signature)
            status = "SUCCESS"
            self.passport_status[passport_number] = status
        except Exception as exc:  # pylint: disable=broad-except
            self.logger.exception("Failed to persist passport %s", passport_number)
            context.set_details(str(exc))
            context.set_code(grpc.StatusCode.INTERNAL)
            status = "ERROR"
            self.passport_status[passport_number] = status

        return passport_engine_pb2.PassportResponse(status=status)
