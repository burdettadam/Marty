"""Passport engine using external storage and asynchronous dependencies."""

from __future__ import annotations

import base64
import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from marty_common.grpc_types import GrpcServicerContext, ProtoMessage, ServiceDependencies

import grpc
from cryptography.hazmat.primitives import serialization

from marty_common.infrastructure import (
    KeyVaultClient,
    ObjectStorageClient,
    OutboxRepository,
    PassportRepository,
)
from marty_common.models.passport import DataGroupType, Gender, ICaoPassport, MRZData
from proto import (
    document_signer_pb2_grpc,
    passport_engine_pb2,
    passport_engine_pb2_grpc,
)
from src.marty_common.crypto.document_signer_certificate import (
    DOCUMENT_SIGNER_KEY_ID,
    load_or_create_document_signer_certificate,
)
from src.marty_common.crypto.sod_signer import create_sod
from src.marty_common.utils.mrz_utils import MRZFormatter


class PassportEngine(passport_engine_pb2_grpc.PassportEngineServicer):
    """Generates passports and persists artifacts asynchronously."""

    def __init__(
        self,
        channels: dict[str, Any] | None = None,
        dependencies: ServiceDependencies | None = None,
    ) -> None:
        if dependencies is None:
            msg = "PassportEngine requires service dependencies"
            raise ValueError(msg)
        self.logger = logging.getLogger(__name__)
        self.channels = channels or {}
        self._object_storage: ObjectStorageClient = dependencies.object_storage
        self._database = dependencies.database
        self._key_vault: KeyVaultClient = dependencies.key_vault
        self.passport_status: dict[str, str] = {}
        service_config = dependencies.runtime_config.get_service("passport_engine")
        self._signing_key_id = service_config.get("signing_key_id", DOCUMENT_SIGNER_KEY_ID)
        self._signing_algorithm = service_config.get("signing_algorithm", "rsa2048")

    def _document_signer_stub(self) -> document_signer_pb2_grpc.DocumentSignerStub | None:
        channel = self.channels.get("document_signer")
        if channel is None:
            self.logger.warning("Document signer channel unavailable")
            return None
        return document_signer_pb2_grpc.DocumentSignerStub(channel)

    def _generate_passport_data(
        self, passport_number: str
    ) -> tuple[ICaoPassport, dict[int, bytes]]:
        now = datetime.now(timezone.utc)
        issue_date = now.date().isoformat()
        expiry_dt = now.replace(year=now.year + 10)
        expiry_date = expiry_dt.date().isoformat()

        dob_dt = now - timedelta(days=365 * 30)
        dob_str = dob_dt.strftime("%y%m%d")
        expiry_str = expiry_dt.strftime("%y%m%d")

        mrz_model = MRZData(
            document_type="P",
            issuing_country="USA",
            document_number=passport_number,
            surname="SPECIMEN",
            given_names="TEST",
            nationality="USA",
            date_of_birth=dob_str,
            gender=Gender.UNSPECIFIED,
            date_of_expiry=expiry_str,
            personal_number=None,
        )
        mrz_string = MRZFormatter.generate_td3_mrz(mrz_model)

        data_group_bytes: dict[int, bytes] = {
            1: mrz_string.encode("ascii"),
            2: f"PHOTO-DATA-{passport_number}".encode(),
            3: f"FINGERPRINT-DATA-{passport_number}".encode(),
            4: f"IRIS-DATA-{passport_number}".encode(),
        }

        encoded_groups = {
            DataGroupType.DG1.value: data_group_bytes[1].hex(),
            DataGroupType.DG2.value: data_group_bytes[2].hex(),
            DataGroupType.DG3.value: data_group_bytes[3].hex(),
            DataGroupType.DG4.value: data_group_bytes[4].hex(),
        }

        passport = ICaoPassport(
            passport_number=passport_number,
            issue_date=issue_date,
            expiry_date=expiry_date,
            data_groups=encoded_groups,
            sod="",
        )
        return passport, data_group_bytes

    async def _sign_passport_data(
        self,
        passport_data: ICaoPassport,
        data_group_bytes: dict[int, bytes],
    ) -> tuple[bytes | None, dict[str, str] | None]:
        async def _load_certificate(session):
            return await load_or_create_document_signer_certificate(
                session,
                self._key_vault,
                signing_algorithm=self._signing_algorithm,
                key_id=self._signing_key_id,
            )

        try:
            certificate = await self._database.run_within_transaction(_load_certificate)
            private_key_pem = await self._key_vault.load_private_key(self._signing_key_id)
            private_key = serialization.load_pem_private_key(private_key_pem, password=None)
            sod_bytes = create_sod(data_group_bytes, private_key, certificate)
        except Exception:  # pylint: disable=broad-except
            self.logger.exception(
                "Failed to create SOD for passport %s", passport_data.passport_number
            )
            return None, None

        signature_info = {
            "signature_date": datetime.now(timezone.utc).isoformat(),
            "signer_id": self._signing_key_id,
            "certificate_subject": certificate.subject.rfc4514_string(),
        }
        return sod_bytes, signature_info

    async def _persist_payload(
        self,
        passport_number: str,
        passport_payload: dict[str, Any],
        signature: bytes | None,
    ) -> str:
        if signature and not passport_payload.get("sod"):
            passport_payload["sod"] = base64.b64encode(signature).decode("ascii")
        serialized = json.dumps(passport_payload, indent=2).encode("utf-8")
        object_key = f"passports/{passport_number}.json"
        await self._object_storage.put_object(object_key, serialized, "application/json")
        return object_key

    async def _persist_metadata(
        self,
        passport_number: str,
        storage_key: str,
        status: str,
        details: dict[str, Any],
        signature: bytes | None,
        event_payload: dict[str, Any] | None = None,
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

            if event_payload is not None:
                payload = dict(event_payload)
                payload.setdefault("issued_at", datetime.now(timezone.utc).isoformat())
                await self._publish_event(
                    "passport.issued",
                    payload,
                    session=session,
                    key=passport_number,
                )

        await self._database.run_within_transaction(handler)

    async def _publish_event(
        self,
        topic: str,
        payload: dict[str, Any],
        *,
        session=None,
        key: str | None = None,
    ) -> None:
        serialized = json.dumps(payload).encode("utf-8")

        async def handler(db_session):
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

    async def ProcessPassport(
        self,
        request: ProtoMessage,
        context: GrpcServicerContext,
    ) -> ProtoMessage:
        passport_number = request.passport_number or f"P{uuid.uuid4().hex[:8].upper()}"
        self.logger.info("Processing passport %s", passport_number)

        passport_data, data_group_bytes = self._generate_passport_data(passport_number)
        signature, signature_info = await self._sign_passport_data(passport_data, data_group_bytes)
        passport_details = passport_data.model_dump()
        if signature:
            passport_details["sod"] = base64.b64encode(signature).decode("ascii")
        else:
            passport_details["sod"] = ""
        if signature_info:
            passport_details["signature_info"] = signature_info
        status = "ISSUED" if signature else "PENDING_SIGNATURE"

        try:
            storage_key = await self._persist_payload(
                passport_number, dict(passport_details), signature
            )
            event_payload = {
                "passport_number": passport_number,
                "storage_key": storage_key,
                "status": status,
            }
            if signature_info:
                event_payload["signature_info"] = signature_info
            await self._persist_metadata(
                passport_number,
                storage_key,
                status,
                passport_details,
                signature,
                event_payload=event_payload,
            )
            grpc_status = "SUCCESS"
            self.passport_status[passport_number] = status
        except Exception as exc:  # pylint: disable=broad-except
            self.logger.exception("Failed to persist passport %s", passport_number)
            self.passport_status[passport_number] = "ERROR"
            try:
                await self._persist_metadata(
                    passport_number, "", "ERROR", passport_details, signature
                )
            except Exception:  # pylint: disable=broad-except
                self.logger.warning("Failed to record error state for passport %s", passport_number)
            grpc_status = "ERROR"
            await context.abort(grpc.StatusCode.INTERNAL, str(exc))
            return passport_engine_pb2.PassportResponse(status=grpc_status)

        return passport_engine_pb2.PassportResponse(status=grpc_status)
