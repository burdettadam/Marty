"""Mobile Driving Licence engine backed by async storage and event bus."""

from __future__ import annotations

import base64
import io
import json
import logging
import uuid
from datetime import date, datetime, timezone
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from marty_common.grpc_types import (
        GrpcServicerContext,
        ServiceDependencies,
    )

import grpc

from marty_common.infrastructure import (
    MobileDrivingLicenseRepository,
    ObjectStorageClient,
    OutboxRepository,
)
from src.proto import (
    document_signer_pb2,
    document_signer_pb2_grpc,
    mdl_engine_pb2,
    mdl_engine_pb2_grpc,
)

DEFAULT_DISCLOSURE_POLICIES = {
    "BASIC": ["first_name", "last_name", "license_number"],
    "STANDARD": ["first_name", "last_name", "license_number", "date_of_birth", "issuing_authority"],
    "ENHANCED": [
        "first_name",
        "last_name",
        "license_number",
        "date_of_birth",
        "issuing_authority",
        "license_categories",
        "additional_fields",
    ],
}


class MDLEngineServicer(mdl_engine_pb2_grpc.MDLEngineServicer):
    """Issues, signs, and manages mDLs with externalized persistence."""

    def __init__(
        self,
        channels: dict[str, Any] | None = None,
        dependencies: ServiceDependencies | None = None,
    ) -> None:
        if dependencies is None:
            msg = "MDLEngineServicer requires service dependencies"
            raise ValueError(msg)
        self.logger = logging.getLogger(__name__)
        self.channels = channels or {}
        self._database = dependencies.database
        self._object_storage: ObjectStorageClient = dependencies.object_storage

    def _document_signer_stub(self) -> document_signer_pb2_grpc.DocumentSignerStub | None:
        channel = self.channels.get("document_signer")
        if channel is None:
            self.logger.warning("Document signer channel unavailable")
            return None
        return document_signer_pb2_grpc.DocumentSignerStub(channel)

    async def _store_portrait(self, mdl_id: str, portrait_bytes: bytes) -> str | None:
        if not portrait_bytes:
            return None
        object_key = f"mdl/{mdl_id}/portrait.bin"
        await self._object_storage.put_object(object_key, portrait_bytes, "image/octet-stream")
        return object_key

    async def _persist_payload(self, object_key: str, details: dict[str, Any]) -> None:
        payload = json.dumps(details, indent=2).encode("utf-8")
        await self._object_storage.put_object(object_key, payload, "application/json")

    async def _publish_event(
        self,
        topic: str,
        payload: dict[str, Any],
        *,
        session: Any = None,  # AsyncSession
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

    def _prepare_license_categories(self, request: Any) -> list[dict[str, Any]]:
        categories = []
        for category in request.license_categories:
            categories.append(
                {
                    "category_code": category.category_code,
                    "issue_date": category.issue_date,
                    "expiry_date": category.expiry_date,
                    "restrictions": list(category.restrictions),
                }
            )
        return categories

    def _prepare_additional_fields(self, request: Any) -> list[dict[str, str]]:
        fields = []
        for field in request.additional_fields:
            fields.append({"field_name": field.field_name, "field_value": field.field_value})
        return fields

    def _calculate_age(self, dob_iso: str | None) -> int | None:
        if not dob_iso:
            return None
        try:
            dob = date.fromisoformat(dob_iso)
        except ValueError:
            return None
        today = date.today()
        years = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))
        return max(years, 0)

    def _filter_details(
        self,
        details: dict[str, Any],
        requested_fields: list[str] | None,
        include_photo: bool,
    ) -> dict[str, Any]:
        if not requested_fields:
            filtered = dict(details)
        else:
            filtered: dict[str, Any] = {}
            additional_filter: set[str] = set()
            for field in requested_fields:
                if field in details:
                    filtered[field] = details[field]
                    continue
                if field == "age":
                    age = self._calculate_age(details.get("date_of_birth"))
                    if age is not None:
                        filtered["age"] = age
                    continue
                additional_filter.add(field)
            if additional_filter and details.get("additional_fields"):
                filtered_fields = [
                    entry
                    for entry in details["additional_fields"]
                    if entry.get("field_name") in additional_filter
                ]
                if filtered_fields:
                    filtered["additional_fields"] = filtered_fields
        if not include_photo:
            filtered.pop("portrait_reference", None)
        return filtered

    def _build_signature_info_message(
        self, record_signature: bytes | None, details: dict[str, Any]
    ) -> Any | None:
        signature_info = details.get("signature_info") if isinstance(details, dict) else None
        if not record_signature and not signature_info:
            return None
        return mdl_engine_pb2.SignatureInfo(
            signature_date=signature_info.get("signature_date", "") if signature_info else "",
            signer_id=signature_info.get("signer_id", "") if signature_info else "",
            signature=record_signature or b"",
            is_valid=bool(record_signature),
        )

    def _build_mdl_response(self, record: Any, details: dict[str, Any]) -> Any:
        license_categories = [
            mdl_engine_pb2.LicenseCategory(
                category_code=item.get("category_code", ""),
                issue_date=item.get("issue_date", ""),
                expiry_date=item.get("expiry_date", ""),
                restrictions=item.get("restrictions", []),
            )
            for item in details.get("license_categories", [])
        ]
        additional_fields = [
            mdl_engine_pb2.AdditionalField(
                field_name=item.get("field_name", ""),
                field_value=item.get("field_value", ""),
            )
            for item in details.get("additional_fields", [])
        ]
        signature_info = self._build_signature_info_message(record.signature, details)
        return mdl_engine_pb2.MDLResponse(
            mdl_id=record.mdl_id,
            license_number=details.get("license_number", ""),
            first_name=details.get("first_name", ""),
            last_name=details.get("last_name", ""),
            date_of_birth=details.get("date_of_birth", ""),
            issuing_authority=details.get("issuing_authority", ""),
            issue_date=details.get("issue_date", ""),
            expiry_date=details.get("expiry_date", ""),
            portrait=b"",
            license_categories=license_categories,
            additional_fields=additional_fields,
            signature_info=signature_info,
            status=record.status,
            error_message="",
        )

    async def _load_record(self, mdl_id: str) -> Any:
        async def handler(session):
            repo = MobileDrivingLicenseRepository(session)
            return await repo.get(mdl_id)

        return await self._database.run_within_transaction(handler)

    async def _load_record_by_license(self, license_number: str) -> Any:
        async def handler(session):
            repo = MobileDrivingLicenseRepository(session)
            return await repo.get_by_license(license_number)

        return await self._database.run_within_transaction(handler)

    async def _update_status(self, mdl_id: str, status: str) -> None:
        async def handler(session):
            repo = MobileDrivingLicenseRepository(session)
            await repo.update_status(mdl_id, status)

        await self._database.run_within_transaction(handler)

    async def CreateMDL(
        self,
        request: Any,  # type: ignore[misc]
        context: GrpcServicerContext,
    ) -> Any:  # type: ignore[misc]
        if not request.license_number:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "license_number is required")
            return mdl_engine_pb2.CreateMDLResponse(
                status="ERROR", error_message="license_number is required"
            )
        if not request.user_id:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "user_id is required")
            return mdl_engine_pb2.CreateMDLResponse(
                status="ERROR", error_message="user_id is required"
            )

        existing = await self._load_record_by_license(request.license_number)
        if existing is not None:
            await context.abort(
                grpc.StatusCode.ALREADY_EXISTS, "MDL already exists for license number"
            )
            return mdl_engine_pb2.CreateMDLResponse(
                status="ERROR", error_message="MDL already exists"
            )

        mdl_id = f"MDL{uuid.uuid4().hex[:12].upper()}"
        portrait_reference = await self._store_portrait(mdl_id, request.portrait)
        license_categories = self._prepare_license_categories(request)
        additional_fields = self._prepare_additional_fields(request)

        details: dict[str, Any] = {
            "mdl_id": mdl_id,
            "license_number": request.license_number,
            "user_id": request.user_id,
            "first_name": request.first_name,
            "last_name": request.last_name,
            "date_of_birth": request.date_of_birth,
            "issuing_authority": request.issuing_authority,
            "issue_date": request.issue_date,
            "expiry_date": request.expiry_date,
            "license_categories": license_categories,
            "additional_fields": additional_fields,
            "portrait_reference": portrait_reference,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        disclosure_policies = {
            key: list(values) for key, values in DEFAULT_DISCLOSURE_POLICIES.items()
        }
        payload_key = f"mdl/{mdl_id}.json"

        try:
            await self._persist_payload(payload_key, details)
        except Exception as exc:  # pylint: disable=broad-except
            self.logger.exception("Failed to persist MDL payload")
            await context.abort(grpc.StatusCode.INTERNAL, str(exc))
            return mdl_engine_pb2.CreateMDLResponse(status="ERROR", error_message=str(exc))

        async def handler(session):
            repo = MobileDrivingLicenseRepository(session)
            await repo.create(
                mdl_id=mdl_id,
                license_number=request.license_number,
                user_id=request.user_id,
                status="PENDING_SIGNATURE",
                details=details,
                payload_location=payload_key,
                disclosure_policies=disclosure_policies,
            )
            await self._publish_event(
                "mdl.created",
                {
                    "mdl_id": mdl_id,
                    "license_number": request.license_number,
                    "user_id": request.user_id,
                    "payload_location": payload_key,
                },
                session=session,
                key=mdl_id,
            )

        await self._database.run_within_transaction(handler)

        return mdl_engine_pb2.CreateMDLResponse(
            mdl_id=mdl_id, status="PENDING_SIGNATURE", error_message=""
        )

    async def GetMDL(  # noqa: N802
        self,
        request: Any,  # type: ignore[misc] # mdl_engine_pb2.GetMDLRequest
        context: GrpcServicerContext,  # grpc.ServicerContext
    ) -> Any:  # type: ignore[misc] # mdl_engine_pb2.MDLResponse
        if not request.license_number:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "license_number is required")
            return mdl_engine_pb2.MDLResponse(
                status="FAILED", error_message="license_number is required"
            )

        record = await self._load_record_by_license(request.license_number)
        if record is None:
            await context.abort(grpc.StatusCode.NOT_FOUND, "MDL not found")
            return mdl_engine_pb2.MDLResponse(status="NOT_FOUND", error_message="MDL not found")

        details = record.details or {}
        return self._build_mdl_response(record, details)

    async def SignMDL(  # noqa: N802
        self,
        request: Any,  # type: ignore[misc] # mdl_engine_pb2.SignMDLRequest
        context: GrpcServicerContext,  # grpc.ServicerContext
    ) -> Any:  # type: ignore[misc] # mdl_engine_pb2.SignMDLResponse
        if not request.mdl_id:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "mdl_id is required")
            return mdl_engine_pb2.SignMDLResponse(success=False, error_message="mdl_id is required")

        record = await self._load_record(request.mdl_id)
        if record is None:
            await context.abort(grpc.StatusCode.NOT_FOUND, "MDL not found")
            return mdl_engine_pb2.SignMDLResponse(success=False, error_message="MDL not found")

        details = record.details or {}
        payload = json.dumps(details, sort_keys=True, separators=(",", ":")).encode("utf-8")
        stub = self._document_signer_stub()
        if stub is None:
            await context.abort(grpc.StatusCode.UNAVAILABLE, "Document signer unavailable")
            return mdl_engine_pb2.SignMDLResponse(success=False, error_message="Signer unavailable")

        try:
            response = await stub.SignDocument(
                document_signer_pb2.SignRequest(
                    document_id=record.mdl_id,
                    document_content=payload,
                )
            )
        except grpc.RpcError as rpc_err:
            self.logger.error("Signer RPC error: %s", rpc_err.details())
            await context.abort(rpc_err.code(), rpc_err.details())
            return mdl_engine_pb2.SignMDLResponse(success=False, error_message=rpc_err.details())

        if not response.success:
            await context.abort(grpc.StatusCode.INTERNAL, response.error_message)
            return mdl_engine_pb2.SignMDLResponse(
                success=False, error_message=response.error_message
            )

        signature_bytes = response.signature_info.signature
        signature_info = {
            "signature_date": response.signature_info.signature_date,
            "signer_id": response.signature_info.signer_id,
        }

        async def handler(session):
            repo = MobileDrivingLicenseRepository(session)
            await repo.update_signature(record.mdl_id, signature_bytes, signature_info)
            await repo.update_status(record.mdl_id, "ISSUED")

            await self._publish_event(
                "mdl.signed",
                {
                    "mdl_id": record.mdl_id,
                    "license_number": record.license_number,
                    "signature_date": signature_info["signature_date"],
                    "signer_id": signature_info["signer_id"],
                },
                session=session,
                key=record.mdl_id,
            )

        await self._database.run_within_transaction(handler)

        return mdl_engine_pb2.SignMDLResponse(
            success=True,
            signature_info=mdl_engine_pb2.SignatureInfo(
                signature_date=signature_info["signature_date"],
                signer_id=signature_info["signer_id"],
                signature=signature_bytes,
                is_valid=True,
            ),
        )

    async def GenerateMDLQRCode(  # noqa: N802
        self,
        request: Any,  # type: ignore[misc] # mdl_engine_pb2.GenerateMDLQRCodeRequest
        context: GrpcServicerContext,  # grpc.ServicerContext
    ) -> Any:  # type: ignore[misc] # mdl_engine_pb2.GenerateMDLQRCodeResponse
        if not request.mdl_id:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "mdl_id is required")
            return mdl_engine_pb2.GenerateQRCodeResponse(error_message="mdl_id is required")

        record = await self._load_record(request.mdl_id)
        if record is None:
            await context.abort(grpc.StatusCode.NOT_FOUND, "MDL not found")
            return mdl_engine_pb2.GenerateQRCodeResponse(error_message="MDL not found")

        details = record.details or {}
        fields = list(request.fields_to_include)
        if not fields:
            policies = record.disclosure_policies or DEFAULT_DISCLOSURE_POLICIES
            fields = policies.get("BASIC", [])
        filtered = self._filter_details(details, fields, request.include_photo)
        portrait_key = filtered.get("portrait_reference")
        if request.include_photo and portrait_key:
            try:
                portrait_bytes = await self._object_storage.get_object(portrait_key)
                filtered["portrait"] = base64.b64encode(portrait_bytes).decode("ascii")
            except Exception:  # pylint: disable=broad-except
                self.logger.warning("Failed to load portrait for %s", record.mdl_id)
        filtered.pop("portrait_reference", None)

        import qrcode

        qr = qrcode.QRCode(
            version=None,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=4,
            border=2,
        )
        qr.add_data(json.dumps(filtered, separators=(",", ":")))
        qr.make(fit=True)
        image = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        image.save(buffer, format="PNG")
        return mdl_engine_pb2.GenerateQRCodeResponse(qr_code=buffer.getvalue())

    async def TransferMDLToDevice(self, request: Any, context: Any) -> Any:  # noqa: N802
        if not request.mdl_id:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "mdl_id is required")
            return mdl_engine_pb2.TransferMDLResponse(
                success=False, error_message="mdl_id is required"
            )
        transfer_id = f"XFER-{uuid.uuid4().hex[:8].upper()}"
        await self._publish_event(
            "mdl.transfer_requested",
            {
                "mdl_id": request.mdl_id,
                "device_id": request.device_id,
                "transfer_method": request.transfer_method,
                "transfer_id": transfer_id,
            },
            key=request.mdl_id,
        )
        return mdl_engine_pb2.TransferMDLResponse(success=True, transfer_id=transfer_id)

    async def VerifyMDL(self, request: Any, context: Any) -> Any:  # noqa: N802
        details: dict[str, Any]
        record = None
        if request.mdl_id:
            record = await self._load_record(request.mdl_id)
            if record is None:
                context.set_code(grpc.StatusCode.NOT_FOUND)
                context.set_details("MDL not found")
                return mdl_engine_pb2.VerifyMDLResponse(
                    is_valid=False,
                    error_message="MDL not found",
                )
            details = record.details or {}
        elif request.qr_code_data:
            try:
                decoded = request.qr_code_data.decode("utf-8")
                details = json.loads(decoded)
            except Exception as exc:  # pylint: disable=broad-except
                context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
                context.set_details("Invalid QR payload")
                return mdl_engine_pb2.VerifyMDLResponse(
                    is_valid=False,
                    error_message=f"Invalid QR payload: {exc}",
                )
        else:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("Provide mdl_id or qr_code_data")
            return mdl_engine_pb2.VerifyMDLResponse(
                is_valid=False,
                error_message="mdl_id or qr_code_data required",
            )

        level = request.verification_level or "BASIC"
        if record is not None:
            policies = record.disclosure_policies or DEFAULT_DISCLOSURE_POLICIES
            allowed_fields = policies.get(level, policies.get("BASIC", []))
            filtered = self._filter_details(details, allowed_fields, include_photo=False)
        else:
            filtered = details

        verification_results = [
            mdl_engine_pb2.VerificationResult(
                check_name="syntactic_validation",
                passed=True,
                details="MDL payload parsed successfully",
            )
        ]
        signature_info = None
        if record is not None:
            signature_info = self._build_signature_info_message(record.signature, details)

        mdl_response = mdl_engine_pb2.MDLResponse(
            mdl_id=filtered.get("mdl_id", ""),
            license_number=filtered.get("license_number", ""),
            first_name=filtered.get("first_name", ""),
            last_name=filtered.get("last_name", ""),
            date_of_birth=filtered.get("date_of_birth", ""),
            issuing_authority=filtered.get("issuing_authority", ""),
            issue_date=filtered.get("issue_date", ""),
            expiry_date=filtered.get("expiry_date", ""),
            portrait=b"",
            license_categories=[
                mdl_engine_pb2.LicenseCategory(
                    category_code=item.get("category_code", ""),
                    issue_date=item.get("issue_date", ""),
                    expiry_date=item.get("expiry_date", ""),
                    restrictions=item.get("restrictions", []),
                )
                for item in filtered.get("license_categories", [])
            ],
            additional_fields=[
                mdl_engine_pb2.AdditionalField(
                    field_name=item.get("field_name", ""),
                    field_value=item.get("field_value", ""),
                )
                for item in filtered.get("additional_fields", [])
            ],
            signature_info=signature_info or mdl_engine_pb2.SignatureInfo(),
            status=record.status if record is not None else "UNKNOWN",
            error_message="",
        )

        if "age" in filtered:
            mdl_response.additional_fields.append(
                mdl_engine_pb2.AdditionalField(field_name="age", field_value=str(filtered["age"]))
            )

        return mdl_engine_pb2.VerifyMDLResponse(
            is_valid=True,
            verification_results=verification_results,
            mdl_data=mdl_response,
            error_message="",
        )
