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

# ISO 18013-5 Device Engagement and Session Establishment
DEVICE_ENGAGEMENT_VERSION = "1.0"
SESSION_ESTABLISHMENT_VERSION = "1.0"

class DeviceEngagementMethod:
    """Supported device engagement methods per ISO 18013-5."""
    QR_CODE = "qr_code"
    NFC = "nfc"
    BLUETOOTH = "bluetooth"
    WIFI_AWARE = "wifi_aware"

class SessionTransportMethod:
    """Supported session transport methods per ISO 18013-5."""
    BLE = "ble"
    WIFI_AWARE = "wifi_aware"
    NFC = "nfc"


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
        async def handler(session) -> None:
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

        async def handler(session) -> None:
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

    async def GetMDL(
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

    async def SignMDL(
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
            self.logger.exception("Signer RPC error: %s", rpc_err.details())
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

        async def handler(session) -> None:
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

    async def GenerateMDLQRCode(
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

    async def TransferMDLToDevice(self, request: Any, context: Any) -> Any:
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

    async def VerifyMDL(self, request: Any, context: Any) -> Any:
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

    # ISO 18013-5 Session Establishment and Device Engagement Methods

    async def EstablishSession(self, request: Any, context: Any) -> Any:
        """Establish an ISO 18013-5 session with device engagement."""
        try:
            session_id = str(uuid.uuid4())
            
            # Create device engagement data
            device_engagement = {
                "version": DEVICE_ENGAGEMENT_VERSION,
                "device_engagement_method": getattr(request, 'engagement_method', DeviceEngagementMethod.QR_CODE),
                "transport_methods": getattr(request, 'transport_methods', [SessionTransportMethod.BLE]),
                "device_key": {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": base64.b64encode(b"device_key_x").decode(),
                    "y": base64.b64encode(b"device_key_y").decode()
                },
                "session_id": session_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "reader_key": {
                    "kty": "EC", 
                    "crv": "P-256",
                    "x": base64.b64encode(b"reader_key_x").decode(),
                    "y": base64.b64encode(b"reader_key_y").decode()
                }
            }
            
            # Store session information
            session_data = {
                "session_id": session_id,
                "device_engagement": device_engagement,
                "status": "ESTABLISHED",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "transport_method": device_engagement["transport_methods"][0],
                "mdl_request": None,
                "response_sent": False
            }
            
            # Store in object storage
            session_key = f"mdl/sessions/{session_id}.json"
            await self._persist_payload(session_key, session_data)
            
            # Log session establishment with clear details
            self.logger.info(
                f"✓ ISO 18013-5 Session Established: "
                f"ID={session_id[:8]}..., "
                f"Method={device_engagement['device_engagement_method']}, "
                f"Transport={device_engagement['transport_methods']}"
            )
            
            # Publish event
            await self._publish_event(
                "mdl.session.established",
                {
                    "event_type": "session_established",
                    "session_id": session_id,
                    "engagement_method": device_engagement["device_engagement_method"],
                    "transport_methods": device_engagement["transport_methods"],
                    "timestamp": datetime.now(timezone.utc).isoformat()
                },
                key=session_id
            )
            
            # Generate engagement data based on method
            qr_code_data = ""
            nfc_data = ""
            if device_engagement["device_engagement_method"] == DeviceEngagementMethod.QR_CODE:
                qr_code_data = self._generate_qr_code_data(device_engagement)
                self.logger.info(f"✓ QR Code generated for session {session_id[:8]}...")
            elif device_engagement["device_engagement_method"] == DeviceEngagementMethod.NFC:
                nfc_data = self._generate_nfc_data(device_engagement)
                self.logger.info(f"✓ NFC data generated for session {session_id[:8]}...")
            
            return {
                "status": "SUCCESS",
                "session_id": session_id,
                "device_engagement": json.dumps(device_engagement),
                "qr_code_data": qr_code_data,
                "nfc_data": nfc_data
            }
            
        except Exception as exc:
            self.logger.exception("✗ Failed to establish session")
            return {
                "status": "ERROR",
                "error_message": str(exc)
            }

    async def ProcessMDLRequest(self, request: Any, context: Any) -> Any:
        """Process an mDL request within an established session."""
        try:
            session_id = getattr(request, 'session_id', '')
            if not session_id:
                return {
                    "status": "ERROR",
                    "error_message": "session_id is required"
                }
            
            # Load session data
            session_key = f"mdl/sessions/{session_id}.json"
            try:
                session_payload = await self._object_storage.get_object(session_key)
                session_data = json.loads(session_payload.decode("utf-8"))
            except Exception:
                return {
                    "status": "ERROR", 
                    "error_message": "Session not found or expired"
                }
            
            # Parse mDL request
            mdl_request_data = {
                "doc_type": getattr(request, 'doc_type', 'org.iso.18013.5.1.mDL'),
                "name_spaces": getattr(request, 'name_spaces', ['org.iso.18013.5.1']),
                "intent_to_retain": getattr(request, 'intent_to_retain', False),
                "reader_auth": getattr(request, 'reader_auth', ''),
                "requested_elements": self._parse_requested_elements(getattr(request, 'name_spaces', ['org.iso.18013.5.1']))
            }
            
            # Apply disclosure policy
            disclosure_policy = getattr(request, 'disclosure_policy', 'STANDARD')
            allowed_elements = DEFAULT_DISCLOSURE_POLICIES.get(disclosure_policy, DEFAULT_DISCLOSURE_POLICIES["STANDARD"])
            
            # Filter requested elements based on policy
            disclosed_elements = self._apply_disclosure_policy(
                mdl_request_data["requested_elements"], 
                allowed_elements
            )
            
            # Generate response with disclosed elements
            mdl_response = {
                "version": SESSION_ESTABLISHMENT_VERSION,
                "documents": [
                    {
                        "doc_type": "org.iso.18013.5.1.mDL",
                        "issuer_signed": {
                            "name_spaces": {
                                "org.iso.18013.5.1": disclosed_elements
                            }
                        },
                        "device_signed": {
                            "name_spaces": {},
                            "device_auth": {
                                "device_signature": base64.b64encode(b"mock_device_signature").decode()
                            }
                        }
                    }
                ],
                "status": 0  # Success
            }
            
            # Update session with request and response
            session_data["mdl_request"] = mdl_request_data
            session_data["mdl_response"] = mdl_response
            session_data["response_sent"] = True
            session_data["completed_at"] = datetime.now(timezone.utc).isoformat()
            
            # Store updated session
            await self._persist_payload(session_key, session_data)
            
            # Log the transaction with clear details
            disclosed_fields = list(disclosed_elements.keys())
            self.logger.info(
                f"✓ mDL Request Processed: "
                f"Session={session_id[:8]}..., "
                f"Policy={disclosure_policy}, "
                f"Disclosed={len(disclosed_fields)} fields: {', '.join(disclosed_fields[:3])}{'...' if len(disclosed_fields) > 3 else ''}"
            )
            
            # Publish event
            await self._publish_event(
                "mdl.request.processed",
                {
                    "event_type": "mdl_request_processed",
                    "session_id": session_id,
                    "doc_type": mdl_request_data["doc_type"],
                    "disclosed_elements": disclosed_fields,
                    "disclosure_policy": disclosure_policy,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                },
                key=session_id
            )
            
            return {
                "status": "SUCCESS",
                "mdl_response": json.dumps(mdl_response),
                "disclosed_elements": json.dumps(disclosed_elements),
                "session_transcript": json.dumps(session_data)
            }
            
        except Exception as exc:
            self.logger.exception("✗ Failed to process mDL request")
            return {
                "status": "ERROR",
                "error_message": str(exc)
            }

    def _generate_qr_code_data(self, device_engagement: dict[str, Any]) -> str:
        """Generate QR code data for device engagement."""
        # In a real implementation, this would generate CBOR-encoded device engagement
        qr_data = {
            "mdoc": device_engagement,
            "handover": {
                "transport": device_engagement["transport_methods"][0],
                "uuid": device_engagement["session_id"]
            }
        }
        return base64.b64encode(json.dumps(qr_data).encode()).decode()

    def _generate_nfc_data(self, device_engagement: dict[str, Any]) -> str:
        """Generate NFC data for device engagement."""
        # In a real implementation, this would generate proper NFC NDEF records
        nfc_data = {
            "mdoc_engagement": device_engagement,
            "transport": "nfc"
        }
        return base64.b64encode(json.dumps(nfc_data).encode()).decode()

    def _parse_requested_elements(self, name_spaces: list[str]) -> dict[str, Any]:
        """Parse requested elements from name spaces."""
        # This is a simplified parsing - real implementation would handle CBOR
        requested = {}
        for ns in name_spaces:
            if "org.iso.18013.5.1" in ns:
                # Parse standard mDL elements
                requested.update({
                    "family_name": True,
                    "given_name": True,
                    "birth_date": True,
                    "issue_date": True,
                    "expiry_date": True,
                    "issuing_country": True,
                    "issuing_authority": True,
                    "document_number": True,
                    "portrait": True,
                    "driving_privileges": True
                })
        return requested

    def _apply_disclosure_policy(self, requested: dict[str, Any], allowed: list[str]) -> dict[str, Any]:
        """Apply disclosure policy to filter requested elements."""
        # Demo data - in production this would come from actual mDL data
        demo_mdl_data = {
            "family_name": "Wonderland",
            "given_name": "Alice",
            "birth_date": "1990-01-01",
            "issue_date": "2023-01-01",
            "expiry_date": "2028-01-01",
            "issuing_country": "US",
            "issuing_authority": "State DMV",
            "document_number": "DL123456789",
            "portrait": base64.b64encode(b"mock_portrait_data").decode(),
            "driving_privileges": [
                {
                    "vehicle_category_code": "A",
                    "issue_date": "2023-01-01",
                    "expiry_date": "2028-01-01"
                }
            ]
        }
        
        disclosed = {}
        for element in requested:
            # Map field names (simplified mapping)
            mapped_field = self._map_element_name(element)
            if mapped_field in allowed and element in demo_mdl_data:
                disclosed[element] = demo_mdl_data[element]
        
        return disclosed

    def _map_element_name(self, element: str) -> str:
        """Map ISO 18013-5 element names to policy field names."""
        mapping = {
            "family_name": "last_name",
            "given_name": "first_name", 
            "document_number": "license_number",
            "birth_date": "date_of_birth",
            "issuing_authority": "issuing_authority",
            "driving_privileges": "license_categories",
            "portrait": "additional_fields",
            "issue_date": "additional_fields",
            "expiry_date": "additional_fields",
            "issuing_country": "additional_fields"
        }
        return mapping.get(element, element)
