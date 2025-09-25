# Placeholder for MDL Engine service implementation
# This file will contain the gRPC service logic for the MDL Engine.

import json
import logging
import time
from concurrent import futures
from datetime import datetime, timezone
from typing import Any

import grpc
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm.attributes import flag_modified

# Assuming models.py defines MDLStatus correctly with a DRAFT member
from src.mdl_engine.models import MDLStatus, MobileDrivingLicense
from src.proto import (
    common_services_pb2_grpc,
    document_signer_pb2,
    document_signer_pb2_grpc,
    mdl_engine_pb2,
    mdl_engine_pb2_grpc,
)
from src.shared.config import settings  # settings object is now in config.py
from src.shared.database import SessionLocal
from src.shared.utils import datetime_to_string, string_to_datetime

# Initialize logger
LOGGER = logging.getLogger(__name__)

# pylint: disable=too-many-lines
# ruff: noqa: E501
# pylint: disable=logging-fstring-interpolation, duplicate-code, too-many-statements, too-many-locals, line-too-long, no-member


class MDLEngineService(mdl_engine_pb2_grpc.MDLEngineServicer):  # type: ignore[misc]
    """
    gRPC service for managing Mobile Driving Licenses (MDLs).
    """

    def CreateMDL(self, request: mdl_engine_pb2.CreateMDLRequest, context: grpc.ServicerContext):  # type: ignore[no-member]
        LOGGER.info("CreateMDL request received for license: %s", request.license_number)

        if not request.license_number:
            LOGGER.warning("CreateMDL failed: License number is missing.")
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("License number is required.")
            return mdl_engine_pb2.CreateMDLResponse(  # type: ignore[no-member]
                status="ERROR", error_message="License number is required."
            )

        if not request.user_id:
            LOGGER.warning("CreateMDL failed: User ID is missing.")
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("User ID is required.")
            return mdl_engine_pb2.CreateMDLResponse(  # type: ignore[no-member]
                status="ERROR", error_message="User ID is required."
            )

        with SessionLocal() as db:
            try:
                try:
                    issue_datetime = (
                        string_to_datetime(request.issue_date) if request.issue_date else None
                    )
                    expiry_datetime = (
                        string_to_datetime(request.expiry_date) if request.expiry_date else None
                    )
                except ValueError as ve:
                    LOGGER.warning("CreateMDL failed due to invalid date format: %s", ve)
                    context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
                    context.set_details(f"Invalid date format. Dates should be YYYY-MM-DD. {ve}")
                    return mdl_engine_pb2.CreateMDLResponse(  # type: ignore[no-member]
                        status="ERROR", error_message=f"Invalid date format: {ve}"
                    )

                document_id = f"mdl_{request.license_number}"
                existing_mdl = (
                    db.query(MobileDrivingLicense)
                    .filter(MobileDrivingLicense.document_id == document_id)
                    .first()
                )
                if existing_mdl:
                    msg = f"MDL with license number {request.license_number} " "already exists."
                    LOGGER.warning("CreateMDL failed: %s", msg)
                    context.set_code(grpc.StatusCode.ALREADY_EXISTS)
                    context.set_details(msg)
                    return mdl_engine_pb2.CreateMDLResponse(  # type: ignore[no-member]
                        status="ERROR", error_message=msg
                    )

                license_categories_list = [
                    {
                        "category_code": lc_proto.category_code,
                        "issue_date": lc_proto.issue_date,
                        "expiry_date": lc_proto.expiry_date,
                        "restrictions": list(lc_proto.restrictions),
                    }
                    for lc_proto in request.license_categories
                ]

                additional_fields_list = [
                    {"field_name": af.field_name, "field_value": af.field_value}
                    for af in request.additional_fields
                ]

                new_mdl = MobileDrivingLicense(
                    user_id=request.user_id,
                    document_id=document_id,
                    issuing_authority=request.issuing_authority,
                    issue_date=issue_datetime,  # type: ignore[assignment]
                    expiry_date=expiry_datetime,  # type: ignore[assignment]
                    data_groups={  # type: ignore[assignment]
                        "license_number": request.license_number,
                        "first_name": request.first_name,
                        "last_name": request.last_name,
                        "date_of_birth": request.date_of_birth,
                        "portrait_hex": request.portrait.hex() if request.portrait else None,
                        "license_categories": license_categories_list,
                        "additional_fields": additional_fields_list,
                        "signatures": [],
                    },
                    status=MDLStatus.PENDING_SIGNATURE,  # type: ignore[assignment]
                )
                db.add(new_mdl)
                db.commit()
                db.refresh(new_mdl)

                LOGGER.info(
                    "MDL created: %s, Status: %s",
                    new_mdl.document_id,
                    new_mdl.status.value,  # status is non-nullable MDLStatus enum
                )
                return mdl_engine_pb2.CreateMDLResponse(  # type: ignore[no-member]
                    mdl_id=new_mdl.document_id,
                    status=new_mdl.status.value,  # status is non-nullable MDLStatus enum
                )

            except SQLAlchemyError as db_e:
                LOGGER.error("Database error in CreateMDL: %s", db_e, exc_info=True)
                db.rollback()
                context.set_code(grpc.StatusCode.INTERNAL)
                context.set_details(f"Database error: {db_e!s}")
                return mdl_engine_pb2.CreateMDLResponse(  # type: ignore[no-member]
                    status="ERROR", error_message=f"Database error: {db_e!s}"
                )
            except grpc.RpcError as rpc_e:
                LOGGER.exception("Error creating MDL record: %s", rpc_e)
                details_str = str(rpc_e.details())  # type: ignore[attr-defined]
                status_code_obj = rpc_e.code()  # type: ignore[attr-defined]
                if not isinstance(status_code_obj, grpc.StatusCode):
                    status_code_obj = grpc.StatusCode.INTERNAL
                context.abort(status_code_obj, details_str)
                return mdl_engine_pb2.CreateMDLResponse()  # type: ignore[no-member] # Unreachable
            except Exception as e:  # pylint: disable=broad-except
                LOGGER.exception("Unexpected error in CreateMDL: %s", e)
                context.set_code(grpc.StatusCode.INTERNAL)
                context.set_details(f"Unexpected internal error: {e!s}")
                return mdl_engine_pb2.CreateMDLResponse(  # type: ignore[no-member]
                    status="ERROR", error_message=f"Unexpected internal error: {e!s}"
                )

    def GetMDL(self, request: mdl_engine_pb2.GetMDLRequest, context: grpc.ServicerContext):  # type: ignore[no-member]
        LOGGER.info("GetMDL request for license number: %s", request.license_number)
        if not request.license_number:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("License number is required.")
            return mdl_engine_pb2.MDLDataResponse(error_message="License number is required.")  # type: ignore[no-member]

        expected_mdl_id = f"mdl_{request.license_number}"

        with SessionLocal() as db:
            try:
                mdl_record: MobileDrivingLicense | None = (
                    db.query(MobileDrivingLicense)
                    .filter(MobileDrivingLicense.document_id == expected_mdl_id)
                    .first()
                )

                if not mdl_record:
                    msg = f"MDL with license number {request.license_number} not found."
                    LOGGER.warning("GetMDL: %s (Doc ID: %s)", msg, expected_mdl_id)
                    context.set_code(grpc.StatusCode.NOT_FOUND)
                    context.set_details(msg)
                    return mdl_engine_pb2.MDLDataResponse(error_message=msg)  # type: ignore[no-member]

                data = mdl_record.data_groups
                if not isinstance(data, dict):
                    LOGGER.error(
                        "MDL data_groups for %s is not a dictionary. Found: %s",
                        expected_mdl_id,
                        type(data),
                    )
                    context.set_code(grpc.StatusCode.INTERNAL)
                    context.set_details("Internal error: MDL data format incorrect.")
                    return mdl_engine_pb2.MDLDataResponse(  # type: ignore[no-member]
                        error_message="Internal data format error."
                    )

                portrait_hex = data.get("portrait_hex")
                portrait_bytes = bytes.fromhex(portrait_hex) if portrait_hex else b""

                license_categories_proto = []
                db_license_categories = data.get("license_categories", [])
                if isinstance(db_license_categories, list):
                    for lc_db in db_license_categories:
                        if isinstance(lc_db, dict):
                            license_categories_proto.append(
                                mdl_engine_pb2.LicenseCategory(  # type: ignore[no-member]
                                    category_code=lc_db.get("category_code", ""),
                                    issue_date=lc_db.get("issue_date", ""),
                                    expiry_date=lc_db.get("expiry_date", ""),
                                    restrictions=lc_db.get("restrictions", []),
                                )
                            )

                additional_fields_proto = []
                db_additional_fields = data.get("additional_fields", [])
                if isinstance(db_additional_fields, list):
                    for af_db in db_additional_fields:
                        if isinstance(af_db, dict):
                            additional_fields_proto.append(
                                mdl_engine_pb2.AdditionalField(  # type: ignore[no-member]
                                    field_name=af_db.get("field_name", ""),
                                    field_value=af_db.get("field_value", ""),
                                )
                            )

                response_sig_info = []
                db_signatures = data.get("signatures", [])
                if isinstance(db_signatures, list):
                    for sig_db in db_signatures:
                        if isinstance(sig_db, dict):
                            signed_at_str = sig_db.get("signed_at")
                            dt_obj = string_to_datetime(signed_at_str) if signed_at_str else None  # type: ignore[arg-type]
                            response_sig_info.append(
                                mdl_engine_pb2.SignatureInfo(  # type: ignore[no-member]
                                    signer_id=sig_db.get("signer_id", ""),
                                    signature_hex=sig_db.get("signature_hex", ""),
                                    signed_at=datetime_to_string(dt_obj) if dt_obj else "",  # type: ignore[arg-type]
                                )
                            )

                issue_date_str = ""
                if mdl_record.issue_date is not None:  # mdl_record.issue_date is datetime
                    # issue_date_str = datetime_to_string(mdl_record.issue_date) # This is fine
                    # Attempt to parse and reformat if it's a full ISO string
                    try:
                        # dt_obj = string_to_datetime(issue_date_str) # Already datetime
                        issue_date_str = mdl_record.issue_date.strftime("%Y-%m-%d")
                    except ValueError:
                        issue_date_str = str(mdl_record.issue_date)  # fallback to string

                expiry_date_str = ""
                if mdl_record.expiry_date is not None:  # mdl_record.expiry_date is datetime
                    # expiry_date_str = datetime_to_string(mdl_record.expiry_date) # This is fine
                    try:
                        # dt_obj = string_to_datetime(expiry_date_str) # Already datetime
                        expiry_date_str = mdl_record.expiry_date.strftime("%Y-%m-%d")
                    except ValueError:
                        expiry_date_str = str(mdl_record.expiry_date)  # fallback to string

                mdl_data_payload = mdl_engine_pb2.MDLData(  # type: ignore[no-member]
                    user_id=mdl_record.user_id,
                    license_number=data.get("license_number", ""),
                    first_name=data.get("first_name", ""),
                    last_name=data.get("last_name", ""),
                    date_of_birth=data.get("date_of_birth", ""),
                    issuing_authority=mdl_record.issuing_authority or "",
                    issue_date=issue_date_str,
                    expiry_date=expiry_date_str,
                    portrait=portrait_bytes,
                    license_categories=license_categories_proto,
                    additional_fields=additional_fields_proto,
                    status=mdl_record.status.value,  # status is non-nullable MDLStatus enum
                    signature_info=response_sig_info,
                )
                LOGGER.info("MDL retrieved from DB for license number: %s", request.license_number)
                return mdl_engine_pb2.MDLDataResponse(mdl_data=mdl_data_payload)  # type: ignore[no-member]

            except SQLAlchemyError as db_e:
                LOGGER.error("Database error in GetMDL: %s", db_e, exc_info=True)
                context.set_code(grpc.StatusCode.INTERNAL)
                context.set_details(f"Database error: {db_e!s}")
                return mdl_engine_pb2.MDLDataResponse(error_message=f"Database error: {db_e!s}")  # type: ignore[no-member]
            except Exception as e:  # pylint: disable=broad-except
                LOGGER.exception("Unexpected error in GetMDL: %s", e)
                context.set_code(grpc.StatusCode.INTERNAL)
                context.set_details(f"Unexpected internal error: {e!s}")
                return mdl_engine_pb2.MDLDataResponse(  # type: ignore[no-member]
                    error_message=f"Unexpected internal error: {e!s}"
                )

    def SignMDL(self, request: mdl_engine_pb2.SignMDLRequest, context: grpc.ServicerContext):  # type: ignore[no-member]
        LOGGER.info(
            "SignMDL request for MDL ID: %s, Signer ID: %s",
            request.mdl_id,
            request.signer_id,
        )

        if not request.mdl_id:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("MDL ID is required.")
            return mdl_engine_pb2.SignMDLResponse(  # type: ignore[no-member]
                status="ERROR", error_message="MDL ID is required."
            )
        if not request.signer_id:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("Signer ID is required.")
            return mdl_engine_pb2.SignMDLResponse(  # type: ignore[no-member]
                status="ERROR", error_message="Signer ID is required."
            )

        signature_hex = ""

        with SessionLocal() as db:
            try:
                mdl_record: MobileDrivingLicense | None = (
                    db.query(MobileDrivingLicense)
                    .filter(MobileDrivingLicense.document_id == request.mdl_id)
                    .with_for_update()
                    .first()
                )

                if not mdl_record:
                    msg = f"MDL with ID {request.mdl_id} not found."
                    LOGGER.warning("SignMDL: %s", msg)
                    context.set_code(grpc.StatusCode.NOT_FOUND)
                    context.set_details(msg)
                    return mdl_engine_pb2.SignMDLResponse(  # type: ignore[no-member]
                        status="ERROR", error_message=msg
                    )

                # mdl_record.status is an enum instance here
                if mdl_record.status != MDLStatus.PENDING_SIGNATURE:
                    msg = (
                        f"MDL with ID {request.mdl_id} is not in "
                        f"PENDING_SIGNATURE state. Current state: "
                        f"{mdl_record.status.value}"  # status is non-nullable MDLStatus enum
                    )
                    LOGGER.warning("SignMDL: %s", msg)
                    context.set_code(grpc.StatusCode.FAILED_PRECONDITION)
                    context.set_details(msg)
                    return mdl_engine_pb2.SignMDLResponse(  # type: ignore[no-member]
                        status="ERROR", error_message=msg
                    )

                if not isinstance(mdl_record.data_groups, dict):
                    LOGGER.error(
                        "Data groups for MDL ID %s is not a dictionary. Found: %s",
                        request.mdl_id,
                        type(mdl_record.data_groups),
                    )
                    context.set_code(grpc.StatusCode.INTERNAL)
                    context.set_details("Internal error: MDL data format incorrect.")
                    return mdl_engine_pb2.SignMDLResponse(  # type: ignore[no-member]
                        status="ERROR", error_message="Internal data format error."
                    )

                current_data_groups: dict[str, Any] = mdl_record.data_groups.copy()  # type: ignore[union-attr]

                document_content_bytes = json.dumps(
                    mdl_record.data_groups, sort_keys=True  # Use original data_groups for signing
                ).encode("utf-8")

                if not settings.DOCUMENT_SIGNER_SERVICE_URL:
                    LOGGER.error("DocumentSignerService URL not configured.")
                    context.set_code(grpc.StatusCode.INTERNAL)
                    context.set_details("Internal configuration error.")
                    return mdl_engine_pb2.SignMDLResponse(  # type: ignore[no-member]
                        status="ERROR",
                        error_message="Internal configuration error: Signer service URL missing.",
                    )

                with grpc.insecure_channel(settings.DOCUMENT_SIGNER_SERVICE_URL) as channel:
                    signer_stub = document_signer_pb2_grpc.DocumentSignerStub(channel)  # type: ignore[misc]
                    sign_request_proto = document_signer_pb2.SignRequest(  # type: ignore[no-member]
                        document_id=request.mdl_id,
                        content_to_sign=document_content_bytes,
                        signer_id=request.signer_id,
                    )
                    try:
                        sign_response = signer_stub.SignDocument(  # type: ignore[no-member]
                            sign_request_proto, timeout=settings.GRPC_TIMEOUT_SECONDS
                        )
                        signature_hex = sign_response.signature_hex  # type: ignore[no-member]
                    except grpc.RpcError as rpc_e:
                        db.rollback()
                        LOGGER.exception("DocumentSigner service call failed: %s", rpc_e)
                        details_str = str(rpc_e.details())  # type: ignore[attr-defined]
                        status_code_obj = rpc_e.code()  # type: ignore[attr-defined]

                        if not isinstance(status_code_obj, grpc.StatusCode):
                            status_code_obj = grpc.StatusCode.INTERNAL

                        if mdl_record:
                            mdl_record.status = MDLStatus.DRAFT  # type: ignore[assignment]
                            db.commit()

                        context.set_code(status_code_obj)
                        context.set_details(f"Signing service error: {details_str}")
                        return mdl_engine_pb2.SignMDLResponse(  # type: ignore[no-member]
                            status="ERROR",
                            error_message=f"Signing service error: {details_str}",
                        )

                if not signature_hex:
                    LOGGER.error(
                        "Signing service did not return a signature for MDL ID %s.", request.mdl_id
                    )
                    context.set_code(grpc.StatusCode.INTERNAL)
                    context.set_details("Signing service failed to provide a signature.")
                    if mdl_record:
                        mdl_record.status = MDLStatus.DRAFT  # type: ignore[assignment]
                        db.commit()
                    return mdl_engine_pb2.SignMDLResponse(  # type: ignore[no-member]
                        status="ERROR",
                        error_message="Signing service failed to provide a signature.",
                    )

                if not isinstance(current_data_groups.get("signatures"), list):
                    current_data_groups["signatures"] = []

                current_data_groups["signatures"].append(
                    {
                        "signer_id": request.signer_id,
                        "signature_hex": signature_hex,
                        "signed_at": datetime_to_string(datetime.now(timezone.utc)),
                    }
                )

                mdl_record.data_groups = current_data_groups  # type: ignore[assignment]
                flag_modified(mdl_record, "data_groups")
                mdl_record.status = MDLStatus.ACTIVE  # type: ignore[assignment]
                db.commit()
                db.refresh(mdl_record)

                LOGGER.info(
                    "MDL ID %s signed successfully by %s. Status updated to ACTIVE.",
                    request.mdl_id,
                    request.signer_id,
                )
                return mdl_engine_pb2.SignMDLResponse(  # type: ignore[no-member]
                    status="SUCCESS",
                    message="MDL signed and status updated to ACTIVE.",
                    signature_info=mdl_engine_pb2.SignatureInfo(  # type: ignore[no-member]
                        signer_id=request.signer_id,
                        signature_hex=signature_hex,
                        signed_at=datetime_to_string(datetime.now(timezone.utc)),
                    ),
                )

            except grpc.RpcError as rpc_e:
                db.rollback()
                LOGGER.error(
                    "RpcError during signing process for MDL ID %s: %s",
                    request.mdl_id,
                    rpc_e,
                    exc_info=True,
                )
                details_str = str(rpc_e.details())  # type: ignore[attr-defined]
                status_code_obj = rpc_e.code()  # type: ignore[attr-defined]

                if not isinstance(status_code_obj, grpc.StatusCode):
                    status_code_obj = grpc.StatusCode.INTERNAL

                context.set_code(status_code_obj)
                context.set_details(f"Signing service error: {details_str}")
                return mdl_engine_pb2.SignMDLResponse(  # type: ignore[no-member]
                    status="ERROR",
                    error_message=f"Signing service error: {details_str}",
                )
            except SQLAlchemyError as db_e:
                LOGGER.error(
                    "Database error in SignMDL for ID %s: %s",
                    request.mdl_id,
                    db_e,
                    exc_info=True,
                )
                db.rollback()
                context.set_code(grpc.StatusCode.INTERNAL)
                context.set_details(f"Database error: {db_e!s}")
                return mdl_engine_pb2.SignMDLResponse(  # type: ignore[no-member]
                    status="ERROR", error_message=f"Database error: {db_e!s}"
                )
            except Exception as e:  # pylint: disable=broad-except
                LOGGER.exception("Unexpected error in SignMDL for ID %s: %s", request.mdl_id, e)
                db.rollback()
                if "mdl_record" in locals() and mdl_record:
                    try:
                        mdl_record.status = MDLStatus.DRAFT  # type: ignore[assignment]
                        db.commit()
                    except Exception as db_except_on_general_fail:  # pylint: disable=broad-except
                        LOGGER.exception(
                            "Failed to revert status to DRAFT on general error: %s",
                            db_except_on_general_fail,
                        )

                context.set_code(grpc.StatusCode.INTERNAL)
                context.set_details(f"Unexpected internal error: {e!s}")
                return mdl_engine_pb2.SignMDLResponse(  # type: ignore[no-member]
                    status="ERROR", error_message=f"Unexpected internal error: {e!s}"
                )

    def UpdateMDLData(self, request: mdl_engine_pb2.UpdateMDLDataRequest, context: grpc.ServicerContext):  # type: ignore[no-member]
        LOGGER.info("UpdateMDLData request for license number: %s", request.license_number)
        if not request.license_number:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("License number is required.")
            return mdl_engine_pb2.UpdateMDLDataResponse(  # type: ignore[no-member]
                status="ERROR", error_message="License number is required."
            )

        expected_mdl_id = f"mdl_{request.license_number}"

        with SessionLocal() as db:
            try:
                mdl_record: MobileDrivingLicense | None = (
                    db.query(MobileDrivingLicense)
                    .filter(MobileDrivingLicense.document_id == expected_mdl_id)
                    .with_for_update()
                    .first()
                )

                if not mdl_record:
                    msg = f"MDL with license number {request.license_number} not found."
                    LOGGER.warning("UpdateMDLData: %s", msg)
                    context.set_code(grpc.StatusCode.NOT_FOUND)
                    context.set_details(msg)
                    return mdl_engine_pb2.UpdateMDLDataResponse(  # type: ignore[no-member]
                        status="ERROR", error_message=msg
                    )

                # mdl_record.status is an enum instance
                if mdl_record.status in [MDLStatus.EXPIRED, MDLStatus.REVOKED]:
                    msg = (
                        f"MDL {request.license_number} cannot be updated. "
                        f"Current status: {mdl_record.status.value}"  # status is non-nullable MDLStatus enum
                    )
                    LOGGER.warning("UpdateMDLData: %s", msg)
                    context.set_code(grpc.StatusCode.FAILED_PRECONDITION)
                    context.set_details(msg)
                    return mdl_engine_pb2.UpdateMDLDataResponse(  # type: ignore[no-member]
                        status="ERROR", error_message=msg
                    )

                current_data_groups: dict[str, Any] = mdl_record.data_groups.copy() if mdl_record.data_groups is not None else {}  # type: ignore[union-attr]
                updated_fields = False

                if request.HasField("first_name"):  # type: ignore[no-member]
                    current_data_groups["first_name"] = request.first_name
                    updated_fields = True
                if request.HasField("last_name"):  # type: ignore[no-member]
                    current_data_groups["last_name"] = request.last_name
                    updated_fields = True
                if request.HasField("date_of_birth"):  # type: ignore[no-member]
                    current_data_groups["date_of_birth"] = request.date_of_birth
                    updated_fields = True
                if request.HasField("issuing_authority"):  # type: ignore[no-member]
                    mdl_record.issuing_authority = request.issuing_authority  # type: ignore[assignment]
                    updated_fields = True

                if request.HasField("issue_date"):  # type: ignore[no-member]
                    try:
                        mdl_record.issue_date = string_to_datetime(request.issue_date)  # type: ignore[assignment]
                        updated_fields = True
                    except ValueError:
                        context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
                        context.set_details("Invalid issue_date format. Use YYYY-MM-DD.")
                        return mdl_engine_pb2.UpdateMDLDataResponse(status="ERROR", error_message="Invalid issue_date format.")  # type: ignore[no-member]

                if request.HasField("expiry_date"):  # type: ignore[no-member]
                    try:
                        mdl_record.expiry_date = string_to_datetime(request.expiry_date)  # type: ignore[assignment]
                        updated_fields = True
                    except ValueError:
                        context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
                        context.set_details("Invalid expiry_date format. Use YYYY-MM-DD.")
                        return mdl_engine_pb2.UpdateMDLDataResponse(status="ERROR", error_message="Invalid expiry_date format.")  # type: ignore[no-member]

                if request.HasField("portrait"):  # type: ignore[no-member]
                    current_data_groups["portrait_hex"] = request.portrait.hex()
                    updated_fields = True

                if request.license_categories:
                    new_license_categories = [
                        {
                            "category_code": lc.category_code,
                            "issue_date": lc.issue_date,
                            "expiry_date": lc.expiry_date,
                            "restrictions": list(lc.restrictions),
                        }
                        for lc in request.license_categories
                    ]
                    current_data_groups["license_categories"] = new_license_categories
                    updated_fields = True

                if request.additional_fields:
                    new_additional_fields = [
                        {"field_name": af.field_name, "field_value": af.field_value}
                        for af in request.additional_fields
                    ]
                    current_data_groups["additional_fields"] = new_additional_fields
                    updated_fields = True

                if updated_fields:
                    mdl_record.data_groups = current_data_groups  # type: ignore[assignment]
                    flag_modified(mdl_record, "data_groups")

                    if mdl_record.status == MDLStatus.ACTIVE or mdl_record.status not in [
                        MDLStatus.DRAFT,
                        MDLStatus.PENDING_SIGNATURE,
                    ]:
                        mdl_record.status = MDLStatus.PENDING_SIGNATURE  # type: ignore[assignment]

                    current_data_groups["signatures"] = []

                    db.commit()
                    db.refresh(mdl_record)
                    LOGGER.info(
                        "MDL data updated for %s. New status: %s",
                        expected_mdl_id,
                        mdl_record.status.value,  # status is non-nullable MDLStatus enum
                    )
                else:
                    LOGGER.info("No updatable fields provided for MDL: %s", expected_mdl_id)
                    context.set_code(grpc.StatusCode.OK)
                    context.set_details("No updatable fields provided or data is identical.")
                    return mdl_engine_pb2.UpdateMDLDataResponse(  # type: ignore[no-member]
                        status="NO_CHANGE",
                        message="No updatable fields provided or data is identical.",
                    )

                return mdl_engine_pb2.UpdateMDLDataResponse(  # type: ignore[no-member]
                    status="SUCCESS",
                    message="MDL data updated successfully.",
                    mdl_id=mdl_record.document_id,
                    new_status=mdl_record.status.value,  # status is non-nullable MDLStatus enum
                )

            except SQLAlchemyError as db_e:
                LOGGER.error("Database error in UpdateMDLData: %s", db_e, exc_info=True)
                db.rollback()
                context.set_code(grpc.StatusCode.INTERNAL)
                context.set_details(f"Database error: {db_e!s}")
                return mdl_engine_pb2.UpdateMDLDataResponse(  # type: ignore[no-member]
                    status="ERROR", error_message=f"Database error: {db_e!s}"
                )
            except grpc.RpcError as rpc_e:
                LOGGER.exception("gRPC error in UpdateMDLData: %s", rpc_e)
                db.rollback()
                details_str = str(rpc_e.details())  # type: ignore[attr-defined]
                status_code_obj = rpc_e.code()  # type: ignore[attr-defined]
                if not isinstance(status_code_obj, grpc.StatusCode):
                    status_code_obj = grpc.StatusCode.INTERNAL
                context.set_code(status_code_obj)
                context.set_details(f"gRPC error: {details_str}")
                return mdl_engine_pb2.UpdateMDLDataResponse(  # type: ignore[no-member]
                    status="ERROR", error_message=f"gRPC error: {details_str}"
                )
            except Exception as e:  # pylint: disable=broad-except
                LOGGER.exception("Unexpected error in UpdateMDLData: %s", e)
                db.rollback()
                context.set_code(grpc.StatusCode.INTERNAL)
                context.set_details(f"Unexpected internal error: {e!s}")
                return mdl_engine_pb2.UpdateMDLDataResponse(  # type: ignore[no-member]
                    status="ERROR", error_message=f"Unexpected internal error: {e!s}"
                )

    def GetMDLStatus(self, request: mdl_engine_pb2.GetMDLStatusRequest, context: grpc.ServicerContext):  # type: ignore[no-member]
        LOGGER.info("GetMDLStatus request for license number: %s", request.license_number)
        if not request.license_number:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("License number is required.")
            return mdl_engine_pb2.MDLStatusResponse(error_message="License number is required.")  # type: ignore[no-member]

        expected_mdl_id = f"mdl_{request.license_number}"
        with SessionLocal() as db:
            try:
                # Query only the status column and ensure it's the MobileDrivingLicense instance's status
                mdl_status_result = (
                    db.query(MobileDrivingLicense.status)
                    .filter(MobileDrivingLicense.document_id == expected_mdl_id)
                    .first()
                )

                if not mdl_status_result:
                    msg = f"MDL with license number {request.license_number} not found."
                    LOGGER.warning("GetMDLStatus: %s", msg)
                    context.set_code(grpc.StatusCode.NOT_FOUND)
                    context.set_details(msg)
                    return mdl_engine_pb2.MDLStatusResponse(error_message=msg)  # type: ignore[no-member]

                # mdl_status_result is a tuple with one element: the status enum instance
                status_enum_instance = mdl_status_result[0] if mdl_status_result else None
                status_value = status_enum_instance.value if status_enum_instance else "UNKNOWN"

                LOGGER.info("Status for MDL %s: %s", expected_mdl_id, status_value)
                return mdl_engine_pb2.MDLStatusResponse(  # type: ignore[no-member]
                    mdl_id=expected_mdl_id, status=status_value
                )
            except SQLAlchemyError as db_e:
                LOGGER.error("Database error in GetMDLStatus: %s", db_e, exc_info=True)
                context.set_code(grpc.StatusCode.INTERNAL)
                context.set_details(f"Database error: {db_e!s}")
                return mdl_engine_pb2.MDLStatusResponse(error_message=f"Database error: {db_e!s}")  # type: ignore[no-member]
            except Exception as e:  # pylint: disable=broad-except
                LOGGER.exception("Unexpected error in GetMDLStatus: %s", e)
                context.set_code(grpc.StatusCode.INTERNAL)
                context.set_details(f"Unexpected internal error: {e!s}")
                return mdl_engine_pb2.MDLStatusResponse(error_message=f"Unexpected internal error: {e!s}")  # type: ignore[no-member]

    def RevokeMDL(self, request: mdl_engine_pb2.RevokeMDLRequest, context: grpc.ServicerContext):  # type: ignore[no-member]
        LOGGER.info("RevokeMDL request for license number: %s", request.license_number)
        if not request.license_number:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("License number is required.")
            return mdl_engine_pb2.RevokeMDLResponse(  # type: ignore[no-member]
                status="ERROR", error_message="License number is required."
            )

        expected_mdl_id = f"mdl_{request.license_number}"
        with SessionLocal() as db:
            try:
                mdl_record: MobileDrivingLicense | None = (
                    db.query(MobileDrivingLicense)
                    .filter(MobileDrivingLicense.document_id == expected_mdl_id)
                    .with_for_update()
                    .first()
                )

                if not mdl_record:
                    msg = f"MDL with license number {request.license_number} not found."
                    LOGGER.warning("RevokeMDL: %s", msg)
                    context.set_code(grpc.StatusCode.NOT_FOUND)
                    context.set_details(msg)
                    return mdl_engine_pb2.RevokeMDLResponse(  # type: ignore[no-member]
                        status="ERROR", error_message=msg
                    )

                if mdl_record.status == MDLStatus.REVOKED:  # mdl_record.status is enum instance
                    msg = f"MDL {request.license_number} is already revoked."
                    LOGGER.info("RevokeMDL: %s", msg)
                    return mdl_engine_pb2.RevokeMDLResponse(  # type: ignore[no-member]
                        status="SUCCESS", message=msg, new_status=MDLStatus.REVOKED.value
                    )

                mdl_record.status = MDLStatus.REVOKED  # type: ignore[assignment]
                db.commit()
                db.refresh(mdl_record)

                LOGGER.info("MDL %s revoked. Reason: %s", expected_mdl_id, request.reason)
                return mdl_engine_pb2.RevokeMDLResponse(  # type: ignore[no-member]
                    status="SUCCESS",
                    message=f"MDL {expected_mdl_id} revoked successfully.",
                    new_status=MDLStatus.REVOKED.value,
                )
            except SQLAlchemyError as db_e:
                LOGGER.error("Database error in RevokeMDL: %s", db_e, exc_info=True)
                db.rollback()
                context.set_code(grpc.StatusCode.INTERNAL)
                context.set_details(f"Database error: {db_e!s}")
                return mdl_engine_pb2.RevokeMDLResponse(  # type: ignore[no-member]
                    status="ERROR", error_message=f"Database error: {db_e!s}"
                )
            except Exception as e:  # pylint: disable=broad-except
                LOGGER.exception("Unexpected error in RevokeMDL: %s", e)
                db.rollback()
                context.set_code(grpc.StatusCode.INTERNAL)
                context.set_details(f"Unexpected internal error: {e!s}")
                return mdl_engine_pb2.RevokeMDLResponse(  # type: ignore[no-member]
                    status="ERROR", error_message=f"Unexpected internal error: {e!s}"
                )


def serve(port: int = 50051) -> None:
    """Starts the gRPC server."""

    logging.basicConfig(level=logging.INFO)

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    mdl_engine_pb2_grpc.add_MDLEngineServicer_to_server(MDLEngineService(), server)  # type: ignore[no-member]
    server.add_insecure_port(f"[::]:{port}")
    server.start()
    LOGGER.info(f"MDL Engine gRPC server started on port {port}")
    try:
        while True:
            time.sleep(86400)
    except KeyboardInterrupt:
        LOGGER.info("MDL Engine gRPC server shutting down.")
        server.stop(0)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    serve()

# FUTURE ENHANCEMENTS:
# The following features are planned for future releases:
#   - ListMDLs with pagination and advanced filtering capabilities
#   - RenewMDL for license renewal workflows
#   - Automated MDL expiry notification system
#   - Enhanced authentication and authorization mechanisms
#   - Comprehensive input validation and error handling
#   - Full observability stack (metrics, tracing, logging)
#   - Expanded test coverage including performance testing
#
# These enhancements will be prioritized based on production requirements
# and user feedback in future development cycles.
# - Idempotency for create/update operations where applicable.
# - Asynchronous operations for long-running tasks if needed.
# - Linting and formatting consistency (e.g., using black, isort, pylint, ruff).
# - Ensure all `type: ignore` comments are reviewed and addressed if possible.
#   Many `no-member` errors for protobuf objects might indicate issues with
#   how protobuf files are generated or how the linter/type checker is configured.
#   It might be necessary to generate `*.pyi` stub files for the protobuf modules
#   or configure the linter to recognize them properly.
