#!/usr/bin/env python

"""
Digital Travel Credential (DTC) Engine Service Implementation.

This service handles the creation, management, signing, and verification of
Digital Travel Credentials (DTCs) according to ICAO standards.
"""

import io
import json
import logging
import os
import uuid
from datetime import datetime
from types import SimpleNamespace
from typing import Any

import grpc
import qrcode

from src.marty_common.config import Config
from src.marty_common.crypto import hash_password, verify_password, verify_signature
from src.marty_common.grpc_client import GRPCClient
from src.proto import (
    common_services_pb2_grpc,
    document_signer_pb2,
    document_signer_pb2_grpc,
    dtc_engine_pb2,
    dtc_engine_pb2_grpc,
)


class DTCEngineService(dtc_engine_pb2_grpc.DTCEngineServicer):
    """Service for managing Digital Travel Credentials."""

    def __init__(self, config: Config) -> None:
        """Initialize the DTC Engine Service.

        Args:
            config: Configuration object containing service settings
        """
        self.logger = logging.getLogger(__name__)
        self.config = config
        self._dtc_store: dict[str, dict[str, Any]] = {}

        # Set up data directories
        self.data_dir = os.environ.get("DATA_DIR", "/data")
        self.dtc_storage_dir = os.path.join(self.data_dir, "dtc_store")
        os.makedirs(self.dtc_storage_dir, exist_ok=True)

        # Initialize document signer client for signing DTCs
        self.document_signer_client = None
        try:
            self.document_signer_client = GRPCClient(
                service_name="document-signer",
                stub_class=document_signer_pb2_grpc.DocumentSignerStub,
                config=config,
            )
            self.logger.info("Successfully connected to Document Signer service")
        except Exception as e:
            self.logger.exception(f"Failed to connect to Document Signer service: {e!s}")

    def _vr(self, name: str) -> int:
        """Resolve overall verification result enum to its integer value."""
        try:
            return dtc_engine_pb2.VerificationResult.Value(name)
        except Exception:
            # Fallback to UNKNOWN_RESULT
            return dtc_engine_pb2.VerificationResult.Value("UNKNOWN_RESULT")

    def CreateDTC(
        self, request: dtc_engine_pb2.CreateDTCRequest, context: grpc.ServicerContext
    ) -> dtc_engine_pb2.CreateDTCResponse:
        """Create a new Digital Travel Credential.

        Args:
            request: The CreateDTCRequest containing DTC details
            context: The gRPC service context

        Returns:
            CreateDTCResponse with the status of the operation and DTC ID
        """
        self.logger.info(f"Creating DTC for passport: {request.passport_number}")

        try:
            # Generate a unique ID for the DTC
            dtc_id = str(uuid.uuid4())

            # Create DTC data structure
            dtc_data = {
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
                    "other_names": list(request.personal_details.other_names),
                },
                "data_groups": [
                    {
                        "dg_number": dg.dg_number,
                        "data_type": dg.data_type,
                        "data": dg.data.decode("latin1") if isinstance(dg.data, bytes) else dg.data,
                    }
                    for dg in request.data_groups
                ],
                "dtc_type": request.dtc_type,
                "access_control": request.access_control,
                "access_key_hash": hash_password(request.access_key),
                "creation_date": datetime.now().isoformat(),
                "dtc_valid_from": request.dtc_valid_from,
                "dtc_valid_until": request.dtc_valid_until,
                "is_signed": False,
                "signature": None,
                "signature_info": None,
                "is_revoked": False,
                "revocation_date": None,
                "revocation_reason": None,
            }

            # Store binary data separately (portrait and signature)
            if request.personal_details.portrait:
                portrait_path = os.path.join(self.dtc_storage_dir, f"{dtc_id}_portrait.bin")
                with open(portrait_path, "wb") as f:
                    f.write(request.personal_details.portrait)
                dtc_data["personal_details"]["portrait_path"] = portrait_path

            if request.personal_details.signature:
                signature_path = os.path.join(self.dtc_storage_dir, f"{dtc_id}_signature.bin")
                with open(signature_path, "wb") as f:
                    f.write(request.personal_details.signature)
                dtc_data["personal_details"]["signature_path"] = signature_path

            # Save DTC data to storage
            dtc_file_path = os.path.join(self.dtc_storage_dir, f"{dtc_id}.json")
            with open(dtc_file_path, "w") as f:
                json.dump(dtc_data, f, indent=2)
            self._dtc_store[dtc_id] = dtc_data

            self.logger.info(f"Successfully created DTC with ID: {dtc_id}")

            # Return success response
            return dtc_engine_pb2.CreateDTCResponse(
                status="SUCCESS", dtc_id=dtc_id, error_message=""
            )

        except Exception as e:
            self.logger.exception(f"Failed to create DTC: {e!s}")
            return dtc_engine_pb2.CreateDTCResponse(
                status="ERROR", dtc_id="", error_message=f"Failed to create DTC: {e!s}"
            )

    def GetDTC(self, request: dtc_engine_pb2.GetDTCRequest, context: grpc.ServicerContext):
        """Retrieve a Digital Travel Credential.

        Args:
            request: The GetDTCRequest containing DTC ID and access key
            context: The gRPC service context

        Returns:
            GetDTCResponse with the DTC details
        """
        self.logger.info(f"Retrieving DTC with ID: {request.dtc_id}")

        try:
            # Check if DTC exists
            dtc_file_path = os.path.join(self.dtc_storage_dir, f"{request.dtc_id}.json")
            if not os.path.exists(dtc_file_path):
                dtc_data = self._dtc_store.get(request.dtc_id)
                if not dtc_data:
                    self.logger.error(f"DTC with ID {request.dtc_id} not found")
                    return SimpleNamespace(
                        status="NOT_FOUND",
                        error_message=f"DTC with ID {request.dtc_id} not found",
                        dtc_id="",
                    )
            else:
                # Read DTC data
                with open(dtc_file_path) as f:
                    dtc_data = json.load(f)

            # Verify access key
            if not verify_password(request.access_key, dtc_data["access_key_hash"]):
                self.logger.error(f"Access denied for DTC with ID {request.dtc_id}")
                return SimpleNamespace(
                    status="ACCESS_DENIED",
                    error_message="Access denied: Invalid access key",
                    dtc_id=request.dtc_id,
                )

            # Prepare response
            response = SimpleNamespace(
                status="SUCCESS",
                error_message="",
                dtc_id=dtc_data["dtc_id"],
                passport_number=dtc_data["passport_number"],
                issuing_authority=dtc_data["issuing_authority"],
                issue_date=dtc_data["issue_date"],
                expiry_date=dtc_data["expiry_date"],
                dtc_type=dtc_data["dtc_type"],
                creation_date=dtc_data["creation_date"],
                dtc_valid_from=dtc_data["dtc_valid_from"],
                dtc_valid_until=dtc_data["dtc_valid_until"],
                is_signed=dtc_data["is_signed"],
                is_revoked=dtc_data["is_revoked"],
                revocation_reason=dtc_data.get("revocation_reason", ""),
                personal_details=dtc_engine_pb2.PersonalDetails(),
                data_groups=[],
                signature_info=dtc_engine_pb2.SignatureInfo(),
            )

            # Add personal details
            personal_details = dtc_engine_pb2.PersonalDetails(
                first_name=dtc_data["personal_details"]["first_name"],
                last_name=dtc_data["personal_details"]["last_name"],
                date_of_birth=dtc_data["personal_details"]["date_of_birth"],
                gender=dtc_data["personal_details"]["gender"],
                nationality=dtc_data["personal_details"]["nationality"],
                place_of_birth=dtc_data["personal_details"]["place_of_birth"],
                other_names=dtc_data["personal_details"].get("other_names", []),
            )

            # Load portrait and signature if available
            if "portrait_path" in dtc_data["personal_details"]:
                with open(dtc_data["personal_details"]["portrait_path"], "rb") as f:
                    personal_details.portrait = f.read()

            if "signature_path" in dtc_data["personal_details"]:
                with open(dtc_data["personal_details"]["signature_path"], "rb") as f:
                    personal_details.signature = f.read()

            response.personal_details = personal_details

            # Add data groups
            for dg in dtc_data["data_groups"]:
                data_group = dtc_engine_pb2.DataGroup(
                    dg_number=dg["dg_number"], data_type=dg["data_type"]
                )

                # Convert data back to bytes if needed
                if isinstance(dg["data"], str):
                    data_group.data = dg["data"].encode("latin1")
                else:
                    data_group.data = dg["data"]

                response.data_groups.append(data_group)

            # Add signature info if available
            if dtc_data.get("signature_info"):
                signature_info = dtc_engine_pb2.SignatureInfo(
                    signature_date=dtc_data["signature_info"]["signature_date"],
                    signer_id=dtc_data["signature_info"]["signer_id"],
                    is_valid=dtc_data["signature_info"]["is_valid"],
                )
                response.signature_info = signature_info

            self.logger.info(f"Successfully retrieved DTC with ID: {request.dtc_id}")
            return response

        except Exception as e:
            self.logger.exception(f"Failed to retrieve DTC: {e!s}")
            return SimpleNamespace(
                status="ERROR",
                error_message=f"Failed to retrieve DTC: {e!s}",
                dtc_id=request.dtc_id,
            )

    def SignDTC(
        self, request: dtc_engine_pb2.SignDTCRequest, context: grpc.ServicerContext
    ) -> dtc_engine_pb2.SignDTCResponse:
        """Sign a Digital Travel Credential.

        Args:
            request: The SignDTCRequest containing DTC ID and access key
            context: The gRPC service context

        Returns:
            SignDTCResponse with the status of the signing operation
        """
        self.logger.info(f"Signing DTC with ID: {request.dtc_id}")

        try:
            # Check if DTC exists
            dtc_file_path = os.path.join(self.dtc_storage_dir, f"{request.dtc_id}.json")
            if os.path.exists(dtc_file_path):
                with open(dtc_file_path) as f:
                    dtc_data = json.load(f)
            else:
                dtc_data = self._dtc_store.get(request.dtc_id)
                if not dtc_data:
                    self.logger.error(f"DTC with ID {request.dtc_id} not found")
                    return dtc_engine_pb2.SignDTCResponse(
                        success=False, error_message=f"DTC with ID {request.dtc_id} not found"
                    )

            # Verify access key
            if not verify_password(request.access_key, dtc_data["access_key_hash"]):
                self.logger.error(f"Access denied for DTC with ID {request.dtc_id}")
                return dtc_engine_pb2.SignDTCResponse(
                    success=False, error_message="Access denied: Invalid access key"
                )

            # Check if DTC is already signed
            if dtc_data.get("is_signed", False):
                self.logger.warning(f"DTC with ID {request.dtc_id} is already signed")

                # Return the existing signature info
                signature_info = dtc_engine_pb2.SignatureInfo(
                    signature_date=dtc_data["signature_info"]["signature_date"],
                    signer_id=dtc_data["signature_info"]["signer_id"],
                    is_valid=dtc_data["signature_info"]["is_valid"],
                )

                return dtc_engine_pb2.SignDTCResponse(
                    success=True,
                    error_message="DTC is already signed",
                    signature_info=signature_info,
                )

            # Check if document signer service is available
            if not self.document_signer_client:
                self.logger.error("Document Signer service is not available")
                return dtc_engine_pb2.SignDTCResponse(
                    success=False, error_message="Document Signer service is not available"
                )

            # Prepare data to be signed
            dtc_content = json.dumps(dtc_data).encode("utf-8")

            # Call document signer service
            sign_request = document_signer_pb2.SignRequest(
                document_id=request.dtc_id,
                document_content=dtc_content,
            )

            sign_response = self.document_signer_client.stub.SignDocument(sign_request)

            if not sign_response.success:
                self.logger.error(f"Failed to sign DTC: {sign_response.error_message}")
                return dtc_engine_pb2.SignDTCResponse(
                    success=False,
                    error_message=f"Failed to sign DTC: {sign_response.error_message}",
                )

            # Update DTC with signature information
            signature_date = datetime.now().isoformat()
            dtc_data["is_signed"] = True
            dtc_data["signature"] = (
                sign_response.signature.decode("latin1")
                if isinstance(sign_response.signature, bytes)
                else sign_response.signature
            )
            dtc_data["signature_info"] = {
                "signature_date": signature_date,
                "signer_id": sign_response.signer_id,
                "is_valid": True,
            }

            # Save updated DTC
            with open(dtc_file_path, "w") as f:
                json.dump(dtc_data, f, indent=2)
            self._dtc_store[request.dtc_id] = dtc_data

            # Prepare response
            signature_info = dtc_engine_pb2.SignatureInfo(
                signature_date=signature_date, signer_id=sign_response.signer_id, is_valid=True
            )

            self.logger.info(f"Successfully signed DTC with ID: {request.dtc_id}")
            return dtc_engine_pb2.SignDTCResponse(
                success=True, error_message="", signature_info=signature_info
            )

        except Exception as e:
            self.logger.exception(f"Failed to sign DTC: {e!s}")
            return dtc_engine_pb2.SignDTCResponse(
                success=False, error_message=f"Failed to sign DTC: {e!s}"
            )

    def RevokeDTC(
        self, request: dtc_engine_pb2.RevokeDTCRequest, context: grpc.ServicerContext
    ) -> dtc_engine_pb2.RevokeDTCResponse:
        """Revoke a Digital Travel Credential.

        Args:
            request: The RevokeDTCRequest containing DTC ID, reason, and access key
            context: The gRPC service context

        Returns:
            RevokeDTCResponse with the status of the revocation operation
        """
        self.logger.info(f"Revoking DTC with ID: {request.dtc_id}")

        try:
            # Check if DTC exists
            dtc_file_path = os.path.join(self.dtc_storage_dir, f"{request.dtc_id}.json")
            if not os.path.exists(dtc_file_path):
                self.logger.error(f"DTC with ID {request.dtc_id} not found")
                return dtc_engine_pb2.RevokeDTCResponse(
                    success=False, error_message=f"DTC with ID {request.dtc_id} not found"
                )

            # Read DTC data
            with open(dtc_file_path) as f:
                dtc_data = json.load(f)

            # Verify access key
            if not verify_password(request.access_key, dtc_data["access_key_hash"]):
                self.logger.error(f"Access denied for DTC with ID {request.dtc_id}")
                return dtc_engine_pb2.RevokeDTCResponse(
                    success=False, error_message="Access denied: Invalid access key"
                )

            # Check if DTC is already revoked
            if dtc_data.get("is_revoked", False):
                self.logger.warning(f"DTC with ID {request.dtc_id} is already revoked")
                return dtc_engine_pb2.RevokeDTCResponse(
                    success=True, error_message="DTC is already revoked"
                )

            # Update DTC with revocation information
            dtc_data["is_revoked"] = True
            dtc_data["revocation_date"] = datetime.now().isoformat()
            dtc_data["revocation_reason"] = request.reason

            # Save updated DTC
            with open(dtc_file_path, "w") as f:
                json.dump(dtc_data, f, indent=2)

            self.logger.info(f"Successfully revoked DTC with ID: {request.dtc_id}")
            return dtc_engine_pb2.RevokeDTCResponse(success=True, error_message="")

        except Exception as e:
            self.logger.exception(f"Failed to revoke DTC: {e!s}")
            return dtc_engine_pb2.RevokeDTCResponse(
                success=False, error_message=f"Failed to revoke DTC: {e!s}"
            )

    def GenerateDTCQRCode(
        self, request: dtc_engine_pb2.GenerateDTCQRCodeRequest, context: grpc.ServicerContext
    ):
        """Generate a QR code for a Digital Travel Credential.

        Args:
            request: The GenerateDTCQRCodeRequest containing DTC ID and access key
            context: The gRPC service context

        Returns:
            GenerateDTCQRCodeResponse with the QR code image data
        """
        self.logger.info(f"Generating QR code for DTC with ID: {request.dtc_id}")

        try:
            # Check if DTC exists
            dtc_file_path = os.path.join(self.dtc_storage_dir, f"{request.dtc_id}.json")
            if os.path.exists(dtc_file_path):
                with open(dtc_file_path) as f:
                    dtc_data = json.load(f)
            else:
                dtc_data = self._dtc_store.get(request.dtc_id)
                if not dtc_data:
                    self.logger.error(f"DTC with ID {request.dtc_id} not found")
                    return SimpleNamespace(
                        success=False,
                        error_message=f"DTC with ID {request.dtc_id} not found",
                        qr_code=b"",
                        mime_type="",
                    )

            # Verify access key
            if not verify_password(request.access_key, dtc_data["access_key_hash"]):
                self.logger.error(f"Access denied for DTC with ID {request.dtc_id}")
                return SimpleNamespace(
                    success=False,
                    error_message="Access denied: Invalid access key",
                    qr_code=b"",
                    mime_type="",
                )

            # Check if DTC is signed (optional check based on requirements)
            if getattr(request, "require_signature", False) and not dtc_data.get(
                "is_signed", False
            ):
                self.logger.error(f"DTC with ID {request.dtc_id} is not signed")
                return SimpleNamespace(
                    success=False,
                    error_message="DTC must be signed before generating QR code",
                    qr_code=b"",
                    mime_type="",
                )

            # Check if DTC is revoked
            if dtc_data.get("is_revoked", False):
                self.logger.error(f"DTC with ID {request.dtc_id} is revoked")
                return SimpleNamespace(
                    success=False,
                    error_message=f"DTC is revoked: {dtc_data.get('revocation_reason', 'No reason provided')}",
                    qr_code=b"",
                    mime_type="",
                )

            # Prepare QR code content
            qr_data = {
                "dtc_id": dtc_data["dtc_id"],
                "passport_number": dtc_data["passport_number"],
                "issuing_authority": dtc_data["issuing_authority"],
                "name": f"{dtc_data['personal_details']['first_name']} {dtc_data['personal_details']['last_name']}",
                "nationality": dtc_data["personal_details"]["nationality"],
                "date_of_birth": dtc_data["personal_details"]["date_of_birth"],
                "expiry_date": dtc_data["expiry_date"],
                "dtc_type": dtc_data["dtc_type"],
            }

            # Add signature information if available
            if dtc_data.get("is_signed", False) and dtc_data.get("signature_info"):
                qr_data["signature_date"] = dtc_data["signature_info"]["signature_date"]
                qr_data["signer_id"] = dtc_data["signature_info"]["signer_id"]

            # Generate QR code
            qr = qrcode.QRCode(
                version=10,
                error_correction=qrcode.constants.ERROR_CORRECT_H,
                box_size=10,
                border=4,
            )
            qr.add_data(json.dumps(qr_data))
            qr.make(fit=True)

            # Create image
            img = qr.make_image(fill_color="black", back_color="white")

            # Convert to bytes
            img_bytes = io.BytesIO()
            img.save(img_bytes, format="PNG")
            qr_code_data = img_bytes.getvalue()

            self.logger.info(f"Successfully generated QR code for DTC with ID: {request.dtc_id}")

            # Return response with QR code image
            return SimpleNamespace(
                success=True, error_message="", qr_code=qr_code_data, mime_type="image/png"
            )

        except Exception as e:
            self.logger.exception(f"Failed to generate QR code: {e!s}")
            return SimpleNamespace(
                success=False,
                error_message=f"Failed to generate QR code: {e!s}",
                qr_code=b"",
                mime_type="",
            )

    def VerifyDTC(self, request: dtc_engine_pb2.VerifyDTCRequest, context: grpc.ServicerContext):
        """Verify a Digital Travel Credential.

        Args:
            request: The VerifyDTCRequest containing DTC ID and access key
            context: The gRPC service context

        Returns:
            VerifyDTCResponse with the verification result
        """
        self.logger.info(f"Verifying DTC with ID: {request.dtc_id}")

        try:
            # Check if DTC exists
            dtc_file_path = os.path.join(self.dtc_storage_dir, f"{request.dtc_id}.json")
            if not os.path.exists(dtc_file_path):
                self.logger.error(f"DTC with ID {request.dtc_id} not found")
                return SimpleNamespace(
                    success=False,
                    error_message=f"DTC with ID {request.dtc_id} not found",
                    verification_result=self._vr("INVALID"),
                )

            # Read DTC data
            with open(dtc_file_path) as f:
                dtc_data = json.load(f)

            # Verify access key
            if not verify_password(request.access_key, dtc_data["access_key_hash"]):
                self.logger.error(f"Access denied for DTC with ID {request.dtc_id}")
                return SimpleNamespace(
                    success=False,
                    error_message="Access denied: Invalid access key",
                    verification_result=self._vr("ACCESS_DENIED"),
                )

            # Check if DTC is revoked
            if dtc_data.get("is_revoked", False):
                self.logger.warning(f"DTC with ID {request.dtc_id} is revoked")
                return SimpleNamespace(
                    success=True,
                    error_message="DTC is revoked",
                    verification_result=self._vr("REVOKED"),
                )

            # Check if DTC is signed
            if not dtc_data.get("is_signed", False):
                self.logger.warning(f"DTC with ID {request.dtc_id} is not signed")
                return SimpleNamespace(
                    success=True,
                    error_message="DTC is not signed",
                    verification_result=self._vr("NOT_SIGNED"),
                )

            # Check if DTC is expired
            try:
                valid_until = datetime.fromisoformat(dtc_data["dtc_valid_until"])
                if valid_until < datetime.now():
                    self.logger.warning(f"DTC with ID {request.dtc_id} is expired")
                    return SimpleNamespace(
                        success=True,
                        error_message="DTC has expired",
                        verification_result=self._vr("EXPIRED"),
                    )
            except (ValueError, KeyError):
                self.logger.warning(f"DTC with ID {request.dtc_id} has invalid date format")

            # Verify the signature
            signature = dtc_data.get("signature")
            if not signature:
                self.logger.error(f"DTC with ID {request.dtc_id} has no signature data")
                return SimpleNamespace(
                    success=False,
                    error_message="DTC has no signature data",
                    verification_result=self._vr("INVALID"),
                )

            # Create copy of data without signature for verification
            verification_data = dict(dtc_data)
            verification_data.pop("signature")
            data_to_verify = json.dumps(verification_data).encode("utf-8")

            # Decode signature if stored as string
            if isinstance(signature, str):
                signature = signature.encode("latin1")

            # Verify the signature
            # In this simplified demo, treat signer_id as a public key placeholder
            is_valid = verify_signature(
                data_to_verify,
                signature,
                dtc_data["signature_info"].get("signer_id", "").encode("utf-8"),
            )

            if not is_valid:
                self.logger.error(f"Signature verification failed for DTC with ID {request.dtc_id}")
                return SimpleNamespace(
                    success=True,
                    error_message="Signature verification failed",
                    verification_result=self._vr("INVALID_SIGNATURE"),
                )

            self.logger.info(f"Successfully verified DTC with ID: {request.dtc_id}")
            # Map to enum value; import here to avoid circulars
            return SimpleNamespace(
                success=True, error_message="", verification_result=self._vr("VALID")
            )

        except Exception as e:
            self.logger.exception(f"Failed to verify DTC: {e!s}")
            return SimpleNamespace(
                success=False,
                error_message=f"Failed to verify DTC: {e!s}",
                verification_result=self._vr("INVALID"),
            )
