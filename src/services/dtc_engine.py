import datetime
import hashlib
import io
import json
import logging
import os
import sys
import uuid
from concurrent import futures

import cbor2
import grpc
import qrcode

# Add the parent directory to sys.path to be able to import other modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from proto import document_signer_pb2, document_signer_pb2_grpc, dtc_engine_pb2, dtc_engine_pb2_grpc

# Import the proto-generated files
# Import common utilities
from src.marty_common.config import load_config


class DTCEngineServicer(dtc_engine_pb2_grpc.DTCEngineServicer):
    """
    Implementation of the Digital Travel Credential (DTC) Engine service as defined in the proto file.
    """

    def __init__(self, config=None) -> None:
        self.config = config or load_config()
        self.data_dir = os.environ.get("DATA_DIR", "/app/data")
        os.makedirs(self.data_dir, exist_ok=True)
        self.logger = logging.getLogger(__name__)

        # Service discovery environment variables for dependencies
        self.document_signer_host = os.environ.get("DOCUMENT_SIGNER_HOST", "document-signer")
        self.document_signer_port = os.environ.get("DOCUMENT_SIGNER_PORT", "8082")
        self.passport_engine_host = os.environ.get("PASSPORT_ENGINE_HOST", "passport-engine")
        self.passport_engine_port = os.environ.get("PASSPORT_ENGINE_PORT", "8084")

        # Create directories for DTC data if they don't exist
        self.dtc_data_dir = os.path.join(self.data_dir, "dtcs")
        self.revoked_dtc_dir = os.path.join(self.data_dir, "revoked_dtcs")
        os.makedirs(self.dtc_data_dir, exist_ok=True)
        os.makedirs(self.revoked_dtc_dir, exist_ok=True)

    def CreateDTC(self, request, context):
        """
        Create a new Digital Travel Credential (DTC) from passport data.
        """
        self.logger.info(
            "Creating DTC for passport number: %s, type: %s",
            request.passport_number,
            dtc_engine_pb2.DTCType.Name(request.dtc_type),
        )

        try:
            # Generate a unique ID for the DTC
            dtc_id = f"DTC{uuid.uuid4().hex[:8].upper()}"

            # Determine validity period
            valid_from = request.dtc_valid_from if request.dtc_valid_from else request.issue_date
            valid_until = (
                request.dtc_valid_until if request.dtc_valid_until else request.expiry_date
            )

            # Create DTC record
            dtc_data = {
                "dtc_id": dtc_id,
                "passport_number": request.passport_number,
                "passport_mrz": request.passport_mrz.hex() if request.passport_mrz else None,
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
                    "portrait": (
                        request.personal_details.portrait.hex()
                        if request.personal_details.portrait
                        else None
                    ),
                    "signature": (
                        request.personal_details.signature.hex()
                        if request.personal_details.signature
                        else None
                    ),
                    "other_names": list(request.personal_details.other_names),
                },
                "data_groups": [
                    {
                        "dg_number": dg.dg_number,
                        "data": dg.data.hex() if dg.data else None,
                        "data_type": dg.data_type,
                    }
                    for dg in request.data_groups
                ],
                "dtc_type": dtc_engine_pb2.DTCType.Name(request.dtc_type),
                "access_control": dtc_engine_pb2.AccessControl.Name(request.access_control),
                "access_key_hash": (
                    self._hash_access_key(request.access_key) if request.access_key else None
                ),
                "dtc_valid_from": valid_from,
                "dtc_valid_until": valid_until,
                "created_at": datetime.datetime.now().isoformat(),
                "signature_info": None,
                "is_revoked": False,
                "revocation_reason": None,
                "revocation_date": None,
                "passport_link_status": (
                    "NOT_LINKED"
                    if request.dtc_type == dtc_engine_pb2.DTCType.PHYSICAL
                    else "NOT_APPLICABLE"
                ),
            }

            # Save DTC data to file
            dtc_file_path = os.path.join(self.dtc_data_dir, f"{dtc_id}.json")
            with open(dtc_file_path, "w") as dtc_file:
                json.dump(dtc_data, dtc_file, indent=2)

            self.logger.info("DTC created successfully with ID: %s", dtc_id)
            return dtc_engine_pb2.CreateDTCResponse(
                dtc_id=dtc_id, status="SUCCESS", error_message=""
            )

        except Exception as e:
            self.logger.exception("Error creating DTC: %s", str(e))
            return dtc_engine_pb2.CreateDTCResponse(
                dtc_id="", status="ERROR", error_message=f"Failed to create DTC: {e!s}"
            )

    def GetDTC(self, request, context):
        """
        Retrieve a DTC by its ID.
        """
        self.logger.info("Retrieving DTC with ID: %s", request.dtc_id)

        try:
            # Find DTC file by ID
            dtc_file_path = os.path.join(self.dtc_data_dir, f"{request.dtc_id}.json")

            if not os.path.exists(dtc_file_path):
                # Check if it's in the revoked directory
                revoked_file_path = os.path.join(self.revoked_dtc_dir, f"{request.dtc_id}.json")
                if os.path.exists(revoked_file_path):
                    dtc_file_path = revoked_file_path
                else:
                    return dtc_engine_pb2.DTCResponse(
                        status="NOT_FOUND", error_message=f"DTC with ID {request.dtc_id} not found"
                    )

            # Load DTC data
            with open(dtc_file_path) as dtc_file:
                dtc_data = json.load(dtc_file)

            # Check access control if applicable
            if dtc_data.get("access_key_hash") and not self._validate_access_key(
                request.access_key, dtc_data["access_key_hash"]
            ):
                return dtc_engine_pb2.DTCResponse(
                    status="ACCESS_DENIED", error_message="Invalid access key provided"
                )

            # Convert DTC data to response format
            personal_details = dtc_engine_pb2.PersonalDetails(
                first_name=dtc_data["personal_details"]["first_name"],
                last_name=dtc_data["personal_details"]["last_name"],
                date_of_birth=dtc_data["personal_details"]["date_of_birth"],
                gender=dtc_data["personal_details"]["gender"],
                nationality=dtc_data["personal_details"]["nationality"],
                place_of_birth=dtc_data["personal_details"]["place_of_birth"],
                portrait=(
                    bytes.fromhex(dtc_data["personal_details"]["portrait"])
                    if dtc_data["personal_details"].get("portrait")
                    else b""
                ),
                signature=(
                    bytes.fromhex(dtc_data["personal_details"]["signature"])
                    if dtc_data["personal_details"].get("signature")
                    else b""
                ),
                other_names=dtc_data["personal_details"].get("other_names", []),
            )

            data_groups = [
                dtc_engine_pb2.DataGroup(
                    dg_number=dg["dg_number"],
                    data=bytes.fromhex(dg["data"]) if dg.get("data") else b"",
                    data_type=dg["data_type"],
                )
                for dg in dtc_data.get("data_groups", [])
            ]

            signature_info = None
            if dtc_data.get("signature_info"):
                sig_info = dtc_data["signature_info"]
                signature_info = dtc_engine_pb2.SignatureInfo(
                    signature_date=sig_info["signature_date"],
                    signer_id=sig_info["signer_id"],
                    signature=(
                        bytes.fromhex(sig_info["signature"]) if sig_info.get("signature") else b""
                    ),
                    is_valid=sig_info["is_valid"],
                )
            else:
                signature_info = dtc_engine_pb2.SignatureInfo()

            # Get DTC type enum value from name
            dtc_type = dtc_engine_pb2.DTCType.Value(dtc_data["dtc_type"])

            return dtc_engine_pb2.DTCResponse(
                dtc_id=dtc_data["dtc_id"],
                passport_number=dtc_data["passport_number"],
                issuing_authority=dtc_data["issuing_authority"],
                issue_date=dtc_data["issue_date"],
                expiry_date=dtc_data["expiry_date"],
                personal_details=personal_details,
                data_groups=data_groups,
                dtc_type=dtc_type,
                dtc_valid_from=dtc_data["dtc_valid_from"],
                dtc_valid_until=dtc_data["dtc_valid_until"],
                signature_info=signature_info,
                is_revoked=dtc_data.get("is_revoked", False),
                revocation_reason=dtc_data.get("revocation_reason", ""),
                revocation_date=dtc_data.get("revocation_date", ""),
                status="SUCCESS",
                error_message="",
            )

        except Exception as e:
            self.logger.exception("Error retrieving DTC: %s", str(e))
            return dtc_engine_pb2.DTCResponse(
                status="ERROR", error_message=f"Failed to retrieve DTC: {e!s}"
            )

    def SignDTC(self, request, context):
        """
        Sign a DTC using the Document Signer service.
        """
        self.logger.info("Signing DTC with ID: %s", request.dtc_id)

        try:
            # Find DTC file by ID
            dtc_file_path = os.path.join(self.dtc_data_dir, f"{request.dtc_id}.json")
            if not os.path.exists(dtc_file_path):
                return dtc_engine_pb2.SignDTCResponse(
                    success=False, error_message=f"DTC with ID {request.dtc_id} not found"
                )

            # Load DTC data
            with open(dtc_file_path) as dtc_file:
                dtc_data = json.load(dtc_file)

            # Create CBOR representation of DTC data for signing
            # This follows ICAO DTC specification structure
            dtc_cbor = {
                "id": dtc_data["dtc_id"],
                "type": dtc_data["dtc_type"],
                "passportNumber": dtc_data["passport_number"],
                "issuer": dtc_data["issuing_authority"],
                "issuanceDate": dtc_data["issue_date"],
                "expiryDate": dtc_data["expiry_date"],
                "validFrom": dtc_data["dtc_valid_from"],
                "validUntil": dtc_data["dtc_valid_until"],
                "holder": {
                    "firstName": dtc_data["personal_details"]["first_name"],
                    "lastName": dtc_data["personal_details"]["last_name"],
                    "dateOfBirth": dtc_data["personal_details"]["date_of_birth"],
                    "nationality": dtc_data["personal_details"]["nationality"],
                    "gender": dtc_data["personal_details"]["gender"],
                },
                "dataGroupHashes": {
                    str(dg["dg_number"]): self._hash_data(
                        bytes.fromhex(dg["data"]) if dg.get("data") else b""
                    )
                    for dg in dtc_data["data_groups"]
                },
            }

            cbor_bytes = cbor2.dumps(dtc_cbor)

            # Call document signer service to sign the DTC data
            with grpc.insecure_channel(
                f"{self.document_signer_host}:{self.document_signer_port}"
            ) as channel:
                document_signer_stub = document_signer_pb2_grpc.DocumentSignerStub(channel)
                sign_response = document_signer_stub.SignDocument(
                    document_signer_pb2.SignRequest(
                        document_id=dtc_data["dtc_id"],
                        document_type="DTC",
                        document_data=cbor_bytes,
                    )
                )

            if not sign_response.success:
                return dtc_engine_pb2.SignDTCResponse(
                    success=False,
                    error_message=f"Document signer failed: {sign_response.error_message}",
                )

            # Update signature info in DTC data
            dtc_data["signature_info"] = {
                "signature_date": datetime.datetime.now().isoformat(),
                "signer_id": sign_response.signer_id,
                "signature": sign_response.signature.hex(),
                "is_valid": True,
            }

            # Save updated DTC data
            with open(dtc_file_path, "w") as dtc_file:
                json.dump(dtc_data, dtc_file, indent=2)

            # Create response
            signature_info = dtc_engine_pb2.SignatureInfo(
                signature_date=dtc_data["signature_info"]["signature_date"],
                signer_id=dtc_data["signature_info"]["signer_id"],
                signature=sign_response.signature,
                is_valid=True,
            )

            return dtc_engine_pb2.SignDTCResponse(
                success=True, signature_info=signature_info, error_message=""
            )

        except Exception as e:
            self.logger.exception("Error signing DTC: %s", str(e))
            return dtc_engine_pb2.SignDTCResponse(
                success=False, error_message=f"Failed to sign DTC: {e!s}"
            )

    def RevokeDTC(self, request, context):
        """
        Revoke a DTC.
        """
        self.logger.info("Revoking DTC with ID: %s, reason: %s", request.dtc_id, request.reason)

        try:
            # Find DTC file by ID
            dtc_file_path = os.path.join(self.dtc_data_dir, f"{request.dtc_id}.json")
            if not os.path.exists(dtc_file_path):
                return dtc_engine_pb2.RevokeDTCResponse(
                    success=False, error_message=f"DTC with ID {request.dtc_id} not found"
                )

            # Load DTC data
            with open(dtc_file_path) as dtc_file:
                dtc_data = json.load(dtc_file)

            # Check if already revoked
            if dtc_data.get("is_revoked", False):
                return dtc_engine_pb2.RevokeDTCResponse(
                    success=False, error_message=f"DTC with ID {request.dtc_id} is already revoked"
                )

            # Update revocation info
            revocation_date = datetime.datetime.now().isoformat()
            dtc_data["is_revoked"] = True
            dtc_data["revocation_reason"] = request.reason
            dtc_data["revocation_date"] = revocation_date

            # Move to revoked directory
            revoked_file_path = os.path.join(self.revoked_dtc_dir, f"{request.dtc_id}.json")
            with open(revoked_file_path, "w") as revoked_file:
                json.dump(dtc_data, revoked_file, indent=2)

            # Delete from active DTC directory
            os.remove(dtc_file_path)

            return dtc_engine_pb2.RevokeDTCResponse(
                success=True, revocation_date=revocation_date, error_message=""
            )

        except Exception as e:
            self.logger.exception("Error revoking DTC: %s", str(e))
            return dtc_engine_pb2.RevokeDTCResponse(
                success=False, error_message=f"Failed to revoke DTC: {e!s}"
            )

    def GenerateDTCQRCode(self, request, context):
        """
        Generate QR code for offline verification of a DTC.
        """
        self.logger.info("Generating QR code for DTC ID: %s", request.dtc_id)

        try:
            # Find DTC file by ID
            dtc_file_path = os.path.join(self.dtc_data_dir, f"{request.dtc_id}.json")
            if not os.path.exists(dtc_file_path):
                # Check if it's revoked
                revoked_file_path = os.path.join(self.revoked_dtc_dir, f"{request.dtc_id}.json")
                if os.path.exists(revoked_file_path):
                    return dtc_engine_pb2.GenerateDTCQRCodeResponse(
                        error_message=f"DTC with ID {request.dtc_id} has been revoked"
                    )
                return dtc_engine_pb2.GenerateDTCQRCodeResponse(
                    error_message=f"DTC with ID {request.dtc_id} not found"
                )

            # Load DTC data
            with open(dtc_file_path) as dtc_file:
                dtc_data = json.load(dtc_file)

            # Check if DTC is signed
            if not dtc_data.get("signature_info"):
                return dtc_engine_pb2.GenerateDTCQRCodeResponse(
                    error_message="DTC must be signed before generating QR code"
                )

            # Create filtered data for QR code
            qr_data = {
                "dtc_id": dtc_data["dtc_id"],
                "passport_number": dtc_data["passport_number"],
                "issuing_authority": dtc_data["issuing_authority"],
                "issue_date": dtc_data["issue_date"],
                "expiry_date": dtc_data["expiry_date"],
                "dtc_valid_from": dtc_data["dtc_valid_from"],
                "dtc_valid_until": dtc_data["dtc_valid_until"],
                "dtc_type": dtc_data["dtc_type"],
                "signature_info": dtc_data["signature_info"],
                "personal_details": {
                    "first_name": dtc_data["personal_details"]["first_name"],
                    "last_name": dtc_data["personal_details"]["last_name"],
                    "date_of_birth": dtc_data["personal_details"]["date_of_birth"],
                    "gender": dtc_data["personal_details"]["gender"],
                    "nationality": dtc_data["personal_details"]["nationality"],
                },
            }

            # Include portrait if requested
            if request.include_portrait and dtc_data["personal_details"].get("portrait"):
                qr_data["personal_details"]["portrait"] = dtc_data["personal_details"]["portrait"]

            # Filter data groups based on what's requested
            if request.dg_numbers_to_include:
                dg_numbers = set(request.dg_numbers_to_include)
                qr_data["data_groups"] = [
                    dg for dg in dtc_data["data_groups"] if dg["dg_number"] in dg_numbers
                ]
            else:
                qr_data["data_groups"] = dtc_data["data_groups"]

            # Remove biometric data groups if not requested
            if not request.include_biometrics:
                biometric_dgs = {2, 3, 4}  # DG2, DG3, DG4 contain biometrics
                qr_data["data_groups"] = [
                    dg for dg in qr_data["data_groups"] if dg["dg_number"] not in biometric_dgs
                ]

            # Create CBOR representation for QR code
            cbor_bytes = cbor2.dumps(qr_data)

            # Generate QR code
            qr = qrcode.QRCode(
                version=None,
                error_correction=qrcode.constants.ERROR_CORRECT_H,
                box_size=10,
                border=4,
            )
            qr.add_data(cbor_bytes)
            qr.make(fit=True)

            img = qr.make_image(fill_color="black", back_color="white")

            # Convert image to bytes
            img_byte_arr = io.BytesIO()
            img.save(img_byte_arr, format="PNG")
            img_byte_arr = img_byte_arr.getvalue()

            return dtc_engine_pb2.GenerateDTCQRCodeResponse(qr_code=img_byte_arr, error_message="")

        except Exception as e:
            self.logger.exception("Error generating QR code: %s", str(e))
            return dtc_engine_pb2.GenerateDTCQRCodeResponse(
                error_message=f"Failed to generate QR code: {e!s}"
            )

    def TransferDTCToDevice(self, request, context):
        """
        Transfer a DTC to a mobile device.
        """
        self.logger.info(
            "Transferring DTC ID: %s to device: %s via %s",
            request.dtc_id,
            request.device_id,
            request.transfer_method,
        )

        # In a real implementation, this would integrate with a device communication service
        # For now, we'll simulate the transfer

        try:
            # Find DTC file by ID
            dtc_file_path = os.path.join(self.dtc_data_dir, f"{request.dtc_id}.json")
            if not os.path.exists(dtc_file_path):
                # Check if it's revoked
                revoked_file_path = os.path.join(self.revoked_dtc_dir, f"{request.dtc_id}.json")
                if os.path.exists(revoked_file_path):
                    return dtc_engine_pb2.TransferDTCToDeviceResponse(
                        success=False,
                        error_message=f"DTC with ID {request.dtc_id} has been revoked",
                    )
                return dtc_engine_pb2.TransferDTCToDeviceResponse(
                    success=False, error_message=f"DTC with ID {request.dtc_id} not found"
                )

            # Generate a transfer ID (would be used to track transfer status in a real system)
            transfer_id = f"T{uuid.uuid4().hex[:8].upper()}"

            return dtc_engine_pb2.TransferDTCToDeviceResponse(
                success=True, transfer_id=transfer_id, error_message=""
            )

        except Exception as e:
            self.logger.exception("Error transferring DTC: %s", str(e))
            return dtc_engine_pb2.TransferDTCToDeviceResponse(
                success=False, error_message=f"Failed to transfer DTC: {e!s}"
            )

    def VerifyDTC(self, request, context):
        """
        Verify a DTC.
        """
        self.logger.info("Verifying DTC")

        try:
            dtc_data = None
            verification_results = []

            # Handle different types of DTC data
            if request.HasField("dtc_id"):
                # Load DTC by ID
                dtc_file_path = os.path.join(self.dtc_data_dir, f"{request.dtc_id}.json")
                if not os.path.exists(dtc_file_path):
                    # Check if it's revoked
                    revoked_file_path = os.path.join(self.revoked_dtc_dir, f"{request.dtc_id}.json")
                    if os.path.exists(revoked_file_path):
                        with open(revoked_file_path) as dtc_file:
                            dtc_data = json.load(dtc_file)

                        verification_results.append(
                            dtc_engine_pb2.VerificationResult(
                                check_name="REVOCATION_CHECK",
                                passed=False,
                                details=f"DTC is revoked. Reason: {dtc_data.get('revocation_reason', 'Unknown')}",
                            )
                        )
                    else:
                        return dtc_engine_pb2.VerifyDTCResponse(
                            is_valid=False, error_message=f"DTC with ID {request.dtc_id} not found"
                        )
                else:
                    with open(dtc_file_path) as dtc_file:
                        dtc_data = json.load(dtc_file)

                    verification_results.append(
                        dtc_engine_pb2.VerificationResult(
                            check_name="REVOCATION_CHECK", passed=True, details="DTC is not revoked"
                        )
                    )

            elif request.HasField("qr_code_data"):
                # Parse QR code data (CBOR format)
                try:
                    dtc_data = cbor2.loads(request.qr_code_data)
                    verification_results.append(
                        dtc_engine_pb2.VerificationResult(
                            check_name="QR_CODE_FORMAT",
                            passed=True,
                            details="QR code CBOR format is valid",
                        )
                    )

                    # Check if it's in revoked list
                    dtc_id = dtc_data.get("dtc_id")
                    revoked_file_path = os.path.join(self.revoked_dtc_dir, f"{dtc_id}.json")
                    if os.path.exists(revoked_file_path):
                        verification_results.append(
                            dtc_engine_pb2.VerificationResult(
                                check_name="REVOCATION_CHECK",
                                passed=False,
                                details="DTC has been revoked",
                            )
                        )
                    else:
                        verification_results.append(
                            dtc_engine_pb2.VerificationResult(
                                check_name="REVOCATION_CHECK",
                                passed=True,
                                details="DTC is not revoked",
                            )
                        )

                except Exception as e:
                    verification_results.append(
                        dtc_engine_pb2.VerificationResult(
                            check_name="QR_CODE_FORMAT",
                            passed=False,
                            details=f"Invalid QR code format: {e!s}",
                        )
                    )
                    return dtc_engine_pb2.VerifyDTCResponse(
                        is_valid=False,
                        verification_results=verification_results,
                        error_message="Invalid QR code format",
                    )

            elif request.HasField("device_data"):
                # Parse device data (CBOR format from BLE/NFC)
                try:
                    dtc_data = cbor2.loads(request.device_data)
                    verification_results.append(
                        dtc_engine_pb2.VerificationResult(
                            check_name="DEVICE_DATA_FORMAT",
                            passed=True,
                            details="Device data CBOR format is valid",
                        )
                    )

                    # Check if it's in revoked list
                    dtc_id = dtc_data.get("dtc_id")
                    revoked_file_path = os.path.join(self.revoked_dtc_dir, f"{dtc_id}.json")
                    if os.path.exists(revoked_file_path):
                        verification_results.append(
                            dtc_engine_pb2.VerificationResult(
                                check_name="REVOCATION_CHECK",
                                passed=False,
                                details="DTC has been revoked",
                            )
                        )
                    else:
                        verification_results.append(
                            dtc_engine_pb2.VerificationResult(
                                check_name="REVOCATION_CHECK",
                                passed=True,
                                details="DTC is not revoked",
                            )
                        )

                except Exception as e:
                    verification_results.append(
                        dtc_engine_pb2.VerificationResult(
                            check_name="DEVICE_DATA_FORMAT",
                            passed=False,
                            details=f"Invalid device data format: {e!s}",
                        )
                    )
                    return dtc_engine_pb2.VerifyDTCResponse(
                        is_valid=False,
                        verification_results=verification_results,
                        error_message="Invalid device data format",
                    )

            # Verify DTC data
            if not dtc_data:
                return dtc_engine_pb2.VerifyDTCResponse(
                    is_valid=False, error_message="No valid DTC data provided"
                )

            # Check expiry
            today = datetime.date.today().isoformat()
            if dtc_data["dtc_valid_until"] < today:
                verification_results.append(
                    dtc_engine_pb2.VerificationResult(
                        check_name="EXPIRY_CHECK",
                        passed=False,
                        details=f"DTC expired on {dtc_data['dtc_valid_until']}",
                    )
                )
            else:
                verification_results.append(
                    dtc_engine_pb2.VerificationResult(
                        check_name="EXPIRY_CHECK", passed=True, details="DTC is not expired"
                    )
                )

            # Check signature if available
            if dtc_data.get("signature_info"):
                # In a real implementation, would verify with document signer public key
                # For now, just check if signature exists
                verification_results.append(
                    dtc_engine_pb2.VerificationResult(
                        check_name="SIGNATURE_PRESENT", passed=True, details="DTC has a signature"
                    )
                )
            else:
                verification_results.append(
                    dtc_engine_pb2.VerificationResult(
                        check_name="SIGNATURE_PRESENT",
                        passed=False,
                        details="DTC does not have a signature",
                    )
                )

            # Check passport link if required (for physical DTCs)
            if request.check_passport_link and dtc_data["dtc_type"] != "VIRTUAL":
                if dtc_data.get("passport_link_status") == "VERIFIED":
                    verification_results.append(
                        dtc_engine_pb2.VerificationResult(
                            check_name="PASSPORT_LINK",
                            passed=True,
                            details="DTC is linked to physical passport",
                        )
                    )
                elif (
                    request.passport_number
                    and dtc_data["passport_number"] == request.passport_number
                ):
                    verification_results.append(
                        dtc_engine_pb2.VerificationResult(
                            check_name="PASSPORT_NUMBER_MATCH",
                            passed=True,
                            details="Passport number matches DTC data",
                        )
                    )
                else:
                    verification_results.append(
                        dtc_engine_pb2.VerificationResult(
                            check_name="PASSPORT_LINK",
                            passed=False,
                            details="DTC is not linked to physical passport",
                        )
                    )

            # Prepare the DTC response data
            personal_details = dtc_engine_pb2.PersonalDetails(
                first_name=dtc_data["personal_details"]["first_name"],
                last_name=dtc_data["personal_details"]["last_name"],
                date_of_birth=dtc_data["personal_details"]["date_of_birth"],
                gender=dtc_data["personal_details"]["gender"],
                nationality=dtc_data["personal_details"]["nationality"],
            )

            if "place_of_birth" in dtc_data["personal_details"]:
                personal_details.place_of_birth = dtc_data["personal_details"]["place_of_birth"]

            if dtc_data["personal_details"].get("portrait"):
                personal_details.portrait = bytes.fromhex(dtc_data["personal_details"]["portrait"])

            if dtc_data["personal_details"].get("signature"):
                personal_details.signature = bytes.fromhex(
                    dtc_data["personal_details"]["signature"]
                )

            if "other_names" in dtc_data["personal_details"]:
                personal_details.other_names.extend(dtc_data["personal_details"]["other_names"])

            data_groups = []
            if "data_groups" in dtc_data:
                for dg in dtc_data["data_groups"]:
                    data_group = dtc_engine_pb2.DataGroup(
                        dg_number=dg["dg_number"], data_type=dg["data_type"]
                    )
                    if dg.get("data"):
                        data_group.data = bytes.fromhex(dg["data"])
                    data_groups.append(data_group)

            signature_info = None
            if dtc_data.get("signature_info"):
                sig_info = dtc_data["signature_info"]
                signature_info = dtc_engine_pb2.SignatureInfo(
                    signature_date=sig_info["signature_date"],
                    signer_id=sig_info["signer_id"],
                    signature=bytes.fromhex(sig_info["signature"]),
                    is_valid=sig_info["is_valid"],
                )
            else:
                signature_info = dtc_engine_pb2.SignatureInfo()

            # Determine overall validity
            is_valid = all(
                result.passed
                for result in verification_results
                if result.check_name != "PASSPORT_NUMBER_MATCH"
            )

            # Get DTC type enum value from name
            dtc_type = dtc_engine_pb2.DTCType.Value(dtc_data["dtc_type"])

            return dtc_engine_pb2.VerifyDTCResponse(
                is_valid=is_valid,
                verification_results=verification_results,
                dtc_data=dtc_engine_pb2.DTCResponse(
                    dtc_id=dtc_data.get("dtc_id", ""),
                    passport_number=dtc_data.get("passport_number", ""),
                    issuing_authority=dtc_data.get("issuing_authority", ""),
                    issue_date=dtc_data.get("issue_date", ""),
                    expiry_date=dtc_data.get("expiry_date", ""),
                    personal_details=personal_details,
                    data_groups=data_groups,
                    dtc_type=dtc_type,
                    dtc_valid_from=dtc_data.get("dtc_valid_from", ""),
                    dtc_valid_until=dtc_data.get("dtc_valid_until", ""),
                    signature_info=signature_info,
                    is_revoked=dtc_data.get("is_revoked", False),
                    revocation_reason=dtc_data.get("revocation_reason", ""),
                    revocation_date=dtc_data.get("revocation_date", ""),
                    status="SUCCESS",
                    error_message="",
                ),
                error_message="",
            )

        except Exception as e:
            self.logger.exception("Error verifying DTC: %s", str(e))
            return dtc_engine_pb2.VerifyDTCResponse(
                is_valid=False, error_message=f"Failed to verify DTC: {e!s}"
            )

    def LinkDTCToPassport(self, request, context):
        """
        Link a DTC to a physical passport.
        """
        self.logger.info(
            "Linking DTC ID: %s to passport: %s", request.dtc_id, request.passport_number
        )

        try:
            # Find DTC file by ID
            dtc_file_path = os.path.join(self.dtc_data_dir, f"{request.dtc_id}.json")
            if not os.path.exists(dtc_file_path):
                return dtc_engine_pb2.LinkDTCToPassportResponse(
                    success=False, error_message=f"DTC with ID {request.dtc_id} not found"
                )

            # Load DTC data
            with open(dtc_file_path) as dtc_file:
                dtc_data = json.load(dtc_file)

            # Check if passport number matches
            if dtc_data["passport_number"] != request.passport_number:
                return dtc_engine_pb2.LinkDTCToPassportResponse(
                    success=False, error_message="Passport number does not match DTC record"
                )

            # In a real implementation, would verify passport authenticity
            # For example by checking the MRZ and authenticating with passport chip

            # Update link status
            link_date = datetime.datetime.now().isoformat()
            dtc_data["passport_link_status"] = "VERIFIED"
            dtc_data["passport_link_date"] = link_date

            # Save updated DTC data
            with open(dtc_file_path, "w") as dtc_file:
                json.dump(dtc_data, dtc_file, indent=2)

            return dtc_engine_pb2.LinkDTCToPassportResponse(
                success=True, link_date=link_date, error_message=""
            )

        except Exception as e:
            self.logger.exception("Error linking DTC to passport: %s", str(e))
            return dtc_engine_pb2.LinkDTCToPassportResponse(
                success=False, error_message=f"Failed to link DTC to passport: {e!s}"
            )

    def _hash_access_key(self, access_key):
        """Simple hash function for access key. In production, use proper hashing."""
        return hashlib.sha256(access_key.encode()).hexdigest()

    def _validate_access_key(self, provided_key, stored_hash):
        """Validate an access key against stored hash."""
        if not provided_key:
            return False
        return self._hash_access_key(provided_key) == stored_hash

    def _hash_data(self, data):
        """Hash function for data groups. In production, use algorithm specified in ICAO doc."""
        return hashlib.sha256(data).hexdigest()


def serve() -> None:
    """
    Start the gRPC server for the DTC Engine service.
    """
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    dtc_engine_pb2_grpc.add_DTCEngineServicer_to_server(DTCEngineServicer(), server)

    port = os.environ.get("GRPC_PORT", "8087")
    server.add_insecure_port(f"[::]:{port}")
    server.start()

    print(f"DTC Engine service listening on port {port}", flush=True)
    server.wait_for_termination()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    serve()
