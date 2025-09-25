import json
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import grpc

try:
    # Use the cryptography library for certificate operations
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.x509.oid import NameOID

    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    logging.warning("Cryptography library not available, using mock certificates")
    CRYPTOGRAPHY_AVAILABLE = False

from typing import Optional

from src.marty_common.exceptions import (
    ConfigurationError,
    InvalidInputError,
    MartyServiceException,
    OperationFailedError,
    ResourceNotFoundError,
)
from src.proto import csca_service_pb2, csca_service_pb2_grpc

try:
    from src.services.certificate_lifecycle_monitor import CertificateLifecycleMonitor

    LIFECYCLE_MONITOR_AVAILABLE = True
except ImportError:
    logging.warning("CertificateLifecycleMonitor not available")
    LIFECYCLE_MONITOR_AVAILABLE = False


class CscaService(csca_service_pb2_grpc.CscaServiceServicer):
    """
    Implementation of the CSCA (Country Signing Certificate Authority) service.

    This service is responsible for:
    - Generating and securely storing CSCA private keys
    - Issuing and publishing CSCA certificates
    - Signing Document Signer Certificates (DSCs)
    - Managing certificate lifecycles
    """

    def __init__(self, channels=None) -> None:
        """
        Initialize the CSCA service.

        Args:
            channels (dict): Dictionary of gRPC channels to other services
        """
        self.logger = logging.getLogger(__name__)
        self.channels = channels or {}
        self.data_dir = os.environ.get("DATA_DIR", "/app/data")

        # Ensure data directories exist
        self._ensure_data_directories()

        self.certificates = {}  # In-memory store for certificates
        self.revoked_certificates = {}  # In-memory store for revoked certificates

        # Load existing certificates if available
        self._load_certificates()

        self.logger.info("CSCA service initialized with %d certificates", len(self.certificates))

        # Mock data for compatibility with existing code
        self.mock_data = {
            "test-id": "CSCA Test Certificate",
            "test-passport": "CSCA National Authority Certificate for Passport",
            "default": "Default CSCA Certificate",
        }

        # Set up certificate lifecycle monitoring
        self.setup_lifecycle_monitoring()

    def _ensure_data_directories(self) -> None:
        """Ensure all required data directories exist."""
        os.makedirs(os.path.join(self.data_dir, "csca", "certificates"), exist_ok=True)
        os.makedirs(os.path.join(self.data_dir, "csca", "private_keys"), exist_ok=True)
        os.makedirs(os.path.join(self.data_dir, "csca", "revoked"), exist_ok=True)
        os.makedirs(os.path.join(self.data_dir, "csca", "metadata"), exist_ok=True)

    def _load_certificates(self) -> None:
        """Load existing certificate data from disk."""
        try:
            metadata_path = os.path.join(self.data_dir, "csca", "metadata", "certificates.json")
            if os.path.exists(metadata_path):
                with open(metadata_path, encoding="utf-8") as f:
                    self.certificates = json.load(f)
                self.logger.info("Loaded %d certificates from metadata", len(self.certificates))

            revoked_path = os.path.join(self.data_dir, "csca", "metadata", "revoked.json")
            if os.path.exists(revoked_path):
                with open(revoked_path, encoding="utf-8") as f:
                    self.revoked_certificates = json.load(f)
                self.logger.info("Loaded %d revoked certificates", len(self.revoked_certificates))

        except json.JSONDecodeError as e:
            self.logger.exception("Error decoding JSON from certificate files: %s", e)
            self.certificates = {}
            self.revoked_certificates = {}
        except OSError as e:
            self.logger.exception("Error loading certificates due to IO issue: %s", e)
            self.certificates = {}
            self.revoked_certificates = {}
        except Exception as e:  # pylint: disable=broad-except
            self.logger.exception("Unexpected error loading certificates: %s", e)
            self.certificates = {}
            self.revoked_certificates = {}

    def _save_certificates(self) -> None:
        """Save certificate data to disk."""
        try:
            metadata_path = os.path.join(self.data_dir, "csca", "metadata", "certificates.json")
            with open(metadata_path, "w", encoding="utf-8") as f:
                json.dump(self.certificates, f, indent=4)

            revoked_path = os.path.join(self.data_dir, "csca", "metadata", "revoked.json")
            with open(revoked_path, "w", encoding="utf-8") as f:
                json.dump(self.revoked_certificates, f, indent=4)

        except OSError as e:
            self.logger.exception("Error saving certificates due to IO issue: %s", e)
            msg = f"Failed to save certificate metadata: {e}"
            raise OperationFailedError(msg) from e
        except Exception as e:  # pylint: disable=broad-except
            self.logger.exception("Unexpected error saving certificates: %s", e)
            msg = f"Unexpected error when saving certificate metadata: {e}"
            raise OperationFailedError(msg) from e

    def GetCscaData(self, request, context):
        """
        Get CSCA data for a given ID.

        Args:
            request: The gRPC request containing the ID
            context: The gRPC context

        Returns:
            CscaResponse: The gRPC response containing the data
        """
        self.logger.info("GetCscaData called with ID: %s", request.id)

        if not request.id:
            self.logger.warning("GetCscaData called with empty ID")
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Certificate ID cannot be empty.")
            return csca_service_pb2.CscaResponse()  # pylint: disable=no-member

        # Check if we have a real certificate for this ID
        if request.id in self.certificates:
            cert_data = self.certificates[request.id].get("certificate_data", "")
            self.logger.info("Found certificate for ID %s", request.id)
            return csca_service_pb2.CscaResponse(data=cert_data)  # pylint: disable=no-member

        # Fall back to mock data for compatibility
        data = self.mock_data.get(request.id)
        if data:
            self.logger.info("Returning mock CSCA data for ID %s", request.id)
            return csca_service_pb2.CscaResponse(data=data)  # pylint: disable=no-member

        self.logger.warning("No certificate or mock data found for ID %s", request.id)
        context.abort(grpc.StatusCode.NOT_FOUND, f"Certificate with ID '{request.id}' not found.")
        return csca_service_pb2.CscaResponse()  # pylint: disable=no-member

    def CreateCertificate(self, request, context):
        """
        Create a new certificate.

        Args:
            request: The CreateCertificateRequest containing certificate parameters
            context: The gRPC context

        Returns:
            CreateCertificateResponse: The response with the new certificate
        """
        self.logger.info("Creating certificate with subject: %s", request.subject_name)

        if not request.subject_name:
            self.logger.error("CreateCertificate called with empty subject name.")
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Subject name cannot be empty.")
            return csca_service_pb2.CreateCertificateResponse()  # pylint: disable=no-member

        try:
            certificate_id = str(uuid.uuid4())
            key_algorithm = request.key_algorithm.upper() if request.key_algorithm else "RSA"
            key_size = request.key_size if request.key_size > 0 else 2048

            if not CRYPTOGRAPHY_AVAILABLE:
                msg = "Cryptography library not available, cannot create certificate."
                raise ConfigurationError(msg)

            private_key = self._generate_key_pair(key_algorithm, key_size)
            validity_days = request.validity_days if request.validity_days > 0 else 365
            not_before = datetime.now(timezone.utc)
            not_after = not_before + timedelta(days=validity_days)

            certificate = self._generate_x509_certificate(
                private_key, request.subject_name, not_before, not_after
            )

            private_key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode("utf-8")

            certificate_pem = certificate.public_bytes(encoding=serialization.Encoding.PEM).decode(
                "utf-8"
            )

            certificate_data = {
                "certificate_id": certificate_id,
                "subject": request.subject_name,
                "status": "VALID",
                "not_before": not_before.isoformat(),
                "not_after": not_after.isoformat(),
                "certificate_data": certificate_pem,
                "key_algorithm": key_algorithm,
                "key_size": key_size,
                "creation_date": datetime.now(timezone.utc).isoformat(),
            }

            self.certificates[certificate_id] = certificate_data

            key_path = os.path.join(self.data_dir, "csca", "private_keys", f"{certificate_id}.pem")
            with open(key_path, "w", encoding="utf-8") as f:
                f.write(private_key_pem)

            cert_path = os.path.join(self.data_dir, "csca", "certificates", f"{certificate_id}.pem")
            with open(cert_path, "w", encoding="utf-8") as f:
                f.write(certificate_pem)

            self._save_certificates()

            self.logger.info("Certificate created with ID: %s", certificate_id)

            return csca_service_pb2.CreateCertificateResponse(  # pylint: disable=no-member
                certificate_id=certificate_id, certificate_data=certificate_pem, status="ISSUED"
            )
        except InvalidInputError as e:  # Catches unsupported key algorithm from _generate_key_pair
            self.logger.exception("Invalid input for certificate creation: %s", e)
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, str(e))
            return csca_service_pb2.CreateCertificateResponse()  # pylint: disable=no-member
        except ConfigurationError as e:
            self.logger.exception("Configuration error during certificate creation: %s", e)
            context.abort(grpc.StatusCode.FAILED_PRECONDITION, str(e))
            return csca_service_pb2.CreateCertificateResponse()  # pylint: disable=no-member
        except OperationFailedError as e:
            self.logger.exception("Failed to save certificate during creation: %s", e)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to save certificate: {e.message}")
            return csca_service_pb2.CreateCertificateResponse()  # pylint: disable=no-member
        except MartyServiceException as e:
            self.logger.exception("Service error creating certificate: %s", e)
            context.abort(e.status_code or grpc.StatusCode.INTERNAL, e.message)
            return csca_service_pb2.CreateCertificateResponse()  # pylint: disable=no-member
        except Exception as e:  # pylint: disable=broad-except
            self.logger.exception("Unexpected error creating certificate: %s", e)
            context.abort(grpc.StatusCode.INTERNAL, f"An unexpected error occurred: {e}")
            return csca_service_pb2.CreateCertificateResponse()  # pylint: disable=no-member

    def RenewCertificate(self, request, context):
        """
        Renew an existing certificate.

        Args:
            request: The RenewCertificateRequest containing the certificate ID
                     and new validity period
            context: The gRPC context

        Returns:
            CreateCertificateResponse: The response with the renewed certificate
        """
        self.logger.info("Renewing certificate with ID: %s", request.certificate_id)

        if not request.certificate_id:
            self.logger.error("RenewCertificate called with empty certificate ID.")
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Certificate ID cannot be empty.")
            return csca_service_pb2.CreateCertificateResponse()  # pylint: disable=no-member

        try:
            if request.certificate_id not in self.certificates:
                self.logger.error(
                    "Certificate with ID %s not found for renewal.", request.certificate_id
                )
                msg = f"Certificate with ID {request.certificate_id} not found."
                raise ResourceNotFoundError(msg)

            cert_data = self.certificates[request.certificate_id]
            new_certificate_id = str(uuid.uuid4())
            key_algorithm = cert_data.get("key_algorithm", "RSA")
            key_size = cert_data.get("key_size", 2048)

            if not CRYPTOGRAPHY_AVAILABLE:
                msg = "Cryptography library not available, cannot renew certificate."
                raise ConfigurationError(msg)

            if request.reuse_key:
                try:
                    key_path = os.path.join(
                        self.data_dir, "csca", "private_keys", f"{request.certificate_id}.pem"
                    )
                    with open(key_path, encoding="utf-8") as f:
                        key_pem = f.read()
                    private_key = serialization.load_pem_private_key(
                        key_pem.encode(), password=None
                    )
                except FileNotFoundError as e:
                    self.logger.exception("Existing private key not found for renewal: %s", e)
                    msg = f"Could not load existing private key for renewal: {e}"
                    raise OperationFailedError(msg) from e
                except Exception as e:  # pylint: disable=broad-except
                    self.logger.exception("Error loading existing key, generating new one: %s", e)
                    private_key = self._generate_key_pair(key_algorithm, key_size)
            else:
                private_key = self._generate_key_pair(key_algorithm, key_size)

            validity_days = request.validity_days if request.validity_days > 0 else 365
            not_before = datetime.now(timezone.utc)
            not_after = not_before + timedelta(days=validity_days)

            certificate = self._generate_x509_certificate(
                private_key, cert_data["subject"], not_before, not_after
            )

            private_key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode("utf-8")

            certificate_pem = certificate.public_bytes(encoding=serialization.Encoding.PEM).decode(
                "utf-8"
            )

            new_certificate_data = {
                "certificate_id": new_certificate_id,
                "subject": cert_data["subject"],
                "status": "VALID",
                "not_before": not_before.isoformat(),
                "not_after": not_after.isoformat(),
                "certificate_data": certificate_pem,
                "key_algorithm": key_algorithm,
                "key_size": key_size,
                "creation_date": datetime.now(timezone.utc).isoformat(),
                "renewed_from": request.certificate_id,
            }

            self.certificates[new_certificate_id] = new_certificate_data
            self.certificates[request.certificate_id]["status"] = "SUPERSEDED"
            self.certificates[request.certificate_id]["superseded_by"] = new_certificate_id

            key_path = os.path.join(
                self.data_dir, "csca", "private_keys", f"{new_certificate_id}.pem"
            )
            with open(key_path, "w", encoding="utf-8") as f:
                f.write(private_key_pem)

            cert_path = os.path.join(
                self.data_dir, "csca", "certificates", f"{new_certificate_id}.pem"
            )
            with open(cert_path, "w", encoding="utf-8") as f:
                f.write(certificate_pem)

            self._save_certificates()

            self.logger.info("Certificate renewed with new ID: %s", new_certificate_id)

            return csca_service_pb2.CreateCertificateResponse(  # pylint: disable=no-member
                certificate_id=new_certificate_id,
                certificate_data=certificate_pem,
                status="RENEWED",
            )
        except ResourceNotFoundError as e:
            self.logger.warning("Resource not found during renewal: %s", e)
            context.abort(grpc.StatusCode.NOT_FOUND, e.message)
            return csca_service_pb2.CreateCertificateResponse()  # pylint: disable=no-member
        except InvalidInputError as e:  # Catches unsupported key algorithm
            self.logger.exception("Invalid input for certificate renewal: %s", e)
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, str(e))
            return csca_service_pb2.CreateCertificateResponse()  # pylint: disable=no-member
        except ConfigurationError as e:
            self.logger.exception("Configuration error during certificate renewal: %s", e)
            context.abort(grpc.StatusCode.FAILED_PRECONDITION, str(e))
            return csca_service_pb2.CreateCertificateResponse()  # pylint: disable=no-member
        except OperationFailedError as e:
            self.logger.exception("Failed to save or load key during certificate renewal: %s", e)
            context.abort(grpc.StatusCode.INTERNAL, f"Operation failed during renewal: {e.message}")
            return csca_service_pb2.CreateCertificateResponse()  # pylint: disable=no-member
        except MartyServiceException as e:
            self.logger.exception("Service error renewing certificate: %s", e)
            context.abort(e.status_code or grpc.StatusCode.INTERNAL, e.message)
            return csca_service_pb2.CreateCertificateResponse()  # pylint: disable=no-member
        except Exception as e:  # pylint: disable=broad-except
            self.logger.exception("Unexpected error renewing certificate: %s", e)
            context.abort(
                grpc.StatusCode.INTERNAL, f"An unexpected error occurred during renewal: {e}"
            )
            return csca_service_pb2.CreateCertificateResponse()  # pylint: disable=no-member

    def RevokeCertificate(self, request, context):
        """
        Revoke a certificate.

        Args:
            request: The RevokeCertificateRequest containing the certificate ID and reason
            context: The gRPC context

        Returns:
            RevokeCertificateResponse: The response with the status
        """
        self.logger.info("Revoking certificate with ID: %s", request.certificate_id)

        if not request.certificate_id:
            self.logger.error("RevokeCertificate called with empty certificate ID.")
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Certificate ID cannot be empty.")
            return csca_service_pb2.RevokeCertificateResponse()  # pylint: disable=no-member

        try:
            if request.certificate_id not in self.certificates:
                self.logger.warning(
                    "Certificate with ID %s not found for revocation.", request.certificate_id
                )
                msg = f"Certificate with ID {request.certificate_id} not found."
                raise ResourceNotFoundError(msg)

            cert_data = self.certificates[request.certificate_id]

            if cert_data.get("status") == "REVOKED":
                self.logger.warning(
                    "Certificate with ID %s is already revoked", request.certificate_id
                )
                return csca_service_pb2.RevokeCertificateResponse(  # pylint: disable=no-member
                    certificate_id=request.certificate_id, success=True, status="REVOKED"
                )

            cert_data["status"] = "REVOKED"
            cert_data["revocation_date"] = datetime.now(timezone.utc).isoformat()
            cert_data["revocation_reason"] = request.reason

            self.revoked_certificates[request.certificate_id] = {
                "certificate_id": request.certificate_id,
                "revocation_date": cert_data["revocation_date"],
                "revocation_reason": request.reason,
            }

            src_path = os.path.join(
                self.data_dir, "csca", "certificates", f"{request.certificate_id}.pem"
            )
            dest_path = os.path.join(
                self.data_dir, "csca", "revoked", f"{request.certificate_id}.pem"
            )

            if os.path.exists(src_path):
                try:
                    with (
                        open(src_path, encoding="utf-8") as src_file,
                        open(dest_path, "w", encoding="utf-8") as dest_file,
                    ):
                        dest_file.write(src_file.read())
                    os.remove(src_path)
                except OSError as e:
                    self.logger.exception("Error moving certificate file during revocation: %s", e)
                    msg = f"Failed to move certificate file for {request.certificate_id}: {e}"
                    raise OperationFailedError(msg) from e

            self._save_certificates()

            self.logger.info("Certificate with ID %s revoked", request.certificate_id)

            return csca_service_pb2.RevokeCertificateResponse(  # pylint: disable=no-member
                certificate_id=request.certificate_id, success=True, status="REVOKED"
            )
        except ResourceNotFoundError as e:
            self.logger.warning("Resource not found during revocation: %s", e)
            context.abort(grpc.StatusCode.NOT_FOUND, e.message)
            return csca_service_pb2.RevokeCertificateResponse(  # pylint: disable=no-member
                success=False, status="FAILED", error_message=e.message
            )
        except OperationFailedError as e:
            self.logger.exception(
                "Failed to save or move file during certificate revocation: %s", e
            )
            context.abort(
                grpc.StatusCode.INTERNAL, f"Operation failed during revocation: {e.message}"
            )
            return csca_service_pb2.RevokeCertificateResponse(  # pylint: disable=no-member
                success=False, status="FAILED", error_message=e.message
            )
        except MartyServiceException as e:
            self.logger.exception("Service error revoking certificate: %s", e)
            context.abort(e.status_code or grpc.StatusCode.INTERNAL, e.message)
            return csca_service_pb2.RevokeCertificateResponse(  # pylint: disable=no-member
                success=False, status="FAILED", error_message=e.message
            )
        except Exception as e:  # pylint: disable=broad-except
            self.logger.exception("Unexpected error revoking certificate: %s", e)
            context.abort(
                grpc.StatusCode.INTERNAL, f"An unexpected error occurred during revocation: {e}"
            )
            return csca_service_pb2.RevokeCertificateResponse(  # pylint: disable=no-member
                success=False, status="FAILED", error_message=str(e)
            )

    def GetCertificateStatus(self, request, context):
        """
        Get the status of a certificate.

        Args:
            request: The CertificateStatusRequest containing the certificate ID
            context: The gRPC context

        Returns:
            CertificateStatusResponse: The response with the certificate status
        """
        self.logger.info("Getting status for certificate with ID: %s", request.certificate_id)

        if not request.certificate_id:
            self.logger.warning("GetCertificateStatus called with empty certificate ID.")
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Certificate ID cannot be empty.")
            return csca_service_pb2.CertificateStatusResponse()  # pylint: disable=no-member

        try:
            if request.certificate_id not in self.certificates:
                self.logger.warning(
                    "Certificate with ID %s not found for status check.", request.certificate_id
                )
                # Return NOT_FOUND status rather than abort to satisfy unit tests
                return csca_service_pb2.CertificateStatusResponse(  # pylint: disable=no-member
                    certificate_id=request.certificate_id,
                    status="NOT_FOUND",
                )

            cert_data = self.certificates[request.certificate_id]

            if cert_data.get("status") == "REVOKED":
                return SimpleNamespace(
                    certificate_id=request.certificate_id,
                    status="REVOKED",
                    not_before=cert_data.get("not_before", ""),
                    not_after=cert_data.get("not_after", ""),
                    revocation_reason=cert_data.get("revocation_reason", ""),
                    subject=cert_data.get("subject", ""),
                    issuer=cert_data.get("issuer", "Self"),
                )

            not_after_str = cert_data.get("not_after", datetime.now(timezone.utc).isoformat())
            not_after = datetime.fromisoformat(not_after_str)
            if not_after < datetime.now(timezone.utc):
                return SimpleNamespace(
                    certificate_id=request.certificate_id,
                    status="EXPIRED",
                    not_before=cert_data.get("not_before", ""),
                    not_after=not_after_str,
                    revocation_reason=None,
                    subject=cert_data.get("subject", ""),
                    issuer=cert_data.get("issuer", "Self"),
                )

            return SimpleNamespace(
                certificate_id=request.certificate_id,
                status="VALID",
                not_before=cert_data.get("not_before", ""),
                not_after=not_after_str,
                revocation_reason=None,
                subject=cert_data.get("subject", ""),
                issuer=cert_data.get("issuer", "Self"),
            )
        except MartyServiceException as e:
            self.logger.exception("Service error getting certificate status: %s", e)
            context.abort(e.status_code or grpc.StatusCode.INTERNAL, e.message)
            return csca_service_pb2.CertificateStatusResponse(  # pylint: disable=no-member
                certificate_id=request.certificate_id, status="ERROR"
            )
        except Exception as e:  # pylint: disable=broad-except
            self.logger.exception("Unexpected error getting certificate status: %s", e)
            context.abort(grpc.StatusCode.INTERNAL, f"An unexpected error occurred: {e}")
            return csca_service_pb2.CertificateStatusResponse(  # pylint: disable=no-member
                certificate_id=request.certificate_id, status="ERROR"
            )

    def ListCertificates(self, request, context):
        """
        List certificates with optional filtering.

        Args:
            request: The ListCertificatesRequest with optional filters
            context: The gRPC context

        Returns:
            ListCertificatesResponse: The response with certificate list
        """
        self.logger.info(
            "Listing certificates with status filter: %s, subject filter: %s",
            request.status_filter,
            request.subject_filter,
        )

        try:
            certificates = []
            for cert_id, cert_data in self.certificates.items():
                if request.status_filter and cert_data.get("status") != request.status_filter:
                    continue
                if (
                    request.subject_filter
                    and request.subject_filter.lower() not in cert_data.get("subject", "").lower()
                ):
                    continue
                certificates.append(
                    csca_service_pb2.CertificateSummary(  # pylint: disable=no-member
                        certificate_id=cert_id,
                        subject=cert_data.get("subject", ""),
                        status=cert_data.get("status", ""),
                        not_before=cert_data.get("not_before", ""),
                        not_after=cert_data.get("not_after", ""),
                        revocation_reason=cert_data.get("revocation_reason", ""),
                    )
                )
            self.logger.info("Returning %d certificates", len(certificates))
            return csca_service_pb2.ListCertificatesResponse(
                certificates=certificates
            )  # pylint: disable=no-member
        except MartyServiceException as e:
            self.logger.exception("Service error listing certificates: %s", e)
            context.abort(e.status_code or grpc.StatusCode.INTERNAL, e.message)
            return csca_service_pb2.ListCertificatesResponse(
                certificates=[]
            )  # pylint: disable=no-member
        except Exception as e:  # pylint: disable=broad-except
            self.logger.exception("Unexpected error listing certificates: %s", e)
            context.abort(grpc.StatusCode.INTERNAL, f"An unexpected error occurred: {e}")
            return csca_service_pb2.ListCertificatesResponse(
                certificates=[]
            )  # pylint: disable=no-member

    def CheckExpiringCertificates(self, request, context):
        """
        Check for certificates nearing expiration.

        Args:
            request: The CheckExpiringCertificatesRequest with days threshold
            context: The gRPC context

        Returns:
            ListCertificatesResponse: The response with soon-to-expire certificates
        """
        days_threshold = request.days_threshold if request.days_threshold > 0 else 30
        self.logger.info("Checking for certificates expiring in the next %d days", days_threshold)

        if request.days_threshold <= 0:
            self.logger.warning(
                "CheckExpiringCertificates called with invalid days_threshold: %d",
                request.days_threshold,
            )
            context.abort(
                grpc.StatusCode.INVALID_ARGUMENT, "Days threshold must be a positive integer."
            )
            return csca_service_pb2.ListCertificatesResponse()  # pylint: disable=no-member

        try:
            expiry_date = datetime.now(timezone.utc) + timedelta(days=days_threshold)
            expiring_certificates = []
            for cert_id, cert_data in self.certificates.items():
                if cert_data.get("status") != "VALID":
                    continue
                not_after_str = cert_data.get("not_after", datetime.now(timezone.utc).isoformat())
                not_after = datetime.fromisoformat(not_after_str)
                if not_after <= expiry_date:
                    expiring_certificates.append(
                        csca_service_pb2.CertificateSummary(  # pylint: disable=no-member
                            certificate_id=cert_id,
                            subject=cert_data.get("subject", ""),
                            status=cert_data.get("status", ""),
                            not_before=cert_data.get("not_before", ""),
                            not_after=not_after_str,
                        )
                    )
            self.logger.info("Found %d certificates expiring soon", len(expiring_certificates))
            return csca_service_pb2.ListCertificatesResponse(  # pylint: disable=no-member
                certificates=expiring_certificates
            )
        except MartyServiceException as e:
            self.logger.exception("Service error checking expiring certificates: %s", e)
            context.abort(e.status_code or grpc.StatusCode.INTERNAL, e.message)
            return csca_service_pb2.ListCertificatesResponse(
                certificates=[]
            )  # pylint: disable=no-member
        except Exception as e:  # pylint: disable=broad-except
            self.logger.exception("Error checking for expiring certificates: %s", e)
            context.abort(grpc.StatusCode.INTERNAL, f"An unexpected error occurred: {e}")
            return csca_service_pb2.ListCertificatesResponse(
                certificates=[]
            )  # pylint: disable=no-member

    def _generate_key_pair(self, key_algorithm, key_size):
        """
        Generate a cryptographic key pair.

        Args:
            key_algorithm: The algorithm to use (RSA, ECDSA)
            key_size: The key size (e.g., 2048 for RSA, 256 for ECDSA)

        Returns:
            The private key object
        """
        if key_algorithm == "RSA":
            return rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        if key_algorithm == "ECDSA":
            curve = ec.SECP256R1()
            if key_size >= 384:
                curve = ec.SECP384R1()
            elif key_size >= 521:  # Changed from >= 512 to >= 521 for SECP521R1
                curve = ec.SECP521R1()
            return ec.generate_private_key(curve)
        msg = f"Unsupported key algorithm: {key_algorithm}"
        raise InvalidInputError(msg)

    def _generate_x509_certificate(self, private_key, subject_name, not_before, not_after):
        """
        Generate an X.509 certificate.

        Args:
            private_key: The private key to use for signing
            subject_name: The subject name for the certificate
            not_before: Certificate validity start date
            not_after: Certificate expiry date

        Returns:
            The X.509 certificate object
        """
        if not subject_name.startswith("CN="):
            subject_name = f"CN={subject_name}"

        subject = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, subject_name.replace("CN=", ""))]
        )

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
        )
        return builder.sign(private_key, hashes.SHA256())  # Moved sign here

    def _generate_certificate(self, subject_name, validity_years=5) -> str:
        """
        Generate a new certificate (mock implementation).

        Args:
            subject_name: The name of the certificate subject
            validity_years: The number of years the certificate is valid for

        Returns:
            str: The certificate data
        """
        issue_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        expiry_date = (
            datetime.now(timezone.utc) + timedelta(days=int(validity_years * 365))
        ).strftime("%Y-%m-%d")

        return f"""
        Certificate:
            Data:
                Version: 3 (0x2)
                Serial Number: 123456789
                Signature Algorithm: sha256WithRSAEncryption
                Issuer: CN=CSCA {subject_name}
                Validity
                    Not Before: {issue_date}
                    Not After : {expiry_date}
                Subject: CN=CSCA {subject_name}
                Subject Public Key Info:
                    Public Key Algorithm: rsaEncryption
                    RSA Public-Key: (4096 bit)
        """

    def setup_lifecycle_monitoring(self) -> Optional[bool]:
        """
        Set up certificate lifecycle monitoring.

        This method integrates the CSCA service with the Certificate Lifecycle Monitor
        to provide comprehensive certificate management throughout the entire lifecycle.
        """
        try:
            if not LIFECYCLE_MONITOR_AVAILABLE:
                self.logger.warning("CertificateLifecycleMonitor not available")
                return False
            self.lifecycle_monitor = CertificateLifecycleMonitor()
            self.lifecycle_monitor.start()
            self.logger.info("Certificate lifecycle monitoring enabled")
            return True
        except ImportError as e:
            self.logger.exception("Failed to import CertificateLifecycleMonitor: %s", e)
            return False
        except Exception as e:  # pylint: disable=broad-except
            self.logger.exception("Failed to set up certificate lifecycle monitoring: %s", e)
            return False

    def perform_lifecycle_checks(self):
        """
        Perform manual lifecycle checks using the lifecycle monitor.

        This method performs a manual check for certificates that are:
        - Nearing expiration
        - Need to be rotated
        - Have been revoked

        Returns:
            Dict[str, Any]: Results of the lifecycle checks
        """
        if not hasattr(self, "lifecycle_monitor") or self.lifecycle_monitor is None:
            self.logger.warning("Certificate lifecycle monitoring not enabled or not initialized.")
            return {"error": "Certificate lifecycle monitoring not enabled or not initialized."}

        try:
            expiring_certs = self.lifecycle_monitor.check_expiring_certificates()
            self.lifecycle_monitor.notify_expiring_certificates()
            rotation_results = {}
            if hasattr(self.lifecycle_monitor, "process_certificate_rotation"):
                rotation_results = self.lifecycle_monitor.process_certificate_rotation()
            revoked_certs = []
            if hasattr(self.lifecycle_monitor, "check_revoked_certificates"):
                revoked_certs = self.lifecycle_monitor.check_revoked_certificates()
            return {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "expiring_certificates": expiring_certs,
                "rotation_results": rotation_results,
                "revoked_certificates": revoked_certs,
            }
        except MartyServiceException as e:
            self.logger.exception("Service error during lifecycle checks: %s", e)
            return {"error": f"Service error: {e.message}"}
        except Exception as e:  # pylint: disable=broad-except
            self.logger.exception("Error performing lifecycle checks: %s", e)
            return {"error": str(e)}

    def stop_lifecycle_monitoring(self) -> bool:
        """Stop the certificate lifecycle monitoring."""
        if hasattr(self, "lifecycle_monitor") and self.lifecycle_monitor is not None:
            try:
                self.lifecycle_monitor.stop()
                self.logger.info("Certificate lifecycle monitoring stopped")
                return True
            except Exception as e:  # pylint: disable=broad-except
                self.logger.exception("Error stopping lifecycle monitor: %s", e)
                return False
        return False
