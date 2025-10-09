"""Advanced X.509 certificate parsing and validation for Trust Service.

This module provides comprehensive ASN.1/X.509 certificate parsing capabilities
specifically designed for ICAO PKD certificates (CSCAs and DSCs) with support
for extended validation, chain verification, and ICAO-specific extensions.
"""

import hashlib
import logging
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import constraint, namedtype, tag, univ
from pyasn1_modules import rfc5280

logger = logging.getLogger(__name__)


class CertificateType(Enum):
    """Certificate type enumeration."""

    CSCA = "csca"
    DSC = "dsc"
    CRL_SIGNER = "crl_signer"
    UNKNOWN = "unknown"


class ValidationResult(Enum):
    """Certificate validation result."""

    VALID = "valid"
    INVALID = "invalid"
    EXPIRED = "expired"
    NOT_YET_VALID = "not_yet_valid"
    REVOKED = "revoked"
    UNKNOWN = "unknown"


class KeyUsageFlags:
    """Key usage flag constants."""

    DIGITAL_SIGNATURE = "digital_signature"
    CONTENT_COMMITMENT = "content_commitment"
    KEY_ENCIPHERMENT = "key_encipherment"
    DATA_ENCIPHERMENT = "data_encipherment"
    KEY_AGREEMENT = "key_agreement"
    KEY_CERT_SIGN = "key_cert_sign"
    CRL_SIGN = "crl_sign"
    ENCIPHER_ONLY = "encipher_only"
    DECIPHER_ONLY = "decipher_only"


class ICAOExtensions:
    """ICAO-specific certificate extension OIDs."""

    # ICAO Document Type List
    DOCUMENT_TYPE_LIST = "2.23.136.1.1.1"
    # ICAO Master List Identifier
    MASTER_LIST_IDENTIFIER = "2.23.136.1.1.2"
    # ICAO Document Security Object
    DOCUMENT_SECURITY_OBJECT = "2.23.136.1.1.3"
    # ICAO Country Identifier
    COUNTRY_IDENTIFIER = "2.23.136.1.1.4"


class CertificateInfo:
    """Comprehensive certificate information container."""

    def __init__(self):
        self.subject: str | None = None
        self.issuer: str | None = None
        self.serial_number: str | None = None
        self.version: int | None = None
        self.not_before: datetime | None = None
        self.not_after: datetime | None = None
        self.signature_algorithm: str | None = None
        self.public_key_algorithm: str | None = None
        self.public_key_size: int | None = None
        self.fingerprint_sha1: str | None = None
        self.fingerprint_sha256: str | None = None
        self.fingerprint_md5: str | None = None
        self.key_usage: list[str] = []
        self.extended_key_usage: list[str] = []
        self.basic_constraints: dict[str, Any] | None = None
        self.subject_alternative_names: list[str] = []
        self.issuer_alternative_names: list[str] = []
        self.authority_key_identifier: str | None = None
        self.subject_key_identifier: str | None = None
        self.crl_distribution_points: list[str] = []
        self.authority_info_access: dict[str, list[str]] = {}
        self.certificate_policies: list[str] = []
        self.icao_extensions: dict[str, Any] = {}
        self.country_code: str | None = None
        self.certificate_type: CertificateType = CertificateType.UNKNOWN
        self.is_ca: bool = False
        self.path_length_constraint: int | None = None
        self.raw_der: bytes | None = None


class ASN1Parser:
    """Advanced ASN.1 structure parser for certificate extensions."""

    @staticmethod
    def parse_document_type_list(extension_value: bytes) -> list[str]:
        """Parse ICAO Document Type List extension."""
        try:
            asn1_obj, _ = decoder.decode(extension_value)
            document_types = []

            for item in asn1_obj:
                if hasattr(item, "prettyPrint"):
                    doc_type = str(item.prettyPrint())
                    document_types.append(doc_type)

            return document_types
        except Exception as e:
            logger.warning(f"Failed to parse document type list: {e}")
            return []

    @staticmethod
    def parse_master_list_identifier(extension_value: bytes) -> str | None:
        """Parse ICAO Master List Identifier extension."""
        try:
            asn1_obj, _ = decoder.decode(extension_value)
            return str(asn1_obj.prettyPrint())
        except Exception as e:
            logger.warning(f"Failed to parse master list identifier: {e}")
            return None

    @staticmethod
    def parse_country_identifier(extension_value: bytes) -> str | None:
        """Parse ICAO Country Identifier extension."""
        try:
            asn1_obj, _ = decoder.decode(extension_value)
            country_code = str(asn1_obj.prettyPrint()).strip("\"'")

            # Validate country code format (should be 3-letter ISO code)
            if len(country_code) == 3 and country_code.isalpha():
                return country_code.upper()

            return None
        except Exception as e:
            logger.warning(f"Failed to parse country identifier: {e}")
            return None


class X509CertificateParser:
    """Advanced X.509 certificate parser with ICAO extensions support."""

    def __init__(self):
        self.asn1_parser = ASN1Parser()

    def parse_certificate(self, cert_data: bytes | str) -> CertificateInfo:
        """Parse X.509 certificate and extract comprehensive information.

        Args:
            cert_data: Certificate data in DER, PEM, or base64 format

        Returns:
            CertificateInfo object with parsed certificate data

        Raises:
            ValueError: If certificate data is invalid or cannot be parsed
        """
        try:
            # Convert certificate data to bytes if needed
            cert_bytes = self._normalize_certificate_data(cert_data)

            # Parse certificate using cryptography library
            certificate = x509.load_der_x509_certificate(cert_bytes)

            # Create certificate info object
            cert_info = CertificateInfo()
            cert_info.raw_der = cert_bytes

            # Extract basic certificate information
            self._extract_basic_info(certificate, cert_info)

            # Extract public key information
            self._extract_public_key_info(certificate, cert_info)

            # Extract extensions
            self._extract_extensions(certificate, cert_info)

            # Generate fingerprints
            self._generate_fingerprints(cert_bytes, cert_info)

            # Determine certificate type
            self._determine_certificate_type(cert_info)

            return cert_info

        except Exception as e:
            logger.error(f"Failed to parse certificate: {e}")
            raise ValueError(f"Invalid certificate data: {e}")

    def _normalize_certificate_data(self, cert_data: bytes | str) -> bytes:
        """Normalize certificate data to DER format bytes."""
        if isinstance(cert_data, str):
            # Handle PEM format
            if cert_data.startswith("-----BEGIN CERTIFICATE-----"):
                try:
                    return x509.load_pem_x509_certificate(cert_data.encode()).public_bytes(
                        Encoding.DER
                    )
                except Exception:
                    pass

            # Handle base64 encoded data
            import base64

            try:
                return base64.b64decode(cert_data)
            except Exception:
                # Try as hex string
                try:
                    return bytes.fromhex(cert_data.replace(" ", "").replace(":", ""))
                except Exception:
                    raise ValueError("Invalid certificate format")

        return cert_data

    def _extract_basic_info(self, certificate: x509.Certificate, cert_info: CertificateInfo):
        """Extract basic certificate information."""
        # Subject and issuer
        cert_info.subject = certificate.subject.rfc4514_string()
        cert_info.issuer = certificate.issuer.rfc4514_string()

        # Serial number
        cert_info.serial_number = f"{certificate.serial_number:X}"

        # Version
        cert_info.version = certificate.version.value

        # Validity period
        cert_info.not_before = certificate.not_valid_before.replace(tzinfo=timezone.utc)
        cert_info.not_after = certificate.not_valid_after.replace(tzinfo=timezone.utc)

        # Signature algorithm
        cert_info.signature_algorithm = certificate.signature_algorithm_oid._name

    def _extract_public_key_info(self, certificate: x509.Certificate, cert_info: CertificateInfo):
        """Extract public key information."""
        public_key = certificate.public_key()

        if isinstance(public_key, rsa.RSAPublicKey):
            cert_info.public_key_algorithm = "RSA"
            cert_info.public_key_size = public_key.key_size
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            cert_info.public_key_algorithm = "EC"
            cert_info.public_key_size = public_key.curve.key_size
        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            cert_info.public_key_algorithm = "Ed25519"
            cert_info.public_key_size = 256
        elif isinstance(public_key, ed448.Ed448PublicKey):
            cert_info.public_key_algorithm = "Ed448"
            cert_info.public_key_size = 448
        else:
            cert_info.public_key_algorithm = "Unknown"

    def _extract_extensions(self, certificate: x509.Certificate, cert_info: CertificateInfo):
        """Extract certificate extensions."""
        for extension in certificate.extensions:
            try:
                self._process_extension(extension, cert_info)
            except Exception as e:
                logger.warning(f"Failed to process extension {extension.oid}: {e}")

    def _process_extension(self, extension: x509.Extension, cert_info: CertificateInfo):
        """Process individual certificate extension."""
        oid = extension.oid.dotted_string

        # Key Usage
        if oid == "2.5.29.15":  # Key Usage
            key_usage = extension.value
            if key_usage.digital_signature:
                cert_info.key_usage.append(KeyUsageFlags.DIGITAL_SIGNATURE)
            if key_usage.content_commitment:
                cert_info.key_usage.append(KeyUsageFlags.CONTENT_COMMITMENT)
            if key_usage.key_encipherment:
                cert_info.key_usage.append(KeyUsageFlags.KEY_ENCIPHERMENT)
            if key_usage.data_encipherment:
                cert_info.key_usage.append(KeyUsageFlags.DATA_ENCIPHERMENT)
            if key_usage.key_agreement:
                cert_info.key_usage.append(KeyUsageFlags.KEY_AGREEMENT)
            if key_usage.key_cert_sign:
                cert_info.key_usage.append(KeyUsageFlags.KEY_CERT_SIGN)
            if key_usage.crl_sign:
                cert_info.key_usage.append(KeyUsageFlags.CRL_SIGN)

        # Extended Key Usage
        elif oid == "2.5.29.37":  # Extended Key Usage
            ext_key_usage = extension.value
            for usage in ext_key_usage:
                cert_info.extended_key_usage.append(usage.dotted_string)

        # Basic Constraints
        elif oid == "2.5.29.19":  # Basic Constraints
            basic_constraints = extension.value
            cert_info.is_ca = basic_constraints.ca
            cert_info.path_length_constraint = basic_constraints.path_length
            cert_info.basic_constraints = {
                "ca": basic_constraints.ca,
                "path_length": basic_constraints.path_length,
            }

        # Subject Alternative Names
        elif oid == "2.5.29.17":  # Subject Alternative Names
            san = extension.value
            for name in san:
                cert_info.subject_alternative_names.append(str(name.value))

        # Authority Key Identifier
        elif oid == "2.5.29.35":  # Authority Key Identifier
            aki = extension.value
            if aki.key_identifier:
                cert_info.authority_key_identifier = aki.key_identifier.hex()

        # Subject Key Identifier
        elif oid == "2.5.29.14":  # Subject Key Identifier
            ski = extension.value
            cert_info.subject_key_identifier = ski.digest.hex()

        # CRL Distribution Points
        elif oid == "2.5.29.31":  # CRL Distribution Points
            crl_dp = extension.value
            for dp in crl_dp:
                if dp.full_name:
                    for name in dp.full_name:
                        cert_info.crl_distribution_points.append(str(name.value))

        # Authority Information Access
        elif oid == "1.3.6.1.5.5.7.1.1":  # Authority Information Access
            aia = extension.value
            for access_desc in aia:
                access_method = access_desc.access_method.dotted_string
                location = str(access_desc.access_location.value)

                if access_method not in cert_info.authority_info_access:
                    cert_info.authority_info_access[access_method] = []
                cert_info.authority_info_access[access_method].append(location)

        # Certificate Policies
        elif oid == "2.5.29.32":  # Certificate Policies
            policies = extension.value
            for policy in policies:
                cert_info.certificate_policies.append(policy.policy_identifier.dotted_string)

        # ICAO Extensions
        elif oid in [
            ICAOExtensions.DOCUMENT_TYPE_LIST,
            ICAOExtensions.MASTER_LIST_IDENTIFIER,
            ICAOExtensions.DOCUMENT_SECURITY_OBJECT,
            ICAOExtensions.COUNTRY_IDENTIFIER,
        ]:
            self._process_icao_extension(oid, extension.value.value, cert_info)

    def _process_icao_extension(self, oid: str, extension_value: bytes, cert_info: CertificateInfo):
        """Process ICAO-specific certificate extensions."""
        if oid == ICAOExtensions.DOCUMENT_TYPE_LIST:
            doc_types = self.asn1_parser.parse_document_type_list(extension_value)
            cert_info.icao_extensions["document_types"] = doc_types

        elif oid == ICAOExtensions.MASTER_LIST_IDENTIFIER:
            ml_id = self.asn1_parser.parse_master_list_identifier(extension_value)
            cert_info.icao_extensions["master_list_id"] = ml_id

        elif oid == ICAOExtensions.COUNTRY_IDENTIFIER:
            country = self.asn1_parser.parse_country_identifier(extension_value)
            if country:
                cert_info.country_code = country
                cert_info.icao_extensions["country_code"] = country

    def _generate_fingerprints(self, cert_bytes: bytes, cert_info: CertificateInfo):
        """Generate certificate fingerprints."""
        cert_info.fingerprint_md5 = hashlib.md5(cert_bytes).hexdigest()
        cert_info.fingerprint_sha1 = hashlib.sha1(cert_bytes).hexdigest()
        cert_info.fingerprint_sha256 = hashlib.sha256(cert_bytes).hexdigest()

    def _determine_certificate_type(self, cert_info: CertificateInfo):
        """Determine certificate type based on extensions and attributes."""
        # Check if it's a CA certificate
        if cert_info.is_ca and KeyUsageFlags.KEY_CERT_SIGN in cert_info.key_usage:
            # CSCA certificates are typically root CAs or intermediate CAs
            # with specific ICAO extensions
            if cert_info.icao_extensions or cert_info.country_code:
                cert_info.certificate_type = CertificateType.CSCA
            else:
                cert_info.certificate_type = CertificateType.CSCA  # Assume CSCA for CA certs in PKD

        # Check for CRL signing capability
        elif KeyUsageFlags.CRL_SIGN in cert_info.key_usage:
            cert_info.certificate_type = CertificateType.CRL_SIGNER

        # DSC certificates are typically end-entity certificates
        elif KeyUsageFlags.DIGITAL_SIGNATURE in cert_info.key_usage and not cert_info.is_ca:
            cert_info.certificate_type = CertificateType.DSC

        else:
            cert_info.certificate_type = CertificateType.UNKNOWN


class CertificateValidator:
    """Advanced certificate validation with chain verification."""

    def __init__(self):
        self.parser = X509CertificateParser()
        self.trusted_cscas: dict[str, CertificateInfo] = {}

    def add_trusted_csca(self, csca_cert: bytes | str, identifier: str = None):
        """Add a trusted CSCA certificate to the trust store."""
        try:
            cert_info = self.parser.parse_certificate(csca_cert)
            key = identifier or cert_info.fingerprint_sha256
            self.trusted_cscas[key] = cert_info
            logger.info(f"Added trusted CSCA: {cert_info.subject}")
        except Exception as e:
            logger.error(f"Failed to add trusted CSCA: {e}")

    def validate_certificate(
        self, cert_data: bytes | str, issuer_cert: bytes | str | None = None
    ) -> tuple[ValidationResult, dict[str, Any]]:
        """Validate certificate with comprehensive checks.

        Args:
            cert_data: Certificate to validate
            issuer_cert: Optional issuer certificate for chain validation

        Returns:
            Tuple of (ValidationResult, validation_details)
        """
        try:
            cert_info = self.parser.parse_certificate(cert_data)
            validation_details = {
                "certificate_info": cert_info,
                "validation_time": datetime.now(timezone.utc),
                "checks_performed": [],
                "errors": [],
                "warnings": [],
            }

            # Time validity check
            result = self._check_time_validity(cert_info, validation_details)
            if result != ValidationResult.VALID:
                return result, validation_details

            # Signature verification
            if issuer_cert:
                result = self._verify_signature(cert_data, issuer_cert, validation_details)
                if result != ValidationResult.VALID:
                    return result, validation_details

            # Chain validation
            result = self._validate_chain(cert_info, validation_details)
            if result != ValidationResult.VALID:
                return result, validation_details

            # ICAO-specific validation
            self._validate_icao_compliance(cert_info, validation_details)

            return ValidationResult.VALID, validation_details

        except Exception as e:
            logger.error(f"Certificate validation failed: {e}")
            return ValidationResult.INVALID, {"error": str(e)}

    def _check_time_validity(
        self, cert_info: CertificateInfo, validation_details: dict[str, Any]
    ) -> ValidationResult:
        """Check certificate time validity."""
        now = datetime.now(timezone.utc)
        validation_details["checks_performed"].append("time_validity")

        if now < cert_info.not_before:
            validation_details["errors"].append("Certificate not yet valid")
            return ValidationResult.NOT_YET_VALID

        if now > cert_info.not_after:
            validation_details["errors"].append("Certificate expired")
            return ValidationResult.EXPIRED

        return ValidationResult.VALID

    def _verify_signature(
        self,
        cert_data: bytes,
        issuer_cert_data: bytes | str,
        validation_details: dict[str, Any],
    ) -> ValidationResult:
        """Verify certificate signature against issuer."""
        try:
            validation_details["checks_performed"].append("signature_verification")

            # Load certificates
            cert = x509.load_der_x509_certificate(cert_data)
            issuer_cert_bytes = self.parser._normalize_certificate_data(issuer_cert_data)
            issuer_cert = x509.load_der_x509_certificate(issuer_cert_bytes)

            # Get issuer public key
            issuer_public_key = issuer_cert.public_key()

            # Verify signature
            if isinstance(issuer_public_key, rsa.RSAPublicKey):
                issuer_public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    cert.signature_hash_algorithm,
                )
            elif isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
                issuer_public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    ec.ECDSA(cert.signature_hash_algorithm),
                )
            else:
                validation_details["warnings"].append("Unsupported signature algorithm")
                return ValidationResult.UNKNOWN

            return ValidationResult.VALID

        except Exception as e:
            validation_details["errors"].append(f"Signature verification failed: {e}")
            return ValidationResult.INVALID

    def _validate_chain(
        self, cert_info: CertificateInfo, validation_details: dict[str, Any]
    ) -> ValidationResult:
        """Validate certificate chain against trusted CSCAs."""
        validation_details["checks_performed"].append("chain_validation")

        # Check if certificate is directly trusted
        if cert_info.fingerprint_sha256 in self.trusted_cscas:
            return ValidationResult.VALID

        # For DSC certificates, check if issuer is trusted
        if cert_info.certificate_type == CertificateType.DSC:
            # Try to find trusted issuer by authority key identifier
            if cert_info.authority_key_identifier:
                for csca in self.trusted_cscas.values():
                    if (
                        csca.subject_key_identifier == cert_info.authority_key_identifier
                        or csca.subject == cert_info.issuer
                    ):
                        return ValidationResult.VALID

            validation_details["warnings"].append("Cannot verify chain - issuer not in trust store")
            return ValidationResult.UNKNOWN

        return ValidationResult.VALID

    def _validate_icao_compliance(
        self, cert_info: CertificateInfo, validation_details: dict[str, Any]
    ):
        """Validate ICAO-specific requirements."""
        validation_details["checks_performed"].append("icao_compliance")

        # Check for required extensions in ICAO certificates
        if cert_info.certificate_type == CertificateType.CSCA:
            if not cert_info.country_code:
                validation_details["warnings"].append("CSCA missing country code")

            if KeyUsageFlags.KEY_CERT_SIGN not in cert_info.key_usage:
                validation_details["warnings"].append("CSCA missing key certificate signing usage")

        elif cert_info.certificate_type == CertificateType.DSC:
            if KeyUsageFlags.DIGITAL_SIGNATURE not in cert_info.key_usage:
                validation_details["warnings"].append("DSC missing digital signature usage")


class CertificateChainBuilder:
    """Build and validate certificate chains."""

    def __init__(self):
        self.certificates: dict[str, CertificateInfo] = {}
        self.parser = X509CertificateParser()

    def add_certificate(self, cert_data: bytes | str, identifier: str = None) -> str:
        """Add certificate to the builder."""
        cert_info = self.parser.parse_certificate(cert_data)
        key = identifier or cert_info.fingerprint_sha256
        self.certificates[key] = cert_info
        return key

    def build_chain(self, end_entity_id: str) -> list[CertificateInfo]:
        """Build certificate chain from end entity to root."""
        if end_entity_id not in self.certificates:
            raise ValueError(f"Certificate {end_entity_id} not found")

        chain = []
        current_cert = self.certificates[end_entity_id]
        visited = set()

        while current_cert and current_cert.fingerprint_sha256 not in visited:
            chain.append(current_cert)
            visited.add(current_cert.fingerprint_sha256)

            # Find issuer
            issuer_cert = self._find_issuer(current_cert)
            if issuer_cert and issuer_cert.fingerprint_sha256 != current_cert.fingerprint_sha256:
                current_cert = issuer_cert
            else:
                break

        return chain

    def _find_issuer(self, cert: CertificateInfo) -> CertificateInfo | None:
        """Find the issuer certificate for a given certificate."""
        for candidate in self.certificates.values():
            # Check if subject matches issuer
            if candidate.subject == cert.issuer:
                # Check authority key identifier if available
                if (
                    cert.authority_key_identifier
                    and candidate.subject_key_identifier == cert.authority_key_identifier
                ):
                    return candidate
                # If no key identifiers, assume match based on subject/issuer
                elif not cert.authority_key_identifier:
                    return candidate

        return None
