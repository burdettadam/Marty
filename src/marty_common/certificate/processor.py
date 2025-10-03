"""
Certificate processing utilities to eliminate duplicate cryptography patterns.

This module consolidates common certificate operations using cryptography.x509
to reduce code duplication across services that handle certificates.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

logger = logging.getLogger(__name__)


class CertificateError(Exception):
    """Base exception for certificate processing errors."""

    def __init__(self, message: str, certificate_path: str | None = None) -> None:
        """Initialize certificate error."""
        super().__init__(message)
        self.certificate_path = certificate_path
        self.message = message


class CertificateValidationError(CertificateError):
    """Exception raised when certificate validation fails."""


class CertificateExpirationError(CertificateError):
    """Exception raised when certificate is expired or expires soon."""


class CertificateProcessor:
    """
    Unified certificate processing utilities.

    Consolidates common patterns for certificate loading, parsing,
    validation, and information extraction.
    """

    @staticmethod
    def load_certificate_from_file(cert_path: str | Path) -> x509.Certificate:
        """
        Load certificate from PEM or DER file.

        Args:
            cert_path: Path to certificate file

        Returns:
            Loaded certificate object

        Raises:
            CertificateError: If certificate cannot be loaded
        """
        cert_path = Path(cert_path)
        if not cert_path.exists():
            error_msg = "Certificate file not found"
            raise CertificateError(error_msg, str(cert_path))

        try:
            with cert_path.open("rb") as f:
                cert_data = f.read()

            # Try PEM format first
            try:
                return x509.load_pem_x509_certificate(cert_data)
            except ValueError:
                # Fall back to DER format
                return x509.load_der_x509_certificate(cert_data)

        except (OSError, ValueError) as e:
            error_msg = f"Failed to load certificate: {e}"
            raise CertificateError(error_msg, str(cert_path)) from e

    @staticmethod
    def load_certificate_from_bytes(cert_data: bytes) -> x509.Certificate:
        """
        Load certificate from bytes (PEM or DER format).

        Args:
            cert_data: Certificate data as bytes

        Returns:
            Loaded certificate object

        Raises:
            CertificateError: If certificate cannot be loaded
        """
        try:
            # Try PEM format first
            try:
                return x509.load_pem_x509_certificate(cert_data)
            except ValueError:
                # Fall back to DER format
                return x509.load_der_x509_certificate(cert_data)
        except ValueError as e:
            error_msg = f"Failed to parse certificate data: {e}"
            raise CertificateError(error_msg) from e

    @staticmethod
    def get_certificate_info(certificate: x509.Certificate) -> dict[str, Any]:
        """
        Extract comprehensive information from certificate.

        Args:
            certificate: Certificate to analyze

        Returns:
            Dictionary containing certificate information
        """
        subject_parts = CertificateProcessor._extract_name_parts(certificate.subject)
        issuer_parts = CertificateProcessor._extract_name_parts(certificate.issuer)
        san_list = CertificateProcessor._extract_subject_alt_names(certificate)

        return {
            "subject": subject_parts,
            "issuer": issuer_parts,
            "serial_number": str(certificate.serial_number),
            "version": certificate.version.name,
            "not_valid_before": certificate.not_valid_before,
            "not_valid_after": certificate.not_valid_after,
            "subject_alternative_names": san_list,
            "signature_algorithm": str(certificate.signature_algorithm_oid),
            "public_key_algorithm": type(certificate.public_key()).__name__,
            "fingerprint_sha256": certificate.fingerprint(hashes.SHA256()).hex(),
        }

    @staticmethod
    def _extract_name_parts(name: x509.Name) -> dict[str, str]:
        """Extract name parts from X.509 Name object."""
        parts = {}
        for attribute in name:
            if attribute.oid == NameOID.COMMON_NAME:
                parts["common_name"] = attribute.value
            elif attribute.oid == NameOID.COUNTRY_NAME:
                parts["country"] = attribute.value
            elif attribute.oid == NameOID.ORGANIZATION_NAME:
                parts["organization"] = attribute.value
            elif attribute.oid == NameOID.ORGANIZATIONAL_UNIT_NAME:
                parts["organizational_unit"] = attribute.value
        return parts

    @staticmethod
    def _extract_subject_alt_names(certificate: x509.Certificate) -> list[str]:
        """Extract subject alternative names from certificate."""
        san_list = []
        try:
            san_extension = certificate.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            for name in san_extension.value:
                if isinstance(name, x509.DNSName):
                    san_list.append(f"DNS:{name.value}")
                elif isinstance(name, x509.IPAddress):
                    san_list.append(f"IP:{name.value}")
                elif isinstance(name, x509.RFC822Name):
                    san_list.append(f"EMAIL:{name.value}")
                elif isinstance(name, x509.UniformResourceIdentifier):
                    san_list.append(f"URI:{name.value}")
        except x509.ExtensionNotFound:
            pass  # No SAN extension
        return san_list

    @staticmethod
    def validate_certificate(
        certificate: x509.Certificate,
        check_expiration: bool = True,
        days_warning: int = 30,
    ) -> dict[str, Any]:
        """
        Validate certificate and check expiration.

        Args:
            certificate: Certificate to validate
            check_expiration: Whether to check expiration dates
            days_warning: Days before expiration to warn

        Returns:
            Dictionary with validation results

        Raises:
            CertificateValidationError: If validation fails
            CertificateExpirationError: If certificate is expired or expires soon
        """
        now = datetime.now(timezone.utc)
        validation_result = {
            "valid": True,
            "warnings": [],
            "errors": [],
            "expires_in_days": None,
        }

        # Check if certificate is currently valid
        if now < certificate.not_valid_before:
            validation_result["valid"] = False
            validation_result["errors"].append(
                f"Certificate not yet valid (valid from {certificate.not_valid_before})"
            )

        if now > certificate.not_valid_after:
            validation_result["valid"] = False
            validation_result["errors"].append(
                f"Certificate expired on {certificate.not_valid_after}"
            )

        if check_expiration and validation_result["valid"]:
            # Calculate days until expiration
            time_until_expiry = certificate.not_valid_after - now
            days_until_expiry = time_until_expiry.days
            validation_result["expires_in_days"] = days_until_expiry

            # Check if expiring soon
            if days_until_expiry <= days_warning:
                warning_msg = (
                    f"Certificate expires in {days_until_expiry} days "
                    f"({certificate.not_valid_after})"
                )
                validation_result["warnings"].append(warning_msg)

        # Validate key usage and extended key usage if present
        try:
            key_usage = certificate.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.KEY_USAGE
            ).value
            validation_result["key_usage"] = {
                "digital_signature": key_usage.digital_signature,
                "key_cert_sign": key_usage.key_cert_sign,
                "crl_sign": key_usage.crl_sign,
            }
        except x509.ExtensionNotFound:
            validation_result["warnings"].append("No Key Usage extension found")

        if validation_result["errors"]:
            error_msg = "; ".join(validation_result["errors"])
            raise CertificateValidationError(error_msg)

        return validation_result

    @staticmethod
    def extract_public_key_info(certificate: x509.Certificate) -> dict[str, Any]:
        """
        Extract public key information from certificate.

        Args:
            certificate: Certificate to analyze

        Returns:
            Dictionary containing public key information
        """
        public_key = certificate.public_key()
        key_info = {
            "algorithm": type(public_key).__name__,
        }

        if isinstance(public_key, rsa.RSAPublicKey):
            key_info.update({
                "key_size": public_key.key_size,
                "public_exponent": public_key.public_numbers().e,
                "modulus_size": public_key.key_size,
            })
        elif hasattr(public_key, "curve"):
            # EC public key
            key_info.update({
                "curve": public_key.curve.name,
                "key_size": public_key.curve.key_size,
            })

        return key_info

    @staticmethod
    def compare_certificates(cert1: x509.Certificate, cert2: x509.Certificate) -> dict[str, Any]:
        """
        Compare two certificates for equality and differences.

        Args:
            cert1: First certificate
            cert2: Second certificate

        Returns:
            Dictionary with comparison results
        """
        result = {
            "identical": False,
            "same_subject": False,
            "same_issuer": False,
            "same_public_key": False,
            "differences": [],
        }

        # Check if certificates are identical
        if cert1 == cert2:
            result["identical"] = True
            return result

        # Compare subjects
        if cert1.subject == cert2.subject:
            result["same_subject"] = True
        else:
            result["differences"].append("Different subjects")

        # Compare issuers
        if cert1.issuer == cert2.issuer:
            result["same_issuer"] = True
        else:
            result["differences"].append("Different issuers")

        # Compare public keys
        try:
            key1_bytes = cert1.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            key2_bytes = cert2.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            if key1_bytes == key2_bytes:
                result["same_public_key"] = True
            else:
                result["differences"].append("Different public keys")
        except (ValueError, TypeError, AttributeError):
            result["differences"].append("Could not compare public keys")

        # Compare validity periods
        if cert1.not_valid_before != cert2.not_valid_before:
            result["differences"].append("Different start dates")
        if cert1.not_valid_after != cert2.not_valid_after:
            result["differences"].append("Different expiration dates")

        # Compare serial numbers
        if cert1.serial_number != cert2.serial_number:
            result["differences"].append("Different serial numbers")

        return result

    @staticmethod
    def get_certificate_chain_info(certificates: list[x509.Certificate]) -> dict[str, Any]:
        """
        Analyze a certificate chain.

        Args:
            certificates: List of certificates in chain order

        Returns:
            Dictionary with chain analysis
        """
        if not certificates:
            return {"valid_chain": False, "error": "Empty certificate chain"}

        chain_info = {
            "valid_chain": True,
            "length": len(certificates),
            "certificates": [],
            "warnings": [],
            "errors": [],
        }

        for i, cert in enumerate(certificates):
            cert_info = CertificateProcessor.get_certificate_info(cert)
            cert_info["position"] = i
            cert_info["is_root"] = i == len(certificates) - 1
            cert_info["is_leaf"] = i == 0
            chain_info["certificates"].append(cert_info)

        # Validate chain order
        for i in range(len(certificates) - 1):
            current_cert = certificates[i]
            next_cert = certificates[i + 1]

            # Check if current cert was issued by next cert
            if current_cert.issuer != next_cert.subject:
                chain_info["valid_chain"] = False
                chain_info["errors"].append(
                    f"Certificate {i} issuer does not match certificate {i+1} subject"
                )

        return chain_info


# Convenience functions for common operations
def load_and_validate_certificate(
    cert_path: str | Path,
    check_expiration: bool = True,
    days_warning: int = 30,
) -> tuple[x509.Certificate, dict[str, Any]]:
    """
    Load and validate a certificate from file.

    Args:
        cert_path: Path to certificate file
        check_expiration: Whether to check expiration dates
        days_warning: Days before expiration to warn

    Returns:
        Tuple of (certificate, validation_result)

    Raises:
        CertificateError: If certificate cannot be loaded or validated
    """
    certificate = CertificateProcessor.load_certificate_from_file(cert_path)
    validation_result = CertificateProcessor.validate_certificate(
        certificate, check_expiration, days_warning
    )
    return certificate, validation_result


def get_certificate_summary(cert_path: str | Path) -> dict[str, Any]:
    """
    Get a comprehensive summary of certificate information.

    Args:
        cert_path: Path to certificate file

    Returns:
        Dictionary with certificate summary
    """
    certificate = CertificateProcessor.load_certificate_from_file(cert_path)
    cert_info = CertificateProcessor.get_certificate_info(certificate)
    validation_result = CertificateProcessor.validate_certificate(certificate)
    key_info = CertificateProcessor.extract_public_key_info(certificate)

    return {
        "file_path": str(cert_path),
        "certificate_info": cert_info,
        "validation": validation_result,
        "public_key": key_info,
    }


def check_certificate_expiration(
    cert_path: str | Path, days_warning: int = 30
) -> dict[str, Any]:
    """
    Check certificate expiration status.

    Args:
        cert_path: Path to certificate file
        days_warning: Days before expiration to warn

    Returns:
        Dictionary with expiration information
    """
    certificate = CertificateProcessor.load_certificate_from_file(cert_path)
    validation_result = CertificateProcessor.validate_certificate(
        certificate, check_expiration=True, days_warning=days_warning
    )

    now = datetime.now(timezone.utc)
    time_until_expiry = certificate.not_valid_after - now

    return {
        "file_path": str(cert_path),
        "expires_on": certificate.not_valid_after,
        "expires_in_days": time_until_expiry.days,
        "expires_in_hours": int(time_until_expiry.total_seconds() // 3600),
        "is_expired": now > certificate.not_valid_after,
        "warnings": validation_result.get("warnings", []),
        "needs_renewal": time_until_expiry.days <= days_warning,
    }