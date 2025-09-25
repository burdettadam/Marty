"""
Certificate Validator utility for validating X.509 certificates

This module provides functionality to validate X.509 certificates
used in eMRTD (electronic Machine Readable Travel Documents) systems.
"""

import logging
from datetime import datetime
from typing import Optional, Union

from certvalidator import CertificateValidator as CertValidatorLib
from certvalidator import ValidationContext
from certvalidator.errors import InvalidCertificateError, PathValidationError, RevokedError
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class CertificateValidator:
    """
    Validator for X.509 certificates used in eMRTD systems.

    This class provides methods to validate:
    - Certificate structure (via certvalidator)
    - Signature validity (via certvalidator)
    - Certificate chain (via certvalidator)
    - Expiration dates (via certvalidator)
    - Revocation status (basic check, full check depends on CRL/OCSP availability)
    """

    def __init__(
        self,
        trust_roots: Optional[list[Union[str, x509.Certificate]]] = None,
        other_certs: Optional[list[Union[str, x509.Certificate]]] = None,
        logger=None,
        revocation_mode: str = "soft_fail",
    ) -> None:
        """
        Initialize the Certificate Validator.

        Args:
            trust_roots: A list of PEM-encoded CA certificates or
                         cryptography.x509.Certificate objects.
            other_certs: A list of other PEM-encoded certificates or
                         cryptography.x509.Certificate objects that might be
                         useful for path building (e.g., intermediates).
            logger: Logger instance.
            revocation_mode: "hard_fail", "soft_fail", or "require"
                             for CRL/OCSP checks.
        """
        self.logger = logger or logging.getLogger(__name__)

        self.parsed_trust_roots = []
        if trust_roots:
            for root in trust_roots:
                if isinstance(root, str):
                    try:
                        self.parsed_trust_roots.append(
                            x509.load_pem_x509_certificate(root.encode(), default_backend())
                        )
                    except ValueError as e:
                        self.logger.exception("Failed to load trust root PEM: %s", e)
                elif isinstance(root, x509.Certificate):
                    self.parsed_trust_roots.append(root)
                else:
                    self.logger.warning("Unsupported trust root type: %s", type(root))

        self.parsed_other_certs = []
        if other_certs:
            for cert_data in other_certs:
                if isinstance(cert_data, str):
                    try:
                        self.parsed_other_certs.append(
                            x509.load_pem_x509_certificate(cert_data.encode(), default_backend())
                        )
                    except ValueError as e:
                        self.logger.exception("Failed to load other certificate PEM: %s", e)
                elif isinstance(cert_data, x509.Certificate):
                    self.parsed_other_certs.append(cert_data)
                else:
                    self.logger.warning("Unsupported other certificate type: %s", type(cert_data))

        self.base_validation_context_args = {
            "crl_mode": revocation_mode,
            "ocsp_mode": revocation_mode,
        }

        self.default_validation_context = ValidationContext(
            trust_roots=self.parsed_trust_roots,
            other_certs=self.parsed_other_certs,
            **self.base_validation_context_args,
        )

    def _load_certificate(
        self, certificate_data: Union[str, bytes, x509.Certificate]
    ) -> Optional[x509.Certificate]:
        """Helper to load a certificate from various formats."""
        if isinstance(certificate_data, x509.Certificate):
            return certificate_data
        try:
            if isinstance(certificate_data, str):
                cert_bytes = certificate_data.encode("utf-8")
            elif isinstance(certificate_data, bytes):
                cert_bytes = certificate_data
            else:
                self.logger.error("Unsupported certificate data type: %s", type(certificate_data))
                return None

            try:
                return x509.load_pem_x509_certificate(cert_bytes, default_backend())
            except ValueError:
                return x509.load_der_x509_certificate(cert_bytes, default_backend())
        except ValueError as e:
            self.logger.exception("Failed to parse certificate data: %s", e)
        except (TypeError, AttributeError) as e:
            self.logger.exception("Invalid certificate data type or format: %s", e)
        except Exception as e:
            self.logger.exception("Unexpected error loading certificate: %s", e)
            return None
        return None

    def validate(
        self,
        certificate_to_validate: Union[str, bytes, x509.Certificate],
        usage: str = "digital_signature",
        moment: Optional[datetime] = None,
    ) -> bool:
        """
        Validate a single certificate.

        Args:
            certificate_to_validate: The certificate to validate (PEM string,
                                     DER bytes, or x509.Certificate).
            usage: The key usage to validate for (e.g., 'digital_signature',
                   'key_cert_sign', 'crl_sign'). Use None to skip.
            moment: The datetime moment at which to perform validation (defaults to now).

        Returns:
            bool: True if the certificate is valid for the specified usage, False otherwise.
        """
        cert_obj = self._load_certificate(certificate_to_validate)
        if not cert_obj:
            return False

        validation_ctx_to_use = self.default_validation_context
        if moment:
            validation_ctx_to_use = ValidationContext(
                trust_roots=self.parsed_trust_roots,
                other_certs=self.parsed_other_certs,
                moment=moment,
                **self.base_validation_context_args,
            )

        validator = CertValidatorLib(
            end_entity_cert=cert_obj, validation_context=validation_ctx_to_use
        )

        subject_str = cert_obj.subject.rfc4514_string()
        try:
            path = validator.validate_usage(key_usage={usage} if usage else set())
            if path:
                self.logger.info(
                    "Certificate %s validated successfully for usage '%s'. Path: %s",
                    subject_str,
                    usage,
                    path,
                )
                return True
            self.logger.warning(
                "Validation for %s returned no path but no error for usage '%s'.",
                subject_str,
                usage,
            )
            return False
        except RevokedError as e:
            self.logger.exception(
                "Certificate %s is revoked (usage: %s): %s", subject_str, usage, e
            )
        except InvalidCertificateError as e:
            self.logger.exception(
                "Certificate %s is invalid (usage: %s): %s", subject_str, usage, e
            )
        except PathValidationError as e:
            self.logger.exception(
                "Path validation failed for %s (usage: %s): %s", subject_str, usage, e
            )
        except Exception as e:
            self.logger.exception(
                "Unexpected error during validation for %s (usage: %s): %s", subject_str, usage, e
            )

        return False

    def validate_chain(
        self,
        certificate_chain: list[Union[str, bytes, x509.Certificate]],
        usage: str = "digital_signature",
        moment: Optional[datetime] = None,
    ) -> bool:
        """
        Validate a given certificate chain. The first certificate in the list is
        the end-entity, and the last is expected to be (or chain to) a trust root.

        Args:
            certificate_chain: List of certificates (PEM, DER, or
                               x509.Certificate objects) forming the chain,
                               starting with the end-entity.
            usage: The key usage to validate for the end-entity certificate.
            moment: The datetime moment at which to perform validation (defaults to now).

        Returns:
            bool: True if the certificate chain is valid, False otherwise.
        """
        if not certificate_chain:
            self.logger.error("Certificate chain is empty.")
            return False

        loaded_chain = []
        for cert_data in certificate_chain:
            cert_obj = self._load_certificate(cert_data)
            if not cert_obj:
                self.logger.error("Failed to load a certificate in the chain.")
                return False
            loaded_chain.append(cert_obj)

        end_entity_cert = loaded_chain[0]
        intermediate_certs = loaded_chain[1:] if len(loaded_chain) > 1 else []
        subject_str = end_entity_cert.subject.rfc4514_string()

        validation_ctx_to_use = self.default_validation_context
        if moment:
            validation_ctx_to_use = ValidationContext(
                trust_roots=self.parsed_trust_roots,
                other_certs=self.parsed_other_certs,
                moment=moment,
                **self.base_validation_context_args,
            )

        validator = CertValidatorLib(
            end_entity_cert=end_entity_cert,
            intermediate_certs=intermediate_certs,
            validation_context=validation_ctx_to_use,
        )

        try:
            path = validator.validate_usage(key_usage={usage} if usage else set())
            if path:
                self.logger.info(
                    "Certificate chain for %s validated successfully for usage '%s'. Path: %s",
                    subject_str,
                    usage,
                    path,
                )
                return True
            self.logger.warning(
                "Chain validation for %s returned no path but no error for usage '%s'.",
                subject_str,
                usage,
            )
            return False
        except RevokedError as e:
            self.logger.exception(
                "Certificate in chain for %s is revoked (usage: %s): %s", subject_str, usage, e
            )
        except InvalidCertificateError as e:
            self.logger.exception(
                "Certificate in chain for %s is invalid (usage: %s): %s", subject_str, usage, e
            )
        except PathValidationError as e:
            self.logger.exception(
                "Path validation failed for chain %s (usage: %s): %s", subject_str, usage, e
            )
        except Exception as e:
            self.logger.exception(
                "Unexpected error during chain validation for %s (usage: %s): %s",
                subject_str,
                usage,
                e,
            )

        return False
