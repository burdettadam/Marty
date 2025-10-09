"""Certificate validation service for Trust Service.

This module provides high-level certificate validation services that integrate
the advanced parsing capabilities with the Trust Service database and business logic.
"""

import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Union

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .certificate_parser import (
    CertificateChainBuilder,
    CertificateInfo,
    CertificateType,
    CertificateValidator,
    ValidationResult,
    X509CertificateParser,
)
from .database import get_async_session
from .metrics import record_certificate_validation, record_error
from .models import CRL, CSCA, DSC, CertificateStatus, TrustLevel

logger = logging.getLogger(__name__)


class TrustServiceCertificateValidator:
    """High-level certificate validation service for Trust Service."""

    def __init__(self):
        self.parser = X509CertificateParser()
        self.validator = CertificateValidator()
        self.chain_builder = CertificateChainBuilder()
        self._trusted_cscas_loaded = False

    async def load_trusted_cscas(self, session: AsyncSession):
        """Load trusted CSCAs from database into validator."""
        try:
            # Query active CSCAs
            query = select(CSCA).where(CSCA.status == CertificateStatus.ACTIVE)
            result = await session.execute(query)
            cscas = result.scalars().all()

            for csca in cscas:
                if csca.certificate_data:
                    try:
                        self.validator.add_trusted_csca(
                            csca.certificate_data, identifier=str(csca.id)
                        )
                        self.chain_builder.add_certificate(
                            csca.certificate_data, identifier=str(csca.id)
                        )
                    except Exception as e:
                        logger.error(f"Failed to load CSCA {csca.id}: {e}")

            self._trusted_cscas_loaded = True
            logger.info(f"Loaded {len(cscas)} trusted CSCAs")

        except Exception as e:
            logger.error(f"Failed to load trusted CSCAs: {e}")
            raise

    async def validate_certificate_data(
        self,
        cert_data: bytes | str,
        country_code: str | None = None,
        session: AsyncSession | None = None,
    ) -> dict:
        """Validate certificate data with comprehensive checks.

        Args:
            cert_data: Certificate data to validate
            country_code: Expected country code for validation
            session: Database session (optional, will create if not provided)

        Returns:
            Dictionary with validation results
        """
        start_time = datetime.now(timezone.utc)
        validation_result = {
            "is_valid": False,
            "certificate_info": None,
            "validation_details": {},
            "errors": [],
            "warnings": [],
            "trust_path": None,
            "revocation_status": "unknown",
        }

        try:
            # Parse certificate
            cert_info = self.parser.parse_certificate(cert_data)
            validation_result["certificate_info"] = self._cert_info_to_dict(cert_info)

            # Load trusted CSCAs if not already loaded
            if not self._trusted_cscas_loaded:
                if not session:
                    async for db_session in get_async_session():
                        await self.load_trusted_cscas(db_session)
                        break
                else:
                    await self.load_trusted_cscas(session)

            # Validate country code if provided
            if country_code and cert_info.country_code:
                if cert_info.country_code.upper() != country_code.upper():
                    validation_result["errors"].append(
                        f"Country code mismatch: expected {country_code}, got {cert_info.country_code}"
                    )
                    record_certificate_validation(
                        cert_info.certificate_type.value,
                        country_code,
                        "country_mismatch",
                        (datetime.now(timezone.utc) - start_time).total_seconds(),
                    )
                    return validation_result

            # Perform validation
            result, details = self.validator.validate_certificate(cert_data)
            validation_result["validation_details"] = details
            validation_result["is_valid"] = result == ValidationResult.VALID

            if result != ValidationResult.VALID:
                validation_result["errors"].append(f"Validation failed: {result.value}")

            # Check revocation status
            revocation_status = await self._check_revocation_status(
                cert_info, session or await self._get_session()
            )
            validation_result["revocation_status"] = revocation_status

            if revocation_status == "revoked":
                validation_result["is_valid"] = False
                validation_result["errors"].append("Certificate is revoked")

            # Build trust path
            try:
                self.chain_builder.add_certificate(cert_data, cert_info.fingerprint_sha256)
                chain = self.chain_builder.build_chain(cert_info.fingerprint_sha256)
                validation_result["trust_path"] = [
                    {"subject": cert.subject, "fingerprint": cert.fingerprint_sha256}
                    for cert in chain
                ]
            except Exception as e:
                logger.warning(f"Failed to build trust path: {e}")
                validation_result["warnings"].append("Could not build complete trust path")

            # Record metrics
            result_label = "valid" if validation_result["is_valid"] else "invalid"
            record_certificate_validation(
                cert_info.certificate_type.value,
                cert_info.country_code or "unknown",
                result_label,
                (datetime.now(timezone.utc) - start_time).total_seconds(),
            )

        except Exception as e:
            logger.error(f"Certificate validation error: {e}")
            validation_result["errors"].append(f"Validation error: {str(e)}")
            record_error("certificate_validation", "trust_service")

        return validation_result

    async def validate_certificate_chain(
        self, cert_chain: list[bytes | str], session: AsyncSession | None = None
    ) -> dict:
        """Validate a complete certificate chain.

        Args:
            cert_chain: List of certificates in chain order (end-entity first)
            session: Database session

        Returns:
            Dictionary with chain validation results
        """
        if not cert_chain:
            return {"is_valid": False, "error": "Empty certificate chain"}

        try:
            # Parse all certificates in chain
            chain_info = []
            for i, cert_data in enumerate(cert_chain):
                cert_info = self.parser.parse_certificate(cert_data)
                chain_info.append(
                    {
                        "position": i,
                        "certificate_info": self._cert_info_to_dict(cert_info),
                        "cert_data": cert_data,
                    }
                )

            # Validate each certificate against its issuer
            validation_results = []
            for i in range(len(cert_chain)):
                if i < len(cert_chain) - 1:
                    # Validate against next certificate in chain
                    result = await self.validate_certificate_data(cert_chain[i], session=session)
                    # Add chain-specific validation
                    issuer_validation = self._validate_issuer_relationship(
                        chain_info[i]["certificate_info"], chain_info[i + 1]["certificate_info"]
                    )
                    result["issuer_validation"] = issuer_validation
                else:
                    # Root certificate - validate against trusted store
                    result = await self.validate_certificate_data(cert_chain[i], session=session)

                validation_results.append(result)

            # Overall chain validity
            chain_valid = all(result["is_valid"] for result in validation_results)

            return {
                "is_valid": chain_valid,
                "chain_length": len(cert_chain),
                "certificate_validations": validation_results,
                "chain_info": chain_info,
            }

        except Exception as e:
            logger.error(f"Chain validation error: {e}")
            return {"is_valid": False, "error": str(e)}

    async def parse_and_store_certificate(
        self,
        cert_data: bytes | str,
        certificate_type: CertificateType,
        source_id: str | None = None,
        session: AsyncSession | None = None,
    ) -> str | None:
        """Parse certificate and store in database.

        Args:
            cert_data: Certificate data
            certificate_type: Type of certificate (CSCA or DSC)
            source_id: Source identifier for provenance
            session: Database session

        Returns:
            Certificate ID if stored successfully, None otherwise
        """
        try:
            # Parse certificate
            cert_info = self.parser.parse_certificate(cert_data)

            # Check if certificate already exists
            if not session:
                async for db_session in get_async_session():
                    return await self._store_certificate_in_db(
                        cert_info, cert_data, certificate_type, source_id, db_session
                    )
            else:
                return await self._store_certificate_in_db(
                    cert_info, cert_data, certificate_type, source_id, session
                )

        except Exception as e:
            logger.error(f"Failed to parse and store certificate: {e}")
            return None

    async def _store_certificate_in_db(
        self,
        cert_info: CertificateInfo,
        cert_data: bytes | str,
        certificate_type: CertificateType,
        source_id: str | None,
        session: AsyncSession,
    ) -> str | None:
        """Store certificate in database."""
        try:
            if certificate_type == CertificateType.CSCA:
                # Check if CSCA already exists
                existing_query = select(CSCA).where(
                    CSCA.certificate_hash == cert_info.fingerprint_sha256
                )
                existing_result = await session.execute(existing_query)
                if existing_result.scalar_one_or_none():
                    logger.info(f"CSCA already exists: {cert_info.fingerprint_sha256}")
                    return None

                # Create new CSCA
                csca = CSCA(
                    country_code=cert_info.country_code or "UNK",
                    subject_dn=cert_info.subject,
                    issuer_dn=cert_info.issuer,
                    serial_number=cert_info.serial_number,
                    certificate_hash=cert_info.fingerprint_sha256,
                    certificate_data=(
                        cert_data if isinstance(cert_data, bytes) else cert_data.encode()
                    ),
                    trust_level=TrustLevel.STANDARD,
                    status=CertificateStatus.ACTIVE,
                    valid_from=cert_info.not_before,
                    valid_to=cert_info.not_after,
                    key_usage=cert_info.key_usage,
                    signature_algorithm=cert_info.signature_algorithm,
                    public_key_algorithm=cert_info.public_key_algorithm,
                )

                session.add(csca)
                await session.flush()
                return str(csca.id)

            elif certificate_type == CertificateType.DSC:
                # Check if DSC already exists
                existing_query = select(DSC).where(
                    DSC.certificate_hash == cert_info.fingerprint_sha256
                )
                existing_result = await session.execute(existing_query)
                if existing_result.scalar_one_or_none():
                    logger.info(f"DSC already exists: {cert_info.fingerprint_sha256}")
                    return None

                # Find issuer CSCA
                issuer_csca = None
                if cert_info.authority_key_identifier:
                    issuer_query = select(CSCA).where(
                        CSCA.subject_key_identifier == cert_info.authority_key_identifier
                    )
                    issuer_result = await session.execute(issuer_query)
                    issuer_csca = issuer_result.scalar_one_or_none()

                # Create new DSC
                dsc = DSC(
                    country_code=cert_info.country_code or "UNK",
                    subject_dn=cert_info.subject,
                    issuer_dn=cert_info.issuer,
                    serial_number=cert_info.serial_number,
                    certificate_hash=cert_info.fingerprint_sha256,
                    certificate_data=(
                        cert_data if isinstance(cert_data, bytes) else cert_data.encode()
                    ),
                    status=CertificateStatus.ACTIVE,
                    valid_from=cert_info.not_before,
                    valid_to=cert_info.not_after,
                    issuer_csca_id=issuer_csca.id if issuer_csca else None,
                    key_usage=cert_info.key_usage,
                    signature_algorithm=cert_info.signature_algorithm,
                    public_key_algorithm=cert_info.public_key_algorithm,
                )

                session.add(dsc)
                await session.flush()
                return str(dsc.id)

        except Exception as e:
            logger.error(f"Database storage error: {e}")
            await session.rollback()
            return None

    async def _check_revocation_status(
        self, cert_info: CertificateInfo, session: AsyncSession
    ) -> str:
        """Check certificate revocation status against CRLs."""
        try:
            # Query relevant CRLs
            crl_query = select(CRL).where(
                CRL.country_code == cert_info.country_code, CRL.is_active == True
            )
            result = await session.execute(crl_query)
            crls = result.scalars().all()

            # Check each CRL for the certificate serial number
            for crl in crls:
                if self._is_certificate_revoked(cert_info.serial_number, crl):
                    return "revoked"

            return "not_revoked"

        except Exception as e:
            logger.error(f"Revocation check error: {e}")
            return "unknown"

    def _is_certificate_revoked(self, serial_number: str, crl: CRL) -> bool:
        """Check if certificate serial number is in CRL."""
        # This would parse the actual CRL data and check for the serial number
        # For now, return False as placeholder
        # TODO: Implement actual CRL parsing
        return False

    def _validate_issuer_relationship(self, cert_info: dict, issuer_info: dict) -> dict:
        """Validate the relationship between certificate and its issuer."""
        validation = {
            "subject_issuer_match": False,
            "key_identifier_match": False,
            "signature_valid": False,
        }

        # Check if certificate's issuer matches issuer's subject
        validation["subject_issuer_match"] = cert_info.get("issuer") == issuer_info.get("subject")

        # Check key identifiers
        if cert_info.get("authority_key_identifier") and issuer_info.get("subject_key_identifier"):
            validation["key_identifier_match"] = (
                cert_info["authority_key_identifier"] == issuer_info["subject_key_identifier"]
            )

        return validation

    def _cert_info_to_dict(self, cert_info: CertificateInfo) -> dict:
        """Convert CertificateInfo to dictionary for serialization."""
        return {
            "subject": cert_info.subject,
            "issuer": cert_info.issuer,
            "serial_number": cert_info.serial_number,
            "version": cert_info.version,
            "not_before": cert_info.not_before.isoformat() if cert_info.not_before else None,
            "not_after": cert_info.not_after.isoformat() if cert_info.not_after else None,
            "signature_algorithm": cert_info.signature_algorithm,
            "public_key_algorithm": cert_info.public_key_algorithm,
            "public_key_size": cert_info.public_key_size,
            "fingerprint_sha1": cert_info.fingerprint_sha1,
            "fingerprint_sha256": cert_info.fingerprint_sha256,
            "fingerprint_md5": cert_info.fingerprint_md5,
            "key_usage": cert_info.key_usage,
            "extended_key_usage": cert_info.extended_key_usage,
            "basic_constraints": cert_info.basic_constraints,
            "subject_alternative_names": cert_info.subject_alternative_names,
            "authority_key_identifier": cert_info.authority_key_identifier,
            "subject_key_identifier": cert_info.subject_key_identifier,
            "crl_distribution_points": cert_info.crl_distribution_points,
            "authority_info_access": cert_info.authority_info_access,
            "certificate_policies": cert_info.certificate_policies,
            "icao_extensions": cert_info.icao_extensions,
            "country_code": cert_info.country_code,
            "certificate_type": cert_info.certificate_type.value,
            "is_ca": cert_info.is_ca,
            "path_length_constraint": cert_info.path_length_constraint,
        }

    async def _get_session(self) -> AsyncSession:
        """Get database session."""
        async for session in get_async_session():
            return session
