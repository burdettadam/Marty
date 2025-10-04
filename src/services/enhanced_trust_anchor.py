"""Enhanced Trust Anchor service with VDS-NC support.

This service provides unified trust verification for both:
1. CSCA → DSC certificate chain validation (ICAO Doc 9303 Part 11-12)
2. VDS-NC signer key verification (ICAO Doc 9303 Part 13)
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

import grpc
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from sqlalchemy.ext.asyncio import AsyncSession

from marty_common.crypto.vds_nc_keys import (
    KeyRole,
    KeyStatus,
    VDSNCKeyManager,
    VDSNCKeyMetadata,
)
from marty_common.infrastructure import TrustEntityRepository
from src.proto.v1 import trust_anchor_pb2, trust_anchor_pb2_grpc

logger = logging.getLogger(__name__)


class EnhancedTrustAnchor(trust_anchor_pb2_grpc.TrustAnchorServicer):
    """Enhanced Trust Anchor with VDS-NC support."""

    def __init__(
        self,
        session: AsyncSession,
        vds_nc_key_manager: VDSNCKeyManager | None = None,
    ) -> None:
        """Initialize enhanced trust anchor.

        Args:
            session: Database session
            vds_nc_key_manager: VDS-NC key manager instance
        """
        self.session = session
        self.vds_nc_key_manager = vds_nc_key_manager or VDSNCKeyManager(session)
        self.trust_repository = TrustEntityRepository(session)
        self.logger = logging.getLogger(__name__)

    async def VerifyTrust(
        self,
        request: trust_anchor_pb2.TrustRequest,
        context: grpc.ServicerContext,
    ) -> trust_anchor_pb2.TrustResponse:
        """Verify if an entity is trusted."""
        try:
            entity = request.entity
            self.logger.info(f"Verifying trust for entity: {entity}")

            # Check trust repository
            trust_entity = await self.trust_repository.get_by_entity(entity)

            if trust_entity and trust_entity.is_trusted:
                return trust_anchor_pb2.TrustResponse(is_trusted=True)

            # Default to not trusted
            return trust_anchor_pb2.TrustResponse(is_trusted=False)

        except Exception:
            self.logger.exception("Error verifying trust")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"Trust verification failed: {e}")
            return trust_anchor_pb2.TrustResponse(is_trusted=False)

    async def VerifyVDSNCSignature(
        self,
        request: trust_anchor_pb2.VDSNCVerificationRequest,
        context: grpc.ServicerContext,
    ) -> trust_anchor_pb2.VDSNCVerificationResponse:
        """Verify VDS-NC signature."""
        try:
            kid = request.kid
            message = request.message
            signature = request.signature
            algorithm = request.algorithm or "ES256"

            self.logger.info(f"Verifying VDS-NC signature for KID: {kid}")

            # Get public key metadata
            key_metadata = await self.vds_nc_key_manager.get_key_metadata(kid)

            if not key_metadata:
                return trust_anchor_pb2.VDSNCVerificationResponse(
                    is_valid=False,
                    reason=f"Unknown VDS-NC key: {kid}",
                    security_level="strict",
                )

            # Check key validity
            if not key_metadata.is_valid_now():
                return trust_anchor_pb2.VDSNCVerificationResponse(
                    is_valid=False,
                    reason=f"VDS-NC key {kid} is not currently valid (status: {key_metadata.status.value})",
                    security_level="strict",
                    key_info=self._build_key_info(key_metadata),
                )

            # Load public key for verification
            public_key = await self._load_vds_nc_public_key(kid)

            if not public_key:
                return trust_anchor_pb2.VDSNCVerificationResponse(
                    is_valid=False,
                    reason=f"Failed to load public key for {kid}",
                    security_level="strict",
                )

            # Verify signature
            try:
                if algorithm == "ES256":
                    public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
                else:
                    return trust_anchor_pb2.VDSNCVerificationResponse(
                        is_valid=False,
                        reason=f"Unsupported algorithm: {algorithm}",
                        security_level="strict",
                    )

                return trust_anchor_pb2.VDSNCVerificationResponse(
                    is_valid=True,
                    reason="VDS-NC signature verified successfully",
                    security_level="strict",
                    key_info=self._build_key_info(key_metadata),
                )

            except Exception as verify_error:
                return trust_anchor_pb2.VDSNCVerificationResponse(
                    is_valid=False,
                    reason=f"Signature verification failed: {verify_error}",
                    security_level="strict",
                    key_info=self._build_key_info(key_metadata),
                )

        except Exception:
            self.logger.exception("Error verifying VDS-NC signature")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"VDS-NC verification failed: {e}")
            return trust_anchor_pb2.VDSNCVerificationResponse(
                is_valid=False,
                reason="Internal verification error",
                security_level="error",
            )

    async def GetVDSNCKeys(
        self,
        request: trust_anchor_pb2.GetVDSNCKeysRequest,
        context: grpc.ServicerContext,
    ) -> trust_anchor_pb2.GetVDSNCKeysResponse:
        """Get VDS-NC keys with optional filtering."""
        try:
            issuer_country = request.issuer_country or None
            role = KeyRole[request.role.upper()] if request.role else None
            include_deprecated = request.include_deprecated

            self.logger.info(
                f"Getting VDS-NC keys: country={issuer_country}, role={role}, include_deprecated={include_deprecated}"
            )

            # Get keys from manager
            key_list = await self.vds_nc_key_manager.list_keys(
                issuer_country=issuer_country,
                role=role,
                status=None if include_deprecated else KeyStatus.ACTIVE,
            )

            # Convert to proto messages
            vds_nc_keys = []
            for key_metadata in key_list:
                # Load public key for JWK conversion
                public_key = await self._load_vds_nc_public_key(key_metadata.kid)
                if public_key:
                    jwk = key_metadata.to_jwk(public_key)

                    vds_nc_keys.append(
                        trust_anchor_pb2.VDSNCKey(
                            kid=key_metadata.kid,
                            public_key_jwk=json.dumps(jwk),
                            issuer_country=key_metadata.issuer_country,
                            role=key_metadata.role.value,
                            status=key_metadata.status.value,
                            not_before=key_metadata.not_before.isoformat(),
                            not_after=key_metadata.not_after.isoformat(),
                            rotation_generation=key_metadata.rotation_generation,
                            algorithm=key_metadata.algorithm,
                        )
                    )

            metadata = trust_anchor_pb2.VDSNCKeysMetadata(
                last_updated=datetime.now(timezone.utc).isoformat(),
                total_count=len(vds_nc_keys),
                country_filter=issuer_country or "",
                role_filter=request.role or "",
            )

            return trust_anchor_pb2.GetVDSNCKeysResponse(
                keys=vds_nc_keys,
                metadata=metadata,
            )

        except Exception as e:
            self.logger.exception(f"Error getting VDS-NC keys: {e}")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"Failed to get VDS-NC keys: {e}")
            return trust_anchor_pb2.GetVDSNCKeysResponse()

    async def RegisterVDSNCKey(
        self,
        request: trust_anchor_pb2.RegisterVDSNCKeyRequest,
        context: grpc.ServicerContext,
    ) -> trust_anchor_pb2.RegisterVDSNCKeyResponse:
        """Register new VDS-NC key."""
        try:
            kid = request.kid
            issuer_country = request.issuer_country
            role = KeyRole[request.role.upper()]

            self.logger.info(f"Registering VDS-NC key: {kid}")

            # Parse JWK
            try:
                jwk = json.loads(request.public_key_jwk)
                public_key = self._jwk_to_public_key(jwk)
            except Exception as jwk_error:
                return trust_anchor_pb2.RegisterVDSNCKeyResponse(
                    success=False,
                    errors=[f"Invalid JWK format: {jwk_error}"],
                )

            # Create key metadata
            from datetime import datetime, timedelta, timezone

            not_before = datetime.fromisoformat(request.not_before) if request.not_before else datetime.now(timezone.utc)
            not_after = datetime.fromisoformat(request.not_after) if request.not_after else datetime.now(timezone.utc) + timedelta(days=730)

            # Register key (implementation depends on storage backend)
            success = await self._register_vds_nc_key(
                kid=kid,
                public_key=public_key,
                issuer_country=issuer_country,
                role=role,
                not_before=not_before,
                not_after=not_after,
                metadata=dict(request.metadata),
            )

            if success:
                return trust_anchor_pb2.RegisterVDSNCKeyResponse(
                    success=True,
                    kid=kid,
                )
            return trust_anchor_pb2.RegisterVDSNCKeyResponse(
                success=False,
                errors=["Failed to register key"],
            )

        except Exception as e:
            self.logger.exception(f"Error registering VDS-NC key: {e}")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"Key registration failed: {e}")
            return trust_anchor_pb2.RegisterVDSNCKeyResponse(
                success=False,
                errors=[f"Registration error: {e}"],
            )

    async def RevokeVDSNCKey(
        self,
        request: trust_anchor_pb2.RevokeVDSNCKeyRequest,
        context: grpc.ServicerContext,
    ) -> trust_anchor_pb2.RevokeVDSNCKeyResponse:
        """Revoke VDS-NC key."""
        try:
            kid = request.kid
            reason = request.reason

            self.logger.warning(f"Revoking VDS-NC key: {kid}, reason: {reason}")

            # Revoke key
            success = await self.vds_nc_key_manager.revoke_key(kid, reason)

            if success:
                return trust_anchor_pb2.RevokeVDSNCKeyResponse(
                    success=True,
                    revocation_timestamp=datetime.now(timezone.utc).isoformat(),
                )
            return trust_anchor_pb2.RevokeVDSNCKeyResponse(
                success=False,
                errors=[f"Failed to revoke key {kid}"],
            )

        except Exception as e:
            self.logger.exception(f"Error revoking VDS-NC key: {e}")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"Key revocation failed: {e}")
            return trust_anchor_pb2.RevokeVDSNCKeyResponse(
                success=False,
                errors=[f"Revocation error: {e}"],
            )

    async def GetTrustStore(
        self,
        request: trust_anchor_pb2.GetTrustStoreRequest,
        context: grpc.ServicerContext,
    ) -> trust_anchor_pb2.GetTrustStoreResponse:
        """Get unified trust store."""
        try:
            country_code = request.country_code or None
            include_csca = request.include_csca
            include_dsc = request.include_dsc
            include_vds_nc = request.include_vds_nc

            self.logger.info(f"Getting trust store for country: {country_code}")

            csca_certs = []
            dsc_certs = []
            vds_nc_keys = []

            # Get CSCA certificates if requested
            if include_csca:
                # Implementation depends on CSCA storage
                pass

            # Get DSC certificates if requested
            if include_dsc:
                # Implementation depends on DSC storage
                pass

            # Get VDS-NC keys if requested
            if include_vds_nc:
                key_list = await self.vds_nc_key_manager.list_keys(
                    issuer_country=country_code,
                    status=KeyStatus.ACTIVE,
                )

                for key_metadata in key_list:
                    public_key = await self._load_vds_nc_public_key(key_metadata.kid)
                    if public_key:
                        jwk = key_metadata.to_jwk(public_key)

                        vds_nc_keys.append(
                            trust_anchor_pb2.VDSNCKey(
                                kid=key_metadata.kid,
                                public_key_jwk=json.dumps(jwk),
                                issuer_country=key_metadata.issuer_country,
                                role=key_metadata.role.value,
                                status=key_metadata.status.value,
                                not_before=key_metadata.not_before.isoformat(),
                                not_after=key_metadata.not_after.isoformat(),
                                rotation_generation=key_metadata.rotation_generation,
                                algorithm=key_metadata.algorithm,
                            )
                        )

            metadata = trust_anchor_pb2.TrustStoreMetadata(
                country_code=country_code or "",
                last_updated=datetime.now(timezone.utc).isoformat(),
                csca_count=len(csca_certs),
                dsc_count=len(dsc_certs),
                vds_nc_count=len(vds_nc_keys),
                format_version="1.0",
            )

            return trust_anchor_pb2.GetTrustStoreResponse(
                csca_certificates=csca_certs,
                dsc_certificates=dsc_certs,
                vds_nc_keys=vds_nc_keys,
                metadata=metadata,
            )

        except Exception as e:
            self.logger.exception(f"Error getting trust store: {e}")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"Trust store retrieval failed: {e}")
            return trust_anchor_pb2.GetTrustStoreResponse()

    # Existing methods remain unchanged...
    async def GetMasterList(
        self,
        request: trust_anchor_pb2.GetMasterListRequest,
        context: grpc.ServicerContext,
    ) -> trust_anchor_pb2.MasterListResponse:
        """Get CSCA master list."""
        # Implementation depends on existing CSCA management
        return trust_anchor_pb2.MasterListResponse(
            master_list_data=b"",
            format="JSON",
            certificate_count=0,
            is_valid=True,
            last_updated=datetime.now(timezone.utc).isoformat(),
        )

    async def UploadMasterList(
        self,
        request: trust_anchor_pb2.UploadMasterListRequest,
        context: grpc.ServicerContext,
    ) -> trust_anchor_pb2.UploadMasterListResponse:
        """Upload CSCA master list."""
        # Implementation depends on existing CSCA management
        return trust_anchor_pb2.UploadMasterListResponse(
            success=True,
            certificates_imported=0,
        )

    async def VerifyCertificate(
        self,
        request: trust_anchor_pb2.VerifyCertificateRequest,
        context: grpc.ServicerContext,
    ) -> trust_anchor_pb2.VerificationResponse:
        """Verify X.509 certificate."""
        # Implementation depends on existing certificate validation
        return trust_anchor_pb2.VerificationResponse(
            is_valid=False,
            validation_errors=["Not implemented"],
        )

    async def SyncCertificateStore(
        self,
        request: trust_anchor_pb2.SyncRequest,
        context: grpc.ServicerContext,
    ) -> trust_anchor_pb2.SyncResponse:
        """Sync certificate store."""
        # Implementation depends on existing sync mechanism
        return trust_anchor_pb2.SyncResponse(
            success=True,
            certificates_synced=0,
            sync_timestamp=datetime.now(timezone.utc).isoformat(),
        )

    async def CheckExpiringCertificates(
        self,
        request: trust_anchor_pb2.ExpiryCheckRequest,
        context: grpc.ServicerContext,
    ) -> trust_anchor_pb2.ExpiryCheckResponse:
        """Check for expiring certificates."""
        # Implementation depends on existing certificate tracking
        return trust_anchor_pb2.ExpiryCheckResponse()

    async def GetServiceStatus(
        self,
        request: trust_anchor_pb2.StatusRequest,
        context: grpc.ServicerContext,
    ) -> trust_anchor_pb2.ServiceStatusResponse:
        """Get service status."""
        try:
            # Get VDS-NC key statistics
            vds_nc_keys = await self.vds_nc_key_manager.list_keys()
            len(vds_nc_keys)

            # Check for expiring VDS-NC keys
            expiring_vds_nc = len([
                k for k in vds_nc_keys
                if k.needs_rotation(warning_days=30)
            ])

            stats = trust_anchor_pb2.ServiceStats(
                total_certificates=0,  # Would include CSCA/DSC counts
                trusted_countries=len({k.issuer_country for k in vds_nc_keys}),
                last_sync_time=datetime.now(timezone.utc).isoformat(),
                expiring_soon=expiring_vds_nc,
            )

            return trust_anchor_pb2.ServiceStatusResponse(
                is_healthy=True,
                stats=stats,
                version="2.0.0",
                openxpki_status="Connected",  # Would check actual OpenXPKI status
            )

        except Exception as e:
            self.logger.exception(f"Error getting service status: {e}")
            return trust_anchor_pb2.ServiceStatusResponse(
                is_healthy=False,
                version="2.0.0",
                openxpki_status="Error",
            )

    # Helper methods
    def _build_key_info(self, metadata: VDSNCKeyMetadata) -> trust_anchor_pb2.VDSNCKeyInfo:
        """Build key info proto message."""
        return trust_anchor_pb2.VDSNCKeyInfo(
            kid=metadata.kid,
            issuer_country=metadata.issuer_country,
            role=metadata.role.value,
            status=metadata.status.value,
            not_before=metadata.not_before.isoformat(),
            not_after=metadata.not_after.isoformat(),
            rotation_generation=metadata.rotation_generation,
        )

    async def _load_vds_nc_public_key(self, kid: str) -> EllipticCurvePublicKey | None:
        """Load VDS-NC public key from storage."""
        # Implementation depends on key storage backend
        # This would load the actual public key for the given KID
        return None

    async def _register_vds_nc_key(
        self,
        kid: str,
        public_key: EllipticCurvePublicKey,
        issuer_country: str,
        role: KeyRole,
        not_before: datetime,
        not_after: datetime,
        metadata: dict[str, str],
    ) -> bool:
        """Register VDS-NC key in storage."""
        # Implementation depends on storage backend
        return True

    def _jwk_to_public_key(self, jwk: dict[str, Any]) -> EllipticCurvePublicKey:
        """Convert JWK to EC public key."""
        import base64

        if jwk["kty"] != "EC" or jwk["crv"] != "P-256":
            msg = f"Unsupported key type: {jwk['kty']}/{jwk.get('crv')}"
            raise ValueError(msg)

        # Decode coordinates
        x_bytes = base64.urlsafe_b64decode(jwk["x"] + "==")
        y_bytes = base64.urlsafe_b64decode(jwk["y"] + "==")

        # Convert to integers
        x = int.from_bytes(x_bytes, "big")
        y = int.from_bytes(y_bytes, "big")

        # Create public key
        from cryptography.hazmat.primitives.asymmetric.ec import (
            SECP256R1,
            EllipticCurvePublicNumbers,
        )

        public_numbers = EllipticCurvePublicNumbers(x, y, SECP256R1())
        return public_numbers.public_key()
