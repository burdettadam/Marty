"""CSCA service backed by shared infrastructure components."""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from marty_common.grpc_types import (
        GrpcServicerContext,
        ProtoMessage,
        ServiceDependencies,
    )

import grpc
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from marty_common.infrastructure import (
    CertificateRepository,
    KeyVaultClient,
    ObjectStorageClient,
    OutboxRepository,
)
from src.proto import csca_service_pb2, csca_service_pb2_grpc


class CscaService(csca_service_pb2_grpc.CscaServiceServicer):
    """Country Signing Certificate Authority implementation with vault-backed keys."""

    def __init__(
        self,
        channels: dict[str, Any] | None = None,
        dependencies: ServiceDependencies | None = None,
    ) -> None:
        if dependencies is None:
            msg = "CscaService requires service dependencies"
            raise ValueError(msg)
        self.logger = logging.getLogger(__name__)
        self.channels = channels or {}
        self._database = dependencies.database
        self._key_vault: KeyVaultClient = dependencies.key_vault
        self._object_storage: ObjectStorageClient = dependencies.object_storage
        self._certificate_cache: dict[str, dict[str, Any]] = {}
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self._refresh_cache())
        except RuntimeError:
            asyncio.run(self._refresh_cache())

    # ---------------------------------------------------------------------
    # gRPC API
    # ---------------------------------------------------------------------
    async def GetCscaData(  # noqa: N802 - proto naming
        self,
        request: ProtoMessage,  # csca_service_pb2.GetCscaDataRequest
        context: GrpcServicerContext,  # grpc.ServicerContext
    ) -> ProtoMessage:  # csca_service_pb2.GetCscaDataResponse
        certificate_id = request.id
        if not certificate_id:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Certificate ID cannot be empty")
            return csca_service_pb2.CscaResponse()

        record = self._certificate_cache.get(certificate_id)
        if record is None:
            record = await self._fetch_certificate_record(certificate_id)

        if record is None:
            await context.abort(
                grpc.StatusCode.NOT_FOUND, f"Certificate '{certificate_id}' not found"
            )
            return csca_service_pb2.CscaResponse()

        if record.get("revoked"):
            await context.abort(grpc.StatusCode.PERMISSION_DENIED, "Certificate is revoked")
            return csca_service_pb2.CscaResponse()

        return csca_service_pb2.CscaResponse(data=record["pem"])

    async def CreateCertificate(  # noqa: N802
        self,
        request: ProtoMessage,  # csca_service_pb2.CreateCertificateRequest
        context: GrpcServicerContext,  # grpc.ServicerContext
    ) -> ProtoMessage:  # csca_service_pb2.CreateCertificateResponse
        subject_name = request.subject_name
        if not subject_name:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Subject name cannot be empty")
            return csca_service_pb2.CreateCertificateResponse()

        key_algorithm = (request.key_algorithm or "RSA").upper()
        key_size = request.key_size if request.key_size > 0 else 2048
        validity_days = request.validity_days if request.validity_days > 0 else 365
        certificate_id = str(uuid.uuid4())

        try:
            private_key = self._generate_private_key(key_algorithm, key_size)
        except ValueError as exc:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, str(exc))
            return csca_service_pb2.CreateCertificateResponse()

        not_before = datetime.now(timezone.utc)
        not_after = not_before + timedelta(days=validity_days)
        certificate = self._build_self_signed_certificate(
            private_key, subject_name, not_before, not_after
        )

        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        certificate_pem = certificate.public_bytes(serialization.Encoding.PEM)

        details = {
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "key_algorithm": key_algorithm,
            "key_size": key_size,
        }

        await self._key_vault.store_private_key(certificate_id, private_key_pem)
        storage_key = f"certificates/{certificate_id}.pem"
        await self._object_storage.put_object(
            storage_key, certificate_pem, "application/x-pem-file"
        )

        certificate_text = certificate_pem.decode("utf-8")
        persisted_details = {**details, "storage_key": storage_key}

        async def handler(session):
            await self._persist_certificate(
                certificate_id=certificate_id,
                certificate_type="CSCA",
                subject=subject_name,
                pem_text=certificate_text,
                details=persisted_details,
                session=session,
                update_cache=False,
            )
            outbox = OutboxRepository(session)
            await outbox.enqueue(
                topic="certificate.issued",
                payload=json.dumps(
                    {
                        "certificate_id": certificate_id,
                        "subject": subject_name,
                        "storage_key": storage_key,
                        "not_after": details["not_after"],
                    }
                ).encode("utf-8"),
                key=certificate_id.encode("utf-8"),
            )

        await self._database.run_within_transaction(handler)

        self._certificate_cache[certificate_id] = {
            "subject": subject_name,
            "pem": certificate_text,
            "details": persisted_details,
            "revoked": False,
        }

        self.logger.info("Issued CSCA certificate %s", certificate_id)
        return csca_service_pb2.CreateCertificateResponse(
            certificate_id=certificate_id,
            certificate_data=certificate_pem.decode("utf-8"),
            status="ISSUED",
        )

    async def RenewCertificate(  # noqa: N802
        self,
        request: ProtoMessage,  # csca_service_pb2.RenewCertificateRequest
        context: GrpcServicerContext,  # grpc.ServicerContext
    ) -> ProtoMessage:  # csca_service_pb2.RenewCertificateResponse
        if not request.certificate_id:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Certificate ID is required")
            return csca_service_pb2.CreateCertificateResponse()

        existing = await self._fetch_certificate_record(request.certificate_id)
        if existing is None:
            await context.abort(grpc.StatusCode.NOT_FOUND, "Certificate not found")
            return csca_service_pb2.CreateCertificateResponse()

        subject = existing.get("subject") or request.certificate_id
        key_algorithm = existing.get("details", {}).get("key_algorithm", "RSA")
        key_size = existing.get("details", {}).get("key_size", 2048)
        validity_days = request.validity_days if request.validity_days > 0 else 365
        new_certificate_id = str(uuid.uuid4())

        try:
            private_key = self._generate_private_key(key_algorithm, key_size)
        except ValueError as exc:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, str(exc))
            return csca_service_pb2.CreateCertificateResponse()

        not_before = datetime.now(timezone.utc)
        not_after = not_before + timedelta(days=validity_days)
        certificate = self._build_self_signed_certificate(
            private_key, subject, not_before, not_after
        )

        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        certificate_pem = certificate.public_bytes(serialization.Encoding.PEM)

        details = {
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "key_algorithm": key_algorithm,
            "key_size": key_size,
            "renewed_from": request.certificate_id,
        }

        await self._key_vault.store_private_key(new_certificate_id, private_key_pem)
        storage_key = f"certificates/{new_certificate_id}.pem"
        await self._object_storage.put_object(
            storage_key, certificate_pem, "application/x-pem-file"
        )

        certificate_text = certificate_pem.decode("utf-8")
        persisted_details = {**details, "storage_key": storage_key}

        async def handler(session):
            await self._persist_certificate(
                certificate_id=new_certificate_id,
                certificate_type="CSCA",
                subject=subject,
                pem_text=certificate_text,
                details=persisted_details,
                session=session,
                update_cache=False,
            )
            revoked_dt = await self._mark_certificate_revoked(
                request.certificate_id,
                "SUPERSEDED",
                session=session,
                update_cache=False,
            )
            outbox = OutboxRepository(session)
            await outbox.enqueue(
                topic="certificate.renewed",
                payload=json.dumps(
                    {
                        "previous_id": request.certificate_id,
                        "certificate_id": new_certificate_id,
                        "subject": subject,
                        "storage_key": storage_key,
                    }
                ).encode("utf-8"),
                key=new_certificate_id.encode("utf-8"),
            )
            return revoked_dt

        revoked_at = await self._database.run_within_transaction(handler)

        self._certificate_cache[new_certificate_id] = {
            "subject": subject,
            "pem": certificate_text,
            "details": persisted_details,
            "revoked": False,
        }
        self._update_revocation_cache(request.certificate_id, "SUPERSEDED", revoked_at)

        return csca_service_pb2.CreateCertificateResponse(
            certificate_id=new_certificate_id,
            certificate_data=certificate_pem.decode("utf-8"),
            status="RENEWED",
        )

    async def RevokeCertificate(  # noqa: N802
        self,
        request: ProtoMessage,  # csca_service_pb2.RevokeCertificateRequest
        context: GrpcServicerContext,  # grpc.ServicerContext
    ) -> ProtoMessage:  # csca_service_pb2.RevokeCertificateResponse
        if not request.certificate_id:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Certificate ID is required")
            return csca_service_pb2.RevokeCertificateResponse()

        record = await self._fetch_certificate_record(request.certificate_id)
        if record is None:
            await context.abort(grpc.StatusCode.NOT_FOUND, "Certificate not found")
            return csca_service_pb2.RevokeCertificateResponse()

        if record.get("revoked"):
            return csca_service_pb2.RevokeCertificateResponse(
                certificate_id=request.certificate_id,
                success=True,
                status="REVOKED",
            )

        reason = request.reason or "unspecified"

        async def handler(session):
            revoked_dt = await self._mark_certificate_revoked(
                request.certificate_id,
                reason,
                session=session,
                update_cache=False,
            )
            outbox = OutboxRepository(session)
            await outbox.enqueue(
                topic="certificate.revoked",
                payload=json.dumps(
                    {
                        "certificate_id": request.certificate_id,
                        "reason": reason,
                    }
                ).encode("utf-8"),
                key=request.certificate_id.encode("utf-8"),
            )
            return revoked_dt

        revoked_at = await self._database.run_within_transaction(handler)
        self._update_revocation_cache(request.certificate_id, reason, revoked_at)

        return csca_service_pb2.RevokeCertificateResponse(
            certificate_id=request.certificate_id,
            success=True,
            status="REVOKED",
        )

    async def GetCertificateStatus(  # noqa: N802
        self,
        request: ProtoMessage,  # csca_service_pb2.GetCertificateStatusRequest
        context: GrpcServicerContext,  # grpc.ServicerContext
    ) -> ProtoMessage:  # csca_service_pb2.GetCertificateStatusResponse
        if not request.certificate_id:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Certificate ID is required")
            return csca_service_pb2.CertificateStatusResponse()

        record = await self._fetch_certificate_record(request.certificate_id)
        if record is None:
            await context.abort(grpc.StatusCode.NOT_FOUND, "Certificate not found")
            return csca_service_pb2.CertificateStatusResponse()

        status = "REVOKED" if record.get("revoked") else "VALID"
        return csca_service_pb2.CertificateStatusResponse(
            certificate_id=request.certificate_id,
            status=status,
            revoked=record.get("revoked", False),
            metadata=json.dumps(record.get("details", {})),
        )

    async def ListCertificates(  # noqa: N802
        self,
        request: ProtoMessage,  # csca_service_pb2.ListCertificatesRequest
        context: GrpcServicerContext,  # grpc.ServicerContext
    ) -> ProtoMessage:  # csca_service_pb2.ListCertificatesResponse
        records = await self._list_certificates()
        summaries = []
        for record in records:
            details = record.details or {}
            summaries.append(
                csca_service_pb2.CertificateSummary(
                    certificate_id=record.certificate_id,
                    subject=record.subject or "",
                    status="REVOKED" if record.revoked else "VALID",
                    not_before=details.get("not_before", ""),
                    not_after=details.get("not_after", ""),
                )
            )
        return csca_service_pb2.ListCertificatesResponse(certificates=summaries)

    async def CheckExpiringCertificates(  # noqa: N802
        self,
        request: ProtoMessage,  # csca_service_pb2.CheckExpiringCertificatesRequest
        context: GrpcServicerContext,  # grpc.ServicerContext
    ) -> ProtoMessage:  # csca_service_pb2.CheckExpiringCertificatesResponse
        threshold_days = request.threshold_days if request.threshold_days > 0 else 30
        now = datetime.now(timezone.utc)
        expiring = []
        for record in await self._list_certificates():
            details = record.details or {}
            if record.revoked or "not_after" not in details:
                continue
            try:
                not_after = datetime.fromisoformat(details["not_after"])
            except ValueError:
                continue
            if 0 <= (not_after - now).days <= threshold_days:
                expiring.append(
                    csca_service_pb2.CertificateSummary(
                        certificate_id=record.certificate_id,
                        subject=record.subject or "",
                        status="VALID",
                        not_before=details.get("not_before", ""),
                        not_after=details["not_after"],
                    )
                )

        return csca_service_pb2.ListCertificatesResponse(certificates=expiring)

    # ------------------------------------------------------------------
    # Lifecycle hooks (no-op placeholders retained for compatibility)
    # ------------------------------------------------------------------
    def setup_lifecycle_monitoring(self) -> bool | None:
        """Lifecycle monitoring is managed externally."""

        self.logger.debug("Lifecycle monitoring integration not yet implemented")
        return None

    def perform_lifecycle_checks(self) -> None:
        """Placeholder for scheduled lifecycle checks."""

        self.logger.debug("perform_lifecycle_checks called – no action")

    def stop_lifecycle_monitoring(self) -> bool:
        """No-op stop hook."""

        return True

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    async def _refresh_cache(self) -> None:
        async def loader(session):
            repo = CertificateRepository(session)
            records = await repo.list_all()
            return {
                record.certificate_id: {
                    "subject": record.subject,
                    "pem": record.pem,
                    "details": record.details or {},
                    "revoked": record.revoked,
                }
                for record in records
            }

        self._certificate_cache = await self._database.run_within_transaction(loader)

    async def _persist_certificate(
        self,
        *,
        certificate_id: str,
        certificate_type: str,
        subject: str,
        pem_text: str,
        details: dict[str, Any],
        session=None,
        update_cache: bool = True,
    ) -> None:
        async def handler(db_session):
            repo = CertificateRepository(db_session)
            await repo.upsert(
                certificate_id,
                certificate_type,
                pem_text,
                issuer=subject,
                subject=subject,
                details=details,
            )

        if session is None:
            await self._database.run_within_transaction(handler)
        else:
            await handler(session)

        if update_cache:
            self._certificate_cache[certificate_id] = {
                "subject": subject,
                "pem": pem_text,
                "details": details,
                "revoked": False,
            }

    async def _mark_certificate_revoked(
        self,
        certificate_id: str,
        reason: str,
        *,
        session=None,
        update_cache: bool = True,
        revoked_at: datetime | None = None,
    ) -> datetime:
        revoked_at = revoked_at or datetime.now(timezone.utc)

        async def handler(db_session):
            repo = CertificateRepository(db_session)
            await repo.mark_revoked(certificate_id, reason, revoked_at)

        if session is None:
            await self._database.run_within_transaction(handler)
        else:
            await handler(session)

        if update_cache:
            self._update_revocation_cache(certificate_id, reason, revoked_at)

        return revoked_at

    def _update_revocation_cache(
        self, certificate_id: str, reason: str, revoked_at: datetime
    ) -> None:
        cache_entry = self._certificate_cache.get(certificate_id)
        if cache_entry is None:
            cache_entry = {
                "subject": certificate_id,
                "pem": "",
                "details": {},
                "revoked": True,
            }
            self._certificate_cache[certificate_id] = cache_entry

        cache_entry["revoked"] = True
        details = cache_entry.setdefault("details", {})
        details["revocation_reason"] = reason
        details["revocation_date"] = revoked_at.isoformat()

    async def _fetch_certificate_record(self, certificate_id: str) -> dict[str, Any] | None:
        async def handler(session):
            repo = CertificateRepository(session)
            return await repo.get(certificate_id)

        record = await self._database.run_within_transaction(handler)
        if record is None:
            return None
        cache_entry = {
            "subject": record.subject,
            "pem": record.pem,
            "details": record.details or {},
            "revoked": record.revoked,
        }
        self._certificate_cache[certificate_id] = cache_entry
        return cache_entry

    async def _list_certificates(self) -> list[dict[str, Any]]:
        async with self._database.session_scope() as session:
            repo = CertificateRepository(session)
            records = await repo.list_all()
            return records

    @staticmethod
    def _generate_private_key(
        key_algorithm: str, key_size: int
    ) -> rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey:
        algorithm = key_algorithm.upper()
        if algorithm == "RSA" or algorithm.startswith("RSA"):
            size = key_size if key_size > 0 else 2048
            return rsa.generate_private_key(public_exponent=65537, key_size=size)
        if algorithm == "ECDSA":
            curve = ec.SECP256R1()
            if key_size >= 521:
                curve = ec.SECP521R1()
            elif key_size >= 384:
                curve = ec.SECP384R1()
            return ec.generate_private_key(curve)
        msg = f"Unsupported key algorithm: {key_algorithm}"
        raise ValueError(msg)

    @staticmethod
    def _build_self_signed_certificate(
        private_key, subject_name: str, not_before: datetime, not_after: datetime
    ) -> x509.Certificate:
        name = subject_name if subject_name.startswith("CN=") else f"CN={subject_name}"
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name.replace("CN=", ""))])

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
        return builder.sign(private_key, hashes.SHA256())
