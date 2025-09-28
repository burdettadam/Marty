"""Database repositories used by services."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from .models import CertificateRecord, DigitalTravelCredentialRecord, TrustEntity


class TrustEntityRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get(self, entity_id: str) -> Optional[TrustEntity]:
        stmt = select(TrustEntity).where(TrustEntity.entity_id == entity_id)
        result = await self._session.execute(stmt)
        return result.scalars().first()

    async def upsert(self, entity_id: str, trusted: bool, attributes: Optional[dict[str, Any]] = None) -> TrustEntity:
        record = await self.get(entity_id)
        if record is None:
            record = TrustEntity(entity_id=entity_id, trusted=trusted, attributes=attributes or {}, version=1)
            self._session.add(record)
        else:
            record.trusted = trusted
            record.attributes = attributes or record.attributes
            record.version += 1
        return record

    async def list_trusted(self) -> list[TrustEntity]:
        stmt = select(TrustEntity).where(TrustEntity.trusted.is_(True))
        result = await self._session.execute(stmt)
        return list(result.scalars().all())


class CertificateRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def upsert(
        self,
        cert_id: str,
        cert_type: str,
        pem: str,
        issuer: str | None = None,
        subject: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> CertificateRecord:
        stmt = select(CertificateRecord).where(CertificateRecord.certificate_id == cert_id)
        result = await self._session.execute(stmt)
        record = result.scalars().first()
        if record is None:
            record = CertificateRecord(
                certificate_id=cert_id,
                certificate_type=cert_type,
                issuer=issuer,
                subject=subject,
                pem=pem,
                details=details,
            )
            self._session.add(record)
        else:
            record.pem = pem
            record.issuer = issuer
            record.subject = subject
            record.details = details or record.details
            record.updated_at = datetime.now(timezone.utc)
        return record

    async def get(self, cert_id: str) -> Optional[CertificateRecord]:
        stmt = select(CertificateRecord).where(CertificateRecord.certificate_id == cert_id)
        result = await self._session.execute(stmt)
        return result.scalars().first()

    async def list_all(self) -> list[CertificateRecord]:
        result = await self._session.execute(select(CertificateRecord))
        return list(result.scalars().all())

    async def mark_revoked(self, cert_id: str, reason: str | None, revoked_at: datetime) -> None:
        current_details: dict[str, Any] | None = None
        existing = await self.get(cert_id)
        if existing is not None:
            current_details = existing.details or {}
        if current_details is None:
            current_details = {}
        current_details.update(
            {
                "revocation_reason": reason,
                "revocation_date": revoked_at.isoformat(),
            }
        )
        stmt = (
            update(CertificateRecord)
            .where(CertificateRecord.certificate_id == cert_id)
            .values(revoked=True, updated_at=revoked_at, details=current_details)
        )
        await self._session.execute(stmt)

    async def list_by_type(self, cert_type: str) -> list[CertificateRecord]:
        stmt = select(CertificateRecord).where(CertificateRecord.certificate_type == cert_type)
        result = await self._session.execute(stmt)
        return list(result.scalars().all())


class DigitalTravelCredentialRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(
        self,
        dtc_id: str,
        passport_number: str,
        dtc_type: str,
        access_control: str,
        details: dict[str, Any],
        payload_location: str,
        signature: bytes | None,
    ) -> DigitalTravelCredentialRecord:
        record = DigitalTravelCredentialRecord(
            dtc_id=dtc_id,
            passport_number=passport_number,
            dtc_type=dtc_type,
            access_control=access_control,
            details=details,
            payload_location=payload_location,
            signature=signature,
        )
        self._session.add(record)
        return record

    async def get(self, dtc_id: str) -> Optional[DigitalTravelCredentialRecord]:
        stmt = select(DigitalTravelCredentialRecord).where(DigitalTravelCredentialRecord.dtc_id == dtc_id)
        result = await self._session.execute(stmt)
        return result.scalars().first()

    async def mark_revoked(self, dtc_id: str, reason: str | None = None) -> None:
        stmt = (
            update(DigitalTravelCredentialRecord)
            .where(DigitalTravelCredentialRecord.dtc_id == dtc_id)
            .values(status="REVOKED", revoked_at=datetime.now(timezone.utc), revocation_reason=reason)
        )
        await self._session.execute(stmt)
