import logging

import pytest
from sqlalchemy import select

from src.marty_common.infrastructure import (
    CredentialLedgerEntry,
    CredentialLedgerRepository,
    DatabaseConfig,
    DatabaseManager,
)
from src.services.credential_ledger import CredentialLedgerProcessor, MessageContext


@pytest.mark.asyncio
async def test_processor_certificate_lifecycle_updates_ledger():
    database = DatabaseManager(DatabaseConfig(url="sqlite+aiosqlite:///:memory:"))
    await database.create_all()

    async with database.session_scope() as session:
        repo = CredentialLedgerRepository(session)
        processor = CredentialLedgerProcessor(repo, logging.getLogger("test-ledger"))
        payload = {
            "certificate_id": "CERT1",
            "subject": "CN=Test",
            "storage_key": "certs/cert1.pem",
            "not_after": "2030-01-01",
        }
        context = MessageContext(topic="certificate.issued", partition=0, offset=1)
        await repo.record_event(topic="certificate.issued", payload=payload, key="CERT1", partition=0, offset=1)
        await processor.process("certificate.issued", payload, "CERT1", context)

    async with database.session_scope() as session:
        result = await session.execute(
            select(CredentialLedgerEntry).where(CredentialLedgerEntry.credential_id == "CERT1")
        )
        entry = result.scalars().first()
        assert entry is not None
        assert entry.status == "ISSUED"
        assert entry.metadata["storage_key"] == "certs/cert1.pem"

    async with database.session_scope() as session:
        repo = CredentialLedgerRepository(session)
        processor = CredentialLedgerProcessor(repo, logging.getLogger("test-ledger"))
        payload = {
            "certificate_id": "CERT2",
            "previous_id": "CERT1",
            "storage_key": "certs/cert2.pem",
        }
        context = MessageContext(topic="certificate.renewed", partition=0, offset=2)
        await repo.record_event(topic="certificate.renewed", payload=payload, key="CERT2", partition=0, offset=2)
        await processor.process("certificate.renewed", payload, "CERT2", context)

    async with database.session_scope() as session:
        old_result = await session.execute(
            select(CredentialLedgerEntry).where(CredentialLedgerEntry.credential_id == "CERT1")
        )
        old_entry = old_result.scalars().first()
        assert old_entry is not None
        assert old_entry.status == "SUPERSEDED"
        assert old_entry.metadata["replacement_id"] == "CERT2"

        new_result = await session.execute(
            select(CredentialLedgerEntry).where(CredentialLedgerEntry.credential_id == "CERT2")
        )
        new_entry = new_result.scalars().first()
        assert new_entry is not None
        assert new_entry.status == "ISSUED"


@pytest.mark.asyncio
async def test_processor_handles_mdl_and_passport_events():
    database = DatabaseManager(DatabaseConfig(url="sqlite+aiosqlite:///:memory:"))
    await database.create_all()

    async with database.session_scope() as session:
        repo = CredentialLedgerRepository(session)
        processor = CredentialLedgerProcessor(repo, logging.getLogger("test-ledger"))

        mdl_created = {
            "mdl_id": "MDL-1",
            "license_number": "L123",
            "user_id": "user-42",
        }
        await repo.record_event(
            topic="mdl.created",
            payload=mdl_created,
            key="MDL-1",
            partition=None,
            offset=1,
        )
        await processor.process(
            "mdl.created",
            mdl_created,
            "MDL-1",
            MessageContext(topic="mdl.created", partition=None, offset=1),
        )

        mdl_signed = {
            "mdl_id": "MDL-1",
            "license_number": "L123",
            "signature_date": "2024-01-01",
            "signer_id": "signer",
        }
        await repo.record_event(
            topic="mdl.signed",
            payload=mdl_signed,
            key="MDL-1",
            partition=None,
            offset=2,
        )
        await processor.process(
            "mdl.signed",
            mdl_signed,
            "MDL-1",
            MessageContext(topic="mdl.signed", partition=None, offset=2),
        )

        passport_payload = {
            "passport_number": "P12345",
            "storage_key": "passports/P12345.json",
            "status": "ISSUED",
        }
        await repo.record_event(
            topic="passport.issued",
            payload=passport_payload,
            key="P12345",
            partition=None,
            offset=3,
        )
        await processor.process(
            "passport.issued",
            passport_payload,
            "P12345",
            MessageContext(topic="passport.issued", partition=None, offset=3),
        )

    async with database.session_scope() as session:
        mdl_result = await session.execute(
            select(CredentialLedgerEntry).where(CredentialLedgerEntry.credential_id == "MDL-1")
        )
        mdl_entry = mdl_result.scalars().first()
        assert mdl_entry is not None
        assert mdl_entry.status == "ISSUED"
        assert mdl_entry.metadata["license_number"] == "L123"
        assert mdl_entry.metadata["signature_date"] == "2024-01-01"

        passport_result = await session.execute(
            select(CredentialLedgerEntry).where(CredentialLedgerEntry.credential_id == "P12345")
        )
        passport_entry = passport_result.scalars().first()
        assert passport_entry is not None
        assert passport_entry.status == "ISSUED"
        assert passport_entry.metadata["storage_key"] == "passports/P12345.json"
