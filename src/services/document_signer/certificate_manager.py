"""Certificate management utilities for the Document Signer service."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from cryptography import x509

from marty_common.crypto.document_signer_certificate import (
    load_or_create_document_signer_certificate,
)
from marty_common.infrastructure import CertificateRepository

if TYPE_CHECKING:
    from marty_common.infrastructure import DatabaseManager, KeyVaultClient


class CertificateManager:
    """Manages certificate operations for the Document Signer service."""

    def __init__(
        self,
        database: DatabaseManager,
        key_vault: KeyVaultClient,
        signing_key_id: str,
        vault_algorithm: str,
        certificate_ids: list[str],
    ) -> None:
        self.logger = logging.getLogger(__name__)
        self._database = database
        self._key_vault = key_vault
        self._signing_key_id = signing_key_id
        self._vault_algorithm = vault_algorithm
        self._certificate_ids = certificate_ids
        self._cached_certificate_chain: list[x509.Certificate] = []

    async def ensure_document_signer_certificate(self) -> None:
        """Ensure the document signer certificate exists."""

        async def handler(session) -> None:
            await load_or_create_document_signer_certificate(
                session,
                self._key_vault,
                signing_algorithm=self._vault_algorithm,
                key_id=self._signing_key_id,
            )

        await self._database.run_within_transaction(handler)

    async def refresh_certificate_cache(self) -> None:
        """Refresh the cached certificate chain."""

        async def handler(session) -> list[x509.Certificate]:
            repo = CertificateRepository(session)
            chain: list[x509.Certificate] = []
            for cert_id in self._certificate_ids:
                if not cert_id:
                    continue
                record = await repo.get(cert_id)
                if record is None or not record.pem:
                    continue
                try:
                    chain.append(x509.load_pem_x509_certificate(record.pem.encode("utf-8")))
                except ValueError:
                    self.logger.warning("Failed to parse certificate %s for x5c chain", cert_id)
            return chain

        self._cached_certificate_chain = await self._database.run_within_transaction(handler)
        if not self._cached_certificate_chain:
            self.logger.warning("No certificates available for SD-JWT x5c header")

    def get_certificate_chain(self) -> list[x509.Certificate]:
        """Get the cached certificate chain for x5c header."""
        return list(self._cached_certificate_chain)
