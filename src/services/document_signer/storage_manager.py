"""Storage utilities for the Document Signer service."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from marty_common.infrastructure import ObjectStorageClient


class StorageManager:
    """Manages storage operations for the Document Signer service."""

    def __init__(self, object_storage: ObjectStorageClient, storage_prefix: str = "sd-jwt") -> None:
        self._object_storage = object_storage
        self._storage_prefix = storage_prefix.rstrip("/")

    async def store_sd_jwt_artifacts(
        self,
        credential_id: str,
        token: str,
        disclosures: list[str],
    ) -> tuple[str, str]:
        """Store SD-JWT token and disclosures in object storage.

        Args:
            credential_id: Unique identifier for the credential
            token: The SD-JWT token
            disclosures: List of disclosure strings

        Returns:
            Tuple of (token_storage_key, disclosures_storage_key)
        """
        base_path = f"{self._storage_prefix}/{credential_id}"
        token_key = f"{base_path}.sdjwt"
        disclosures_key = f"{base_path}-disclosures.json"

        await self._object_storage.put_object(
            token_key,
            token.encode("utf-8"),
            content_type="application/sd-jwt",
        )
        disclosures_payload = json.dumps({"disclosures": disclosures}).encode("utf-8")
        await self._object_storage.put_object(
            disclosures_key,
            disclosures_payload,
            content_type="application/json",
        )
        return token_key, disclosures_key

    async def store_signature(self, document_id: str, signature: bytes, timestamp: int) -> str:
        """Store a document signature in object storage.

        Args:
            document_id: Unique identifier for the document
            signature: The signature bytes
            timestamp: Unix timestamp for when the signature was created

        Returns:
            Storage key for the signature
        """
        storage_key = f"signatures/{document_id}-{timestamp}.sig"
        await self._object_storage.put_object(storage_key, signature)
        return storage_key
