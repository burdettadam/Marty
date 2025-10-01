"""Utility functions and constants for the Document Signer service."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone


def seconds_until(moment: datetime) -> int:
    """Return the number of whole seconds from now until ``moment`` (>=0)."""
    now = datetime.now(timezone.utc)
    delta = max(moment - now, timedelta(0))
    return int(delta.total_seconds())


def build_event_payload(
    document_id: str, payload_hash: bytes, storage_key: str, signing_key_id: str
) -> dict:
    """Build event payload for document signing events."""
    return {
        "document_id": document_id,
        "hash_algo": "SHA256",
        "hash": payload_hash.hex(),
        "signature_location": storage_key,
        "signer": signing_key_id,
    }
