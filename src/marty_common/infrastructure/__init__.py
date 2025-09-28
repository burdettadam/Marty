"""Infrastructure integration helpers for Marty services.

This package exposes shared client abstractions for storage, messaging,
and key management so individual services can avoid hard-coding
environment-specific dependencies.
"""

from .database import DatabaseConfig, DatabaseManager
from .event_bus import EventBusConfig, EventBusMessage, EventBusProvider
from .models import (
    Base,
    CertificateRecord,
    DigitalTravelCredentialRecord,
    MobileDrivingLicenseRecord,
    PassportRecord,
    TrustEntity,
)
from .key_vault import KeyVaultClient, KeyVaultConfig, build_key_vault_client
from .object_storage import ObjectStorageClient, ObjectStorageConfig
from .repositories import (
    CertificateRepository,
    DigitalTravelCredentialRepository,
    MobileDrivingLicenseRepository,
    PassportRepository,
    TrustEntityRepository,
)

__all__ = [
    "DatabaseConfig",
    "DatabaseManager",
    "EventBusConfig",
    "EventBusMessage",
    "EventBusProvider",
    "Base",
    "CertificateRecord",
    "DigitalTravelCredentialRecord",
    "TrustEntity",
    "KeyVaultClient",
    "KeyVaultConfig",
    "ObjectStorageClient",
    "ObjectStorageConfig",
    "CertificateRepository",
    "DigitalTravelCredentialRepository",
    "MobileDrivingLicenseRepository",
    "PassportRepository",
    "TrustEntityRepository",
    "build_key_vault_client",
    "MobileDrivingLicenseRecord",
    "PassportRecord",
]
