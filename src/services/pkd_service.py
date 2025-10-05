"""PKD gRPC service exposing trust anchor data."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from marty_common.grpc_types import (
        GrpcServicerContext,
        ServiceDependencies,
    )

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from marty_common.infrastructure import CertificateRepository, DatabaseManager, OutboxRepository
from src.proto.v1 import pkd_service_pb2, pkd_service_pb2_grpc


class PKDService(pkd_service_pb2_grpc.PKDServiceServicer):
    """Provide trust anchor information sourced from the certificate repository."""

    def __init__(
        self,
        channels: dict[str, Any] | None = None,
        dependencies: ServiceDependencies | None = None,
    ) -> None:
        if dependencies is None:
            msg = "PKDService requires service dependencies"
            raise ValueError(msg)
        self.logger = logging.getLogger(__name__)
        self.channels = channels or {}
        self._database = dependencies.database  # type: ignore
        self._data_dir = Path(os.environ.get("PKD_DATA_DIR", "src/pkd_service/data"))
        self._auto_sync_interval = int(os.environ.get("PKD_AUTO_SYNC_INTERVAL", "0"))
        self._sync_task: asyncio.Task[None] | None = None
        if self._auto_sync_interval > 0:
            self._start_background_sync()

    async def ListTrustAnchors(
        self,
        _request: Any,  # empty_pb2.Empty
        _context: GrpcServicerContext,  # grpc.ServicerContext
    ) -> Any:  # pkd_service_pb2.ListTrustAnchorsResponse
        records = await self._list_csca_records()
        anchors = []
        for record in records:
            details = record.details or {}
            anchors.append(
                pkd_service_pb2.TrustAnchor(
                    certificate_id=record.certificate_id,
                    subject=record.subject or "",
                    certificate_pem=record.pem,
                    storage_key=details.get("storage_key", ""),
                    not_after=details.get("not_after", ""),
                    revoked=record.revoked,
                )
            )
        return pkd_service_pb2.ListTrustAnchorsResponse(anchors=anchors)

    async def Sync(
        self,
        request: Any,  # pkd_service_pb2.SyncRequest
        _context: GrpcServicerContext,  # grpc.ServicerContext
    ) -> Any:  # pkd_service_pb2.SyncResponse
        ingested = await self._ingest_local_dataset(
            force_refresh=request.force_refresh,
            emit_event=True,
        )
        message = f"Ingested {ingested} trust anchors from PKD dataset"
        self.logger.info(message)
        return pkd_service_pb2.SyncResponse(success=True, message=message)

    async def get_trust_material_by_criteria(
        self,
        subject_pattern: Optional[str] = None,
        ski_hex: Optional[str] = None,
        cert_hash: Optional[str] = None,
        country_code: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Get trust material matching various criteria for inspection system.
        
        This method provides a programmatic interface for the inspection system
        to query trust material without requiring gRPC calls.
        """
        async with self._database.session_scope() as session:
            repo = CertificateRepository(session)
            all_records = await repo.list_by_type("CSCA")
            
            matching_records = []
            for record in all_records:
                details = record.details or {}
                
                # Apply filters
                if subject_pattern and subject_pattern.lower() not in (record.subject or "").lower():
                    continue
                
                if ski_hex and details.get("subject_key_identifier", "").lower() != ski_hex.lower():
                    continue
                
                if cert_hash and details.get("sha256_fingerprint", "").lower() != cert_hash.lower():
                    continue
                
                if country_code:
                    cert_country = details.get("country", "")
                    if cert_country.upper() != country_code.upper():
                        continue
                
                # Convert to dictionary for easier consumption
                matching_records.append({
                    "certificate_id": record.certificate_id,
                    "subject": record.subject or "",
                    "issuer": record.issuer or "",
                    "pem": record.pem,
                    "revoked": record.revoked,
                    "not_after": details.get("not_after", ""),
                    "subject_key_identifier": details.get("subject_key_identifier", ""),
                    "authority_key_identifier": details.get("authority_key_identifier", ""),
                    "sha256_fingerprint": details.get("sha256_fingerprint", ""),
                    "sha1_fingerprint": details.get("sha1_fingerprint", ""),
                    "country": details.get("country", ""),
                    "storage_key": details.get("storage_key", ""),
                })
            
            return matching_records

    async def get_indexed_trust_cache(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Get indexed trust material cache for efficient inspection system lookups.
        
        Returns a dictionary with different indexing strategies:
        - by_subject: Indexed by subject DN
        - by_ski: Indexed by Subject Key Identifier  
        - by_hash: Indexed by SHA-256 fingerprint
        - by_country: Indexed by country code
        """
        async with self._database.session_scope() as session:
            repo = CertificateRepository(session)
            all_records = await repo.list_by_type("CSCA")
            
            cache = {
                "by_subject": {},
                "by_ski": {},
                "by_hash": {},
                "by_country": {},
                "metadata": {
                    "total_count": len(all_records),
                    "last_updated": datetime.now(timezone.utc).isoformat(),
                },
            }
            
            for record in all_records:
                details = record.details or {}
                
                cert_data = {
                    "certificate_id": record.certificate_id,
                    "subject": record.subject or "",
                    "issuer": record.issuer or "",
                    "pem": record.pem,
                    "revoked": record.revoked,
                    "not_after": details.get("not_after", ""),
                    "storage_key": details.get("storage_key", ""),
                }
                
                # Index by subject
                subject = record.subject or ""
                if subject:
                    if subject not in cache["by_subject"]:
                        cache["by_subject"][subject] = []
                    cache["by_subject"][subject].append(cert_data)
                
                # Index by SKI
                ski = details.get("subject_key_identifier", "")
                if ski:
                    cache["by_ski"][ski.lower()] = cert_data
                
                # Index by hash
                cert_hash = details.get("sha256_fingerprint", "")
                if cert_hash:
                    cache["by_hash"][cert_hash.lower()] = cert_data
                
                # Index by country
                country = details.get("country", "")
                if country:
                    country_key = country.upper()
                    if country_key not in cache["by_country"]:
                        cache["by_country"][country_key] = []
                    cache["by_country"][country_key].append(cert_data)
            
            return cache

    async def validate_certificate_chain(
        self,
        certificate_pem: str,
        issuer_subject: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Validate certificate chain against PKD trust anchors.
        
        Used by inspection system to verify document signer certificates
        against the PKD trust material.
        """
        validation_result = {
            "valid": False,
            "trust_anchor_found": False,
            "trust_anchor_id": None,
            "chain_length": 0,
            "errors": [],
            "warnings": [],
        }
        
        try:
            # Parse the certificate
            from cryptography import x509
            cert = x509.load_pem_x509_certificate(certificate_pem.encode())
            
            # Extract certificate info
            subject = cert.subject.rfc4514_string()
            issuer = cert.issuer.rfc4514_string()
            
            validation_result["chain_length"] = 1
            
            # If issuer_subject is provided, use it; otherwise use cert issuer
            issuer_to_find = issuer_subject or issuer
            
            # Look for trust anchor
            trust_materials = await self.get_trust_material_by_criteria(
                subject_pattern=issuer_to_find
            )
            
            if trust_materials:
                validation_result["trust_anchor_found"] = True
                validation_result["trust_anchor_id"] = trust_materials[0]["certificate_id"]
                
                # Check if trust anchor is revoked
                if trust_materials[0]["revoked"]:
                    validation_result["errors"].append("Trust anchor is revoked")
                else:
                    validation_result["valid"] = True
            else:
                validation_result["errors"].append(f"No trust anchor found for issuer: {issuer_to_find}")
            
            # Additional validation checks
            now = datetime.now(timezone.utc)
            if cert.not_valid_after < now:
                validation_result["errors"].append("Certificate has expired")
                validation_result["valid"] = False
            
            if cert.not_valid_before > now:
                validation_result["errors"].append("Certificate is not yet valid")
                validation_result["valid"] = False
            
        except Exception as e:
            validation_result["errors"].append(f"Certificate parsing error: {str(e)}")
            self.logger.exception("Certificate validation error: %s", e)
        
        return validation_result

    def get_pkd_cache_stats(self) -> Dict[str, Any]:
        """Get PKD cache statistics for monitoring."""
        cache_dir = Path("data/pkd_cache")
        
        stats = {
            "cache_enabled": cache_dir.exists(),
            "cache_size_mb": 0,
            "file_count": 0,
            "last_sync": None,
        }
        
        if cache_dir.exists():
            try:
                # Calculate cache size
                total_size = sum(f.stat().st_size for f in cache_dir.rglob('*') if f.is_file())
                stats["cache_size_mb"] = round(total_size / (1024 * 1024), 2)
                stats["file_count"] = len(list(cache_dir.rglob('*')))
                
                # Check for metadata file
                metadata_file = cache_dir / "metadata.json"
                if metadata_file.exists():
                    try:
                        metadata = json.loads(metadata_file.read_text())
                        stats["last_sync"] = metadata.get("updated")
                    except Exception:
                        pass
            except Exception as e:
                self.logger.warning("Failed to get cache stats: %s", e)
        
        return stats

    async def _list_csca_records(self) -> list[Any]:  # list[CertificateRecord]
        async with self._database.session_scope() as session:
            repo = CertificateRepository(session)
            return await repo.list_by_type("CSCA")

    async def _ingest_local_dataset(self, force_refresh: bool, emit_event: bool = False) -> int:
        if not self._data_dir.exists():
            self.logger.warning("PKD data directory %s not found", self._data_dir)
            return 0

        sample_files = sorted(self._data_dir.glob("CscaCertificates_*.txt"))
        if not sample_files:
            self.logger.warning("No CSCA dataset found in %s", self._data_dir)
            return 0

        dataset_path = sample_files[-1]
        lines = [line.strip() for line in dataset_path.read_text().splitlines() if line.strip()]
        anchors = [line for line in lines if not line.startswith("Simulated")] or lines

        now = datetime.now(timezone.utc)
        not_after = (now + timedelta(days=365 * 5)).isoformat()
        anchor_count = len(anchors)

        async def handler(session: Any) -> None:  # AsyncSession
            repo = CertificateRepository(session)
            for index, entry in enumerate(anchors):
                certificate_id = f"PKD-CSCA-{index+1:04d}"
                pem_text = self._create_placeholder_pem(certificate_id, entry)
                details = {
                    "storage_key": f"pkd/{certificate_id}.pem",
                    "not_after": not_after,
                    "source": str(dataset_path.name),
                }
                await repo.upsert(
                    certificate_id,
                    "CSCA",
                    pem_text,
                    issuer="ICAO PKD",
                    subject=f"CN={entry or certificate_id}",
                    details=details,
                )
            if emit_event:
                outbox = OutboxRepository(session)
                payload = {
                    "force_refresh": force_refresh,
                    "anchors": anchor_count,
                    "dataset": dataset_path.name,
                }
                key = f"pkd:{dataset_path.name}".encode()
                await outbox.enqueue(
                    topic="pkd.sync.completed",
                    payload=json.dumps(payload).encode("utf-8"),
                    key=key,
                )

        await self._database.run_within_transaction(handler)
        return anchor_count

    @staticmethod
    def _create_placeholder_pem(certificate_id: str, entry: str) -> str:
        body = f"Simulated certificate for {certificate_id}: {entry}".encode().hex()
        return "-----BEGIN CERTIFICATE-----\n" f"{body}\n" "-----END CERTIFICATE-----\n"

    def _start_background_sync(self) -> None:
        if self._sync_task and not self._sync_task.done():
            return

        async def _worker() -> None:
            while True:
                try:
                    self.logger.debug("Auto PKD sync triggered")
                    await self._ingest_local_dataset(force_refresh=False, emit_event=True)
                except Exception:  # pylint: disable=broad-except
                    self.logger.exception("Automatic PKD sync failed")
                await asyncio.sleep(self._auto_sync_interval)

        self._sync_task = asyncio.create_task(_worker())
