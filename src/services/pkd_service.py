"""PKD gRPC service exposing trust anchor data."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import TYPE_CHECKING, Any

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
        self._database: DatabaseManager = dependencies.database
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
