"""PKD gRPC service exposing trust anchor data."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any
import threading
import time

from google.protobuf import empty_pb2

from datetime import datetime, timezone, timedelta
import os
from pathlib import Path

from marty_common.infrastructure import (
    CertificateRepository,
    DatabaseManager,
    EventBusMessage,
    EventBusProvider,
)
from src.proto import pkd_service_pb2, pkd_service_pb2_grpc


class PKDService(pkd_service_pb2_grpc.PKDServiceServicer):
    """Provide trust anchor information sourced from the certificate repository."""

    def __init__(self, channels=None, dependencies=None) -> None:
        if dependencies is None:
            msg = "PKDService requires service dependencies"
            raise ValueError(msg)
        self.logger = logging.getLogger(__name__)
        self.channels = channels or {}
        self._database: DatabaseManager = dependencies.database
        self._event_bus: EventBusProvider = dependencies.event_bus
        self._run = lambda coro: asyncio.run(coro)
        self._data_dir = Path(os.environ.get("PKD_DATA_DIR", "src/pkd_service/data"))
        self._auto_sync_interval = int(os.environ.get("PKD_AUTO_SYNC_INTERVAL", "0"))
        self._sync_thread: threading.Thread | None = None
        if self._auto_sync_interval > 0:
            self._start_background_sync()

    def ListTrustAnchors(self, request: empty_pb2.Empty, context):  # noqa: N802
        records = self._run(self._list_csca_records())
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

    def Sync(self, request, context):  # noqa: N802
        ingested = self._ingest_local_dataset(force_refresh=request.force_refresh)
        message = f"Ingested {ingested} trust anchors from PKD dataset"
        self.logger.info(message)
        self._publish_event(
            "pkd.sync.completed",
            {"force_refresh": request.force_refresh, "anchors": ingested},
        )
        return pkd_service_pb2.SyncResponse(success=True, message=message)

    async def _list_csca_records(self):
        async with self._database.session_scope() as session:
            repo = CertificateRepository(session)
            return await repo.list_by_type("CSCA")

    def _publish_event(self, topic: str, payload: dict[str, Any]) -> None:
        message = EventBusMessage(topic=topic, payload=json.dumps(payload).encode("utf-8"))
        self._run(self._event_bus.publish(message))

    def _ingest_local_dataset(self, force_refresh: bool) -> int:
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

        async def handler(session):
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

        self._run(self._database.run_within_transaction(handler))
        return len(anchors)

    @staticmethod
    def _create_placeholder_pem(certificate_id: str, entry: str) -> str:
        body = f"Simulated certificate for {certificate_id}: {entry}".encode("utf-8").hex()
        return (
            "-----BEGIN CERTIFICATE-----\n"
            f"{body}\n"
            "-----END CERTIFICATE-----\n"
        )

    def _start_background_sync(self) -> None:
        if self._sync_thread and self._sync_thread.is_alive():
            return

        def _worker():
            while True:
                try:
                    self.logger.debug("Auto PKD sync triggered")
                    self._ingest_local_dataset(force_refresh=False)
                except Exception as exc:  # pylint: disable=broad-except
                    self.logger.exception("Automatic PKD sync failed: %s", exc)
                time.sleep(self._auto_sync_interval)

        self._sync_thread = threading.Thread(target=_worker, daemon=True)
        self._sync_thread.start()
