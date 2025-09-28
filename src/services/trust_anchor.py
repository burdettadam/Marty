import asyncio
import json
import logging
from typing import Optional

import grpc
from google.protobuf import empty_pb2

from marty_common.infrastructure import EventBusMessage, EventBusProvider, TrustEntityRepository
from src.proto import pkd_service_pb2, pkd_service_pb2_grpc, trust_anchor_pb2, trust_anchor_pb2_grpc


class TrustAnchor(trust_anchor_pb2_grpc.TrustAnchorServicer):
    """Trust Anchor backed by the shared database and event bus."""

    def __init__(self, channels=None, dependencies=None) -> None:
        if dependencies is None:
            msg = "TrustAnchor requires service dependencies"
            raise ValueError(msg)
        self.logger = logging.getLogger(__name__)
        self.channels = channels or {}
        self._database = dependencies.database
        self._event_bus: EventBusProvider = dependencies.event_bus
        self.logger.info("Trust Anchor service initialized using database-backed trust store")
        try:
            asyncio.get_running_loop().create_task(self._sync_from_pkd())
        except RuntimeError:
            asyncio.run(self._sync_from_pkd())

    async def VerifyTrust(self, request, context):
        entity = request.entity
        self.logger.info("VerifyTrust called for entity: %s", entity)

        async def handler(session):
            repo = TrustEntityRepository(session)
            record = await repo.get(entity)
            return record.trusted if record else False

        try:
            is_trusted = await self._database.run_within_transaction(handler)
        except Exception as exc:  # pylint: disable=broad-except
            self.logger.exception("Trust verification failed for %s", entity)
            await context.abort(grpc.StatusCode.INTERNAL, str(exc))
            return trust_anchor_pb2.TrustResponse(is_trusted=False)

        self.logger.info("Entity %s is trusted: %s", entity, is_trusted)
        return trust_anchor_pb2.TrustResponse(is_trusted=is_trusted)

    async def update_trust_store(self, entity, trusted=True, attributes=None) -> Optional[bool]:
        async def handler(session):
            repo = TrustEntityRepository(session)
            record = await repo.upsert(entity, trusted, attributes)
            return record

        try:
            record = await self._database.run_within_transaction(handler)
            payload = json.dumps(
                {
                    "entity": entity,
                    "trusted": trusted,
                    "version": record.version,
                }
            ).encode("utf-8")
            message = EventBusMessage(topic="trust.updated", payload=payload)
            await self._event_bus.publish(message)
            self.logger.info("Trust store updated for %s (trusted=%s)", entity, trusted)
            return True
        except Exception as exc:  # pylint: disable=broad-except
            self.logger.exception("Error updating trust store for %s", entity)
            return False

    async def _sync_from_pkd(self) -> None:
        pkd_channel = self.channels.get("pkd_service")
        if not pkd_channel:
            self.logger.debug("PKD service channel not configured; skipping sync")
            return

        stub = pkd_service_pb2_grpc.PKDServiceStub(pkd_channel)
        try:
            response = await stub.ListTrustAnchors(empty_pb2.Empty())
        except grpc.RpcError as rpc_err:
            self.logger.warning("PKD sync failed: %s", rpc_err.details())
            return

        async def handler(session):
            repo = TrustEntityRepository(session)
            for anchor in response.anchors:
                await repo.upsert(
                    anchor.certificate_id,
                    trusted=not anchor.revoked,
                    attributes={
                        "subject": anchor.subject,
                        "storage_key": anchor.storage_key,
                        "not_after": anchor.not_after,
                    },
                )

        await self._database.run_within_transaction(handler)
        self.logger.info("Synchronized %d trust anchors from PKD", len(response.anchors))
