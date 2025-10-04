"""Trust Anchor service with database-backed trust store."""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

import grpc

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from marty_common.grpc_types import (
        DatabaseManager,
        GrpcServicerContext,
        ServiceDependencies,
        TrustRequest,
        TrustResponse,
    )

from marty_common.infrastructure import OutboxRepository, TrustEntityRepository
from src.proto.v1 import trust_anchor_pb2, trust_anchor_pb2_grpc


class TrustAnchor(trust_anchor_pb2_grpc.TrustAnchorServicer):
    """Trust Anchor backed by the shared database and event bus."""

    def __init__(
        self,
        channels: dict[str, grpc.Channel] | None = None,
        dependencies: ServiceDependencies | None = None,
    ) -> None:
        if dependencies is None:
            msg = "TrustAnchor requires service dependencies"
            raise ValueError(msg)
        self.logger = logging.getLogger(__name__)
        self.channels = channels or {}
        self._database: DatabaseManager = dependencies.database
        self.logger.info("Trust Anchor service initialized using database-backed trust store")

    async def VerifyTrust(
        self,
        request: TrustRequest,
        context: GrpcServicerContext,
    ) -> TrustResponse:
        """Verify if an entity is trusted."""
        entity = request.entity
        self.logger.info("VerifyTrust called for entity: %s", entity)

        async def handler(session: AsyncSession) -> bool:
            repo = TrustEntityRepository(session)
            record = await repo.get(entity)
            return record.trusted if record else False

        try:
            is_trusted = await self._database.run_within_transaction(handler)
        except Exception:
            self.logger.exception("Trust verification failed for %s", entity)
            await context.abort(grpc.StatusCode.INTERNAL, "Trust verification failed")
            # This line won't execute due to abort, but satisfies type checker
            return trust_anchor_pb2.TrustResponse(is_trusted=False)  # type: ignore[no-any-return,attr-defined]

        self.logger.info("Entity %s is trusted: %s", entity, is_trusted)
        return trust_anchor_pb2.TrustResponse(is_trusted=is_trusted)  # type: ignore[no-any-return,attr-defined]

    async def update_trust_store(
        self,
        entity: str,
        trusted: bool = True,
        attributes: dict[str, str] | None = None,
    ) -> bool | None:
        """Update trust store for an entity."""

        async def handler(session: AsyncSession) -> None:
            repo = TrustEntityRepository(session)
            outbox = OutboxRepository(session)

            # Update the trust entity
            await repo.upsert(entity, trusted, attributes)

            # Queue event for trust update
            await outbox.enqueue(
                topic="trust.entity.updated",
                payload=json.dumps(
                    {
                        "entity_id": entity,
                        "trusted": trusted,
                        "source": "manual_update",
                    }
                ).encode(),
                key=entity.encode(),
            )

        try:
            _ = await self._database.run_within_transaction(handler)
            self.logger.info("Trust store updated for %s (trusted=%s)", entity, trusted)
        except Exception:
            self.logger.exception("Error updating trust store for %s", entity)
            return None
        else:
            return True
