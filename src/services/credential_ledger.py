"""Kafka consumer that maintains a credential audit ledger."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from aiokafka import AIOKafkaConsumer

from marty_common.infrastructure import CredentialLedgerRepository, DatabaseManager, EventBusConfig

logger = logging.getLogger(__name__)

DEFAULT_LEDGER_TOPICS: tuple[str, ...] = (
    "certificate.issued",
    "certificate.renewed",
    "certificate.revoked",
    "passport.issued",
    "dtc.issued",
    "dtc.signed",
    "dtc.revoked",
    "mdl.created",
    "mdl.signed",
    "mdl.transfer_requested",
    "credential.issued",
    "pkd.sync.completed",
    "trust.updated",
)


@dataclass(slots=True)
class MessageContext:
    topic: str
    partition: int | None
    offset: int | None


class CredentialLedgerProcessor:
    """Apply domain-specific updates for ledger events."""

    def __init__(self, repository: CredentialLedgerRepository, logger: logging.Logger) -> None:
        self._repository = repository
        self._logger = logger

    async def process(
        self,
        topic: str,
        payload: dict[str, Any],
        key: str | None,
        context: MessageContext,
    ) -> None:
        handler = getattr(self, f"_handle_{topic.replace('.', '_')}", None)
        if handler is None:
            self._logger.debug("No ledger handler for topic %s", topic)
            return
        try:
            await handler(payload, key, context)
        except Exception:  # pragma: no cover - defensive logging
            self._logger.exception("Credential ledger handler failed for topic %s", topic)

    async def _upsert(
        self,
        credential_id: str | None,
        credential_type: str,
        status: str,
        metadata: dict[str, Any] | None,
        context: MessageContext,
    ) -> None:
        if not credential_id:
            self._logger.warning(
                "Skipping ledger update for %s without credential_id", context.topic
            )
            return
        await self._repository.upsert_entry(
            credential_id=credential_id,
            credential_type=credential_type,
            status=status,
            metadata=metadata,
            topic=context.topic,
            offset=context.offset,
        )

    async def _handle_certificate_issued(
        self, payload: dict[str, Any], key: str | None, context: MessageContext
    ) -> None:
        cert_id = key or payload.get("certificate_id")
        metadata = {
            "subject": payload.get("subject"),
            "storage_key": payload.get("storage_key"),
            "not_after": payload.get("not_after"),
        }
        await self._upsert(cert_id, "certificate", "ISSUED", metadata, context)

    async def _handle_certificate_renewed(
        self, payload: dict[str, Any], key: str | None, context: MessageContext
    ) -> None:
        new_id = key or payload.get("certificate_id")
        previous_id = payload.get("previous_id")
        metadata = {
            "subject": payload.get("subject"),
            "storage_key": payload.get("storage_key"),
            "previous_id": previous_id,
        }
        await self._upsert(new_id, "certificate", "ISSUED", metadata, context)
        if previous_id:
            await self._upsert(
                previous_id,
                "certificate",
                "SUPERSEDED",
                {"replacement_id": new_id},
                context,
            )

    async def _handle_certificate_revoked(
        self, payload: dict[str, Any], key: str | None, context: MessageContext
    ) -> None:
        cert_id = key or payload.get("certificate_id")
        metadata = {"revocation_reason": payload.get("reason")}
        await self._upsert(cert_id, "certificate", "REVOKED", metadata, context)

    async def _handle_passport_issued(
        self, payload: dict[str, Any], key: str | None, context: MessageContext
    ) -> None:
        passport_number = key or payload.get("passport_number")
        status = payload.get("status", "ISSUED")
        metadata = {
            "storage_key": payload.get("storage_key"),
            "signature_info": payload.get("signature_info"),
        }
        await self._upsert(passport_number, "passport", status, metadata, context)

    async def _handle_dtc_issued(
        self, payload: dict[str, Any], key: str | None, context: MessageContext
    ) -> None:
        dtc_id = key or payload.get("dtc_id")
        metadata = {
            "passport_number": payload.get("passport_number"),
            "payload_location": payload.get("payload_location"),
        }
        await self._upsert(dtc_id, "dtc", "ISSUED", metadata, context)

    async def _handle_dtc_signed(
        self, payload: dict[str, Any], key: str | None, context: MessageContext
    ) -> None:
        dtc_id = key or payload.get("dtc_id")
        metadata = {
            "signature_date": payload.get("signature_date"),
            "signer_id": payload.get("signer_id"),
        }
        await self._upsert(dtc_id, "dtc", "SIGNED", metadata, context)

    async def _handle_dtc_revoked(
        self, payload: dict[str, Any], key: str | None, context: MessageContext
    ) -> None:
        dtc_id = key or payload.get("dtc_id")
        metadata = {"revocation_reason": payload.get("reason")}
        await self._upsert(dtc_id, "dtc", "REVOKED", metadata, context)

    async def _handle_mdl_created(
        self, payload: dict[str, Any], key: str | None, context: MessageContext
    ) -> None:
        mdl_id = key or payload.get("mdl_id")
        metadata = {
            "license_number": payload.get("license_number"),
            "user_id": payload.get("user_id"),
            "payload_location": payload.get("payload_location"),
        }
        await self._upsert(mdl_id, "mdl", "PENDING_SIGNATURE", metadata, context)

    async def _handle_mdl_signed(
        self, payload: dict[str, Any], key: str | None, context: MessageContext
    ) -> None:
        mdl_id = key or payload.get("mdl_id")
        metadata = {
            "license_number": payload.get("license_number"),
            "signature_date": payload.get("signature_date"),
            "signer_id": payload.get("signer_id"),
        }
        await self._upsert(mdl_id, "mdl", "ISSUED", metadata, context)

    async def _handle_mdl_transfer_requested(
        self, payload: dict[str, Any], key: str | None, context: MessageContext
    ) -> None:
        mdl_id = key or payload.get("mdl_id")
        metadata = {
            "transfer_id": payload.get("transfer_id"),
            "device_id": payload.get("device_id"),
            "transfer_method": payload.get("transfer_method"),
        }
        await self._upsert(mdl_id, "mdl", "TRANSFER_PENDING", metadata, context)

    async def _handle_credential_issued(
        self, payload: dict[str, Any], key: str | None, context: MessageContext
    ) -> None:
        credential_id = key or payload.get("document_id")
        metadata = {
            "signer": payload.get("signer"),
            "signature_location": payload.get("signature_location"),
            "hash": payload.get("hash"),
        }
        await self._upsert(credential_id, "document", "ISSUED", metadata, context)

    async def _handle_pkd_sync_completed(
        self, payload: dict[str, Any], key: str | None, context: MessageContext
    ) -> None:
        dataset = payload.get("dataset") or key or "pkd"
        metadata = {
            "force_refresh": payload.get("force_refresh"),
            "anchors": payload.get("anchors"),
        }
        await self._upsert(dataset, "pkd_sync", "SYNCED", metadata, context)

    async def _handle_trust_updated(
        self, payload: dict[str, Any], key: str | None, context: MessageContext
    ) -> None:
        entity = key or payload.get("entity")
        status = "TRUSTED" if payload.get("trusted") else "UNTRUSTED"
        metadata = {"version": payload.get("version")}
        await self._upsert(entity, "trust", status, metadata, context)


class CredentialLedgerService:
    """Kafka consumer that projects domain events into a ledger."""

    def __init__(
        self,
        database: DatabaseManager,
        event_config: EventBusConfig,
        topics: Iterable[str] | None = None,
    ) -> None:
        self._database = database
        self._event_config = event_config
        self._topics = list(topics or DEFAULT_LEDGER_TOPICS)
        self._topic_prefix = event_config.topic_prefix or ""
        self._consumer: AIOKafkaConsumer | None = None
        self._task: asyncio.Task[None] | None = None
        self._stopped = asyncio.Event()

        if not event_config.enabled or not event_config.brokers:
            logger.warning("Event bus disabled; credential ledger consumer will not start")
            return

        bootstrap_servers = event_config.brokers
        group_id = event_config.consumer_group or "credential-ledger"
        client_id = f"{event_config.client_id}-ledger"
        subscribe_topics = [self._apply_prefix(topic) for topic in self._topics]

        consumer_kwargs: dict[str, Any] = {
            "bootstrap_servers": bootstrap_servers,
            "group_id": group_id,
            "enable_auto_commit": False,
            "client_id": client_id,
            "auto_offset_reset": event_config.auto_offset_reset or "earliest",
        }
        security_protocol = (event_config.security_protocol or "PLAINTEXT").upper()
        consumer_kwargs["security_protocol"] = security_protocol
        if security_protocol == "SSL":
            consumer_kwargs["ssl_cafile"] = event_config.ssl_cafile
            consumer_kwargs["ssl_certfile"] = event_config.ssl_certfile
            consumer_kwargs["ssl_keyfile"] = event_config.ssl_keyfile

        self._consumer = AIOKafkaConsumer(*subscribe_topics, **consumer_kwargs)

    def _apply_prefix(self, topic: str) -> str:
        if self._topic_prefix and not topic.startswith(self._topic_prefix):
            return f"{self._topic_prefix}{topic}"
        return topic

    def _strip_prefix(self, topic: str) -> str:
        if self._topic_prefix and topic.startswith(self._topic_prefix):
            return topic[len(self._topic_prefix) :]
        return topic

    async def start(self) -> None:
        if self._consumer is None:
            self._stopped.set()
            return
        if self._task is not None and not self._task.done():
            return
        await self._consumer.start()
        self._stopped.clear()
        self._task = asyncio.create_task(self._consume_loop(), name="credential-ledger-consumer")

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None
        if self._consumer is not None:
            await self._consumer.stop()
        self._stopped.set()

    async def _consume_loop(self) -> None:
        assert self._consumer is not None
        try:
            async for message in self._consumer:
                await self._handle_message(message)
        except asyncio.CancelledError:
            raise
        except Exception:  # pragma: no cover - defensive logging
            logger.exception("Credential ledger consumer loop crashed")
        finally:
            self._stopped.set()

    async def wait_until_stopped(self) -> None:
        await self._stopped.wait()

    async def _handle_message(self, message) -> None:
        assert self._consumer is not None
        topic = self._strip_prefix(message.topic)
        key = None
        if message.key is not None:
            try:
                key = message.key.decode("utf-8")
            except UnicodeDecodeError:
                key = message.key.hex()
        try:
            payload = json.loads(message.value.decode("utf-8"))
        except json.JSONDecodeError:
            payload = {"raw": message.value.decode("utf-8", errors="replace")}

        context = MessageContext(topic=topic, partition=message.partition, offset=message.offset)

        async with self._database.session_scope() as session:
            repository = CredentialLedgerRepository(session)
            await repository.record_event(
                topic=topic,
                payload=payload,
                key=key,
                partition=message.partition,
                offset=message.offset,
            )
            processor = CredentialLedgerProcessor(repository, logger)
            await processor.process(topic, payload, key, context)

        await self._consumer.commit()
