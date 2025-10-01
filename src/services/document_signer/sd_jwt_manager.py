"""SD-JWT credential management for the Document Signer service."""

from __future__ import annotations

import json
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from marty_common.infrastructure.repositories import (
    CredentialLedgerRepository,
    OidcSessionRepository,
    SdJwtCredentialRepository,
)
from marty_common.vc import (
    CredentialOffer,
    CredentialOfferGrant,
    CredentialOfferGrantPreAuthorizedCode,
    SdJwtConfig,
    SdJwtIssuanceInput,
    SdJwtIssuer,
)

if TYPE_CHECKING:
    from marty_common.infrastructure import DatabaseManager, KeyVaultClient, ObjectStorageClient


class SdJwtManager:
    """Manages SD-JWT credential operations for the Document Signer service."""

    def __init__(
        self,
        database: DatabaseManager,
        key_vault: KeyVaultClient,
        object_storage: ObjectStorageClient,
        certificate_chain_provider,
        config: SdJwtConfig,
        offer_ttl: timedelta,
        token_ttl: timedelta,
        default_credential_type: str,
    ) -> None:
        self.logger = logging.getLogger(__name__)
        self._database = database
        self._key_vault = key_vault
        self._object_storage = object_storage
        self._config = config
        self._offer_ttl = offer_ttl
        self._token_ttl = token_ttl
        self._default_credential_type = default_credential_type

        self._issuer = SdJwtIssuer(
            key_vault,
            certificate_chain_provider,
            config,
        )

    async def create_credential_offer(
        self,
        subject_id: str,
        credential_type: str | None,
        base_claims: dict,
        selective_disclosures: dict,
        metadata: dict | None = None,
    ) -> tuple[str, dict, str, int]:
        """Create a new credential offer.

        Returns:
            Tuple of (offer_id, offer_dict, pre_authorized_code, expires_in_seconds)
        """
        credential_type = credential_type or self._default_credential_type
        now = datetime.now(timezone.utc)
        expires_at = now + self._offer_ttl
        offer_id = secrets.token_urlsafe(16)
        pre_authorized_code = secrets.token_urlsafe(24)

        credentials_entry = {
            "format": "vc+sd-jwt",
            "types": [credential_type],
        }
        configuration_ids = None
        if isinstance(metadata, dict):
            configuration_ids = metadata.get("credential_configuration_ids")
            if configuration_ids is not None and not isinstance(configuration_ids, list):
                configuration_ids = None

        offer = CredentialOffer(
            credential_issuer=self._config.issuer,
            credentials=[credentials_entry],
            grants=CredentialOfferGrant(
                pre_authorized_code=CredentialOfferGrantPreAuthorizedCode(
                    pre_authorized_code=pre_authorized_code,
                    user_pin_required=False,
                )
            ),
            credential_configuration_ids=configuration_ids,
            session_id=offer_id,
        )
        offer_dict = offer.to_dict()

        async def handler(session) -> None:
            repo = OidcSessionRepository(session)
            await repo.create_offer(
                offer_id=offer_id,
                subject_id=subject_id,
                credential_type=credential_type,
                base_claims=base_claims,
                selective_disclosures=selective_disclosures,
                offer_payload=offer_dict,
                pre_authorized_code=pre_authorized_code,
                expires_at=expires_at,
                metadata=metadata or {},
            )

        await self._database.run_within_transaction(handler)

        expires_in = int((expires_at - now).total_seconds())
        return offer_id, offer_dict, pre_authorized_code, expires_in

    async def get_credential_offer(self, offer_id: str) -> tuple[dict, int, str] | None:
        """Get a credential offer by ID.

        Returns:
            Tuple of (offer_dict, expires_in_seconds, pre_auth_code) or None if not found
        """

        async def handler(session):
            repo = OidcSessionRepository(session)
            return await repo.get_by_offer_id(offer_id)

        record = await self._database.run_within_transaction(handler)
        if record is None:
            return None

        expires_in = int(
            max(
                0,
                (
                    record.pre_authorized_code_expires_at - datetime.now(timezone.utc)
                ).total_seconds(),
            )
        )
        metadata = record.extra_metadata or {}
        internal = metadata.get("_internal", {}) if isinstance(metadata, dict) else {}
        pre_auth_code = (
            internal.get("pre_authorized_code", "") if isinstance(internal, dict) else ""
        )

        return record.offer_payload or {}, expires_in, pre_auth_code

    async def redeem_pre_authorized_code(
        self, pre_authorized_code: str, wallet_attestation: str | None = None
    ) -> tuple[str, str, int, str] | None:
        """Redeem a pre-authorized code for an access token.

        Returns:
            Tuple of (offer_id, access_token, expires_in_seconds, c_nonce) or None if invalid
        """
        now = datetime.now(timezone.utc)
        access_token = secrets.token_urlsafe(32)
        c_nonce = secrets.token_urlsafe(16)
        token_expires_at = now + self._token_ttl

        async def handler(session):
            repo = OidcSessionRepository(session)
            return await repo.get_by_pre_authorized_code(pre_authorized_code)

        record = await self._database.run_within_transaction(handler)
        if record is None or record.pre_authorized_code_expires_at < now:
            return None

        async def update_handler(session) -> bool:
            repo = OidcSessionRepository(session)
            refreshed = await repo.get_by_offer_id(record.offer_id)
            if refreshed is None:
                return False
            await repo.attach_access_token(
                refreshed,
                access_token=access_token,
                expires_at=token_expires_at,
                nonce=c_nonce,
                wallet_attestation=wallet_attestation,
            )
            return True

        updated = await self._database.run_within_transaction(update_handler)
        if not updated:
            return None

        expires_in = int((token_expires_at - now).total_seconds())
        return record.offer_id, access_token, expires_in, c_nonce

    async def issue_sd_jwt_credential(
        self,
        access_token: str,
        disclose_claims: list[str] | None = None,
        audience: str | None = None,
        nonce: str | None = None,
        wallet_attestation: str | None = None,
    ) -> tuple[str, list[str], str, int, str, str, str, str, str, str] | None:
        """Issue an SD-JWT credential.

        Returns:
            Tuple of (token, disclosures, credential_id, expires_in, format,
                     sd_jwt_location, disclosures_location, issuer, credential_type, subject_id)
            or None if invalid
        """
        now = datetime.now(timezone.utc)

        async def load_session(session):
            repo = OidcSessionRepository(session)
            return await repo.get_by_access_token(access_token)

        session_record = await self._database.run_within_transaction(load_session)
        if (
            session_record is None
            or session_record.access_token_expires_at is None
            or session_record.access_token_expires_at < now
        ):
            return None

        if session_record.nonce and nonce and nonce != session_record.nonce:
            return None

        disclose_claims = disclose_claims or list(session_record.selective_disclosures.keys())
        disclosures_map = {
            key: value
            for key, value in session_record.selective_disclosures.items()
            if key in disclose_claims
        }

        issuance_input = SdJwtIssuanceInput(
            subject_id=session_record.subject_id,
            credential_type=session_record.credential_type,
            base_claims=session_record.base_claims,
            selective_disclosures=disclosures_map,
            audience=audience or None,
            nonce=nonce or session_record.nonce,
            additional_payload=(session_record.offer_payload or {}).get("vc", {}),
        )

        issuance_result = await self._issuer.issue(issuance_input)

        # Store the artifacts (this would typically use a storage manager)
        # For now, including the storage logic here to match the original implementation
        base_path = f"sd-jwt/{issuance_result.credential_id}"
        token_key = f"{base_path}.sdjwt"
        disclosures_key = f"{base_path}-disclosures.json"

        await self._object_storage.put_object(
            token_key,
            issuance_result.token.encode("utf-8"),
            content_type="application/sd-jwt",
        )
        disclosures_payload = json.dumps({"disclosures": issuance_result.disclosures}).encode(
            "utf-8"
        )
        await self._object_storage.put_object(
            disclosures_key,
            disclosures_payload,
            content_type="application/json",
        )

        # Persist to database and send events
        event_payload = {
            "credential_id": issuance_result.credential_id,
            "credential_type": session_record.credential_type,
            "format": "vc+sd-jwt",
            "subject_id": session_record.subject_id,
            "issuer": issuance_result.issuer,
            "payload_location": token_key,
            "disclosures_location": disclosures_key,
            "expires_at": issuance_result.expires_at.isoformat(),
        }

        async def persist(session) -> None:
            from marty_common.infrastructure import OutboxRepository

            sd_repo = SdJwtCredentialRepository(session)
            await sd_repo.create(
                credential_id=issuance_result.credential_id,
                subject_id=session_record.subject_id,
                credential_type=session_record.credential_type,
                issuer=issuance_result.issuer,
                audience=issuance_result.audience,
                sd_jwt_location=token_key,
                disclosures_location=disclosures_key,
                expires_at=issuance_result.expires_at,
                metadata=session_record.extra_metadata,
                wallet_attestation=wallet_attestation,
            )

            sessions = OidcSessionRepository(session)
            refreshed = await sessions.get_by_offer_id(session_record.offer_id)
            if refreshed:
                await sessions.mark_issued(refreshed)

            ledger = CredentialLedgerRepository(session)
            await ledger.upsert_entry(
                credential_id=issuance_result.credential_id,
                credential_type=session_record.credential_type,
                status="ISSUED",
                metadata={
                    "issuer": issuance_result.issuer,
                    "subject_id": session_record.subject_id,
                    "payload_location": token_key,
                    "disclosures_location": disclosures_key,
                },
                topic="vc.issued",
                offset=None,
            )

            outbox = OutboxRepository(session)
            await outbox.enqueue(
                topic="vc.issued",
                payload=json.dumps(event_payload).encode("utf-8"),
                key=issuance_result.credential_id.encode("utf-8"),
            )

        await self._database.run_within_transaction(persist)

        expires_in = int((issuance_result.expires_at - now).total_seconds())
        return (
            issuance_result.token,
            issuance_result.disclosures,
            issuance_result.credential_id,
            expires_in,
            "vc+sd-jwt",
            token_key,
            disclosures_key,
            issuance_result.issuer,
            session_record.credential_type,
            session_record.subject_id,
        )
