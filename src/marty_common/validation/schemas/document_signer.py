"""Pydantic request schemas for the Document Signer RPC surface."""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class SignDocumentRequestSchema(BaseModel):
    """Validation schema for the SignDocument RPC."""

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    document_id: str = Field(alias="document_id")
    document_content: bytes = Field(alias="document_content")

    @field_validator("document_id")
    @classmethod
    def _normalise_document_id(cls, value: str) -> str:
        value = (value or "").strip()
        if not value:
            raise ValueError("document_id is required")
        return value

    @field_validator("document_content")
    @classmethod
    def _ensure_payload(cls, value: bytes) -> bytes:
        if not value:
            raise ValueError("document_content must not be empty")
        return bytes(value)


class CreateCredentialOfferRequestSchema(BaseModel):
    """Validation schema for CreateCredentialOffer."""

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    subject_id: str = Field(alias="subject_id")
    credential_type: str | None = Field(alias="credential_type", default=None)
    base_claims: dict[str, Any] = Field(alias="base_claims_json")
    selective_disclosures: dict[str, Any] = Field(alias="selective_disclosures_json")
    metadata: dict[str, Any] | None = Field(default=None, alias="metadata_json")

    @field_validator("subject_id")
    @classmethod
    def _require_subject(cls, value: str) -> str:
        value = (value or "").strip()
        if not value:
            raise ValueError("subject_id is required")
        return value

    @field_validator("credential_type")
    @classmethod
    def _normalise_type(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        return value or None

    @field_validator("base_claims", "selective_disclosures", mode="before")
    @classmethod
    def _parse_json_object(cls, value: Any) -> dict[str, Any]:
        if value is None or value == "":
            raise ValueError("value must be a JSON object")
        if isinstance(value, dict):
            return value
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
            except json.JSONDecodeError as exc:  # pragma: no cover - defensive
                raise ValueError(f"Invalid JSON payload: {exc.msg}") from exc
            if not isinstance(parsed, dict):
                raise ValueError("value must decode to a JSON object")
            return parsed
        raise ValueError("value must be a JSON object")

    @field_validator("metadata", mode="before")
    @classmethod
    def _parse_optional_json(cls, value: Any) -> dict[str, Any] | None:
        if value in (None, ""):
            return None
        if isinstance(value, dict):
            return value
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
            except json.JSONDecodeError as exc:  # pragma: no cover - defensive
                raise ValueError(f"Invalid metadata JSON: {exc.msg}") from exc
            if not isinstance(parsed, dict):
                raise ValueError("metadata must decode to a JSON object")
            return parsed
        raise ValueError("metadata must be a JSON object if provided")


class GetCredentialOfferRequestSchema(BaseModel):
    """Validation schema for GetCredentialOffer."""

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    offer_id: str = Field(alias="offer_id")

    @field_validator("offer_id")
    @classmethod
    def _require_offer_id(cls, value: str) -> str:
        value = (value or "").strip()
        if not value:
            raise ValueError("offer_id is required")
        return value


class RedeemPreAuthorizedCodeRequestSchema(BaseModel):
    """Validation schema for RedeemPreAuthorizedCode."""

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    pre_authorized_code: str = Field(alias="pre_authorized_code")
    wallet_attestation: dict[str, Any] | None = Field(default=None, alias="wallet_attestation")

    @field_validator("pre_authorized_code")
    @classmethod
    def _require_code(cls, value: str) -> str:
        value = (value or "").strip()
        if not value:
            raise ValueError("pre_authorized_code is required")
        return value

    @field_validator("wallet_attestation", mode="before")
    @classmethod
    def _parse_wallet_attestation(cls, value: Any) -> dict[str, Any] | None:
        if value in (None, ""):
            return None
        if isinstance(value, dict):
            return value
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
            except json.JSONDecodeError as exc:  # pragma: no cover - defensive
                raise ValueError(f"Invalid wallet attestation JSON: {exc.msg}") from exc
            if not isinstance(parsed, dict):
                raise ValueError("wallet_attestation must decode to a JSON object")
            return parsed
        raise ValueError("wallet_attestation must be JSON if provided")


class IssueSdJwtCredentialRequestSchema(BaseModel):
    """Validation schema for IssueSdJwtCredential."""

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    access_token: str = Field(alias="access_token")
    disclose_claims: list[str] = Field(default_factory=list, alias="disclose_claims")
    audience: str | None = Field(default=None, alias="audience")
    nonce: str | None = Field(default=None, alias="nonce")
    wallet_attestation: dict[str, Any] | None = Field(default=None, alias="wallet_attestation")

    @field_validator("access_token")
    @classmethod
    def _require_access_token(cls, value: str) -> str:
        value = (value or "").strip()
        if not value:
            raise ValueError("access_token is required")
        return value

    @field_validator("disclose_claims", mode="before")
    @classmethod
    def _normalise_disclosures(cls, value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, (list, tuple)):
            return [str(item) for item in value if str(item).strip()]
        raise ValueError("disclose_claims must be a repeated string field")

    @field_validator("wallet_attestation", mode="before")
    @classmethod
    def _parse_optional_attestation(cls, value: Any) -> dict[str, Any] | None:
        if value in (None, ""):
            return None
        if isinstance(value, dict):
            return value
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
            except json.JSONDecodeError as exc:  # pragma: no cover - defensive
                raise ValueError(f"Invalid wallet attestation JSON: {exc.msg}") from exc
            if not isinstance(parsed, dict):
                raise ValueError("wallet_attestation must decode to a JSON object")
            return parsed
        raise ValueError("wallet_attestation must be JSON if provided")


__all__ = [
    "CreateCredentialOfferRequestSchema",
    "GetCredentialOfferRequestSchema",
    "IssueSdJwtCredentialRequestSchema",
    "RedeemPreAuthorizedCodeRequestSchema",
    "SignDocumentRequestSchema",
]
