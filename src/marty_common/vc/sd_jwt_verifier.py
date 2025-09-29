"""Verification helpers for SD-JWT based verifiable credentials."""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Sequence

import jwt
from cryptography import x509

from src.marty_common.crypto.certificate_validator import CertificateChainValidator
from src.marty_common.vc.sd_jwt import _b64url_encode

LOGGER = logging.getLogger(__name__)


def _decode_x5c_entry(entry: str) -> x509.Certificate:
    padding = '=' * ((4 - len(entry) % 4) % 4)
    der_bytes = base64.b64decode(entry + padding)
    return x509.load_der_x509_certificate(der_bytes)


@dataclass(slots=True)
class SdJwtVerificationResult:
    """Outcome of SD-JWT verification."""

    valid: bool
    payload: dict[str, Any]
    disclosures: dict[str, Any]
    errors: list[str]
    warnings: list[str]
    certificate_subject: str | None = None


class SdJwtVerifier:
    """Verifier for SD-JWT credentials using x5c header chains."""

    def __init__(
        self,
        trust_anchors: Iterable[x509.Certificate] | None = None,
        wallet_trust_anchors: Iterable[x509.Certificate] | None = None,
    ) -> None:
        self._token_validator = CertificateChainValidator()
        if trust_anchors:
            self._token_validator.load_csca_certificates(list(trust_anchors))
        self._wallet_validator = CertificateChainValidator()
        if wallet_trust_anchors:
            self._wallet_validator.load_csca_certificates(list(wallet_trust_anchors))

    def verify(
        self,
        token: str,
        disclosures: Sequence[str],
        *,
        wallet_attestation: str | None = None,
    ) -> SdJwtVerificationResult:
        errors: list[str] = []
        warnings: list[str] = []
        disclosed_claims: dict[str, Any] = {}
        payload: dict[str, Any] = {}
        certificate_subject: str | None = None

        try:
            header = jwt.get_unverified_header(token)
        except jwt.exceptions.InvalidTokenError as exc:
            return SdJwtVerificationResult(
                valid=False,
                payload={},
                disclosures={},
                errors=[f"Invalid JWT header: {exc}"],
                warnings=[],
            )

        x5c_entries = header.get("x5c") or []
        if not x5c_entries:
            errors.append("Missing x5c header with signer certificate chain")
            return SdJwtVerificationResult(False, {}, {}, errors, warnings)

        try:
            certificates = [_decode_x5c_entry(entry) for entry in x5c_entries]
        except (ValueError, base64.binascii.Error) as exc:
            errors.append(f"Unable to parse x5c certificates: {exc}")
            return SdJwtVerificationResult(False, {}, {}, errors, warnings)

        signer_cert = certificates[0]
        certificate_subject = signer_cert.subject.rfc4514_string()

        chain_result = self._token_validator.validate_certificate_chain(
            signer_cert,
            certificates[1:],
        )
        if not chain_result.is_valid:
            chain_errors = [err.error_message for err in chain_result.errors if err.is_critical]
            errors.extend(chain_errors or ["Certificate chain validation failed"])

        algorithm = header.get("alg", "ES256")
        try:
            payload = jwt.decode(
                token,
                signer_cert.public_key(),
                algorithms=[algorithm],
                options={"require": ["iss", "exp"], "verify_aud": False},
            )
        except jwt.exceptions.InvalidTokenError as exc:
            errors.append(f"Invalid SD-JWT signature: {exc}")
            return SdJwtVerificationResult(False, {}, {}, errors, warnings, certificate_subject)

        now_ts = int(time.time())
        if payload.get("nbf") and payload["nbf"] > now_ts:
            errors.append("Credential not yet valid (nbf in future)")
        if payload.get("exp") and payload["exp"] < now_ts:
            errors.append("Credential expired")

        issuer = payload.get("iss")
        if issuer and not self._issuer_matches_certificate(issuer, signer_cert):
            errors.append("Issuer does not match certificate subject alternative names")

        sd_hashes = set(payload.get("_sd", []))
        subject_obj = payload.get("vc", {}).get("credentialSubject", {})
        subject_hashes = set(subject_obj.get("_sd", []))

        for encoded in disclosures:
            try:
                padding = '=' * ((4 - len(encoded) % 4) % 4)
                decoded_bytes = base64.urlsafe_b64decode(encoded + padding)
                disclosure_data = json.loads(decoded_bytes.decode("utf-8"))
            except (ValueError, json.JSONDecodeError) as exc:
                errors.append(f"Invalid disclosure payload: {exc}")
                continue
            if not isinstance(disclosure_data, list) or len(disclosure_data) != 3:
                errors.append("Disclosure must be a list of [salt, claim, value]")
                continue
            _, claim_name, claim_value = disclosure_data
            digest = _b64url_encode(self._hash_disclosure(decoded_bytes))
            if digest not in sd_hashes and digest not in subject_hashes:
                errors.append(f"Disclosure for '{claim_name}' not referenced in SD-JWT payload")
                continue
            disclosed_claims[claim_name] = claim_value

        if sd_hashes and not disclosed_claims:
            warnings.append("No disclosures provided for selectively disclosable claims")

        loa = (payload.get("vc", {}) or {}).get("level_of_assurance")
        if loa is None:
            loa = (payload.get("vc", {}) or {}).get("loa")
        if isinstance(loa, str) and loa.lower() not in {"high", "substantial"}:
            warnings.append(f"Level of assurance '{loa}' is below eIDAS High")

        if wallet_attestation:
            attestation_errors = self._verify_wallet_attestation(wallet_attestation)
            errors.extend(attestation_errors)

        valid = not errors
        return SdJwtVerificationResult(
            valid=valid,
            payload=payload,
            disclosures=disclosed_claims,
            errors=errors,
            warnings=warnings,
            certificate_subject=certificate_subject,
        )

    @staticmethod
    def _hash_disclosure(disclosure_bytes: bytes) -> bytes:
        return hashlib.sha256(disclosure_bytes).digest()

    @staticmethod
    def _issuer_matches_certificate(issuer: str, certificate: x509.Certificate) -> bool:
        try:
            san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        except x509.ExtensionNotFound:
            return False
        names = san.value.get_values_for_type(x509.DNSName)
        names += san.value.get_values_for_type(x509.UniformResourceIdentifier)
        return issuer in names

    def _verify_wallet_attestation(self, attestation: str) -> list[str]:
        errors: list[str] = []
        try:
            header = jwt.get_unverified_header(attestation)
            chain = [
                _decode_x5c_entry(entry)
                for entry in header.get("x5c", [])
            ]
            if not chain:
                return ["Wallet attestation missing x5c chain"]
            public_cert = chain[0]
            if self._wallet_validator.get_trust_anchors():
                chain_result = self._wallet_validator.validate_certificate_chain(public_cert, chain[1:])
                if not chain_result.is_valid:
                    critical = [err.error_message for err in chain_result.errors if err.is_critical]
                    errors.extend(critical or ["Wallet attestation certificate chain invalid"])
            jwt.decode(
                attestation,
                public_cert.public_key(),
                algorithms=[header.get("alg", "ES256")],
                options={"verify_aud": False},
            )
        except jwt.exceptions.InvalidTokenError as exc:
            errors.append(f"Wallet attestation signature invalid: {exc}")
        except (ValueError, base64.binascii.Error) as exc:
            errors.append(f"Wallet attestation x5c parsing failed: {exc}")
        return errors


__all__ = ["SdJwtVerifier", "SdJwtVerificationResult"]
