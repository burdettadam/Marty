"""Error handling utilities for the Document Signer service."""

from __future__ import annotations

from proto import document_signer_pb2


def create_error(
    code: int,
    message: str,
    *,
    details: dict[str, str] | None = None,
) -> document_signer_pb2.ApiError:
    """Create a standardized API error response.

    Args:
        code: Error code from document_signer_pb2
        message: Human-readable error message
        details: Optional dictionary of additional error details

    Returns:
        ApiError protobuf message
    """
    detail_payload = {key: str(value) for key, value in (details or {}).items()}
    return document_signer_pb2.ApiError(code=code, message=message, details=detail_payload)


def create_invalid_argument_error(
    message: str, details: dict[str, str] | None = None
) -> document_signer_pb2.ApiError:
    """Create an invalid argument error."""
    return create_error(
        document_signer_pb2.DOCUMENT_SIGNER_ERROR_INVALID_ARGUMENT,
        message,
        details=details,
    )


def create_not_configured_error(
    message: str = "SD-JWT issuance is not configured",
) -> document_signer_pb2.ApiError:
    """Create a not configured error."""
    return create_error(
        document_signer_pb2.DOCUMENT_SIGNER_ERROR_NOT_CONFIGURED,
        message,
    )


def create_signing_failed_error(
    message: str, details: dict[str, str] | None = None
) -> document_signer_pb2.ApiError:
    """Create a signing failed error."""
    return create_error(
        document_signer_pb2.DOCUMENT_SIGNER_ERROR_SIGNING_FAILED,
        message,
        details=details,
    )


def create_offer_not_found_error(
    message: str = "Credential offer not found",
    details: dict[str, str] | None = None,
) -> document_signer_pb2.ApiError:
    """Create an offer not found error."""
    return create_error(
        document_signer_pb2.DOCUMENT_SIGNER_ERROR_OFFER_NOT_FOUND,
        message,
        details=details,
    )


def create_expired_error(
    message: str, details: dict[str, str] | None = None
) -> document_signer_pb2.ApiError:
    """Create an expired error."""
    return create_error(
        document_signer_pb2.DOCUMENT_SIGNER_ERROR_EXPIRED,
        message,
        details=details,
    )


def create_conflict_error(
    message: str, details: dict[str, str] | None = None
) -> document_signer_pb2.ApiError:
    """Create a conflict error."""
    return create_error(
        document_signer_pb2.DOCUMENT_SIGNER_ERROR_CONFLICT,
        message,
        details=details,
    )


def create_token_invalid_error(
    message: str, details: dict[str, str] | None = None
) -> document_signer_pb2.ApiError:
    """Create a token invalid error."""
    return create_error(
        document_signer_pb2.DOCUMENT_SIGNER_ERROR_TOKEN_INVALID,
        message,
        details=details,
    )
