"""Error handling utilities for Marty services."""

from .handlers import (
    ErrorContext,
    ErrorHandler,
    MartyCertificateError,
    MartyConfigurationError,
    MartyDatabaseError,
    MartyError,
    MartyNetworkError,
    MartyServiceError,
    MartyValidationError,
    handle_certificate_errors,
    handle_database_errors,
    handle_grpc_errors,
)

__all__ = [
    "ErrorContext",
    "ErrorHandler",
    "MartyCertificateError",
    "MartyConfigurationError",
    "MartyDatabaseError",
    "MartyError",
    "MartyNetworkError",
    "MartyServiceError",
    "MartyValidationError",
    "handle_certificate_errors",
    "handle_database_errors",
    "handle_grpc_errors",
]
