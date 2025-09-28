"""TLS helpers for Marty gRPC services."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

import grpc


LOGGER = logging.getLogger(__name__)


def build_client_credentials(tls_options: dict[str, object]) -> Optional[grpc.ChannelCredentials]:
    """Create channel credentials for mTLS client connections."""

    ca_bytes = _read_file_if_exists(tls_options.get("client_ca"))
    cert_bytes = _read_file_if_exists(tls_options.get("client_cert"))
    key_bytes = _read_file_if_exists(tls_options.get("client_key"))

    if not ca_bytes and not cert_bytes and not key_bytes:
        LOGGER.warning("TLS enabled but no client credentials configured; defaulting to system CA")

    return grpc.ssl_channel_credentials(
        root_certificates=ca_bytes,
        private_key=key_bytes,
        certificate_chain=cert_bytes,
    )


def configure_server_security(
    server: grpc.Server, server_address: str, tls_options: dict[str, object]
) -> bool:
    """Add a secure port to the server if TLS is enabled.

    Returns True when a secure port was configured, False otherwise.
    """

    if not tls_options.get("enabled"):
        return False

    cert_bytes = _read_file_if_exists(tls_options.get("server_cert"))
    key_bytes = _read_file_if_exists(tls_options.get("server_key"))

    if not cert_bytes or not key_bytes:
        LOGGER.warning(
            "TLS enabled but server certificate/key missing; falling back to insecure channel"
        )
        return False

    require_client = bool(tls_options.get("require_client_auth"))
    ca_bytes = _read_file_if_exists(tls_options.get("client_ca")) if require_client else None

    credentials = grpc.ssl_server_credentials(
        [(key_bytes, cert_bytes)],
        root_certificates=ca_bytes,
        require_client_auth=require_client,
    )
    server.add_secure_port(server_address, credentials)
    LOGGER.info(
        "gRPC TLS enabled on %s (client auth=%s)",
        server_address,
        "required" if require_client else "optional",
    )
    return True


def _read_file_if_exists(path_value: object) -> Optional[bytes]:
    if not path_value:
        return None
    path = Path(str(path_value))
    if not path.exists():
        LOGGER.warning("TLS material not found at %s", path)
        return None
    return path.read_bytes()


__all__ = ["build_client_credentials", "configure_server_security"]
