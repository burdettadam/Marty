"""
HashiCorp Vault integration for Trust Service.

This module provides secure secrets management, certificate storage,
and dynamic credential handling using HashiCorp Vault.
"""

import asyncio
import json
import logging
import os
import ssl
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union

import hvac
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from hvac.exceptions import InvalidPath, VaultError

logger = logging.getLogger(__name__)


class VaultConnectionError(Exception):
    """Raised when Vault connection fails."""

    pass


class VaultSecretError(Exception):
    """Raised when secret operations fail."""

    pass


class VaultCertificateError(Exception):
    """Raised when certificate operations fail."""

    pass


class TrustServiceVaultClient:
    """
    Vault client specifically designed for Trust Service operations.

    Provides secure storage and retrieval of:
    - Database credentials
    - API keys and tokens
    - TLS certificates and private keys
    - PKI certificate authorities
    - Encryption keys
    """

    def __init__(
        self,
        vault_url: str,
        vault_token: str | None = None,
        vault_role_id: str | None = None,
        vault_secret_id: str | None = None,
        vault_namespace: str | None = None,
        vault_ca_cert: str | None = None,
        verify_ssl: bool = True,
        mount_point_kv: str = "kv",
        mount_point_pki: str = "pki",
        timeout: int = 30,
    ):
        """
        Initialize Vault client.

        Args:
            vault_url: Vault server URL
            vault_token: Direct auth token (for development)
            vault_role_id: AppRole role ID for production auth
            vault_secret_id: AppRole secret ID for production auth
            vault_namespace: Vault namespace (for Vault Enterprise)
            vault_ca_cert: Path to Vault CA certificate
            verify_ssl: Whether to verify SSL certificates
            mount_point_kv: KV secrets engine mount point
            mount_point_pki: PKI secrets engine mount point
            timeout: Request timeout in seconds
        """
        self.vault_url = vault_url
        self.vault_namespace = vault_namespace
        self.mount_point_kv = mount_point_kv
        self.mount_point_pki = mount_point_pki
        self.timeout = timeout

        # Initialize Vault client
        self.client = hvac.Client(
            url=vault_url,
            namespace=vault_namespace,
            timeout=timeout,
            verify=vault_ca_cert if vault_ca_cert else verify_ssl,
        )

        # Store auth credentials
        self.vault_token = vault_token
        self.vault_role_id = vault_role_id
        self.vault_secret_id = vault_secret_id

        # Authentication state
        self._authenticated = False
        self._token_expiry: datetime | None = None

    async def connect(self) -> None:
        """Establish connection and authenticate with Vault."""
        try:
            # Check if Vault is accessible
            if not self.client.sys.is_initialized():
                raise VaultConnectionError("Vault is not initialized")

            if self.client.sys.is_sealed():
                raise VaultConnectionError("Vault is sealed")

            # Authenticate
            await self._authenticate()

            logger.info("Successfully connected to Vault")

        except Exception as e:
            logger.error(f"Failed to connect to Vault: {e}")
            raise VaultConnectionError(f"Vault connection failed: {e}")

    async def _authenticate(self) -> None:
        """Authenticate with Vault using available methods."""
        if self.vault_token:
            # Direct token authentication (development)
            self.client.token = self.vault_token
            if not self.client.is_authenticated():
                raise VaultConnectionError("Invalid Vault token")
            self._authenticated = True
            logger.info("Authenticated with Vault using direct token")

        elif self.vault_role_id and self.vault_secret_id:
            # AppRole authentication (production)
            try:
                response = self.client.auth.approle.login(
                    role_id=self.vault_role_id, secret_id=self.vault_secret_id
                )

                self.client.token = response["auth"]["client_token"]
                self._authenticated = True

                # Calculate token expiry
                lease_duration = response["auth"].get("lease_duration", 3600)
                self._token_expiry = datetime.utcnow() + timedelta(seconds=lease_duration)

                logger.info("Authenticated with Vault using AppRole")

            except Exception as e:
                raise VaultConnectionError(f"AppRole authentication failed: {e}")
        else:
            raise VaultConnectionError("No valid authentication method provided")

    async def _ensure_authenticated(self) -> None:
        """Ensure we have a valid authentication token."""
        if not self._authenticated:
            await self._authenticate()
            return

        # Check token expiry
        if self._token_expiry and datetime.utcnow() >= self._token_expiry - timedelta(minutes=5):
            logger.info("Vault token expiring soon, re-authenticating")
            await self._authenticate()

    async def get_secret(self, path: str, key: str | None = None) -> dict[str, Any] | Any:
        """
        Retrieve a secret from Vault KV store.

        Args:
            path: Secret path (e.g., "trust-service/database")
            key: Specific key to retrieve (optional)

        Returns:
            Secret data or specific key value
        """
        await self._ensure_authenticated()

        try:
            response = self.client.secrets.kv.v2.read_secret_version(
                path=path, mount_point=self.mount_point_kv
            )

            secret_data = response["data"]["data"]

            if key:
                if key not in secret_data:
                    raise VaultSecretError(f"Key '{key}' not found in secret at path '{path}'")
                return secret_data[key]

            return secret_data

        except InvalidPath:
            raise VaultSecretError(f"Secret not found at path: {path}")
        except VaultError as e:
            raise VaultSecretError(f"Failed to retrieve secret: {e}")

    async def set_secret(self, path: str, secret_data: dict[str, Any]) -> None:
        """
        Store a secret in Vault KV store.

        Args:
            path: Secret path
            secret_data: Secret data to store
        """
        await self._ensure_authenticated()

        try:
            self.client.secrets.kv.v2.create_or_update_secret(
                path=path, secret=secret_data, mount_point=self.mount_point_kv
            )

            logger.info(f"Successfully stored secret at path: {path}")

        except VaultError as e:
            raise VaultSecretError(f"Failed to store secret: {e}")

    async def delete_secret(self, path: str) -> None:
        """Delete a secret from Vault KV store."""
        await self._ensure_authenticated()

        try:
            self.client.secrets.kv.v2.delete_metadata_and_all_versions(
                path=path, mount_point=self.mount_point_kv
            )

            logger.info(f"Successfully deleted secret at path: {path}")

        except VaultError as e:
            raise VaultSecretError(f"Failed to delete secret: {e}")

    async def get_database_credentials(self, role_name: str = "trust-service") -> dict[str, str]:
        """
        Get dynamic database credentials from Vault.

        Args:
            role_name: Database role name

        Returns:
            Dictionary with username and password
        """
        await self._ensure_authenticated()

        try:
            response = self.client.secrets.database.generate_credentials(name=role_name)

            return {
                "username": response["data"]["username"],
                "password": response["data"]["password"],
                "lease_id": response["lease_id"],
                "lease_duration": response["lease_duration"],
            }

        except VaultError as e:
            raise VaultSecretError(f"Failed to generate database credentials: {e}")

    async def get_certificate(self, cert_name: str) -> dict[str, str]:
        """
        Retrieve a certificate from Vault.

        Args:
            cert_name: Certificate identifier

        Returns:
            Dictionary with certificate, private key, and CA chain
        """
        await self._ensure_authenticated()

        try:
            # Try to get from KV store first
            cert_data = await self.get_secret(f"certificates/{cert_name}")

            required_fields = ["certificate", "private_key"]
            for field in required_fields:
                if field not in cert_data:
                    raise VaultCertificateError(f"Missing required field '{field}' in certificate")

            return cert_data

        except VaultSecretError:
            # Try PKI engine if not in KV store
            try:
                response = self.client.secrets.pki.read_certificate(
                    serial_number=cert_name, mount_point=self.mount_point_pki
                )

                return {
                    "certificate": response["data"]["certificate"],
                    "ca_chain": response["data"].get("ca_chain", []),
                }

            except VaultError as e:
                raise VaultCertificateError(f"Failed to retrieve certificate: {e}")

    async def store_certificate(
        self,
        cert_name: str,
        certificate: str,
        private_key: str | None = None,
        ca_chain: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """
        Store a certificate in Vault.

        Args:
            cert_name: Certificate identifier
            certificate: PEM-encoded certificate
            private_key: PEM-encoded private key (optional)
            ca_chain: List of CA certificates (optional)
            metadata: Additional metadata (optional)
        """
        cert_data = {
            "certificate": certificate,
            "created_at": datetime.utcnow().isoformat(),
        }

        if private_key:
            cert_data["private_key"] = private_key

        if ca_chain:
            cert_data["ca_chain"] = ca_chain

        if metadata:
            cert_data["metadata"] = metadata

        await self.set_secret(f"certificates/{cert_name}", cert_data)
        logger.info(f"Stored certificate: {cert_name}")

    async def generate_certificate(
        self,
        common_name: str,
        alt_names: list[str] | None = None,
        ttl: str = "24h",
        role_name: str = "trust-service",
    ) -> dict[str, str]:
        """
        Generate a new certificate using Vault PKI.

        Args:
            common_name: Certificate common name
            alt_names: Alternative names (optional)
            ttl: Certificate TTL (e.g., "24h", "30d")
            role_name: PKI role name

        Returns:
            Dictionary with certificate, private key, and CA chain
        """
        await self._ensure_authenticated()

        try:
            request_data = {"common_name": common_name, "ttl": ttl}

            if alt_names:
                request_data["alt_names"] = ",".join(alt_names)

            response = self.client.secrets.pki.generate_certificate(
                name=role_name, extra_params=request_data, mount_point=self.mount_point_pki
            )

            cert_data = {
                "certificate": response["data"]["certificate"],
                "private_key": response["data"]["private_key"],
                "ca_chain": response["data"].get("ca_chain", []),
                "serial_number": response["data"]["serial_number"],
            }

            # Store certificate in KV for easier retrieval
            await self.store_certificate(
                cert_name=f"generated-{common_name}",
                **cert_data,
                metadata={
                    "generated_at": datetime.utcnow().isoformat(),
                    "ttl": ttl,
                    "role": role_name,
                },
            )

            logger.info(f"Generated certificate for: {common_name}")
            return cert_data

        except VaultError as e:
            raise VaultCertificateError(f"Failed to generate certificate: {e}")

    async def revoke_certificate(self, serial_number: str) -> None:
        """
        Revoke a certificate using Vault PKI.

        Args:
            serial_number: Certificate serial number
        """
        await self._ensure_authenticated()

        try:
            self.client.secrets.pki.revoke_certificate(
                serial_number=serial_number, mount_point=self.mount_point_pki
            )

            logger.info(f"Revoked certificate: {serial_number}")

        except VaultError as e:
            raise VaultCertificateError(f"Failed to revoke certificate: {e}")

    async def rotate_secret(self, path: str, generator_func: callable) -> None:
        """
        Rotate a secret using a generator function.

        Args:
            path: Secret path
            generator_func: Function that generates new secret data
        """
        try:
            # Generate new secret
            new_secret = generator_func()

            # Store new secret
            await self.set_secret(path, new_secret)

            logger.info(f"Successfully rotated secret at: {path}")

        except Exception as e:
            logger.error(f"Failed to rotate secret at {path}: {e}")
            raise VaultSecretError(f"Secret rotation failed: {e}")

    async def get_encryption_key(self, key_name: str) -> bytes:
        """
        Retrieve an encryption key from Vault.

        Args:
            key_name: Key identifier

        Returns:
            Encryption key bytes
        """
        try:
            key_data = await self.get_secret(f"encryption-keys/{key_name}", "key")

            if isinstance(key_data, str):
                # Assume base64 encoded
                import base64

                return base64.b64decode(key_data)

            return key_data

        except Exception as e:
            raise VaultSecretError(f"Failed to retrieve encryption key: {e}")

    async def get_jwt_signing_key(self) -> dict[str, str]:
        """Get JWT signing key pair from Vault."""
        try:
            return await self.get_secret("jwt/signing-key")
        except VaultSecretError:
            # Generate new key pair if not exists
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import rsa

            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode("utf-8")

            public_pem = (
                private_key.public_key()
                .public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                .decode("utf-8")
            )

            key_data = {
                "private_key": private_pem,
                "public_key": public_pem,
                "created_at": datetime.utcnow().isoformat(),
            }

            await self.set_secret("jwt/signing-key", key_data)
            logger.info("Generated new JWT signing key pair")

            return key_data

    async def close(self) -> None:
        """Close Vault connection and cleanup."""
        if hasattr(self.client, "close"):
            self.client.close()

        self._authenticated = False
        self._token_expiry = None

        logger.info("Closed Vault connection")


def create_vault_client_from_config(config: dict[str, Any]) -> TrustServiceVaultClient:
    """
    Create Vault client from configuration.

    Args:
        config: Configuration dictionary

    Returns:
        Configured Vault client
    """
    vault_config = config.get("vault", {})

    return TrustServiceVaultClient(
        vault_url=vault_config.get("url", os.getenv("VAULT_ADDR", "http://localhost:8200")),
        vault_token=vault_config.get("token", os.getenv("VAULT_TOKEN")),
        vault_role_id=vault_config.get("role_id", os.getenv("VAULT_ROLE_ID")),
        vault_secret_id=vault_config.get("secret_id", os.getenv("VAULT_SECRET_ID")),
        vault_namespace=vault_config.get("namespace", os.getenv("VAULT_NAMESPACE")),
        vault_ca_cert=vault_config.get("ca_cert", os.getenv("VAULT_CACERT")),
        verify_ssl=vault_config.get("verify_ssl", True),
        mount_point_kv=vault_config.get("mount_point_kv", "kv"),
        mount_point_pki=vault_config.get("mount_point_pki", "pki"),
        timeout=vault_config.get("timeout", 30),
    )


# Global Vault client instance
_vault_client: TrustServiceVaultClient | None = None


async def get_vault_client() -> TrustServiceVaultClient:
    """Get or create global Vault client instance."""
    global _vault_client

    if _vault_client is None:
        from config import get_config

        config = get_config()
        _vault_client = create_vault_client_from_config(config)
        await _vault_client.connect()

    return _vault_client


async def initialize_vault() -> None:
    """Initialize Vault connection for the application."""
    await get_vault_client()
    logger.info("Vault client initialized")


async def cleanup_vault() -> None:
    """Cleanup Vault connection."""
    global _vault_client

    if _vault_client:
        await _vault_client.close()
        _vault_client = None

    logger.info("Vault client cleaned up")
