"""Key vault abstraction with a file-backed development implementation."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, Union

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa

# Type alias for private key types
PrivateKeyTypes = Union[
    rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey
]


class KeyVaultClient(Protocol):
    async def ensure_key(self, key_id: str, algorithm: str) -> None: ...

    async def sign(self, key_id: str, payload: bytes, algorithm: str) -> bytes: ...

    async def public_material(self, key_id: str) -> bytes: ...

    async def store_private_key(self, key_id: str, pem: bytes) -> None: ...

    async def load_private_key(self, key_id: str) -> bytes: ...


@dataclass(slots=True)
class KeyVaultConfig:
    provider: str
    file_path: str | None = None
    hsm_config_path: str | None = None

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> KeyVaultConfig:
        return cls(
            provider=raw.get("provider", "file"),
            file_path=raw.get("file_path", "data/keys"),
            hsm_config_path=raw.get("hsm_config_path"),
        )


class FileKeyVaultClient(KeyVaultClient):
    """Stores private keys on disk for non-production environments."""

    def __init__(self, base_path: str) -> None:
        self._path = Path(base_path)
        self._path.mkdir(parents=True, exist_ok=True)

    async def ensure_key(self, key_id: str, algorithm: str) -> None:
        key_file = self._path / f"{key_id}.pem"
        if key_file.exists():
            return
        private_key = self._generate_key_material(algorithm)
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        await self.store_private_key(key_id, pem)

    def _generate_key_material(self, algorithm: str) -> PrivateKeyTypes:
        key_algorithm = algorithm.lower()
        if key_algorithm.startswith("rsa"):
            key_size = int(key_algorithm.replace("rsa", "") or 2048)
            return rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        if key_algorithm.startswith("ecdsa"):
            curve_map = {
                "p256": ec.SECP256R1(),
                "p384": ec.SECP384R1(),
                "p521": ec.SECP521R1(),
            }
            curve_name = key_algorithm.replace("ecdsa-", "") or "p256"
            curve = curve_map.get(curve_name, ec.SECP256R1())
            return ec.generate_private_key(curve)
        if key_algorithm.startswith(("ed", "eddsa")):
            if "448" in key_algorithm:
                return ed448.Ed448PrivateKey.generate()
            return ed25519.Ed25519PrivateKey.generate()
        msg = f"Unsupported key algorithm: {algorithm}"
        raise ValueError(msg)

    async def sign(self, key_id: str, payload: bytes, algorithm: str) -> bytes:
        private_key = await asyncio.to_thread(self._load_private_key, key_id)
        algo = algorithm.lower()
        if algo.startswith("rsa"):
            hash_alg = hashes.SHA256()
            signature = await asyncio.to_thread(
                lambda: private_key.sign(payload, padding.PKCS1v15(), hash_alg)
            )
            return bytes(signature)
        if algo.startswith("ecdsa"):
            hash_alg = hashes.SHA256()
            signature = await asyncio.to_thread(
                lambda: private_key.sign(payload, ec.ECDSA(hash_alg))
            )
            return bytes(signature)
        if algo.startswith(("ed", "eddsa")):
            signature = await asyncio.to_thread(lambda: private_key.sign(payload))
            return bytes(signature)
        msg = f"Unsupported signing algorithm: {algorithm}"
        raise ValueError(msg)

    async def public_material(self, key_id: str) -> bytes:
        private_key = await asyncio.to_thread(self._load_private_key, key_id)
        public_key = private_key.public_key()
        return await asyncio.to_thread(
            lambda: public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    async def store_private_key(self, key_id: str, pem: bytes) -> None:
        key_file = self._path / f"{key_id}.pem"
        await asyncio.to_thread(key_file.write_bytes, pem)

    async def load_private_key(self, key_id: str) -> bytes:
        key_file = self._path / f"{key_id}.pem"
        if not key_file.exists():
            msg = f"Key {key_id} not found"
            raise FileNotFoundError(msg)
        return await asyncio.to_thread(key_file.read_bytes)

    def _load_private_key(self, key_id: str) -> Any:
        key_file = self._path / f"{key_id}.pem"
        if not key_file.exists():
            msg = f"Key {key_id} not found"
            raise FileNotFoundError(msg)
        data = key_file.read_bytes()
        return serialization.load_pem_private_key(data, password=None)


def build_key_vault_client(config: KeyVaultConfig) -> KeyVaultClient:
    provider = config.provider.lower()
    if provider == "file":
        if not config.file_path:
            msg = "file_path is required for file key vault provider"
            raise ValueError(msg)
        return FileKeyVaultClient(config.file_path)
    msg = f"Provider {config.provider} is not implemented yet"
    raise NotImplementedError(msg)
