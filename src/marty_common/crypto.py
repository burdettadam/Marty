"""
Cryptographic utilities for Marty services.

This module provides cryptographic functions used across multiple Marty services,
including certificate operations, key management, and digital signatures.
"""

import base64
import hashlib
import os
from typing import Literal

try:
    import bcrypt  # type: ignore
except ImportError:  # pragma: no cover
    bcrypt = None  # type: ignore

# Type aliases for better readability
HashAlgorithm = Literal["SHA-256", "SHA-384", "SHA-512"]
SigningAlgorithm = Literal["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]
KeyAlgorithm = Literal["RSA", "EC"]


def generate_key_pair(algorithm: KeyAlgorithm = "RSA", key_size: int = 2048) -> tuple[bytes, bytes]:
    """
    Generate a cryptographic key pair.

    Args:
        algorithm: The algorithm to use ("RSA" or "EC")
        key_size: The key size in bits (must be >= 2048 for RSA, >= 256 for EC)

    Returns:
        A tuple of (private_key, public_key) as bytes

    Raises:
        ValueError: If key_size is too small for the algorithm
    """
    if algorithm == "RSA" and key_size < 2048:
        msg = "RSA key size must be at least 2048 bits"
        raise ValueError(msg)
    if algorithm == "EC" and key_size < 256:
        msg = "EC key size must be at least 256 bits"
        raise ValueError(msg)

    # This is a placeholder - in production, use a proper crypto library
    # such as cryptography.hazmat.primitives
    private_key = os.urandom(key_size // 8)
    # Derive public key (in real implementation, this would use the algorithm)
    public_key = hashlib.sha256(private_key).digest()

    return private_key, public_key


def generate_hash(data: str | bytes, algorithm: HashAlgorithm = "SHA-256") -> str:
    """
    Generate a hash of the provided data.

    Args:
        data: The data to hash (string or bytes)
        algorithm: The hash algorithm to use

    Returns:
        Hexadecimal string representation of the hash

    Raises:
        ValueError: If an unsupported algorithm is provided
    """
    if isinstance(data, str):
        data = data.encode("utf-8")

    if algorithm == "SHA-256":
        hash_obj = hashlib.sha256(data)
    elif algorithm == "SHA-384":
        hash_obj = hashlib.sha384(data)
    elif algorithm == "SHA-512":
        hash_obj = hashlib.sha512(data)
    else:
        msg = f"Unsupported hash algorithm: {algorithm}"
        raise ValueError(msg)

    return hash_obj.hexdigest()


def sign_data(data: bytes, private_key: bytes, algorithm: SigningAlgorithm = "RS256") -> bytes:
    """
    Sign data using the specified private key and algorithm.

    Args:
        data: The data to sign
        private_key: The private key to use for signing
        algorithm: The signing algorithm to use

    Returns:
        The signature as bytes

    Raises:
        ValueError: If the algorithm is not supported
    """
    if algorithm not in ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]:
        msg = f"Unsupported signing algorithm: {algorithm}"
        raise ValueError(msg)

    # Placeholder implementation - use proper crypto in production
    return hashlib.sha256(data + private_key).digest()


def verify_signature(
    data: bytes, signature: bytes, public_key: bytes, algorithm: SigningAlgorithm = "RS256"
) -> bool:
    """
    Verify a digital signature.

    Args:
        data: The data that was signed
        signature: The signature to verify
        public_key: The public key to use for verification
        algorithm: The signing algorithm used

    Returns:
        True if the signature is valid, False otherwise

    Raises:
        ValueError: If the algorithm is not supported
    """
    if algorithm not in ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]:
        msg = f"Unsupported signing algorithm: {algorithm}"
        raise ValueError(msg)

    # Placeholder implementation - use proper crypto in production
    expected_signature = hashlib.sha256(data + public_key).digest()
    return signature == expected_signature


def hash_data(data: bytes, algorithm: HashAlgorithm = "SHA-256") -> bytes:
    """
    Hash data using the specified algorithm.

    Args:
        data: The data to hash
        algorithm: The hashing algorithm to use

    Returns:
        The hash as bytes

    Raises:
        ValueError: If the algorithm is not supported
    """
    if algorithm == "SHA-256":
        return hashlib.sha256(data).digest()
    if algorithm == "SHA-384":
        return hashlib.sha384(data).digest()
    if algorithm == "SHA-512":
        return hashlib.sha512(data).digest()
    msg = f"Unsupported hashing algorithm: {algorithm}"
    raise ValueError(msg)


def encode_base64(data: bytes) -> str:
    """
    Encode binary data as base64.

    Args:
        data: The binary data to encode

    Returns:
        Base64-encoded string
    """
    return base64.b64encode(data).decode("ascii")


def decode_base64(data: str) -> bytes:
    """
    Decode base64 data to binary.

    Args:
        data: The base64-encoded string

    Returns:
        Decoded binary data

    Raises:
        ValueError: If the input is not valid base64
    """
    try:
        return base64.b64decode(data)
    except Exception as e:
        msg = f"Invalid base64 data: {e}"
        raise ValueError(msg)


def hash_password(password: str) -> str:
    """
    Hash a password using bcrypt for secure storage.

    Args:
        password: The plain text password to hash

    Returns:
        The hashed password as a string

    Note:
        Falls back to SHA-256 if bcrypt is not available (for testing only)
    """
    if bcrypt is None:
        # Very weak fallback for environments without bcrypt (tests may mock anyway)
        return base64.b64encode(hashlib.sha256(password.encode("utf-8")).digest()).decode("ascii")
    password_bytes = password.encode("utf-8")
    return bcrypt.hashpw(password_bytes, bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    """
    Verify a password against a bcrypt hash.

    Args:
        password: The plain text password to verify
        hashed: The hashed password to verify against

    Returns:
        True if the password matches the hash, False otherwise

    Note:
        Falls back to SHA-256 comparison if bcrypt is not available (for testing only)
    """
    if bcrypt is None:
        return (
            base64.b64encode(hashlib.sha256(password.encode("utf-8")).digest()).decode("ascii")
            == hashed
        )
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
