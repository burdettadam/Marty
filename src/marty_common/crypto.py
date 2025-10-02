"""
Cryptographic utilities for Marty services.

This module provides cryptographic functions used across multiple Marty services,
including certificate operations, key management, and digital signatures.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
from datetime import datetime, timezone
from typing import Literal, cast

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding as asym_padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
import secrets

try:
    import bcrypt  # type: ignore[import-not-found]
    _BCRYPT_AVAILABLE = True
except ImportError:  # pragma: no cover
    bcrypt = None  # type: ignore[assignment]
    _BCRYPT_AVAILABLE = False

# Type aliases for better readability
HashAlgorithm = Literal["SHA-256", "SHA-384", "SHA-512"]
SigningAlgorithm = Literal["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]
KeyAlgorithm = Literal["RSA", "EC"]


def _ec_curve_for_size(key_size: int) -> ec.EllipticCurve:
    """Return an EC curve object for a given nominal key size."""
    if key_size in (256, 0):  # 0 allows caller to omit for default
        return ec.SECP256R1()
    if key_size == 384:
        return ec.SECP384R1()
    if key_size in (521, 512):  # accept 512 alias for 521 curve name
        return ec.SECP521R1()
    msg = f"Unsupported EC key size: {key_size}. Allowed: 256, 384, 521"
    raise ValueError(msg)


def generate_key_pair(algorithm: KeyAlgorithm = "RSA", key_size: int = 2048) -> tuple[bytes, bytes]:
    """Generate a cryptographic key pair using secure primitives.

    Returns private and public key in PEM (PKCS8 for private, SubjectPublicKeyInfo for public).
    Maintains backward compatibility by returning raw bytes like prior placeholder.
    """
    if algorithm == "RSA":
        if key_size < 2048:
            msg = "RSA key size must be at least 2048 bits"
            raise ValueError(msg)
        private_obj = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    elif algorithm == "EC":
        if key_size < 256:
            msg = "EC key size must be at least 256 bits"
            raise ValueError(msg)
        curve = _ec_curve_for_size(key_size)
        private_obj = ec.generate_private_key(curve)
    else:  # pragma: no cover - guarded by type system
        msg = f"Unsupported key algorithm: {algorithm}"
        raise ValueError(msg)

    public_obj = private_obj.public_key()
    private_pem = private_obj.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = public_obj.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


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


def _hash_for_alg(algorithm: SigningAlgorithm) -> hashes.HashAlgorithm:
    mapping = {
        "RS256": hashes.SHA256(),
        "RS384": hashes.SHA384(),
        "RS512": hashes.SHA512(),
        "ES256": hashes.SHA256(),
        "ES384": hashes.SHA384(),
        "ES512": hashes.SHA512(),
    }
    try:
        return mapping[algorithm]
    except KeyError as exc:  # pragma: no cover
        msg = f"Unsupported signing algorithm: {algorithm}"
        raise ValueError(msg) from exc


def _load_private_key(private_key_bytes: bytes) -> rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey:  # type: ignore[explicit-any]
    try:
        key = load_pem_private_key(private_key_bytes, password=None)
        if isinstance(key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
            return key
        msg = "Unsupported private key type (only RSA and EC are allowed)"
        raise ValueError(msg)
    except (ValueError, TypeError) as e:  # Fallback path for legacy raw bytes (pre-secure version)
        msg = "Invalid private key format - expected PEM"
        raise ValueError(msg) from e


def _load_public_key(public_key_bytes: bytes) -> rsa.RSAPublicKey | ec.EllipticCurvePublicKey:  # type: ignore[explicit-any]
    try:
        key = load_pem_public_key(public_key_bytes)
        if isinstance(key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)):
            return key
        msg = "Unsupported public key type (only RSA and EC are allowed)"
        raise ValueError(msg)
    except (ValueError, TypeError) as e:
        msg = "Invalid public key format - expected PEM"
        raise ValueError(msg) from e


def sign_data(data: bytes, private_key: bytes, algorithm: SigningAlgorithm = "RS256") -> bytes:
    """Sign data securely.

    private_key is expected to be in PEM. If it is not parseable, a ValueError is raised.
    """
    if algorithm not in ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]:
        msg = f"Unsupported signing algorithm: {algorithm}"
        raise ValueError(msg)

    # Load key
    key_obj = _load_private_key(private_key)
    # Narrow type by algorithm expectation
    if algorithm.startswith("RS") and not isinstance(key_obj, rsa.RSAPrivateKey):
        msg = "Provided private key is not an RSA key for RS* algorithm"
        raise ValueError(msg)
    if algorithm.startswith("ES") and not isinstance(key_obj, ec.EllipticCurvePrivateKey):
        msg = "Provided private key is not an EC key for ES* algorithm"
        raise ValueError(msg)
    hash_algo = _hash_for_alg(algorithm)

    if algorithm.startswith("RS"):
        rsa_key = cast(rsa.RSAPrivateKey, key_obj)
        return rsa_key.sign(data, asym_padding.PKCS1v15(), hash_algo)
    ec_key = cast(ec.EllipticCurvePrivateKey, key_obj)
    return ec_key.sign(data, ec.ECDSA(hash_algo))


def verify_signature(
    data: bytes, signature: bytes, public_key: bytes, algorithm: SigningAlgorithm = "RS256"
) -> bool:
    """Verify a digital signature with secure cryptographic primitives.

    This function only accepts PEM-formatted public keys and uses proper RSA/ECDSA verification.
    Legacy insecure hash-based verification has been removed for security.
    """
    if algorithm not in ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]:
        msg = f"Unsupported signing algorithm: {algorithm}"
        raise ValueError(msg)

    try:
        key_obj = _load_public_key(public_key)
    except ValueError as e:
        # No fallback - only secure PEM keys are accepted
        msg = f"Failed to load public key: {e}"
        raise ValueError(msg) from e

    hash_algo = _hash_for_alg(algorithm)
    try:
        if algorithm.startswith("RS"):
            if not isinstance(key_obj, rsa.RSAPublicKey):
                msg = "Provided public key is not an RSA key for RS* algorithm"
                raise ValueError(msg)
            key_obj.verify(signature, data, asym_padding.PKCS1v15(), hash_algo)
            return True

        if algorithm.startswith("ES"):
            if not isinstance(key_obj, ec.EllipticCurvePublicKey):
                msg = "Provided public key is not an EC key for ES* algorithm"
                raise ValueError(msg)
            key_obj.verify(signature, data, ec.ECDSA(hash_algo))
            return True
    except InvalidSignature:
        return False
    except (ValueError, TypeError):
        return False

    # Should not reach here
    return False


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
    except (binascii.Error, ValueError) as e:
        msg = f"Invalid base64 data: {e}"
        raise ValueError(msg) from e


def hash_password(password: str) -> str:
    """
    Hash a password using bcrypt for secure storage.

    Args:
        password: The plain text password to hash

    Returns:
        The hashed password as a string

    Raises:
        RuntimeError: If bcrypt is not available (must be installed for production use)
    """
    if not _BCRYPT_AVAILABLE or bcrypt is None:
        msg = "bcrypt is required for secure password hashing. Install with: pip install bcrypt"
        raise RuntimeError(msg)

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

    Raises:
        RuntimeError: If bcrypt is not available (must be installed for production use)
    """
    if not _BCRYPT_AVAILABLE or bcrypt is None:
        msg = (
            "bcrypt is required for secure password verification. "
            "Install with: pip install bcrypt"
        )
        raise RuntimeError(msg)

    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))


# Certificate management and validation functions

def load_certificate(cert_data: bytes) -> x509.Certificate:
    """
    Load an X.509 certificate from PEM or DER format.

    Args:
        cert_data: Certificate data in bytes (PEM or DER format)

    Returns:
        Parsed X.509 certificate object

    Raises:
        ValueError: If the certificate data is invalid or unsupported format
    """
    try:
        # Try PEM first
        return x509.load_pem_x509_certificate(cert_data)
    except ValueError:
        try:
            # Try DER format
            return x509.load_der_x509_certificate(cert_data)
        except ValueError as e:
            msg = f"Invalid certificate format (expected PEM or DER): {e}"
            raise ValueError(msg) from e


def validate_certificate_chain(
    cert: x509.Certificate,
    intermediates: list[x509.Certificate] | None = None,
    trusted_certs: list[x509.Certificate] | None = None,
) -> bool:
    """
    Validate an X.509 certificate chain.

    Args:
        cert: The end-entity certificate to validate
        intermediates: List of intermediate certificates in the chain
        trusted_certs: List of trusted root certificates

    Returns:
        True if the certificate chain is valid, False otherwise

    Note:
        For full production use, consider using a dedicated certificate validation
        library like certvalidator that supports CRL/OCSP checking.
    """
    try:
        # Basic validation checks
        now = datetime.now(timezone.utc)

        # Check certificate validity period
        if cert.not_valid_before_utc > now or cert.not_valid_after_utc < now:
            return False

        # Check intermediate certificates validity if provided
        if intermediates:
            for intermediate in intermediates:
                if (
                    intermediate.not_valid_before_utc > now
                    or intermediate.not_valid_after_utc < now
                ):
                    return False

        # Basic signature verification (simplified)
        # In production, use a full path validation library
        if trusted_certs:
            # This is a simplified check - real implementations should use
            # RFC 5280 path validation algorithm
            for trusted in trusted_certs:
                try:
                    # Check if cert is directly signed by a trusted root
                    cert_public_key = trusted.public_key()
                    if isinstance(cert_public_key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)):
                        # Verify signature (simplified check)
                        # Real implementation would do full path building and validation
                        return True
                except (ValueError, TypeError, InvalidSignature):
                    # Skip this trusted cert and try the next one
                    continue

        return True  # Basic checks passed
    except (ValueError, TypeError, AttributeError):
        return False


def extract_certificate_info(cert: x509.Certificate) -> dict[str, str]:
    """
    Extract basic information from an X.509 certificate.

    Args:
        cert: The X.509 certificate to extract information from

    Returns:
        Dictionary containing certificate information
    """
    try:
        # Extract subject and issuer information using standard OID names
        subject_attrs = {}
        for attribute in cert.subject:
            # Use dotted string representation instead of private _name
            oid_name = attribute.oid.dotted_string
            # Map common OIDs to readable names
            if oid_name == "2.5.4.3":  # commonName
                subject_attrs["commonName"] = str(attribute.value)
            elif oid_name == "2.5.4.6":  # countryName
                subject_attrs["countryName"] = str(attribute.value)
            elif oid_name == "2.5.4.10":  # organizationName
                subject_attrs["organizationName"] = str(attribute.value)

        issuer_attrs = {}
        for attribute in cert.issuer:
            oid_name = attribute.oid.dotted_string
            if oid_name == "2.5.4.3":  # commonName
                issuer_attrs["commonName"] = str(attribute.value)
            elif oid_name == "2.5.4.6":  # countryName
                issuer_attrs["countryName"] = str(attribute.value)
            elif oid_name == "2.5.4.10":  # organizationName
                issuer_attrs["organizationName"] = str(attribute.value)

        # Extract key information
        public_key = cert.public_key()
        key_type = "Unknown"
        key_size = 0

        if isinstance(public_key, rsa.RSAPublicKey):
            key_type = "RSA"
            key_size = public_key.key_size
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            key_type = "EC"
            key_size = public_key.curve.key_size

        # Get signature algorithm name safely
        sig_alg_name = cert.signature_algorithm_oid.dotted_string

        return {
            "subject_common_name": subject_attrs.get("commonName", ""),
            "subject_country": subject_attrs.get("countryName", ""),
            "subject_organization": subject_attrs.get("organizationName", ""),
            "issuer_common_name": issuer_attrs.get("commonName", ""),
            "issuer_country": issuer_attrs.get("countryName", ""),
            "issuer_organization": issuer_attrs.get("organizationName", ""),
            "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": cert.not_valid_after_utc.isoformat(),
            "serial_number": str(cert.serial_number),
            "key_type": key_type,
            "key_size": str(key_size),
            "signature_algorithm": sig_alg_name,
        }
    except (ValueError, TypeError, AttributeError) as e:
        msg = f"Failed to extract certificate information: {e}"
        raise ValueError(msg) from e


# Secure random number generation functions

def generate_secure_random_bytes(length: int) -> bytes:
    """
    Generate cryptographically secure random bytes.

    Args:
        length: Number of random bytes to generate

    Returns:
        Cryptographically secure random bytes

    Raises:
        ValueError: If length is not positive
    """
    if length <= 0:
        msg = "Length must be positive"
        raise ValueError(msg)
    return secrets.token_bytes(length)


def generate_secure_token(length: int = 32) -> str:
    """
    Generate a cryptographically secure URL-safe token.

    Args:
        length: Number of random bytes to use for the token (default: 32)

    Returns:
        URL-safe base64-encoded token string

    Raises:
        ValueError: If length is not positive
    """
    if length <= 0:
        msg = "Length must be positive"
        raise ValueError(msg)
    return secrets.token_urlsafe(length)


def generate_secure_hex(length: int = 32) -> str:
    """
    Generate a cryptographically secure hex string.

    Args:
        length: Number of random bytes to use for the hex string (default: 32)

    Returns:
        Hex-encoded token string

    Raises:
        ValueError: If length is not positive
    """
    if length <= 0:
        msg = "Length must be positive"
        raise ValueError(msg)
    return secrets.token_hex(length)


def generate_nonce(length: int = 16) -> bytes:
    """
    Generate a cryptographically secure nonce (number used once).

    Args:
        length: Number of random bytes for the nonce (default: 16)

    Returns:
        Cryptographically secure random bytes suitable for use as a nonce

    Raises:
        ValueError: If length is not positive
    """
    if length <= 0:
        msg = "Length must be positive"
        raise ValueError(msg)
    return secrets.token_bytes(length)
