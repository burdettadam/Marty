# Marty Cryptography Implementation

This document summarizes the production-grade cryptography now implemented in the `marty_common.crypto` module.

## Key Algorithms

Supported key algorithms:
- RSA (>= 2048 bits) for RS256 / RS384 / RS512 signatures (PKCS#1 v1.5)
- ECDSA P-256 / P-384 / P-521 for ES256 / ES384 / ES512 signatures (ECDSA with respective SHA hash)

Key generation returns PEM encoded keys (PKCS8 private, SubjectPublicKeyInfo public) to promote interoperability.

## Signatures

`sign_data(data, private_key_pem, algorithm)` and `verify_signature(data, signature, public_key_pem, algorithm)` implement secure signing using the `cryptography` package.

Legacy fallback: if a public key is not PEM and its length is 32 or 64 bytes, verification falls back to the historical (insecure) scheme `sha256(data + public_key)` strictly to avoid breaking legacy test fixtures. This path should be removed once all components are migrated to real key material.

## Password Hashing

`hash_password` and `verify_password` use `bcrypt` when available; they fall back to **insecure** SHA-256 only in constrained test environments. Production deployments must ensure `bcrypt` is installed.

## Base64 and Hash Utilities

Helper functions provide safe wrappers for hashing and encoding. Invalid base64 inputs raise `ValueError` with proper chaining.

## Migration Notes

1. Replace any storage of previous random 32-byte keys with PEM encoded keys.
2. Update any integration tests that depended on deterministic `sha256(data + public_key)` signature derivation to supply real key pairs or mark them for migration.
3. Plan removal of the legacy fallback by a future release (e.g., set a deprecation warning and remove after 2 minor versions).

## Future Hardening

- Consider switching RSA signatures to RSASSA-PSS where interoperable.
- Add certificate chain validation integration points (X.509) feeding into `verify_signature`.
- Introduce hardware security module (HSM) abstraction for key operations.
- Enforce FIPS-approved curves / key sizes via configuration toggle.

## Security Checklist

- [x] No use of `os.urandom` for deriving public keys
- [x] Real asymmetric key generation via `cryptography`
- [x] Signatures use standard primitives (PKCS#1 v1.5 / ECDSA)
- [x] Backward compatibility layer isolated and clearly marked
- [ ] Legacy fallback removal scheduled

## Disclaimer

The legacy fallback MUST NOT be relied upon in production. Ensure all production key material is PEM encoded and generated via `generate_key_pair`.
