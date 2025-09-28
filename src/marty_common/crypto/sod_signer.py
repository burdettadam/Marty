"""Utilities to create and verify Document Security Objects (SOD)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Mapping, Sequence

from asn1crypto import algos as asn1_algos, cms as asn1_cms, core as asn1_core, x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from src.marty_common.models.asn1_structures import (
    DataGroupHash,
    DataGroupHashValues,
    LDSSecurityObject,
    SOD,
)

_HASH_OIDS: Mapping[str, str] = {
    "sha1": "1.3.14.3.2.26",
    "sha224": "2.16.840.1.101.3.4.2.4",
    "sha256": "2.16.840.1.101.3.4.2.1",
    "sha384": "2.16.840.1.101.3.4.2.2",
    "sha512": "2.16.840.1.101.3.4.2.3",
}


def _hash_cls_from_name(name: str):
    mapping = {
        "sha1": hashes.SHA1,
        "sha224": hashes.SHA224,
        "sha256": hashes.SHA256,
        "sha384": hashes.SHA384,
        "sha512": hashes.SHA512,
    }
    return mapping.get(name.lower())


def build_lds_security_object(
    data_group_hashes: Mapping[int, bytes], hash_algorithm: hashes.HashAlgorithm
) -> LDSSecurityObject:
    """Construct an LDS Security Object from data group hashes."""

    algorithm_name = hash_algorithm.name.lower()
    if algorithm_name not in _HASH_OIDS:
        msg = f"Unsupported hash algorithm for SOD: {algorithm_name}"
        raise ValueError(msg)

    dg_hash_values = DataGroupHashValues(
        DataGroupHash(
            {
                "dataGroupNumber": dg_number,
                "dataGroupHashValue": hash_value,
            }
        )
        for dg_number, hash_value in sorted(data_group_hashes.items())
    )

    return LDSSecurityObject(
        {
            "version": 0,
            "hashAlgorithm": {"algorithm": _HASH_OIDS[algorithm_name]},
            "dataGroupHashValues": dg_hash_values,
        }
    )


def create_sod(
    data_group_hashes: Mapping[int, bytes],
    private_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
    certificate: x509.Certificate,
    hash_algorithm: hashes.HashAlgorithm | None = None,
) -> bytes:
    """Create a signed SOD blob from data groups."""

    hash_algorithm = hash_algorithm or hashes.SHA256()
    lds = build_lds_security_object(data_group_hashes, hash_algorithm)
    lds_der = lds.dump()
    algorithm_name = hash_algorithm.name.lower()

    digest_algorithm = asn1_algos.DigestAlgorithm({"algorithm": _HASH_OIDS[algorithm_name]})

    hash_ctx = hashes.Hash(hash_algorithm)
    hash_ctx.update(lds_der)
    digest_value = hash_ctx.finalize()

    signing_time = asn1_core.UTCTime(datetime.now(timezone.utc))

    signed_attrs = asn1_cms.CMSAttributes(
        [
            asn1_cms.CMSAttribute({"type": "content_type", "values": ["data"]}),
            asn1_cms.CMSAttribute({"type": "message_digest", "values": [digest_value]}),
            asn1_cms.CMSAttribute({"type": "signing_time", "values": [signing_time]}),
        ]
    )

    signature_input = signed_attrs.dump(force=True)

    if isinstance(private_key, rsa.RSAPrivateKey):
        signature_algorithm = asn1_algos.SignedDigestAlgorithm({"algorithm": f"{algorithm_name}_rsa"})

        def sign_payload(payload: bytes) -> bytes:
            return private_key.sign(payload, padding.PKCS1v15(), hash_algorithm)

    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        signature_algorithm = asn1_algos.SignedDigestAlgorithm({"algorithm": f"{algorithm_name}_ecdsa"})

        def sign_payload(payload: bytes) -> bytes:
            return private_key.sign(payload, ec.ECDSA(hash_algorithm))

    else:  # pragma: no cover - defensive
        msg = "Unsupported private key type for SOD signing"
        raise ValueError(msg)

    asn1_cert = asn1_x509.Certificate.load(
        certificate.public_bytes(serialization.Encoding.DER)
    )

    signer_info = asn1_cms.SignerInfo(
        {
            "version": 1,
            "sid": asn1_cms.SignerIdentifier(
                {
                    "issuer_and_serial_number": asn1_cms.IssuerAndSerialNumber(
                        {
                            "issuer": asn1_cert.issuer,
                            "serial_number": asn1_cert.serial_number,
                        }
                    )
                }
            ),
            "digest_algorithm": digest_algorithm,
            "signed_attrs": signed_attrs,
            "signature_algorithm": signature_algorithm,
            "signature": b"",
        }
    )

    signature_input = signer_info["signed_attrs"].dump()
    signature = sign_payload(signature_input)
    signer_info["signature"] = signature

    signed_data = asn1_cms.SignedData(
        {
            "version": 3,
            "digest_algorithms": [digest_algorithm],
            "encap_content_info": {
                "content_type": "data",
                "content": lds_der,
            },
            "certificates": [asn1_cert],
            "signer_infos": [signer_info],
        }
    )

    content_info = asn1_cms.ContentInfo(
        {
            "content_type": "signed_data",
            "content": signed_data,
        }
    )

    return content_info.dump()


def verify_sod_signature(
    sod_bytes: bytes,
    trusted_certificates: Sequence[x509.Certificate] | None = None,
) -> bool:
    """Verify SOD signature against the provided trust anchors."""

    sod = SOD.load(sod_bytes)
    signer_infos = sod.signed_data["signer_infos"]

    if not signer_infos:
        return False

    signer_info = signer_infos[0]
    signed_attrs = signer_info["signed_attrs"]
    signature = signer_info["signature"].native
    algorithm = signer_info["digest_algorithm"]["algorithm"].native

    hash_cls = _hash_cls_from_name(algorithm)
    if hash_cls is None:
        msg = f"Unsupported digest algorithm: {algorithm}"
        raise ValueError(msg)

    certificates = list(trusted_certificates or [])
    if not certificates:
        certificate = sod.get_certificate()
        if certificate is None:
            return False
        certificates.append(x509.load_der_x509_certificate(certificate.dump()))

    if signed_attrs:
        data = signed_attrs.dump(force=True)
    else:
        content = sod.signed_data["encap_content_info"]["content"].native
        data = content if isinstance(content, bytes) else bytes(content)

    for certificate in certificates:
        public_key = certificate.public_key()

        try:
            if isinstance(public_key, rsa.RSAPublicKey):
                public_key.verify(signature, data, padding.PKCS1v15(), hash_cls())
                return True
            if isinstance(public_key, ec.EllipticCurvePublicKey):
                public_key.verify(signature, data, ec.ECDSA(hash_cls()))
                return True
        except Exception:  # pragma: no cover - verification failure handled below
            continue

    return False


def load_sod(sod_bytes: bytes) -> SOD:
    """Parse SOD document into ASN.1 structure."""

    return SOD.load(sod_bytes)
