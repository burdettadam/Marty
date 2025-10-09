#!/usr/bin/env python3
"""
Script to generate ES256 keys for Marty development environment.
"""

import sys
from pathlib import Path
from typing import NoReturn

# Add the project root to the path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.shared.services.key_management_service import KeyManagementService, KeyType, KeyUsage


def main() -> NoReturn:
    """Generate ES256 keys for document signer."""
    print("Generating ES256 key for document-signer-sdjwt...")

    # Initialize the key management service
    kms = KeyManagementService()

    # Generate ES256 key for SD-JWT signing
    key_info = kms.generate_key(
        key_id="document-signer-sdjwt",
        key_type=KeyType.EC,
        key_usage=KeyUsage.DOCUMENT_SIGNING,
        curve_name="secp256r1",  # ES256 uses secp256r1
        metadata={"service": "document-signer", "algorithm": "ES256", "purpose": "sd-jwt-signing"},
    )

    print(f"Generated key: {key_info}")
    print("ES256 key generation complete!")
    sys.exit(0)


if __name__ == "__main__":
    main()
