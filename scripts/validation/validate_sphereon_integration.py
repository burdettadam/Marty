#!/usr/bin/env python3
"""
Simple validation script to test Sphereon OIDC4VC integration dependencies.
"""

import sys
from pathlib import Path


def test_imports():
    """Test if all required OIDC4VC dependencies can be imported."""
    print("Testing OIDC4VC integration dependencies...")

    tests = [
        ("httpx", "HTTP client for OIDC4VC requests"),
        ("jwcrypto", "JWT/JWK cryptographic operations"),
        ("responses", "HTTP response mocking for tests"),
        ("pytest", "Testing framework"),
    ]

    all_passed = True

    for module, description in tests:
        try:
            __import__(module)
            print(f"✓ {module}: {description}")
        except ImportError as e:
            print(f"✗ {module}: Failed to import - {e}")
            all_passed = False

    return all_passed


def test_jwcrypto_functionality():
    """Test basic jwcrypto functionality for OIDC4VC."""
    print("\nTesting jwcrypto functionality...")

    try:
        from jwcrypto import jwk, jwt

        # Generate a test key
        key = jwk.JWK.generate(kty="EC", crv="P-256")
        print("✓ JWK key generation")

        # Create a simple JWT
        token = jwt.JWT(header={"alg": "ES256"}, claims={"test": "claim"})
        token.make_signed_token(key)
        print("✓ JWT creation and signing")

        # Verify the token
        jwt.JWT(jwt=token.serialize(), key=key)
        print("✓ JWT verification")

        return True

    except Exception as e:
        print(f"✗ jwcrypto functionality test failed: {e}")
        return False


def test_integration_test_file():
    """Check if the integration test file exists and is valid."""
    print("\nTesting integration test file...")

    test_file = Path("tests/integration/test_sphereon_oidc4vc_integration.py")

    if not test_file.exists():
        print(f"✗ Test file not found: {test_file}")
        return False

    print(f"✓ Test file exists: {test_file}")

    # Check if file has basic content
    try:
        content = test_file.read_text()
        if "TestSphereonOIDC4VCIntegration" in content:
            print("✓ Test classes found in file")
        else:
            print("✗ Expected test classes not found")
            return False

        if "pytest.mark.oidc4vc" in content:
            print("✓ OIDC4VC test markers found")
        else:
            print("✗ OIDC4VC test markers not found")
            return False

        return True

    except Exception as e:
        print(f"✗ Failed to read test file: {e}")
        return False


def main():
    """Main validation function."""
    print("Sphereon OIDC4VC Integration Validation")
    print("=" * 50)

    tests = [
        ("Import Tests", test_imports),
        ("jwcrypto Functionality", test_jwcrypto_functionality),
        ("Integration Test File", test_integration_test_file),
    ]

    all_passed = True

    for test_name, test_func in tests:
        print(f"\n{test_name}:")
        print("-" * len(test_name))
        if not test_func():
            all_passed = False

    print("\n" + "=" * 50)
    if all_passed:
        print("✓ All validation tests passed!")
        print("\nNext steps:")
        print(
            "1. Run integration tests: uv run pytest tests/integration/test_sphereon_oidc4vc_integration.py -v"
        )
        print("2. Start your Marty services and test OIDC4VC endpoints")
        print("3. Review the SPHEREON_OIDC4VC_INTEGRATION.md documentation")
        return True
    else:
        print("✗ Some validation tests failed. Please check the output above.")
        print("\nTo fix issues:")
        print("1. Run: uv sync")
        print("2. Ensure all dependencies are installed")
        print("3. Check that test files are in the correct location")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
