#!/usr/bin/env python3
"""
Setup and validation script for OpenID4VP mDoc/mDL integration tests.

This script ensures all dependencies are properly installed and services
are configured for running comprehensive OpenID4VP presentation tests.
"""

import asyncio
import json
import subprocess
import sys
from pathlib import Path


async def check_dependencies():
    """Check if required dependencies are installed."""
    print("🔍 Checking OpenID4VP test dependencies...")

    required_packages = [
        "httpx",
        "pytest",
        "pytest-asyncio",
        "jwcrypto",
        "responses",
        "cbor2",
        "cose",
        "grpcio",
        "grpcio-tools",
    ]

    missing_packages = []

    for package in required_packages:
        try:
            result = subprocess.run(
                [sys.executable, "-c", f"import {package.replace('-', '_')}"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                print(f"  ✅ {package}")
            else:
                missing_packages.append(package)
                print(f"  ❌ {package}")
        except Exception as e:
            missing_packages.append(package)
            print(f"  ❌ {package} - {e}")

    return missing_packages


def install_missing_packages(packages):
    """Install missing packages using uv."""
    if not packages:
        print("✅ All dependencies are installed!")
        return True

    print(f"📦 Installing missing packages: {', '.join(packages)}")

    try:
        # Use uv to install packages
        cmd = ["uv", "add"] + packages
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode == 0:
            print("✅ Successfully installed missing packages!")
            return True
        else:
            print(f"❌ Failed to install packages: {result.stderr}")
            return False
    except Exception as e:
        print(f"❌ Error installing packages: {e}")
        return False


def check_grpc_services():
    """Check if required gRPC services are available."""
    print("🔍 Checking gRPC service availability...")

    services = [
        {"name": "mDoc Engine", "port": 8081},
        {"name": "mDL Engine", "port": 8085},
        {"name": "Document Signer", "port": 8086},
    ]

    available_services = []
    unavailable_services = []

    for service in services:
        try:
            # Simple port check (in real implementation, you'd do a proper gRPC health check)
            import socket

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex(("localhost", service["port"]))
                if result == 0:
                    available_services.append(service)
                    print(f"  ✅ {service['name']} (port {service['port']})")
                else:
                    unavailable_services.append(service)
                    print(f"  ❌ {service['name']} (port {service['port']})")
        except Exception as e:
            unavailable_services.append(service)
            print(f"  ❌ {service['name']} - {e}")

    return available_services, unavailable_services


def validate_test_configuration():
    """Validate test configuration and pytest setup."""
    print("🔍 Validating test configuration...")

    # Check if pyproject.toml has the required markers
    pyproject_path = Path("pyproject.toml")
    if not pyproject_path.exists():
        print("  ❌ pyproject.toml not found")
        return False

    try:
        with open(pyproject_path) as f:
            content = f.read()

        required_markers = ["openid4vp", "mdoc_presentation", "mdl_presentation"]

        for marker in required_markers:
            if marker in content:
                print(f"  ✅ pytest marker '{marker}' configured")
            else:
                print(f"  ❌ pytest marker '{marker}' missing")

        return True
    except Exception as e:
        print(f"  ❌ Error reading pyproject.toml: {e}")
        return False


def run_test_collection():
    """Run pytest collection to ensure tests are discoverable."""
    print("🔍 Running test collection...")

    try:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "tests/integration/test_mdoc_mdl_openid4vp_integration.py",
                "--collect-only",
                "-q",
            ],
            capture_output=True,
            text=True,
        )

        if result.returncode == 0:
            # Count collected tests
            lines = result.stdout.strip().split("\n")
            collected_line = [line for line in lines if "collected" in line and "test" in line]
            if collected_line:
                print(f"  ✅ {collected_line[0]}")
            else:
                print("  ✅ Tests collected successfully")
            return True
        else:
            print(f"  ❌ Test collection failed: {result.stderr}")
            return False
    except Exception as e:
        print(f"  ❌ Error during test collection: {e}")
        return False


def create_test_data_fixtures():
    """Create test data fixtures for OpenID4VP tests."""
    print("🔍 Creating test data fixtures...")

    fixtures_dir = Path("tests/fixtures/openid4vp")
    fixtures_dir.mkdir(parents=True, exist_ok=True)

    # Create sample presentation definition
    presentation_definition = {
        "id": "sample_mdl_presentation",
        "input_descriptors": [
            {
                "id": "mdl_driving_privileges",
                "format": {"mso_mdoc": {"alg": ["ES256", "ES384", "ES512"]}},
                "constraints": {
                    "fields": [
                        {"path": ["$.driving_privileges"], "purpose": "Verify driving privileges"},
                        {"path": ["$.license_number"], "purpose": "Verify license number"},
                    ]
                },
            }
        ],
    }

    fixtures = {
        "sample_presentation_definition.json": presentation_definition,
        "test_config.json": {
            "base_url": "http://localhost:8000",
            "mdoc_service_url": "localhost:8081",
            "mdl_service_url": "localhost:8085",
            "timeout": 60,
        },
    }

    for filename, data in fixtures.items():
        fixture_path = fixtures_dir / filename
        try:
            with open(fixture_path, "w") as f:
                json.dump(data, f, indent=2)
            print(f"  ✅ Created {filename}")
        except Exception as e:
            print(f"  ❌ Failed to create {filename}: {e}")

    return True


async def main():
    """Main setup and validation function."""
    print("🚀 OpenID4VP mDoc/mDL Integration Test Setup")
    print("=" * 50)

    success = True

    # 1. Check and install dependencies
    missing_deps = await check_dependencies()
    if missing_deps:
        if not install_missing_packages(missing_deps):
            success = False

    print()

    # 2. Check gRPC services
    available, unavailable = check_grpc_services()
    if unavailable:
        print(f"\n⚠️  Warning: {len(unavailable)} services unavailable")
        print("   Run the following to start services:")
        print("   docker-compose up mdoc-engine mdl-engine document-signer")

    print()

    # 3. Validate test configuration
    if not validate_test_configuration():
        success = False

    print()

    # 4. Run test collection
    if not run_test_collection():
        success = False

    print()

    # 5. Create test fixtures
    create_test_data_fixtures()

    print()
    print("=" * 50)

    if success:
        print("✅ Setup completed successfully!")
        print("\nTo run OpenID4VP integration tests:")
        print("pytest tests/integration/test_mdoc_mdl_openid4vp_integration.py -m openid4vp -v")
        print("\nTo run specific test categories:")
        print("pytest -m mdoc_presentation -v")
        print("pytest -m mdl_presentation -v")
    else:
        print("❌ Setup encountered issues. Please resolve them before running tests.")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
