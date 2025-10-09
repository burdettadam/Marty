#!/usr/bin/env python3
"""
Script to install and verify Sphereon OIDC4VC dependencies for integration testing.
"""

import importlib.util
import subprocess
import sys
from pathlib import Path


def check_dependency(package_name: str, import_name: str = None) -> bool:
    """Check if a dependency is installed and importable."""
    if import_name is None:
        import_name = package_name

    try:
        spec = importlib.util.find_spec(import_name.replace("-", "_"))
        if spec is not None:
            print(f"✓ {package_name} is installed and importable")
            return True
        else:
            print(f"✗ {package_name} is not importable")
            return False
    except ImportError:
        print(f"✗ {package_name} is not installed")
        return False


def install_dependencies() -> None:
    """Install the Sphereon OIDC4VC dependencies using uv."""
    print("Installing Sphereon OIDC4VC dependencies using uv...")

    try:
        print("Running uv sync to install dependencies...")
        result = subprocess.run(["uv", "sync"], capture_output=True, text=True, check=True)
        print("✓ Successfully synced dependencies with uv")
    except subprocess.CalledProcessError as e:
        print(f"✗ Failed to sync dependencies: {e.stderr}")
        print("Trying fallback installation...")

        # Fallback: try installing specific packages that are available
        available_deps = [
            "httpx>=0.25.0",
            "responses>=0.24.0",
            "jwcrypto>=1.5.0",
        ]

        for dep in available_deps:
            try:
                print(f"Installing {dep}...")
                subprocess.run(["uv", "add", dep], capture_output=True, text=True, check=True)
                print(f"✓ Successfully installed {dep}")
            except subprocess.CalledProcessError as e:
                print(f"✗ Failed to install {dep}: {e.stderr}")


def verify_installation():
    """Verify that required dependencies are installed."""
    print("\nVerifying installations...")

    dependencies_to_check = [
        ("httpx", "httpx"),
        ("websockets", "websockets"),
        ("responses", "responses"),
        ("jwcrypto", "jwcrypto"),
        ("pyjwt", "jwt"),
    ]

    all_good = True
    for package, import_name in dependencies_to_check:
        if not check_dependency(package, import_name):
            all_good = False

    return all_good


def create_test_runner():
    """Create a test runner script for Sphereon OIDC4VC tests."""
    test_runner_content = '''#!/usr/bin/env python3
"""
Test runner for Sphereon OIDC4VC integration tests.
"""

import subprocess
import sys
from pathlib import Path

def run_sphereon_tests():
    """Run the Sphereon OIDC4VC integration tests."""
    test_file = Path(__file__).parent / "tests" / "integration" / "test_sphereon_oidc4vc_integration.py"

    if not test_file.exists():
        print(f"Test file not found: {test_file}")
        return False

    print("Running Sphereon OIDC4VC integration tests...")

    try:
        result = subprocess.run([
            sys.executable, "-m", "pytest",
            str(test_file),
            "-v",
            "--tb=short",
            "-m", "oidc4vc"
        ], check=True)
        print("✓ All Sphereon OIDC4VC tests passed!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"✗ Some tests failed with exit code {e.returncode}")
        return False

if __name__ == "__main__":
    success = run_sphereon_tests()
    sys.exit(0 if success else 1)
'''

    script_path = Path("run_sphereon_tests.py")
    with open(script_path, "w") as f:
        f.write(test_runner_content)

    # Make it executable
    script_path.chmod(0o755)
    print(f"✓ Created test runner script: {script_path}")


def main():
    """Main function to set up Sphereon OIDC4VC testing environment."""
    print("Setting up Sphereon OIDC4VC testing environment...")
    print("=" * 50)

    # Install dependencies
    install_dependencies()

    # Verify installation
    print("\n" + "=" * 50)
    if verify_installation():
        print("✓ All dependencies verified successfully!")
    else:
        print("✗ Some dependencies are missing. Please check the output above.")
        return False

    # Create test runner
    print("\n" + "=" * 50)
    create_test_runner()

    print("\n" + "=" * 50)
    print("Setup complete! You can now:")
    print("1. Run integration tests: python run_sphereon_tests.py")
    print("2. Run specific tests: pytest tests/integration/test_sphereon_oidc4vc_integration.py -v")
    print("3. Run with markers: pytest -m oidc4vc -v")

    return True


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
