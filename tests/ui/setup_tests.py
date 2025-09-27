#!/usr/bin/env python3
"""
UI Test Setup and Installation Guide
=====================================

This script helps set up the complete testing environment for the Marty UI components.
Run this to install all necessary dependencies and configure the test environment.

Prerequisites:
- Python 3.8 or higher
- pip package manager
- Internet connection for downloading packages

Usage:
    python tests/ui/setup_tests.py
"""

import subprocess
import sys
from pathlib import Path


def run_command(cmd, description=""):
    """Run a command and handle errors gracefully."""
    print(f"📦 {description}")
    print(f"   Running: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print(f"   ✅ Success: {description}")
        if result.stdout.strip():
            print(f"   Output: {result.stdout.strip()}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"   ❌ Failed: {description}")
        if e.stderr:
            print(f"   Error: {e.stderr.strip()}")
        if e.stdout:
            print(f"   Output: {e.stdout.strip()}")
        return False
    except FileNotFoundError:
        print(f"   ❌ Command not found: {cmd[0]}")
        return False


def check_python_version():
    """Check if Python version meets requirements."""
    print("🐍 Checking Python version...")

    version = sys.version_info
    if version.major == 3 and version.minor >= 8:
        print(f"   ✅ Python {version.major}.{version.minor}.{version.micro} is compatible")
        return True
    print(f"   ❌ Python {version.major}.{version.minor}.{version.micro} is too old")
    print("   Please upgrade to Python 3.8 or higher")
    return False


def install_core_dependencies():
    """Install core testing dependencies."""
    dependencies = [
        "playwright",
        "pytest",
        "pytest-asyncio",
        "pytest-html",
        "pytest-xdist",
        "uvicorn",
        "fastapi",
        "requests",
    ]

    for dep in dependencies:
        success = run_command([sys.executable, "-m", "pip", "install", dep], f"Installing {dep}")
        if not success:
            return False

    return True


def install_playwright_browsers():
    """Install Playwright browsers."""
    print("\n🌐 Installing Playwright browsers...")

    # Install all browsers
    success = run_command(["playwright", "install"], "Installing all Playwright browsers")

    if not success:
        # Try installing just Chromium as fallback
        success = run_command(
            ["playwright", "install", "chromium"], "Installing Chromium browser (fallback)"
        )

    return success


def verify_installation():
    """Verify that all components are properly installed."""
    print("\n🔍 Verifying installation...")

    # Check Playwright
    try:
        import playwright

        print("   ✅ Playwright Python package installed")
    except ImportError:
        print("   ❌ Playwright Python package not found")
        return False

    # Check pytest
    try:
        import pytest

        print("   ✅ Pytest installed")
    except ImportError:
        print("   ❌ Pytest not found")
        return False

    # Check Playwright CLI
    success = run_command(["playwright", "--version"], "Checking Playwright CLI")
    if not success:
        return False

    # Check browser installation
    success = run_command(
        ["playwright", "install-deps"], "Installing system dependencies for browsers"
    )

    return True


def create_test_configuration():
    """Create necessary test configuration files."""
    print("\n⚙️ Creating test configuration...")

    project_root = Path(__file__).parent.parent.parent
    pytest_ini_path = project_root / "pytest.ini"

    pytest_config = """[tool:pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
addopts = 
    -v 
    --tb=short
    --strict-markers
    --strict-config
    --disable-warnings
markers =
    smoke: Quick smoke tests for basic functionality
    integration: Integration tests across multiple services
    slow: Tests that take a long time to run
    ui: User interface tests
    api: API endpoint tests
    workflow: End-to-end workflow tests
    accessibility: Accessibility compliance tests
    performance: Performance and load tests
filterwarnings =
    ignore::DeprecationWarning
    ignore::PendingDeprecationWarning
"""

    try:
        with open(pytest_ini_path, "w") as f:
            f.write(pytest_config)
        print("   ✅ Created pytest.ini configuration")
        return True
    except Exception as e:
        print(f"   ❌ Failed to create pytest.ini: {e}")
        return False


def create_vs_code_settings():
    """Create VS Code settings for testing."""
    print("\n⚙️ Creating VS Code test settings...")

    project_root = Path(__file__).parent.parent.parent
    vscode_dir = project_root / ".vscode"
    vscode_dir.mkdir(exist_ok=True)

    settings_path = vscode_dir / "settings.json"

    # Read existing settings if they exist
    existing_settings = {}
    if settings_path.exists():
        try:
            import json

            with open(settings_path) as f:
                existing_settings = json.load(f)
        except Exception:
            pass

    # Add test-related settings
    test_settings = {
        "python.testing.pytestEnabled": True,
        "python.testing.unittestEnabled": False,
        "python.testing.pytestArgs": ["tests"],
        "python.testing.autoTestDiscoverOnSaveEnabled": False,
        "playwright.reuseBrowser": True,
        "playwright.showTrace": True,
    }

    # Merge settings
    existing_settings.update(test_settings)

    try:
        import json

        with open(settings_path, "w") as f:
            json.dump(existing_settings, f, indent=2)
        print("   ✅ Created/updated VS Code settings")
        return True
    except Exception as e:
        print(f"   ❌ Failed to create VS Code settings: {e}")
        return False


def print_next_steps():
    """Print next steps for the user."""
    print("\n🎉 Setup Complete!")
    print("=" * 50)
    print("\nNext Steps:")
    print("1. Run smoke tests to verify everything works:")
    print("   python tests/ui/test_runner.py smoke")
    print("\n2. Run the complete test suite:")
    print("   python tests/ui/test_runner.py")
    print("\n3. Run tests for a specific service:")
    print("   python tests/ui/test_runner.py csca")
    print("\n4. Generate HTML test reports:")
    print("   python tests/ui/test_runner.py report")
    print("\n5. Run tests in VS Code:")
    print("   - Open Command Palette (Cmd/Ctrl+Shift+P)")
    print("   - Type 'Python: Discover Tests'")
    print("   - Click the test beaker icon in the sidebar")
    print("\n📖 For more information, see:")
    print("   - tests/ui/README.md")
    print("   - TESTING.md")


def main():
    """Main setup routine."""
    print("🚀 Marty UI Test Environment Setup")
    print("=" * 50)

    # Check prerequisites
    if not check_python_version():
        sys.exit(1)

    # Install dependencies
    print("\n📦 Installing Dependencies...")
    if not install_core_dependencies():
        print("❌ Failed to install core dependencies")
        sys.exit(1)

    # Install browsers
    if not install_playwright_browsers():
        print("❌ Failed to install browsers")
        sys.exit(1)

    # Verify installation
    if not verify_installation():
        print("❌ Installation verification failed")
        sys.exit(1)

    # Create configuration
    create_test_configuration()
    create_vs_code_settings()

    # Print next steps
    print_next_steps()


if __name__ == "__main__":
    main()
