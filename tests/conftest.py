"""
Test configuration for Marty test suite.
"""

import pytest
from pathlib import Path
import sys

# Configure pytest settings
# pytest_plugins = [
#     "fixtures.test_fixtures"
# ]

# Add project root to Python path
project_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(project_root))

# Test markers
def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers", "unit: mark test as a unit test"
    )
    config.addinivalue_line(
        "markers", "integration: mark test as an integration test"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow running"
    )
    config.addinivalue_line(
        "markers", "docker: mark test as requiring docker"
    )
    config.addinivalue_line(
        "markers", "external: mark test as requiring external services"
    )
    config.addinivalue_line(
        "markers", "mrz: mark test as MRZ related"
    )
    config.addinivalue_line(
        "markers", "ocr: mark test as OCR related"
    )
    config.addinivalue_line(
        "markers", "pdf: mark test as PDF related"
    )


# Collection settings
def pytest_collection_modifyitems(config, items):
    """Modify test collection to add markers."""
    for item in items:
        # Add unit marker to unit tests
        if "unit" in str(item.fspath):
            item.add_marker(pytest.mark.unit)
        
        # Add integration marker to integration tests
        if "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)
        
        # Add docker marker to docker tests
        if "docker" in str(item.fspath):
            item.add_marker(pytest.mark.docker)
        
        # Add specific markers based on file names
        if "mrz" in item.name.lower():
            item.add_marker(pytest.mark.mrz)
        if "ocr" in item.name.lower():
            item.add_marker(pytest.mark.ocr)
        if "pdf" in item.name.lower():
            item.add_marker(pytest.mark.pdf)


# Test environment setup
@pytest.fixture(scope="session", autouse=True)
def test_environment_setup():
    """Set up test environment."""
    import os
    
    # Set test environment variables
    original_env = os.environ.copy()
    
    os.environ["MARTY_ENV"] = "testing"
    os.environ["MARTY_LOG_LEVEL"] = "DEBUG"
    os.environ["MARTY_DATABASE_URL"] = "postgresql://test:test@localhost:5432/test_martydb"
    
    yield
    
    # Restore environment
    os.environ.clear()
    os.environ.update(original_env)


# Skip tests if dependencies are not available
def pytest_runtest_setup(item):
    """Skip tests based on availability of dependencies."""
    
    # Skip PassportEye tests if not available
    if item.get_closest_marker("external"):
        try:
            import passporteye
        except ImportError:
            pytest.skip("PassportEye not available")
    
    # Skip numpy/skimage tests if not available
    if item.get_closest_marker("ocr"):
        try:
            import numpy
            import skimage
        except ImportError:
            pytest.skip("numpy/skimage not available for OCR tests")
    
    # Skip docker tests if docker not available
    if item.get_closest_marker("docker"):
        import subprocess
        try:
            subprocess.run(["docker", "version"], 
                         capture_output=True, check=True)
        except (subprocess.SubprocessError, FileNotFoundError):
            pytest.skip("Docker not available")


# Custom test result reporting
def pytest_report_teststatus(report, config):
    """Custom test status reporting."""
    if report.when == "call":
        if report.outcome == "passed":
            return report.outcome, "P", f"PASSED {report.nodeid}"
        elif report.outcome == "failed":
            return report.outcome, "F", f"FAILED {report.nodeid}"
        elif report.outcome == "skipped":
            return report.outcome, "S", f"SKIPPED {report.nodeid}"