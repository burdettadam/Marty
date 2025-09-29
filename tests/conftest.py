"""
Test configuration for Marty test suite.
"""

import os
import tempfile
from pathlib import Path
from unittest.mock import Mock

import pytest

try:
    from src.marty_common.models.passport import Gender, MRZData
except ModuleNotFoundError:  # pragma: no cover - fallback for minimal test environments
    Gender = Mock()
    MRZData = Mock()
from tests.fixtures.data_loader import test_data_loader


# Test markers
def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line("markers", "unit: mark test as a unit test")
    config.addinivalue_line("markers", "integration: mark test as an integration test")
    config.addinivalue_line("markers", "slow: mark test as slow running")
    config.addinivalue_line("markers", "docker: mark test as requiring docker")
    config.addinivalue_line("markers", "external: mark test as requiring external services")
    config.addinivalue_line("markers", "mrz: mark test as MRZ related")
    config.addinivalue_line("markers", "ocr: mark test as OCR related")
    config.addinivalue_line("markers", "pdf: mark test as PDF related")
    config.addinivalue_line("markers", "document_processing: mark test as document processing service related")


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

        # Add document processing marker
        if "document_processing" in str(item.fspath):
            item.add_marker(pytest.mark.document_processing)

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
            subprocess.run(["docker", "version"], capture_output=True, check=True)
        except (subprocess.SubprocessError, FileNotFoundError):
            pytest.skip("Docker not available")


# Custom test result reporting
def pytest_report_teststatus(report, config):
    """Custom test status reporting."""
    if report.when == "call":
        if report.outcome == "passed":
            return report.outcome, "P", f"PASSED {report.nodeid}"
        if report.outcome == "failed":
            return report.outcome, "F", f"FAILED {report.nodeid}"
        if report.outcome == "skipped":
            return report.outcome, "S", f"SKIPPED {report.nodeid}"
    return None


# Test Data Classes
class TestDataFixtures:
    """Container for test data fixtures."""

    # Sample MRZ data for testing
    SAMPLE_TD3_MRZ = (
        "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<\nL898902C36UTO7408122F1204159ZE184226B<<<<<10"
    )

    SAMPLE_MRZ_DATA = MRZData(
        document_type="P",
        issuing_country="UTO",
        document_number="L898902C3",
        surname="ERIKSSON",
        given_names="ANNA MARIA",
        nationality="UTO",
        date_of_birth="740812",
        gender=Gender.FEMALE,
        date_of_expiry="120415",
        personal_number="ZE184226B",
    )

    # Sample certificate data
    SAMPLE_CERTIFICATE_DATA = {
        "certificate_id": "cert_test_001",
        "subject": "CN=Test Certificate,O=Test Org,C=US",
        "issuer": "CN=Test CA,O=Test CA Org,C=US",
        "not_before": "2024-01-01T00:00:00Z",
        "not_after": "2025-01-01T00:00:00Z",
        "serial_number": "123456789",
    }

    # Sample passport data
    SAMPLE_PASSPORT_DATA = {
        "passport_number": "P123456789",
        "issuing_country": "UTO",
        "holder_name": "ANNA MARIA ERIKSSON",
        "date_of_birth": "1974-08-12",
        "date_of_expiry": "2012-04-15",
        "nationality": "UTO",
        "gender": "F",
    }


class MockPassportEngineStub:
    """Mock passport engine stub for testing."""

    def ProcessPassport(self, request):
        """Mock ProcessPassport method."""

        mock_response = Mock()
        mock_response.status = "SUCCESS"
        mock_response.passport_data = TestDataFixtures.SAMPLE_PASSPORT_DATA
        return mock_response


class MockCscaServiceStub:
    """Mock CSCA service stub for testing."""

    def CreateCertificate(self, request):
        """Mock CreateCertificate method."""

        mock_response = Mock()
        mock_response.status = "SUCCESS"
        mock_response.certificate_id = "cert_test_001"
        return mock_response

    def CheckExpiringCertificates(self, request):
        """Mock CheckExpiringCertificates method."""

        mock_response = Mock()
        mock_response.certificates = []
        return mock_response


# Test Fixtures
@pytest.fixture
def test_data():
    """Provide test data fixtures."""
    return TestDataFixtures()


@pytest.fixture
def mock_mrz_data():
    """Provide mock MRZ data."""
    return TestDataFixtures.SAMPLE_MRZ_DATA


@pytest.fixture
def sample_mrz_string():
    """Provide sample MRZ string."""
    return TestDataFixtures.SAMPLE_TD3_MRZ


@pytest.fixture
def mock_certificate():
    """Provide mock certificate data."""
    return TestDataFixtures.SAMPLE_CERTIFICATE_DATA


@pytest.fixture
def mock_passport():
    """Provide mock passport data."""
    return TestDataFixtures.SAMPLE_PASSPORT_DATA


@pytest.fixture
def temp_directory():
    """Provide a temporary directory for test files."""

    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir)


@pytest.fixture
def mock_grpc_channel():
    """Provide a mock gRPC channel."""

    mock_channel = Mock()
    mock_channel.__enter__ = Mock(return_value=mock_channel)
    mock_channel.__exit__ = Mock(return_value=None)
    return mock_channel


@pytest.fixture
def mock_grpc_stub():
    """Provide a mock gRPC stub."""

    return Mock()


@pytest.fixture(scope="session")
def project_root():
    """Provide the project root path."""
    return Path(__file__).resolve().parents[1]


@pytest.fixture
def test_config():
    """Provide test configuration."""
    return {
        "services": {
            "postgres": {
                "host": "localhost",
                "port": 5432,
                "database": "test_martydb",
                "username": "test_user",
                "password": "test_password",
            },
            "grpc_services": {
                "csca_service": {"host": "localhost", "port": 50051},
                "passport_engine": {"host": "localhost", "port": 50052},
                "trust_anchor": {"host": "localhost", "port": 50053},
            },
        },
        "testing": {"timeout": 30, "retry_attempts": 3, "mock_external_services": True},
    }


@pytest.fixture
def mock_service_response():
    """Provide mock service response."""

    mock_response = Mock()
    mock_response.status = "SUCCESS"
    mock_response.message = "Test operation completed"
    return mock_response


@pytest.fixture
def mock_passport_engine_stub():
    """Provide mock passport engine stub."""
    return MockPassportEngineStub()


@pytest.fixture
def mock_csca_service_stub():
    """Provide mock CSCA service stub."""
    return MockCscaServiceStub()


@pytest.fixture
def test_pdf_bytes():
    """Provide test PDF bytes."""
    return create_test_pdf_bytes()


# Real Data Fixtures using scraped data
@pytest.fixture
def real_passport_data():
    """Provide real passport data from scraped files."""
    return test_data_loader.load_passport_data()


@pytest.fixture
def sample_passport_collection():
    """Provide a collection of sample passport data for comprehensive testing."""
    return test_data_loader.get_sample_passports(10)


@pytest.fixture
def regular_passports():
    """Provide regular passports starting with 'P'."""
    return test_data_loader.get_passport_by_type("P")


@pytest.fixture
def iceland_passports():
    """Provide Iceland passports starting with 'IS'."""
    return test_data_loader.get_passport_by_type("IS")


@pytest.fixture
def special_passports():
    """Provide special passports starting with 'PM'."""
    return test_data_loader.get_passport_by_type("PM")


@pytest.fixture
def invalid_passport_data():
    """Provide invalid passport data for negative testing."""
    return test_data_loader.load_invalid_passport_data()


@pytest.fixture
def csca_lifecycle_data():
    """Provide real CSCA certificate lifecycle data."""
    return test_data_loader.load_csca_lifecycle_data()


@pytest.fixture
def trust_store_config():
    """Provide trust store configuration data."""
    return test_data_loader.load_trust_store_data()


@pytest.fixture
def passport_test_images():
    """Provide real passport test images."""
    return test_data_loader.get_passport_images()


@pytest.fixture
def test_image_files():
    """Provide all test image files."""
    return test_data_loader.get_test_images()


@pytest.fixture
def test_pdf_files():
    """Provide test PDF files."""
    return test_data_loader.get_test_pdfs()


@pytest.fixture
def comprehensive_test_data():
    """Provide comprehensive test data combining all sources."""
    return {
        "passports": {
            "regular": test_data_loader.get_passport_by_type("P")[:5],
            "iceland": test_data_loader.get_passport_by_type("IS")[:5],
            "special": test_data_loader.get_passport_by_type("PM")[:5],
            "invalid": test_data_loader.load_invalid_passport_data(),
        },
        "certificates": test_data_loader.load_csca_lifecycle_data(),
        "trust_store": test_data_loader.load_trust_store_data(),
        "images": test_data_loader.get_passport_images(),
        "pdfs": test_data_loader.get_test_pdfs(),
    }


# Enhanced Mock Classes with Real Data
class EnhancedMockPassportEngineStub:
    """Enhanced mock passport engine stub using real data."""

    def __init__(self):
        self.passport_data = test_data_loader.get_sample_passports(5)

    def ProcessPassport(self, request):
        """Mock ProcessPassport method with real passport data."""

        mock_response = Mock()
        mock_response.status = "SUCCESS"

        # Use real passport data
        if self.passport_data:
            mock_response.passport_data = self.passport_data[0]
        else:
            mock_response.passport_data = TestDataFixtures.SAMPLE_PASSPORT_DATA

        return mock_response


class EnhancedMockCscaServiceStub:
    """Enhanced mock CSCA service stub using real lifecycle data."""

    def __init__(self):
        try:
            self.lifecycle_data = test_data_loader.load_csca_lifecycle_data()
        except FileNotFoundError:
            self.lifecycle_data = {}

    def CreateCertificate(self, request):
        """Mock CreateCertificate method."""

        mock_response = Mock()
        mock_response.status = "SUCCESS"
        mock_response.certificate_id = (
            f"cert_real_{len(self.lifecycle_data.get('certificate_events', {}))}"
        )
        return mock_response

    def CheckExpiringCertificates(self, request):
        """Mock CheckExpiringCertificates method with real lifecycle data."""

        mock_response = Mock()

        # Use real certificate events if available
        if self.lifecycle_data and "certificate_events" in self.lifecycle_data:
            mock_response.certificates = list(self.lifecycle_data["certificate_events"].keys())[:5]
        else:
            mock_response.certificates = []

        return mock_response


@pytest.fixture
def enhanced_passport_engine_stub():
    """Provide enhanced mock passport engine stub with real data."""
    return EnhancedMockPassportEngineStub()


@pytest.fixture
def enhanced_csca_service_stub():
    """Provide enhanced mock CSCA service stub with real data."""
    return EnhancedMockCscaServiceStub()


# Test helper functions
def create_test_image(width: int = 100, height: int = 100):
    """Create a test image for OCR/MRZ testing."""
    try:
        import numpy as np

        return np.ones((height, width), dtype=np.uint8) * 255
    except ImportError:
        pytest.skip("numpy not available for image creation")


def create_test_pdf_bytes():
    """Create test PDF bytes for PDF extraction testing."""
    # Minimal PDF structure
    pdf_content = b"""%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
>>
endobj
xref
0 4
0000000000 65535 f 
0000000010 00000 n 
0000000062 00000 n 
0000000119 00000 n 
trailer
<<
/Size 4
/Root 1 0 R
>>
startxref
197
%%EOF"""
    return pdf_content
