"""
Playwright configuration for E2E tests of the Marty UI application.
"""

import os
from pathlib import Path

# Test configuration
BASE_URL = os.getenv("MARTY_BASE_URL", "http://localhost:8090")
HEADLESS = os.getenv("HEADLESS", "true").lower() == "true"
BROWSER_TIMEOUT = int(os.getenv("BROWSER_TIMEOUT", "30000"))  # 30 seconds
NAVIGATION_TIMEOUT = int(os.getenv("NAVIGATION_TIMEOUT", "15000"))  # 15 seconds

# Screenshot and video settings
SCREENSHOTS_DIR = Path("tests/e2e/screenshots")
VIDEOS_DIR = Path("tests/e2e/videos")
TRACES_DIR = Path("tests/e2e/traces")

# Ensure directories exist
SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)
VIDEOS_DIR.mkdir(parents=True, exist_ok=True)
TRACES_DIR.mkdir(parents=True, exist_ok=True)

# Playwright browser configuration
BROWSER_ARGS = [
    "--no-sandbox",
    "--disable-dev-shm-usage",
    "--disable-gpu",
    "--disable-web-security",
    "--allow-running-insecure-content",
    "--ignore-certificate-errors",
]

VIEWPORT_SIZE = {"width": 1280, "height": 720}
MOBILE_VIEWPORT = {"width": 375, "height": 667}
TABLET_VIEWPORT = {"width": 768, "height": 1024}

# Test data
TEST_PASSPORT_ID = "IS1BA9DA00"  # Known test passport from data
TEST_UPLOAD_FILES = {
    "passport_image": "tests/test_data/passport_sample.jpg",
    "mdl_image": "tests/test_data/mdl_sample.jpg",
}

# Service endpoints for direct testing
SERVICES = {
    "ui": BASE_URL,
    "trust_anchor": "http://localhost:9080",
    "csca": "http://localhost:8081",
    "document_signer": "http://localhost:8082",
    "inspection_system": "http://localhost:8083",
    "passport_engine": "http://localhost:8084",
    "mdl_engine": "http://localhost:8085",
    "mdoc_engine": "http://localhost:8086",
    "dtc_engine": "http://localhost:8087",
    "pkd_service": "http://localhost:8088",
}


class TestConfig:
    """Configuration class for contract testing."""
    
    # Service port mappings for HTTP endpoints
    SERVICE_PORTS = {
        "trust-svc": 8090,
        "trust-anchor": 9080,
        "csca-service": 8092,
        "document-signer": 8093,
        "inspection-system": 8094,
        "passport-engine": 8095,
        "mdl-engine": 8096,
        "mdoc-engine": 8097,
        "dtc-engine": 8098,
        "credential-ledger": 8099,
        "pkd-service": 8088,
        "ui-app": 8000,
    }
    
    # gRPC port mappings
    GRPC_PORTS = {
        "trust-svc": 9090,
        "trust-anchor": 9091,
        "csca-service": 9092,
        "document-signer": 9093,
        "inspection-system": 9094,
        "passport-engine": 9095,
        "mdl-engine": 9096,
        "mdoc-engine": 9097,
        "dtc-engine": 9098,
        "credential-ledger": 9099,
        "pkd-service": 9088,
    }
    
    # Metrics port mappings
    METRICS_PORTS = {
        "trust-svc": 8091,
        "trust-anchor": 8191,
        "csca-service": 8192,
        "document-signer": 8193,
        "inspection-system": 8194,
        "passport-engine": 8195,
        "mdl-engine": 8196,
        "mdoc-engine": 8197,
        "dtc-engine": 8198,
        "credential-ledger": 8199,
        "pkd-service": 8188,
    }
    
    def get_service_port(self, service_name: str) -> int:
        """Get HTTP port for a service."""
        return self.SERVICE_PORTS.get(service_name, 8080)
    
    def get_grpc_port(self, service_name: str) -> int:
        """Get gRPC port for a service."""
        return self.GRPC_PORTS.get(service_name, 9090)
    
    def get_metrics_port(self, service_name: str) -> int:
        """Get metrics port for a service."""
        return self.METRICS_PORTS.get(service_name, 8081)
