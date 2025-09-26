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
