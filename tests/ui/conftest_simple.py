"""
Pytest configuration with improved service handling for E2E tests.
"""

import socket
import threading
import time
from contextlib import closing
from typing import Iterator

import pytest
import uvicorn
from playwright.sync_api import Browser, Page, sync_playwright

from ui_app.app import create_app
from ui_app.config import UiSettings


@pytest.fixture(scope="session")
def ui_settings_with_services() -> UiSettings:
    """Provide UI settings that try to use real services, fallback to mock."""
    return UiSettings(
        title="Test Marty UI",
        environment="test",
        # Try real services first, fallback handled in app
        passport_engine_target="localhost:8084",
        inspection_system_target="localhost:8083",
        mdl_engine_target="localhost:8085",
        trust_anchor_target="localhost:8080",
        grpc_timeout_seconds=5,  # Short timeout to fail fast
        enable_mock_data=True,  # Enable fallback to mock
        theme="light",
    )


@pytest.fixture(scope="session")
def ui_settings_mock_only() -> UiSettings:
    """Provide UI settings for pure mock mode."""
    return UiSettings(
        title="Test Marty UI",
        environment="test",
        passport_engine_target="mock",
        inspection_system_target="mock",
        mdl_engine_target="mock",
        trust_anchor_target="mock",
        grpc_timeout_seconds=2,
        enable_mock_data=True,
        theme="light",
    )


@pytest.fixture(scope="session")
def ui_server_with_services(ui_settings_with_services: UiSettings) -> Iterator[str]:
    """Start UI server that will try to connect to real services."""
    app = create_app(ui_settings_with_services)

    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.bind(("127.0.0.1", 0))
        host, port = sock.getsockname()

    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)

    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    # Wait for server to start
    timeout = time.time() + 10
    while time.time() < timeout:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                if s.connect_ex((host, port)) == 0:
                    break
        except Exception:
            pass
        time.sleep(0.1)

    try:
        yield f"http://{host}:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=5)


@pytest.fixture(scope="session")
def ui_server_mock_only(ui_settings_mock_only: UiSettings) -> Iterator[str]:
    """Start UI server in pure mock mode."""
    app = create_app(ui_settings_mock_only)

    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.bind(("127.0.0.1", 0))
        host, port = sock.getsockname()

    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)

    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    # Wait for server to start
    timeout = time.time() + 10
    while time.time() < timeout:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                if s.connect_ex((host, port)) == 0:
                    break
        except Exception:
            pass
        time.sleep(0.1)

    try:
        yield f"http://{host}:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=5)


@pytest.fixture(scope="session")
def browser() -> Iterator[Browser]:
    """Provide a shared browser instance."""
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            headless=True, args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"]
        )
        yield browser
        browser.close()


@pytest.fixture
def page(browser: Browser) -> Iterator[Page]:
    """Provide a fresh page for each test."""
    context = browser.new_context(viewport={"width": 1280, "height": 720})
    page = context.new_page()
    page.set_default_timeout(10000)

    try:
        yield page
    finally:
        page.close()
        context.close()


# Use the mock-only server as default for most tests
@pytest.fixture(scope="session")
def ui_server(ui_server_mock_only) -> Iterator[str]:
    """Default UI server fixture (mock mode)."""
    yield from ui_server_mock_only


def pytest_configure(config):
    """Configure pytest markers."""
    config.addinivalue_line("markers", "integration: Tests requiring real backend services")
    config.addinivalue_line("markers", "smoke: Quick smoke tests")
    config.addinivalue_line("markers", "mock: Tests that work with mock services only")
