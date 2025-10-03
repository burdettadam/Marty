"""
Shared FastAPI test fixtures and utilities for all services.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Generator
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


def setup_service_path(service_name: str) -> None:
    """
    Set up Python path for a specific service.

    Args:
        service_name: Name of the service (e.g., 'pkd_service', 'document_processing')
    """
    project_root = Path(__file__).parent.parent.parent

    # Add project root to path
    sys.path.insert(0, str(project_root))

    # Add service-specific path
    service_path = project_root / "src" / service_name
    if service_path.exists():
        sys.path.insert(0, str(service_path))

    # Add marty_common to path
    marty_common_path = project_root / "src"
    sys.path.insert(0, str(marty_common_path))


def create_fastapi_client_fixture(
    app: FastAPI, api_key: str = "test_api_key"
) -> Generator[TestClient, None, None]:
    """
    Create a standardized FastAPI test client fixture.

    Args:
        app: The FastAPI application instance
        api_key: API key to use for authentication

    Yields:
        TestClient: Configured test client
    """
    with TestClient(app) as client:
        # Set standard test headers
        client.headers.update({"X-API-Key": api_key})
        yield client


# Standard test sample data
@pytest.fixture
def sample_mrz_base64() -> str:
    """
    Sample base64 encoded image with MRZ (minimal 1x1 pixel PNG).
    """
    return (
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
    )


@pytest.fixture
def test_api_key() -> str:
    """Standard test API key."""
    return "test_api_key"


@pytest.fixture
def sample_process_request() -> dict:
    """
    Sample process request for document processing testing.
    """
    return {
        "processParam": {
            "scenario": "Mrz",
            "resultTypeOutput": ["MrzText", "MrzFields"]
        },
        "List": [
            {
                "ImageSource": {
                    "SourceType": "base64",
                    "SourceData": (
                        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
                    )
                }
            }
        ]
    }


# Database test utilities
@pytest.fixture
def test_database_config() -> dict:
    """Standard test database configuration."""
    return {
        "url": "postgresql://test:test@localhost:5432/test_martydb",
        "echo": True,
        "pool_pre_ping": True
    }


# Environment setup utilities
def setup_test_environment(env_vars: dict | None = None) -> dict:
    """
    Set up standard test environment variables.

    Args:
        env_vars: Additional environment variables to set

    Returns:
        Original environment variables for restoration
    """
    original_env = os.environ.copy()

    # Standard test environment variables
    standard_vars = {
        "MARTY_ENV": "testing",
        "MARTY_LOG_LEVEL": "DEBUG",
        "MARTY_DATABASE_URL": "postgresql://test:test@localhost:5432/test_martydb"
    }

    # Apply standard variables
    os.environ.update(standard_vars)

    # Apply additional variables if provided
    if env_vars:
        os.environ.update(env_vars)

    return original_env


def restore_environment(original_env: dict) -> None:
    """
    Restore original environment variables.

    Args:
        original_env: Original environment to restore
    """
    os.environ.clear()
    os.environ.update(original_env)
