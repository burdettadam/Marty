"""Shared configuration for document processing tests.

Provides a single source of truth for the document processing service base URL
and port. Override with environment variable DOC_PROCESSING_PORT if needed.
"""
from __future__ import annotations

import os

DEFAULT_PORT = "8091"
PORT = os.getenv("DOC_PROCESSING_PORT", DEFAULT_PORT)
BASE_URL = f"http://localhost:{PORT}"

__all__ = ["BASE_URL", "DEFAULT_PORT", "PORT"]
