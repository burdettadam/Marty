"""
Test helper functions for Marty test suite.

Provides utility functions for creating test data and resources.
"""

import pytest


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
    return b"""%PDF-1.4
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
