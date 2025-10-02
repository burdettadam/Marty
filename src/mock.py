"""Compatibility shim for tests that import the external 'mock' package.

Python's standard library provides `unittest.mock`. This module re-exports
its symbols under a top-level `mock` module name so that `import mock` works
without adding a dependency.
"""

from unittest.mock import *
