#!/usr/bin/env python
"""
Test runner for certvalidator tests integrated into Marty project.
This script helps run the tests from the certvalidator repository
that have been integrated into the Marty project.
"""

import os
import sys
import unittest

# Add the certvalidator module path if it's installed as a dependency
try:
    import certvalidator
except ImportError:
    print("Warning: certvalidator module not found. Tests may fail if it's required.")

# Adjust paths to ensure tests can find modules and fixtures
current_dir = os.path.dirname(os.path.abspath(__file__))
fixtures_dir = os.path.join(current_dir, 'fixtures')

# Create a test suite containing all tests
def create_suite():
    """Create a test suite containing all certvalidator tests."""
    import tests.cert_validator.test_certificate_validator
    import tests.cert_validator.test_crl_client
    import tests.cert_validator.test_ocsp_client
    import tests.cert_validator.test_registry
    import tests.cert_validator.test_validate

    # Create a test suite
    suite = unittest.TestSuite()
    
    # Add tests from each module
    suite.addTests(unittest.defaultTestLoader.loadTestsFromModule(
        tests.cert_validator.test_certificate_validator))
    suite.addTests(unittest.defaultTestLoader.loadTestsFromModule(
        tests.cert_validator.test_crl_client))
    suite.addTests(unittest.defaultTestLoader.loadTestsFromModule(
        tests.cert_validator.test_ocsp_client))
    suite.addTests(unittest.defaultTestLoader.loadTestsFromModule(
        tests.cert_validator.test_registry))
    suite.addTests(unittest.defaultTestLoader.loadTestsFromModule(
        tests.cert_validator.test_validate))
    
    return suite

# Function to run specific test modules
def run_specific_tests(test_pattern):
    """
    Run specific tests matching a pattern.
    Example: 'validate' will run all tests from test_validate.py
    """
    import tests.cert_validator.test_certificate_validator
    import tests.cert_validator.test_crl_client
    import tests.cert_validator.test_ocsp_client
    import tests.cert_validator.test_registry
    import tests.cert_validator.test_validate
    
    modules = {
        'certificate_validator': tests.cert_validator.test_certificate_validator,
        'crl': tests.cert_validator.test_crl_client,
        'ocsp': tests.cert_validator.test_ocsp_client,
        'registry': tests.cert_validator.test_registry,
        'validate': tests.cert_validator.test_validate,
    }
    
    suite = unittest.TestSuite()
    for name, module in modules.items():
        if test_pattern.lower() in name.lower():
            suite.addTests(unittest.defaultTestLoader.loadTestsFromModule(module))
    
    if suite.countTestCases() == 0:
        print(f"No tests found matching pattern: {test_pattern}")
        return 1
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1

if __name__ == '__main__':
    # If a specific test is requested, run just that test
    if len(sys.argv) > 1:
        sys.exit(run_specific_tests(sys.argv[1]))
    
    # Otherwise run all tests
    suite = create_suite()
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)