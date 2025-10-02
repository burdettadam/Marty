#!/usr/bin/env python3
"""
Test runner script for running all tests in the project.

This script will:
1. Compile proto files if needed
2. Run unit tests
3. Run integration tests if requested
"""

import argparse
import logging
import os
import sys
import unittest

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Add the parent directory to the path so we can import project modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def compile_protos() -> bool:
    """Compile proto files if needed."""
    try:
        logger.info("Compiling proto files...")
        from compile_protos import compile_all_protos

        success = compile_all_protos()
        if not success:
            logger.error("Failed to compile proto files")
            return False
        logger.info("Proto files compiled successfully")
    except Exception:
        logger.exception("Error compiling proto files")
        return False
    else:
        return True


def run_unit_tests():
    """Run unit tests."""
    logger.info("Running unit tests...")

    # Discover and run all unit tests
    test_loader = unittest.TestLoader()
    test_suite = test_loader.discover(
        os.path.dirname(os.path.abspath(__file__)), pattern="test_unit.py"
    )
    test_runner = unittest.TextTestRunner(verbosity=2)
    result = test_runner.run(test_suite)

    return result.wasSuccessful()


def run_integration_tests():
    """Run integration tests."""
    logger.info("Running integration tests...")

    # Discover and run all integration tests
    test_loader = unittest.TestLoader()
    test_suite = test_loader.discover(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "integration"), pattern="test_*.py"
    )
    test_runner = unittest.TextTestRunner(verbosity=2)
    result = test_runner.run(test_suite)

    return result.wasSuccessful()


def main() -> None:
    """Main entry point for the test runner."""
    parser = argparse.ArgumentParser(description="Run tests for the project")
    parser.add_argument("--unit-only", action="store_true", help="Run only unit tests")
    parser.add_argument(
        "--integration-only", action="store_true", help="Run only integration tests"
    )
    parser.add_argument(
        "--skip-proto-compile", action="store_true", help="Skip compiling proto files"
    )

    args = parser.parse_args()

    if not args.skip_proto_compile and not compile_protos():
        logger.error("Failed to compile proto files, exiting.")
        sys.exit(1)

    success = True

    # Run tests according to arguments
    if args.integration_only:
        success = run_integration_tests()
    elif args.unit_only:
        success = run_unit_tests()
    else:
        # Run both unit and integration tests
        unit_success = run_unit_tests()
        integration_success = run_integration_tests()
        success = unit_success and integration_success

    if success:
        logger.info("All tests passed successfully!")
        sys.exit(0)
    else:
        logger.error("Some tests failed.")
        sys.exit(1)


if __name__ == "__main__":
    main()
