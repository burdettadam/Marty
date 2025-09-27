def check_docker_available():
    """Check if Docker and Docker Compose are available and running."""
    try:
        result = subprocess.run(["docker", "--version"], capture_output=True, text=True, check=True)
        logger.info(f"Docker is available: {result.stdout.strip()}")

        # Check if Docker is running by executing a simple command
        subprocess.run(["docker", "info"], capture_output=True, check=True)
        logger.info("Docker daemon is running")

        # Check Docker Compose - try both the legacy and new command formats
        try:
            # First try the new Docker CLI format (Docker Desktop >= 19.03)
            compose_result = subprocess.run(
                ["docker", "compose", "version"], capture_output=True, text=True, check=True
            )
            logger.info(
                f"Docker Compose is available (docker compose format): {compose_result.stdout.strip()}"
            )
            return True, "compose"
        except (subprocess.SubprocessError, FileNotFoundError):
            # Fall back to legacy docker-compose command
            try:
                compose_result = subprocess.run(
                    ["docker-compose", "--version"], capture_output=True, text=True, check=True
                )
                logger.info(
                    f"Docker Compose is available (legacy format): {compose_result.stdout.strip()}"
                )
                return True, "docker-compose"
            except (subprocess.SubprocessError, FileNotFoundError):
                logger.error("Docker Compose command not found in either format")
                return False, None

    except subprocess.SubprocessError as e:
        logger.error(f"Docker check failed: {e}")
        return False, None
    except FileNotFoundError:
        logger.error(
            "Docker command not found. Please ensure Docker is installed and in your PATH."
        )
        return False, None


"""Docker Integration Test Runner.

Provides a convenient way to run Docker-based integration tests using the
updated orchestrated test structure.

Usage:
    python run_docker_tests.py [options]

Options:
    --skip-proto-compile  Skip compilation of proto files
    --no-cleanup          Do not shut down Docker services after tests
    --service=NAME        Run tests for a specific service only
    --e2e-only            Run only end-to-end tests
    --verbose             Show detailed output
"""

import argparse
import logging
import subprocess
import sys
import unittest
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("docker_integration_test.log"), logging.StreamHandler()],
)
logger = logging.getLogger(__name__)

# Add project root to path
project_root = Path(__file__).resolve().parents[3]
sys.path.append(str(project_root))


def compile_protos():
    """Compile proto files if needed."""
    try:
        logger.info("Compiling proto files...")
        from src.compile_protos import compile_all_protos

        project_root = Path(__file__).resolve().parents[3]
        proto_src_dir = project_root / "proto"
        out_dir = project_root / "src/proto"
        success = compile_all_protos(proto_src_dir, out_dir)
        if not success:
            logger.error("Failed to compile proto files")
            return False
        logger.info("Proto files compiled successfully")
        return True
    except Exception as e:
        logger.error(f"Error compiling proto files: {e}")
        return False


def run_docker_tests(args):
    """Run the Docker-based integration tests based on command line arguments."""
    logger.info("Running Docker-based integration tests...")

    try:
        # Find and load the test modules based on the specified parameters
        test_loader = unittest.TestLoader()
        test_suite = unittest.TestSuite()

        # Determine which test directories to include
        current_dir = Path(__file__).parent

        if args.service:
            # Run tests for specific service
            service_dir = current_dir / "services" / args.service
            if not service_dir.exists():
                logger.error(f"Service test directory not found: {service_dir}")
                return False

            logger.info(f"Running tests for service: {args.service}")
            service_test_suite = test_loader.discover(str(service_dir), pattern="test_*.py")
            test_suite.addTest(service_test_suite)

        elif args.e2e_only:
            # Run only end-to-end tests
            logger.info("Running only end-to-end tests")
            e2e_dir = current_dir / "e2e"
            e2e_test_suite = test_loader.discover(str(e2e_dir), pattern="test_*.py")
            test_suite.addTest(e2e_test_suite)

        else:
            # Run all tests - first service-specific tests, then e2e tests
            logger.info("Running all Docker integration tests")

            # Service-specific tests
            services_dir = current_dir / "services"
            for service_path in services_dir.iterdir():
                if service_path.is_dir():
                    service_test_suite = test_loader.discover(
                        str(service_path), pattern="test_*.py"
                    )
                    test_suite.addTest(service_test_suite)

            # End-to-end tests
            e2e_dir = current_dir / "e2e"
            e2e_test_suite = test_loader.discover(str(e2e_dir), pattern="test_*.py")
            test_suite.addTest(e2e_test_suite)

        # Run the tests
        test_runner = unittest.TextTestRunner(verbosity=2 if args.verbose else 1)
        result = test_runner.run(test_suite)

        return result.wasSuccessful()

    finally:
        # With orchestrated tests each class manages readiness; global shutdown optional.
        if not args.no_cleanup:
            logger.info("No legacy global shutdown required (services managed externally).")
        else:
            logger.info("Skipping optional cleanup due to --no-cleanup flag")


def main():
    """Main entry point for the Docker test runner."""
    parser = argparse.ArgumentParser(description="Run Docker-based integration tests")
    parser.add_argument(
        "--skip-proto-compile", action="store_true", help="Skip compiling proto files"
    )
    parser.add_argument(
        "--no-cleanup", action="store_true", help="Do not clean up Docker services after tests"
    )
    parser.add_argument("--service", help="Run tests for a specific service only")
    parser.add_argument("--e2e-only", action="store_true", help="Run only end-to-end tests")
    parser.add_argument("--verbose", action="store_true", help="Show detailed output")

    args = parser.parse_args()

    # Check Docker availability
    docker_available, compose_format = check_docker_available()
    if not docker_available:
        logger.error(
            "Docker check failed. Please ensure Docker and Docker Compose are installed and running."
        )
        sys.exit(1)

    # Compile proto files if needed
    if not args.skip_proto_compile:
        if not compile_protos():
            logger.error("Failed to compile proto files, exiting.")
            sys.exit(1)

    # Run the tests
    success = run_docker_tests(args)

    if success:
        logger.info("All Docker integration tests passed!")
        sys.exit(0)
    else:
        logger.error("Some Docker integration tests failed.")
        sys.exit(1)


if __name__ == "__main__":
    main()
