#!/usr/bin/env python3
"""
Docker Integration Test Runner Script

This script provides a convenient way to run Docker-based integration tests
for the Marty gRPC service architecture.

Usage:
  python run_docker_tests.py [--skip-proto-compile] [--no-cleanup]

Options:
  --skip-proto-compile  Skip compilation of proto files
  --no-cleanup          Don't shut down Docker services after tests
"""

import argparse
import logging
import os
import subprocess
import sys
import time
import unittest

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("docker_test_runner.log"), logging.StreamHandler()],
)
logger = logging.getLogger(__name__)

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(project_root)


def compile_protos() -> bool:
    """Compile proto files if needed."""
    try:
        logger.info("Compiling proto files...")
        from src.compile_protos import compile_all_protos

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


def check_docker_available():
    """Check if Docker is available and running."""
    try:
        # Check Docker version to confirm it's installed
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
        except (subprocess.SubprocessError, FileNotFoundError):
            # Fall back to legacy docker-compose command
            try:
                compose_result = subprocess.run(
                    ["docker-compose", "--version"], capture_output=True, text=True, check=True
                )
                logger.info(
                    f"Docker Compose is available (legacy format): {compose_result.stdout.strip()}"
                )
            except (subprocess.SubprocessError, FileNotFoundError):
                logger.exception("Docker Compose command not found in either format")
                return False, None
            else:
                return True, "docker-compose"
        else:
            return True, "compose"

    except subprocess.SubprocessError:
        logger.exception("Docker check failed")
        return False, None
    except FileNotFoundError:
        logger.exception(
            "Docker command not found. Please ensure Docker is installed and in your PATH."
        )
        return False, None


def copy_proto_files_to_containers() -> bool:
    """Copy compiled proto files to the service containers."""
    try:
        logger.info("Setting up proto files for Docker containers...")
        # Create a temp directory to be mounted in the containers
        proto_dir = os.path.join(project_root, "src/proto")

        # Ensure the __init__.py file has the right imports
        init_path = os.path.join(proto_dir, "__init__.py")
        if os.path.exists(init_path):
            logger.info("Verifying proto module imports in __init__.py...")
            with open(init_path) as f:
                content = f.read()

            # Check if we need to update imports
            expected_imports = [
                "from . import csca_service_pb2",
                "from . import csca_service_pb2_grpc",
                "from . import document_signer_pb2",
                "from . import document_signer_pb2_grpc",
                "from . import inspection_system_pb2",
                "from . import inspection_system_pb2_grpc",
                "from . import passport_engine_pb2",
                "from . import passport_engine_pb2_grpc",
                "from . import trust_anchor_pb2",
                "from . import trust_anchor_pb2_grpc",
            ]

            # Update the file if necessary
            if not all(imp in content for imp in expected_imports):
                logger.info("Updating __init__.py with missing imports")
                with open(init_path, "w") as f:
                    f.write("# Auto-generated grpc module imports\n")
                    f.writelines(f"{imp}\n" for imp in expected_imports)
                logger.info("Updated __init__.py with all proto imports")

    except Exception:
        logger.exception("Failed to prepare proto files for Docker")
        return False
    else:
        return True


def wait_for_services_ready(compose_cmd, max_retries=12, wait_time=5) -> bool:
    """Wait for services to be ready and check their status."""
    for attempt in range(1, max_retries + 1):
        logger.info(f"Checking service status (attempt {attempt}/{max_retries})...")

        try:
            # Check status of services
            ps_cmd = [*compose_cmd, "ps"]
            result = subprocess.run(
                ps_cmd,
                capture_output=True,
                text=True,
                check=False,  # Don't raise exception on non-zero exit
            )

            if result.returncode != 0:
                logger.warning(
                    f"Docker compose ps returned non-zero exit code: {result.returncode}"
                )
                logger.warning(f"Output: {result.stdout}")
                logger.warning(f"Error: {result.stderr}")

                # Check for failed containers
                logs_cmd = [*compose_cmd, "logs"]
                logs_result = subprocess.run(logs_cmd, capture_output=True, text=True, check=False)

                if "ERROR" in logs_result.stdout or "Error" in logs_result.stdout:
                    logger.error("Found errors in container logs:")
                    for line in logs_result.stdout.splitlines():
                        if "ERROR" in line or "Error" in line:
                            logger.error(f"  {line}")

            # Check if containers are running properly
            if "Up" in result.stdout and all(
                service in result.stdout
                for service in ["csca-service", "trust-anchor", "inspection-system"]
            ):
                logger.info("All services appear to be up and running")
                return True

        except Exception:
            logger.exception("Error checking service status")

        if attempt < max_retries:
            logger.info(f"Waiting {wait_time} seconds before next check...")
            time.sleep(wait_time)

    logger.error(f"Services did not start properly after {max_retries * wait_time} seconds")
    # Get detailed logs for each service
    try:
        for service in ["csca-service", "trust-anchor", "inspection-system"]:
            logger.info(f"Logs for {service}:")
            logs_cmd = [*compose_cmd, "logs", service]
            result = subprocess.run(logs_cmd, capture_output=True, text=True, check=False)
            for line in result.stdout.splitlines()[-20:]:  # Last 20 lines
                logger.info(f"  {line}")
    except Exception:
        logger.exception("Failed to collect container logs")

    return False


def run_docker_tests():
    """Run the Docker-based integration tests."""
    logger.info("Running Docker-based integration tests...")

    # Find and load the test modules
    test_loader = unittest.TestLoader()
    test_suite = test_loader.discover(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "integration"),
        pattern="test_docker_*.py",
    )

    # Run the tests
    test_runner = unittest.TextTestRunner(verbosity=2)
    result = test_runner.run(test_suite)

    return result.wasSuccessful()


def setup_docker_services(compose_cmd_format):
    """Set up Docker services and ensure they're running correctly."""
    # Construct proper Docker Compose command based on available command format
    compose_cmd = ["docker", "compose"] if compose_cmd_format == "compose" else ["docker-compose"]

    # Ensure we have a clean environment
    logger.info("Stopping any existing Docker containers...")
    subprocess.run([*compose_cmd, "down"], capture_output=True, check=False)

    # Copy or prepare proto files for Docker containers
    if not copy_proto_files_to_containers():
        logger.error("Failed to prepare proto files for Docker containers")
        return False, compose_cmd

    # Start Docker containers
    logger.info("Starting Docker Compose services...")
    try:
        # Build and start containers
        subprocess.run([*compose_cmd, "build"], check=True)
        subprocess.run([*compose_cmd, "up", "-d"], check=True)

        # Wait for services to be ready
        if not wait_for_services_ready(compose_cmd):
            logger.error("Services did not start properly")
            return False, compose_cmd

        logger.info("All Docker services are up and running")

    except subprocess.SubprocessError as e:
        logger.exception("Failed to start Docker Compose services")
        if hasattr(e, "stdout") and e.stdout:
            logger.exception(f"stdout: {e.stdout}")
        if hasattr(e, "stderr") and e.stderr:
            logger.exception(f"stderr: {e.stderr}")
        return False, compose_cmd
    else:
        return True, compose_cmd


def main() -> None:
    """Main entry point for the Docker test runner."""
    parser = argparse.ArgumentParser(description="Run Docker-based integration tests")
    parser.add_argument(
        "--skip-proto-compile", action="store_true", help="Skip compiling proto files"
    )
    parser.add_argument(
        "--no-cleanup", action="store_true", help="Do not clean up Docker services after tests"
    )
    parser.add_argument("--verbose", action="store_true", help="Show detailed logs")
    parser.add_argument(
        "--fix-proto-paths", action="store_true", help="Fix proto import paths in containers"
    )

    args = parser.parse_args()

    # Check Docker availability
    docker_available, compose_format = check_docker_available()
    if not docker_available:
        logger.error(
            "Docker check failed. Please ensure Docker and Docker Compose are installed and running."
        )
        sys.exit(1)

    # Compile proto files if needed
    if not args.skip_proto_compile and not compile_protos():
        logger.error("Failed to compile proto files, exiting.")
        sys.exit(1)

    # Set up Docker services
    services_ready, compose_cmd = setup_docker_services(compose_format)
    if not services_ready:
        logger.error("Failed to set up Docker services, exiting.")
        sys.exit(1)

    try:
        # Override tearDown behavior if --no-cleanup is specified
        if args.no_cleanup:
            import integration.test_docker_integration

            @classmethod
            def modified_teardown(cls) -> None:
                logger.info("Skipping Docker service cleanup due to --no-cleanup flag")

            integration.test_docker_integration.DockerIntegrationTest.tearDownClass = (
                modified_teardown
            )
            logger.info("Docker services will not be cleaned up after tests")

        # Run the tests
        success = run_docker_tests()

        if success:
            logger.info("All Docker integration tests passed!")
            sys.exit(0)
        else:
            logger.error("Some Docker integration tests failed.")
            sys.exit(1)

    finally:
        # Clean up unless --no-cleanup is specified
        if not args.no_cleanup:
            logger.info("Cleaning up Docker services...")
            subprocess.run([*compose_cmd, "down"], check=False)


if __name__ == "__main__":
    main()
