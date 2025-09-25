#!/usr/bin/env python3
"""
Base Docker Integration Test Class

This module provides a base class for all Docker integration tests,
with common setup and teardown functionality.
"""

import unittest
import os
import sys
import time
import logging
import subprocess
import json
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("docker_integration_test.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Add project root to path to ensure imports work correctly
project_root = Path(__file__).resolve().parents[4]  # 4 levels up from helpers dir
sys.path.append(str(project_root))

# Track if services are already running to prevent multiple startups/shutdowns
services_running = False


class BaseDockerIntegrationTest(unittest.TestCase):
    """Base class for all Docker integration tests."""
    
    # Mapping of service names to container names in docker-compose.yml
    CONTAINER_NAMES = {
        "trust_anchor": "trust-anchor-service",
        "csca_service": "csca-service",
        "document_signer": "document-signer-service",
        "inspection_system": "inspection-system-service",
        "passport_engine": "passport-engine-service",
        "grpc_test": "grpc-test-service"
    }
    
    # Reverse mapping for looking up service by container name
    CONTAINER_TO_SERVICE = {v: k for k, v in CONTAINER_NAMES.items()}
    
    @classmethod
    def setUpClass(cls):
        """
        Start Docker Compose services before running any tests.
        Uses a global flag to prevent multiple service startups.
        """
        global services_running
        
        if not services_running:
            logger.info("Starting Docker Compose services...")
            
            # Check if Docker is available
            try:
                subprocess.run(["docker", "--version"], check=True, capture_output=True)
            except (subprocess.SubprocessError, FileNotFoundError):
                logger.error("Docker is not available. Please ensure Docker is installed and running.")
                sys.exit(1)
            
            # Determine Docker Compose command format to use
            compose_cmd = cls._get_docker_compose_command()
            if not compose_cmd:
                logger.error("Could not determine Docker Compose command format")
                sys.exit(1)
            
            # Start services in background
            try:
                # First, ensure any previous services are stopped
                try:
                    down_cmd = compose_cmd + ["down"]
                    logger.info(f"Cleaning up any existing services: {' '.join(down_cmd)}")
                    subprocess.run(
                        down_cmd,
                        cwd=project_root,
                        check=False,  # Don't fail if no services are running
                        capture_output=True
                    )
                except Exception as e:
                    logger.warning(f"Error during cleanup (non-critical): {e}")
                
                # Start the services
                cmd = compose_cmd + ["up", "-d"]
                logger.info(f"Running command: {' '.join(cmd)}")
                subprocess.run(
                    cmd,
                    cwd=project_root,
                    check=True
                )
                logger.info("Docker Compose services started successfully")
                
                # Wait for services to be ready with a shorter timeout
                logger.info("Waiting for services to be ready...")
                time.sleep(15)  # Reduced wait time, still enough for most services
                
                # Set the flag that services are running
                services_running = True
                
            except subprocess.SubprocessError as e:
                logger.error(f"Failed to start Docker Compose services: {e}")
                sys.exit(1)
        else:
            logger.info("Docker Compose services are already running, skipping startup")
    
    @classmethod
    def tearDownClass(cls):
        """
        Stop Docker Compose services after all tests have run.
        Only executes if this is the last test class to run.
        """
        # Services will be shut down by the main test runner
        # This prevents individual test classes from shutting down services
        # that other test classes might still be using
        pass
    
    @classmethod
    def shutdown_docker_services(cls):
        """
        Explicitly shutdown Docker services.
        This should be called by the main test runner after all tests are complete.
        """
        global services_running
        
        if services_running:
            logger.info("Stopping Docker Compose services...")
            
            # Determine Docker Compose command format to use
            compose_cmd = cls._get_docker_compose_command()
            if not compose_cmd:
                logger.error("Could not determine Docker Compose command format")
                return False
            
            try:
                cmd = compose_cmd + ["down"]
                logger.info(f"Running command: {' '.join(cmd)}")
                subprocess.run(
                    cmd,
                    cwd=project_root,
                    check=True
                )
                logger.info("Docker Compose services stopped successfully")
                services_running = False
                return True
            except subprocess.SubprocessError as e:
                logger.error(f"Failed to stop Docker Compose services: {e}")
                return False
        else:
            logger.info("No Docker Compose services are running, skipping shutdown")
            return True
    
    @classmethod
    def _get_docker_compose_command(cls):
        """Determine which Docker Compose command format to use."""
        # Try new Docker CLI format (Docker Desktop >= 19.03)
        try:
            result = subprocess.run(
                ["docker", "compose", "version"],
                capture_output=True,
                text=True,
                check=True
            )
            logger.info(f"Using Docker Compose new CLI format: {result.stdout.strip()}")
            return ["docker", "compose"]
        except (subprocess.SubprocessError, FileNotFoundError):
            # Fall back to legacy docker-compose command
            try:
                result = subprocess.run(
                    ["docker-compose", "--version"],
                    capture_output=True,
                    text=True,
                    check=True
                )
                logger.info(f"Using Docker Compose legacy format: {result.stdout.strip()}")
                return ["docker-compose"]
            except (subprocess.SubprocessError, FileNotFoundError):
                logger.error("No Docker Compose command found")
                return None
    
    def get_service_address(self, service_name):
        """Get the service address for a given service."""
        service_ports = {
            "csca_service": "8081",
            "document_signer": "8082",
            "passport_engine": "8084",
            "inspection_system": "8083",
            "trust_anchor": "8080"
        }
        
        # For local testing using docker-compose
        port = service_ports.get(service_name)
        address = f"localhost:{port}"
        
        logger.info(f"Using address {address} for service {service_name}")
        return address
    
    def check_passport_file_exists(self, passport_number):
        """Check if a passport file exists in the data directory."""
        passport_file_path = os.path.join(project_root, "data", "passport", f"{passport_number}.json")
        exists = os.path.exists(passport_file_path)
        logger.info(f"Checking if passport file exists at {passport_file_path}: {exists}")
        
        if exists:
            try:
                with open(passport_file_path, 'r') as f:
                    content = json.load(f)
                    logger.info(f"Passport file content: {json.dumps(content, indent=2)}")
            except Exception as e:
                logger.error(f"Failed to read passport file: {e}")
        else:
            # List all files in passport directory for debugging
            passport_dir = os.path.join(project_root, "data", "passport")
            if os.path.exists(passport_dir):
                files = os.listdir(passport_dir)
                logger.info(f"Files in passport directory: {files}")
            else:
                logger.warning(f"Passport directory does not exist: {passport_dir}")
        
        return exists
    
    def check_service_health(self, service_name):
        """
        Check if a service is healthy by querying Docker.
        Maps service name to container name for proper Docker Compose identification.
        """
        compose_cmd = self._get_docker_compose_command()
        if not compose_cmd:
            logger.error("Could not determine Docker Compose command format")
            return False
            
        # Map the service name to the container name from docker-compose.yml
        container_name = self.CONTAINER_NAMES.get(service_name)
        if not container_name:
            logger.warning(f"Unknown service: {service_name}, no container mapping found")
            # Try using service name directly
            container_name = service_name

        # Try checking with both "docker compose ps" and "docker ps" for wider compatibility 
        try:
            # First try using docker compose ps (preferred method)
            cmd = compose_cmd + ["ps"]
            result = subprocess.run(
                cmd,
                cwd=project_root,
                capture_output=True,
                text=True,
                check=True
            )
            # Check if the container is running by searching for its name in the output
            if container_name in result.stdout and ("Up" in result.stdout or "healthy" in result.stdout.lower()):
                logger.info(f"Service {service_name} (container: {container_name}) is running")
                return True
                
            # If first method didn't find it, try direct docker ps command
            cmd = ["docker", "ps", "--filter", f"name={container_name}", "--format", "{{.Names}} {{.Status}}"]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True
            )
            
            logger.info(f"Service health check for {service_name} (container: {container_name}): {result.stdout}")
            return (container_name in result.stdout and 
                   ("Up" in result.stdout or "healthy" in result.stdout.lower() or "running" in result.stdout.lower()))
                   
        except subprocess.SubprocessError as e:
            logger.error(f"Failed to check service health for {service_name} (container: {container_name}): {e}")
            
            # One more attempt using direct Docker commands
            try:
                cmd = ["docker", "container", "inspect", container_name, "--format", "{{.State.Status}}"]
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    check=True
                )
                status = result.stdout.strip()
                logger.info(f"Container {container_name} status via direct inspect: {status}")
                return status == "running"
            except subprocess.SubprocessError as e2:
                logger.error(f"Failed to inspect container {container_name}: {e2}")
                return False
    
    def get_service_logs(self, service_name, lines=50):
        """
        Get logs from a docker service for debugging.
        Maps service name to container name for proper Docker Compose identification.
        """
        compose_cmd = self._get_docker_compose_command()
        if not compose_cmd:
            logger.error("Could not determine Docker Compose command format")
            return "Failed to get logs - Docker Compose command not found"
        
        # Map the service name to the container name from docker-compose.yml
        container_name = self.CONTAINER_NAMES.get(service_name)
        if not container_name:
            logger.warning(f"Unknown service: {service_name}, no container mapping found")
            # Try using service name directly
            container_name = service_name
            
        try:
            cmd = compose_cmd + ["logs", "--tail", str(lines), container_name]
            result = subprocess.run(
                cmd,
                cwd=project_root,
                capture_output=True,
                text=True,
                check=True
            )
            logger.info(f"Service logs for {service_name} (container: {container_name}, last {lines} lines): {result.stdout}")
            return result.stdout
        except subprocess.SubprocessError as e:
            logger.error(f"Failed to get logs for {service_name} (container: {container_name}): {e}")
            
            # Try direct docker logs command as fallback
            try:
                cmd = ["docker", "logs", "--tail", str(lines), container_name]
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    check=True
                )
                return result.stdout
            except subprocess.SubprocessError as e2:
                logger.error(f"Failed to get logs using direct docker command: {e2}")
                return f"Failed to get logs: {e}, {e2}"