#!/usr/bin/env python3
"""Quick start script for Trust Service development.

This script helps developers quickly set up and run the Trust Service by:
1. Installing dependencies
2. Compiling Protocol Buffers
3. Setting up the database
4. Running the service

Usage:
    python quickstart.py [--dev|--prod]
"""

import argparse
import asyncio
import logging
import subprocess
import sys
from pathlib import Path

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


def run_command(cmd: str, cwd: Path | None = None) -> bool:
    """Run a shell command and return success status."""
    try:
        logger.info(f"Running: {cmd}")
        result = subprocess.run(
            cmd, shell=True, cwd=cwd, check=True, capture_output=True, text=True
        )
        if result.stdout:
            logger.info(result.stdout)
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed: {cmd}")
        logger.error(f"Error: {e.stderr}")
        return False


def install_dependencies():
    """Install Python dependencies."""
    logger.info("Installing dependencies...")
    return run_command("pip install -r requirements.txt")


def compile_protobuf():
    """Compile Protocol Buffer definitions."""
    logger.info("Compiling Protocol Buffers...")
    return run_command("python compile_protos.py")


def setup_database():
    """Set up database with migrations."""
    logger.info("Setting up database...")
    # Note: This would run Alembic migrations in a real setup
    logger.info("Database setup placeholder - run Alembic migrations manually")
    return True


def run_service(dev_mode: bool = True):
    """Run the Trust Service."""
    if dev_mode:
        logger.info("Starting Trust Service in development mode...")
        cmd = "python -m uvicorn main:app --reload --host 0.0.0.0 --port 8080"
    else:
        logger.info("Starting Trust Service in production mode...")
        cmd = "python main.py"

    return run_command(cmd)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Trust Service Quick Start")
    parser.add_argument("--dev", action="store_true", help="Run in development mode")
    parser.add_argument("--prod", action="store_true", help="Run in production mode")
    parser.add_argument("--skip-deps", action="store_true", help="Skip dependency installation")
    parser.add_argument("--skip-proto", action="store_true", help="Skip protobuf compilation")
    parser.add_argument("--skip-db", action="store_true", help="Skip database setup")

    args = parser.parse_args()

    # Determine mode
    dev_mode = not args.prod
    if args.dev:
        dev_mode = True

    logger.info(
        f"Starting Trust Service quick start ({'development' if dev_mode else 'production'} mode)"
    )

    # Step 1: Install dependencies
    if not args.skip_deps:
        if not install_dependencies():
            logger.error("Failed to install dependencies")
            sys.exit(1)

    # Step 2: Compile protobuf
    if not args.skip_proto:
        if not compile_protobuf():
            logger.warning("Failed to compile Protocol Buffers - gRPC features may not work")

    # Step 3: Setup database
    if not args.skip_db:
        if not setup_database():
            logger.error("Failed to set up database")
            sys.exit(1)

    # Step 4: Run service
    logger.info("Setup complete! Starting service...")
    if not run_service(dev_mode):
        logger.error("Failed to start service")
        sys.exit(1)


if __name__ == "__main__":
    main()
