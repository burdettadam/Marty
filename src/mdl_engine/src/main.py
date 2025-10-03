"""
MDL Engine Service
This module serves as the entry point for the Mobile Driving License (MDL) engine service.
It initializes the gRPC server and handles MDL creation, signing, and verification.
"""

import logging
import sys
import time
from pathlib import Path

# Ensure we can import from the parent directory
sys.path.append(str(Path(__file__).resolve().parents[3]))

# Import shared utilities\nfrom marty_common.config import ConfigurationManager

# Import the MDL Engine service implementation
from src.services.mdl_engine import serve

# Import database utility and models
from src.shared.database import Base, engine

# Configure logging globally for the main script
config_manager = ConfigurationManager()
log_level = config_manager.get_env_list("LOG_LEVEL", default=["INFO"])[0].upper()
log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
logging.basicConfig(level=getattr(logging, log_level, logging.INFO), format=log_format)
logger = logging.getLogger(__name__)


def create_db_and_tables() -> None:
    """Creates database tables."""
    logger.info("Creating database tables for MDL Engine...")
    Base.metadata.create_all(bind=engine)  # MobileDrivingLicense is registered with Base
    logger.info("Database tables created successfully.")


def main() -> None:
    """
    Configure logging and start the MDL Engine service.
    """
    logger.info("Starting MDL Engine service...")

    # Initialize database
    try:
        create_db_and_tables()
    except Exception:
        logger.exception("Error initializing database for MDL Engine")
        sys.exit(1)

    # Wait for dependencies if specified via environment variables
    wait_for_deps = config_manager.get_env_bool("WAIT_FOR_DEPENDENCIES", False)
    if wait_for_deps:
        logger.info("Waiting for dependencies to be available...")
        wait_time = config_manager.get_env_int("DEPENDENCY_WAIT_TIME", 5)
        time.sleep(wait_time)

    try:
        # Start the gRPC server
        serve()
    except Exception:
        logger.exception("Error starting MDL Engine service")
        sys.exit(1)


if __name__ == "__main__":
    main()
