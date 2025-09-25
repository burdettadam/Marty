"""
MDL Engine Service
This module serves as the entry point for the Mobile Driving License (MDL) engine service.
It initializes the gRPC server and handles MDL creation, signing, and verification.
"""

import logging
import os
import sys
import time

# Ensure we can import from the parent directory
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# Import the MDL Engine service implementation
from src.services.mdl_engine import serve

# Import database utility and models
from src.shared.database import Base, engine

# Configure logging globally for the main script
log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
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
    except Exception as e:
        logger.exception("Error initializing database for MDL Engine: %s", str(e))
        sys.exit(1)

    # Wait for dependencies if specified via environment variables
    if os.environ.get("WAIT_FOR_DEPENDENCIES", "false").lower() == "true":
        logger.info("Waiting for dependencies to be available...")
        time.sleep(int(os.environ.get("DEPENDENCY_WAIT_TIME", "5")))

    try:
        # Start the gRPC server
        serve()
    except Exception as e:
        logger.exception("Error starting MDL Engine service: %s", str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()
