"""
mDoc Engine Service
This module serves as the entry point for the Mobile Document (mDoc) engine service.
It initializes the gRPC server and handles mDoc creation, signing, and verification.
"""

import logging
import sys
import time
from pathlib import Path
from typing import Callable

# Ensure we can import from the parent directory
sys.path.append(str(Path(__file__).resolve().parents[3]))

# Import shared utilities
from marty_common.services import BaseGrpcService
from marty_common.config import ConfigurationManager

# Import the mDoc Engine service implementation and protobuf generated files
from src.proto import mdoc_engine_pb2_grpc  # Correct import for gRPC add_servicer_to_server
from src.services.mdoc_engine import (
    MDocEngineServicer,  # Corrected: MDocEngineServicer from service.py
)

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
    logger.info("Creating database tables for mDoc Engine...")
    Base.metadata.create_all(bind=engine)  # MobileDocument is registered with Base
    logger.info("Database tables created successfully.")


class MDocGrpcService(BaseGrpcService):
    """MDoc Engine gRPC service using BaseGrpcService."""

    def create_servicer(self) -> MDocEngineServicer:
        """Create the MDoc Engine servicer instance."""
        return MDocEngineServicer()

    def get_add_servicer_function(self) -> Callable:
        """Get the function to add the servicer to the server."""
        return mdoc_engine_pb2_grpc.add_MDocEngineServicer_to_server


def serve_grpc() -> None:
    """
    Start the gRPC server for the mDoc Engine service using BaseGrpcService.
    """
    port = config_manager.get_env_int("GRPC_PORT", 8086)  # Using the port from docker-compose

    # Create the service
    service = MDocGrpcService(
        service_name="mdoc-engine",
        default_port=port,
        max_workers=10
    )

    # Start the server
    service.start_server()


# Note: The MDocEngineService class itself is defined in src/services/mdoc_engine.py
# This main.py is just the entry point to start the server.

if __name__ == "__main__":
    logger.info("Starting mDoc Engine service...")

    # Initialize database
    try:
        create_db_and_tables()
    except Exception:
        logger.exception("Error initializing database for mDoc Engine")
        sys.exit(1)

    # Wait for dependencies (similar to mdl_engine)
    wait_for_deps = config_manager.get_env_bool("WAIT_FOR_DEPENDENCIES", False)
    if wait_for_deps:
        wait_time = config_manager.get_env_int("DEPENDENCY_WAIT_TIME", 5)
        logger.info(f"Waiting for dependencies for {wait_time} seconds...")
        time.sleep(wait_time)

    try:
        serve_grpc()
    except Exception:
        logger.exception("Error starting mDoc Engine service")
        sys.exit(1)
