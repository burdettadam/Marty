"""
mDoc Engine Service
This module serves as the entry point for the Mobile Document (mDoc) engine service.
It initializes the gRPC server and handles mDoc creation, signing, and verification.
"""

import logging
import os
import sys
import time
from concurrent import futures

import grpc

# Ensure we can import from the parent directory
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# Import the mDoc Engine service implementation and protobuf generated files
from src.proto import mdoc_engine_pb2_grpc  # Correct import for gRPC add_servicer_to_server
from src.services.mdoc_engine import (
    MDocEngineServicer,  # Corrected: MDocEngineServicer from service.py
)

# Import database utility and models
from src.shared.database import Base, engine

# Configure logging globally for the main script
log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
logging.basicConfig(level=getattr(logging, log_level, logging.INFO), format=log_format)
logger = logging.getLogger(__name__)


def create_db_and_tables() -> None:
    """Creates database tables."""
    logger.info("Creating database tables for mDoc Engine...")
    Base.metadata.create_all(bind=engine)  # MobileDocument is registered with Base
    logger.info("Database tables created successfully.")


def serve_grpc() -> (
    None
):  # Renamed from 'serve' to avoid conflict if original 'serve' was different
    """
    Start the gRPC server for the mDoc Engine service.
    """
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    # The MDocEngineServicer class is defined in src.services.mdoc_engine
    mdoc_engine_pb2_grpc.add_MDocEngineServicer_to_server(MDocEngineServicer(), server)

    port = os.getenv("GRPC_PORT", "8086")  # Using the port from docker-compose
    server.add_insecure_port(f"[::]:{port}")

    logger.info(f"mDoc Engine Service started on port {port}...")
    server.start()
    server.wait_for_termination()


# Note: The MDocEngineService class itself is defined in src/services/mdoc_engine.py
# This main.py is just the entry point to start the server.

if __name__ == "__main__":
    logger.info("Starting mDoc Engine service...")

    # Initialize database
    try:
        create_db_and_tables()
    except Exception as e:
        logger.exception("Error initializing database for mDoc Engine: %s", str(e))
        sys.exit(1)

    # Wait for dependencies (similar to mdl_engine)
    if os.getenv("WAIT_FOR_DEPENDENCIES", "false").lower() == "true":
        wait_time = int(os.getenv("DEPENDENCY_WAIT_TIME", "5"))
        logger.info(f"Waiting for dependencies for {wait_time} seconds...")
        time.sleep(wait_time)

    try:
        serve_grpc()
    except Exception as e:
        logger.exception("Error starting mDoc Engine service: %s", str(e))
        sys.exit(1)
