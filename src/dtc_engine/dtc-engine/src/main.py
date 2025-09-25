import logging
import os
import sys
from concurrent import futures

import grpc

# Add the parent directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# Import DTC engine servicer
from dtc_engine_service import DTCEngineService
from marty_common.config import Config
from src.proto import dtc_engine_pb2_grpc


def serve() -> None:
    """Start the gRPC server."""
    # Configure logging
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    logger = logging.getLogger(__name__)

    # Get port from environment variable or use default
    port = os.environ.get("GRPC_PORT", "8087")

    # Load configuration
    config_env = os.environ.get("ENV", "development")
    config = Config(config_env)

    # Create gRPC server with 10 workers
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))

    # Add DTC engine servicer to server
    dtc_engine_servicer = DTCEngineService(config)
    dtc_engine_pb2_grpc.add_DTCEngineServicer_to_server(dtc_engine_servicer, server)

    # Add insecure port
    server.add_insecure_port(f"[::]:{port}")

    # Start server
    server.start()
    logger.info(f"DTC Engine service listening on port {port}")

    # Keep server running until terminated
    server.wait_for_termination()


if __name__ == "__main__":
    serve()
