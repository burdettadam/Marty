"""Trust Service main application entry point."""

import asyncio
import logging
import signal
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from prometheus_client import start_http_server

from .app import create_app
from .config import settings
from .database import init_database
from .grpc_server import serve_grpc
from .metrics import init_metrics

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan management."""
    # Startup
    logger.info("Starting Trust Service...")

    # Initialize database
    await init_database()

    # Initialize metrics
    init_metrics()

    # Start Prometheus metrics server
    if settings.metrics_enabled:
        start_http_server(settings.metrics_port)
        logger.info(f"Metrics server started on port {settings.metrics_port}")

    logger.info("Trust Service started successfully")

    yield

    # Shutdown
    logger.info("Shutting down Trust Service...")


async def run_servers():
    """Run both FastAPI and gRPC servers concurrently."""
    # Create FastAPI app
    app = create_app()

    # Configure uvicorn
    config = uvicorn.Config(
        app,
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level.lower(),
        access_log=settings.access_log,
        lifespan="on",
    )

    # Create server instance
    server = uvicorn.Server(config)

    # Start both servers concurrently
    logger.info(f"Starting FastAPI server on {settings.host}:{settings.port}")
    logger.info(f"Starting gRPC server on port {settings.grpc_port}")

    await asyncio.gather(server.serve(), serve_grpc(), return_exceptions=True)


def main() -> None:
    """Main application entry point."""
    # Setup signal handlers for graceful shutdown
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    def signal_handler(signum, frame):
        logger.info(f"Received signal {signum}, shutting down...")
        loop.stop()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Run both servers
    try:
        loop.run_until_complete(run_servers())
    except KeyboardInterrupt:
        logger.info("Received shutdown signal")
    except Exception as e:
        logger.error(f"Application error: {e}")
    finally:
        loop.close()


if __name__ == "__main__":
    main()
