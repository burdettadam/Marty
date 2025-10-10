"""Trust Service - Migrated to use Marty Framework patterns.

This service has been refactored to eliminate custom startup code and use the
unified Marty framework service launcher instead. The startup logic has been
moved to FastAPI lifecycle events, and the service can now be launched using:

    marty runservice

For more information, see MIGRATION_GUIDE.md in the framework repository.
"""

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from prometheus_client import start_http_server

from .app import create_app as _create_base_app
from .config import settings
from .database import init_database
from .metrics import init_metrics

logger = logging.getLogger(__name__)


def create_app() -> FastAPI:
    """Create and configure the Trust Service FastAPI application.
    
    This function replaces the old main() and run_servers() patterns.
    The framework will call this function and manage the server lifecycle.
    """
    
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
    
    # Create the base app with the lifespan
    app = _create_base_app()
    app.router.lifespan_context = lifespan
    
    return app


# Create the app instance - this is what the framework will import and run
app = create_app()


# Optional: Add additional lifecycle events if needed
@app.on_event("startup")
async def startup_event():
    """Additional startup logic if needed."""
    logger.info("Trust Service FastAPI startup event")


@app.on_event("shutdown") 
async def shutdown_event():
    """Additional shutdown logic if needed."""
    logger.info("Trust Service FastAPI shutdown event")


# Note: The original main() function and custom server orchestration has been removed.
# The framework will handle:
# - Signal handling (SIGINT, SIGTERM)
# - Server configuration (host, port, workers, etc.)
# - gRPC server coordination (if enabled in config.yaml)
# - Uvicorn configuration and startup
# - Development features (reload, debug logging)
#
# To run this service:
# 1. cd /path/to/trust-svc
# 2. marty runservice
#
# Or with specific configuration:
# marty runservice --config config/production.yaml --environment production