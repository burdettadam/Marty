"""
None

This is a FastAPI service generated from the Marty Ultra-DRY service template.
It automatically uses all established DRY patterns:
- Service Configuration Factory for centralized config
- Standardized FastAPI setup patterns
- Auto-configuration from environment
- Ultra-DRY testing patterns ready
"""

import uvicorn
from fastapi import FastAPI

from marty_common.logging_config import get_logger
from marty_common.service_config_factory import get_config_manager, get_service_config
from src.test_service.app.api.routes import router
from src.test_service.app.core.error_handlers import setup_error_handlers
from src.test_service.app.core.middleware import setup_middleware

# Get configuration and logger using DRY factory
config_manager = get_config_manager("test-service")
logger = get_logger(__name__)


def create_app() -> FastAPI:
    """
    Create FastAPI application with Ultra-DRY patterns.

    This automatically sets up:
    - Configuration from Service Configuration Factory
    - Standard middleware (CORS, logging, etc.)
    - Error handling patterns
    - OpenAPI documentation
    - Health check endpoints
    - Auto-configured from service defaults
    """
    # Get service configuration using DRY factory
    service_config = get_service_config("test-service", "fastapi")

    # Initialize FastAPI with DRY configuration
    app = FastAPI(
        title=service_config.get("service_description", "None"),
        version="1.0.0",
        debug=service_config.get("debug", False),
        docs_url="/docs" if service_config.get("docs_enabled", True) else None,
        redoc_url="/redoc" if service_config.get("docs_enabled", True) else None,
    )

    # Setup DRY patterns
    setup_middleware(app, service_config)
    setup_error_handlers(app)

    # Include API routes
    app.include_router(router, prefix="/api/v1")

    # Setup logging using DRY patterns
    config.setup_logging()

    return app


def main() -> None:
    """Run the FastAPI application."""
    app = create_app()
    config = create_test_service_config()

    # Run with uvicorn using DRY configuration
    uvicorn.run(
        app,
        host=config.host,
        port=config.http_port,
        log_level=config.log_level.lower(),
        reload=config.debug,
    )


if __name__ == "__main__":
    main()
