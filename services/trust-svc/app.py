"""FastAPI application factory for Trust Service."""

import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse

from .api import router as api_router
from .config import settings
from .database import close_database, init_database
from .metrics import init_metrics

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan management."""
    # Startup
    logger.info("Starting Trust Service...")

    try:
        # Initialize database
        await init_database()

        # Initialize metrics
        init_metrics()

        logger.info("Trust Service started successfully")

        yield

    except Exception as e:
        logger.error(f"Failed to start Trust Service: {e}")
        raise

    finally:
        # Shutdown
        logger.info("Shutting down Trust Service...")
        await close_database()
        logger.info("Trust Service shutdown complete")


def create_app() -> FastAPI:
    """Create and configure FastAPI application."""

    app = FastAPI(
        title="Trust Service",
        description="PKD/HML ingestion and trust management microservice",
        version="1.0.0",
        docs_url="/docs" if settings.debug else None,
        redoc_url="/redoc" if settings.debug else None,
        openapi_url="/openapi.json" if settings.debug else None,
        lifespan=lifespan,
    )

    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=settings.cors_methods,
        allow_headers=settings.cors_headers,
    )

    # Add trusted host middleware for production
    if settings.environment.value == "production":
        app.add_middleware(
            TrustedHostMiddleware,
            allowed_hosts=["*"],  # Configure this properly in production
        )

    # Global exception handler
    @app.exception_handler(Exception)
    async def global_exception_handler(request, exc):
        logger.error(f"Unhandled exception: {exc}", exc_info=True)
        return JSONResponse(status_code=500, content={"detail": "Internal server error"})

    # Health check endpoint
    @app.get("/health", tags=["Health"])
    async def health_check():
        """Health check endpoint."""
        return {"status": "healthy", "service": "trust-svc"}

    # Ready check endpoint
    @app.get("/ready", tags=["Health"])
    async def ready_check():
        """Readiness check endpoint."""
        # Add database connectivity check here
        return {"status": "ready", "service": "trust-svc"}

    # Include API router
    app.include_router(api_router, prefix="/api/v1", tags=["Trust API"])

    return app
