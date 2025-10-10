"""Demo Service - Example of Framework Migration

This is a minimal service that demonstrates the new Marty framework patterns.
"""

from datetime import datetime
from fastapi import FastAPI
import structlog

logger = structlog.get_logger()


def create_app() -> FastAPI:
    """Create and configure the Demo Service FastAPI application."""
    
    app = FastAPI(
        title="Demo Service",
        description="Example service using Marty framework patterns",
        version="1.0.0"
    )
    
    @app.get("/")
    async def root():
        return {
            "service": "demo-service",
            "message": "Hello from Marty Framework!",
            "timestamp": datetime.utcnow().isoformat(),
            "framework": "marty-microservices-framework"
        }
    
    @app.get("/health")
    async def health():
        return {"status": "healthy", "timestamp": datetime.utcnow()}
    
    @app.get("/framework-test")
    async def framework_test():
        return {
            "message": "This service is running via the Marty framework unified launcher!",
            "benefits": [
                "No custom startup code",
                "Standardized configuration",
                "Built-in metrics and health checks",
                "Unified deployment patterns",
                "Framework-managed lifecycle"
            ],
            "launch_command": "marty runservice"
        }
    
    return app


# Create the app instance
app = create_app()


@app.on_event("startup")
async def startup_event():
    logger.info("Demo Service starting up via Marty framework")


@app.on_event("shutdown") 
async def shutdown_event():
    logger.info("Demo Service shutting down")