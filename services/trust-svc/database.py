"""Database management for Trust Service with enhanced security."""

import logging
import ssl
import asyncio
from typing import AsyncGenerator, Optional, Dict, Any
from datetime import datetime, timedelta
import os

from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import (
    AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
)
from sqlalchemy.pool import NullPool
from cryptography.fernet import Fernet

from .config import settings
from .models import Base

logger = logging.getLogger(__name__)

# Global database components
engine: Optional[AsyncEngine] = None
async_session_factory: Optional[async_sessionmaker[AsyncSession]] = None


def create_database_engine() -> AsyncEngine:
    """Create database engine with proper configuration."""
    if not settings.database_url:
        raise ValueError("DATABASE_URL is required")
    
    # Configure engine with connection pooling
    engine_kwargs = {
        "url": settings.database_url,
        "echo": settings.debug,
        "pool_size": settings.database_pool_size,
        "max_overflow": settings.database_pool_overflow,
        "pool_timeout": settings.database_timeout,
        "pool_pre_ping": True,  # Verify connections before use
    }
    
    # Use NullPool for testing environments
    if settings.environment.value == "testing":
        engine_kwargs["poolclass"] = NullPool
    
    db_engine = create_async_engine(**engine_kwargs)
    
    # Add connection event listeners for debugging
    if settings.debug:
        @event.listens_for(db_engine.sync_engine, "connect")
        def receive_connect(dbapi_connection, connection_record):
            logger.debug("Database connection established")
        
        @event.listens_for(db_engine.sync_engine, "checkout")
        def receive_checkout(dbapi_connection, connection_record, connection_proxy):
            logger.debug("Database connection checked out from pool")
    
    return db_engine


async def init_database() -> None:
    """Initialize database connection and create tables."""
    global engine, async_session_factory
    
    logger.info("Initializing database connection...")
    
    try:
        engine = create_database_engine()
        
        # Create session factory
        async_session_factory = async_sessionmaker(
            engine,
            class_=AsyncSession,
            expire_on_commit=False
        )
        
        # Test connection
        async with engine.begin() as conn:
            await conn.execute(text("SELECT 1"))
            logger.info("Database connection established successfully")
        
        # Create schema if it doesn't exist
        async with engine.begin() as conn:
            await conn.execute(text("CREATE SCHEMA IF NOT EXISTS trust_svc"))
            logger.info("Database schema ensured")
        
        # Create tables (in production, use Alembic migrations instead)
        if settings.environment.value == "development":
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
                logger.info("Database tables created")
        
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        raise


async def get_async_session() -> AsyncGenerator[AsyncSession, None]:
    """Get async database session."""
    if not async_session_factory:
        raise RuntimeError("Database not initialized")
    
    async with async_session_factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def close_database() -> None:
    """Close database connections."""
    global engine
    
    if engine:
        await engine.dispose()
        logger.info("Database connections closed")


class DatabaseManager:
    """Database manager for dependency injection."""
    
    def __init__(self):
        self.engine = engine
        self.session_factory = async_session_factory
    
    async def get_session(self) -> AsyncGenerator[AsyncSession, None]:
        """Get database session."""
        async for session in get_async_session():
            yield session
    
    async def health_check(self) -> bool:
        """Check database health."""
        try:
            async with self.session_factory() as session:
                await session.execute(text("SELECT 1"))
                return True
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return False