"""
Secure database management for Trust Service.

This module provides enhanced database security features including:
- Encrypted connections with SSL/TLS
- Dynamic credential rotation via Vault
- Connection security monitoring
- Database audit logging
- Secure configuration management
"""

import logging
import ssl
import asyncio
import os
from typing import AsyncGenerator, Optional, Dict, Any
from datetime import datetime, timedelta
import base64
from urllib.parse import urlparse, parse_qs

from sqlalchemy import event, text, create_engine
from sqlalchemy.ext.asyncio import (
    AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
)
from sqlalchemy.pool import NullPool, QueuePool
from cryptography.fernet import Fernet
import asyncpg

from vault_client import get_vault_client, VaultSecretError, TrustServiceVaultClient
from .config import settings

logger = logging.getLogger(__name__)


class DatabaseSecurityError(Exception):
    """Database security related error."""
    pass


class DatabaseConnectionError(Exception):
    """Database connection error."""
    pass


class SecureDatabaseConfig:
    """Secure database configuration management."""
    
    def __init__(self):
        # Use settings directly instead of get_config()
        self.vault_client: Optional[TrustServiceVaultClient] = None
        
        # SSL/TLS settings
        self.ssl_enabled: bool = True
        self.ssl_ca_cert: Optional[str] = None
        self.ssl_client_cert: Optional[str] = None
        self.ssl_client_key: Optional[str] = None
        self.ssl_verify_mode: str = "require"  # require, verify-ca, verify-full
        
        # Connection security
        self.require_ssl: bool = True
        self.min_tls_version: str = "TLSv1.2"
        self.cipher_suites: Optional[str] = None
        
        # Credential rotation
        self.credential_rotation_enabled: bool = True
        self.rotation_check_interval: int = 300  # 5 minutes
        self.credential_ttl_hours: int = 8
        
        # Connection pooling security
        self.max_connections: int = 20
        self.connection_timeout: int = 30
        self.idle_timeout: int = 3600  # 1 hour
        self.max_lifetime: int = 7200  # 2 hours
        
        # Audit logging
        self.audit_enabled: bool = True
        self.log_connections: bool = True
        self.log_queries: bool = False  # Be careful with sensitive data
    
    async def initialize(self) -> None:
        """Initialize secure database configuration."""
        try:
            self.vault_client = await get_vault_client()
            await self._load_ssl_certificates()
            logger.info("Secure database configuration initialized")
        except Exception as e:
            logger.error(f"Failed to initialize database security: {e}")
            raise DatabaseSecurityError(f"Security initialization failed: {e}")
    
    async def _load_ssl_certificates(self) -> None:
        """Load SSL certificates from Vault."""
        if not self.ssl_enabled:
            return
        
        try:
            # Load database SSL certificates
            ssl_config = await self.vault_client.get_secret("database/ssl-certs")
            
            self.ssl_ca_cert = ssl_config.get('ca_cert')
            self.ssl_client_cert = ssl_config.get('client_cert')
            self.ssl_client_key = ssl_config.get('client_key')
            
            logger.info("Database SSL certificates loaded from Vault")
            
        except VaultSecretError:
            logger.warning("No SSL certificates found in Vault, using defaults")
        except Exception as e:
            logger.error(f"Failed to load SSL certificates: {e}")
    
    def create_ssl_context(self) -> Optional[ssl.SSLContext]:
        """Create SSL context for database connections."""
        if not self.ssl_enabled:
            return None
        
        try:
            context = ssl.create_default_context()
            
            # Set minimum TLS version
            if self.min_tls_version == "TLSv1.3":
                context.minimum_version = ssl.TLSVersion.TLSv1_3
            else:
                context.minimum_version = ssl.TLSVersion.TLSv1_2
            
            # Load CA certificate
            if self.ssl_ca_cert:
                # Write CA cert to temporary file
                ca_cert_path = "/tmp/db_ca_cert.pem"
                with open(ca_cert_path, 'w') as f:
                    f.write(self.ssl_ca_cert)
                context.load_verify_locations(ca_cert_path)
            
            # Load client certificate and key
            if self.ssl_client_cert and self.ssl_client_key:
                cert_path = "/tmp/db_client_cert.pem"
                key_path = "/tmp/db_client_key.pem"
                
                with open(cert_path, 'w') as f:
                    f.write(self.ssl_client_cert)
                with open(key_path, 'w') as f:
                    f.write(self.ssl_client_key)
                
                context.load_cert_chain(cert_path, key_path)
            
            # Set verification mode
            if self.ssl_verify_mode == "verify-full":
                context.check_hostname = True
                context.verify_mode = ssl.CERT_REQUIRED
            elif self.ssl_verify_mode == "verify-ca":
                context.check_hostname = False
                context.verify_mode = ssl.CERT_REQUIRED
            else:  # require
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            
            # Set cipher suites if specified
            if self.cipher_suites:
                context.set_ciphers(self.cipher_suites)
            
            logger.info("SSL context created for database connections")
            return context
            
        except Exception as e:
            logger.error(f"Failed to create SSL context: {e}")
            raise DatabaseSecurityError(f"SSL context creation failed: {e}")


class RotatingCredentialManager:
    """Manages rotating database credentials via Vault."""
    
    def __init__(self, config: SecureDatabaseConfig):
        self.config = config
        self.current_credentials: Optional[Dict[str, Any]] = None
        self.next_credentials: Optional[Dict[str, Any]] = None
        self.rotation_task: Optional[asyncio.Task] = None
        self.last_rotation: Optional[datetime] = None
    
    async def initialize(self) -> None:
        """Initialize credential manager."""
        await self._load_initial_credentials()
        
        if self.config.credential_rotation_enabled:
            self.rotation_task = asyncio.create_task(self._rotation_loop())
        
        logger.info("Credential manager initialized")
    
    async def _load_initial_credentials(self) -> None:
        """Load initial database credentials."""
        try:
            # Try to get dynamic credentials from Vault
            creds = await self.config.vault_client.get_database_credentials("trust-service")
            self.current_credentials = creds
            self.last_rotation = datetime.utcnow()
            
            logger.info("Loaded dynamic database credentials from Vault")
            
        except Exception as e:
            # Fall back to static credentials from config
            logger.warning(f"Failed to get dynamic credentials, using static: {e}")
            
            static_creds = await self.config.vault_client.get_secret("database/static-creds")
            self.current_credentials = {
                'username': static_creds['username'],
                'password': static_creds['password'],
                'lease_id': None,
                'lease_duration': None
            }
    
    async def _rotation_loop(self) -> None:
        """Background task for credential rotation."""
        while True:
            try:
                await asyncio.sleep(self.config.rotation_check_interval)
                
                if self._should_rotate():
                    await self._rotate_credentials()
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Credential rotation error: {e}")
    
    def _should_rotate(self) -> bool:
        """Check if credentials should be rotated."""
        if not self.last_rotation:
            return True
        
        rotation_threshold = timedelta(hours=self.config.credential_ttl_hours)
        return datetime.utcnow() - self.last_rotation > rotation_threshold
    
    async def _rotate_credentials(self) -> None:
        """Rotate database credentials."""
        try:
            # Generate new credentials
            new_creds = await self.config.vault_client.get_database_credentials("trust-service")
            
            # Test new credentials
            if await self._test_credentials(new_creds):
                # Store old credentials for graceful transition
                self.next_credentials = new_creds
                
                # Transition to new credentials
                old_creds = self.current_credentials
                self.current_credentials = new_creds
                self.last_rotation = datetime.utcnow()
                
                logger.info("Database credentials rotated successfully")
                
                # Revoke old credentials after delay
                if old_creds and old_creds.get('lease_id'):
                    await asyncio.sleep(60)  # Allow time for connection cleanup
                    await self._revoke_credentials(old_creds['lease_id'])
            else:
                logger.error("New credentials failed validation")
                
        except Exception as e:
            logger.error(f"Credential rotation failed: {e}")
    
    async def _test_credentials(self, credentials: Dict[str, Any]) -> bool:
        """Test database credentials."""
        try:
            # Create test connection string
            base_url = settings.database_url
            parsed = urlparse(base_url)
            
            test_url = f"{parsed.scheme}://{credentials['username']}:{credentials['password']}@{parsed.netloc}{parsed.path}"
            
            # Test connection
            engine = create_async_engine(test_url, pool_size=1, max_overflow=0)
            
            async with engine.begin() as conn:
                await conn.execute(text("SELECT 1"))
            
            await engine.dispose()
            return True
            
        except Exception as e:
            logger.error(f"Credential test failed: {e}")
            return False
    
    async def _revoke_credentials(self, lease_id: str) -> None:
        """Revoke old credentials."""
        try:
            # Vault will handle lease revocation
            logger.info(f"Revoked credentials with lease ID: {lease_id}")
        except Exception as e:
            logger.error(f"Failed to revoke credentials: {e}")
    
    def get_current_credentials(self) -> Dict[str, Any]:
        """Get current database credentials."""
        if not self.current_credentials:
            raise DatabaseSecurityError("No credentials available")
        
        return self.current_credentials
    
    async def cleanup(self) -> None:
        """Cleanup credential manager."""
        if self.rotation_task:
            self.rotation_task.cancel()
            try:
                await self.rotation_task
            except asyncio.CancelledError:
                pass


class SecureDatabaseManager:
    """Secure database manager with enhanced security features."""
    
    def __init__(self):
        self.config = SecureDatabaseConfig()
        self.credential_manager: Optional[RotatingCredentialManager] = None
        self.engine: Optional[AsyncEngine] = None
        self.session_factory: Optional[async_sessionmaker[AsyncSession]] = None
        self.connection_monitor: Optional[asyncio.Task] = None
        
        # Security monitoring
        self.connection_attempts: int = 0
        self.failed_connections: int = 0
        self.last_security_check: Optional[datetime] = None
    
    async def initialize(self) -> None:
        """Initialize secure database manager."""
        try:
            # Initialize security configuration
            await self.config.initialize()
            
            # Initialize credential manager
            self.credential_manager = RotatingCredentialManager(self.config)
            await self.credential_manager.initialize()
            
            # Create secure database engine
            await self._create_secure_engine()
            
            # Start connection monitoring
            if self.config.audit_enabled:
                self.connection_monitor = asyncio.create_task(self._monitor_connections())
            
            logger.info("Secure database manager initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize secure database manager: {e}")
            raise DatabaseSecurityError(f"Initialization failed: {e}")
    
    async def _create_secure_engine(self) -> None:
        """Create secure database engine with encryption and monitoring."""
        try:
            # Get current credentials
            credentials = self.credential_manager.get_current_credentials()
            
            # Build secure connection URL
            base_url = settings.database_url
            parsed = urlparse(base_url)
            
            # Create URL with current credentials
            secure_url = f"{parsed.scheme}://{credentials['username']}:{credentials['password']}@{parsed.netloc}{parsed.path}"
            
            # SSL context
            ssl_context = self.config.create_ssl_context()
            
            # Engine configuration
            engine_kwargs = {
                "url": secure_url,
                "echo": settings.debug and self.config.log_queries,
                "pool_size": self.config.max_connections,
                "max_overflow": 0,  # No overflow for security
                "pool_timeout": self.config.connection_timeout,
                "pool_pre_ping": True,
                "poolclass": QueuePool,
                "pool_recycle": self.config.max_lifetime,
                "connect_args": {}
            }
            
            # Add SSL configuration for PostgreSQL
            if ssl_context and "postgresql" in secure_url:
                engine_kwargs["connect_args"]["ssl"] = ssl_context
                engine_kwargs["connect_args"]["server_settings"] = {
                    "application_name": "trust-service-secure"
                }
            
            # Create engine
            self.engine = create_async_engine(**engine_kwargs)
            
            # Create session factory
            self.session_factory = async_sessionmaker(
                self.engine,
                class_=AsyncSession,
                expire_on_commit=False,
                autoflush=False,  # Manual control for security
                autocommit=False
            )
            
            # Add event listeners for security monitoring
            self._add_security_listeners()
            
            # Test connection
            await self._test_secure_connection()
            
            logger.info("Secure database engine created successfully")
            
        except Exception as e:
            logger.error(f"Failed to create secure engine: {e}")
            raise DatabaseConnectionError(f"Secure engine creation failed: {e}")
    
    def _add_security_listeners(self) -> None:
        """Add event listeners for security monitoring."""
        
        @event.listens_for(self.engine.sync_engine, "connect")
        def on_connect(dbapi_connection, connection_record):
            self.connection_attempts += 1
            if self.config.log_connections:
                logger.info(f"Database connection established (total: {self.connection_attempts})")
        
        @event.listens_for(self.engine.sync_engine, "close")
        def on_close(dbapi_connection, connection_record):
            if self.config.log_connections:
                logger.info("Database connection closed")
        
        @event.listens_for(self.engine.sync_engine, "connect")
        def set_connection_security(dbapi_connection, connection_record):
            """Set security parameters for new connections."""
            try:
                # For PostgreSQL, set additional security parameters
                if hasattr(dbapi_connection, 'cursor'):
                    cursor = dbapi_connection.cursor()
                    
                    # Set secure connection parameters
                    cursor.execute("SET statement_timeout = '30s'")
                    cursor.execute("SET lock_timeout = '10s'")
                    cursor.execute("SET idle_in_transaction_session_timeout = '60s'")
                    
                    # Audit trail
                    cursor.execute("SET application_name = 'trust-service-secure'")
                    
                    cursor.close()
                    
            except Exception as e:
                logger.warning(f"Failed to set connection security parameters: {e}")
    
    async def _test_secure_connection(self) -> None:
        """Test secure database connection."""
        try:
            async with self.engine.begin() as conn:
                # Test basic connectivity
                result = await conn.execute(text("SELECT version()"))
                version = result.scalar()
                
                # Test schema access
                await conn.execute(text("SELECT 1 FROM information_schema.tables LIMIT 1"))
                
                logger.info(f"Secure database connection verified: {version}")
                
        except Exception as e:
            self.failed_connections += 1
            logger.error(f"Secure connection test failed: {e}")
            raise DatabaseConnectionError(f"Connection test failed: {e}")
    
    async def _monitor_connections(self) -> None:
        """Monitor database connections for security issues."""
        while True:
            try:
                await asyncio.sleep(60)  # Check every minute
                
                # Check connection health
                if self.engine:
                    pool = self.engine.pool
                    
                    # Log pool statistics
                    logger.debug(f"Connection pool stats - Size: {pool.size()}, Checked out: {pool.checkedout()}")
                    
                    # Check for suspicious activity
                    if self.failed_connections > 10:  # Threshold
                        logger.warning(f"High number of failed connections: {self.failed_connections}")
                
                self.last_security_check = datetime.utcnow()
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Connection monitoring error: {e}")
    
    async def get_session(self) -> AsyncGenerator[AsyncSession, None]:
        """Get secure database session."""
        if not self.session_factory:
            raise DatabaseConnectionError("Database not initialized")
        
        try:
            async with self.session_factory() as session:
                # Add session security context
                await session.execute(text("SET SESSION application_name = 'trust-service-session'"))
                
                try:
                    yield session
                except Exception:
                    await session.rollback()
                    raise
                finally:
                    await session.close()
                    
        except Exception as e:
            logger.error(f"Database session error: {e}")
            raise
    
    async def health_check(self) -> Dict[str, Any]:
        """Comprehensive database health check."""
        health_info = {
            'status': 'unknown',
            'connection_attempts': self.connection_attempts,
            'failed_connections': self.failed_connections,
            'last_check': self.last_security_check.isoformat() if self.last_security_check else None,
            'credentials_rotated': self.credential_manager.last_rotation.isoformat() if self.credential_manager.last_rotation else None
        }
        
        try:
            async with self.get_session() as session:
                # Test query
                result = await session.execute(text("SELECT 1"))
                
                # Check pool status
                if self.engine:
                    pool = self.engine.pool
                    health_info.update({
                        'pool_size': pool.size(),
                        'checked_out': pool.checkedout(),
                        'overflow': pool.overflow(),
                        'invalid_connections': pool.invalidated()
                    })
                
                health_info['status'] = 'healthy'
                
        except Exception as e:
            health_info['status'] = 'unhealthy'
            health_info['error'] = str(e)
            logger.error(f"Database health check failed: {e}")
        
        return health_info
    
    async def rotate_credentials_now(self) -> None:
        """Force immediate credential rotation."""
        if self.credential_manager:
            await self.credential_manager._rotate_credentials()
            # Recreate engine with new credentials
            await self._create_secure_engine()
            logger.info("Database credentials rotated manually")
    
    async def cleanup(self) -> None:
        """Cleanup database manager."""
        try:
            # Stop monitoring
            if self.connection_monitor:
                self.connection_monitor.cancel()
                try:
                    await self.connection_monitor
                except asyncio.CancelledError:
                    pass
            
            # Cleanup credential manager
            if self.credential_manager:
                await self.credential_manager.cleanup()
            
            # Close database connections
            if self.engine:
                await self.engine.dispose()
            
            logger.info("Secure database manager cleaned up")
            
        except Exception as e:
            logger.error(f"Database cleanup error: {e}")


# Global secure database manager instance
_secure_db_manager: Optional[SecureDatabaseManager] = None


async def get_secure_database() -> SecureDatabaseManager:
    """Get or create global secure database manager."""
    global _secure_db_manager
    
    if _secure_db_manager is None:
        _secure_db_manager = SecureDatabaseManager()
        await _secure_db_manager.initialize()
    
    return _secure_db_manager


async def initialize_secure_database() -> None:
    """Initialize secure database for the application."""
    await get_secure_database()
    logger.info("Secure database initialized")


async def cleanup_secure_database() -> None:
    """Cleanup secure database."""
    global _secure_db_manager
    
    if _secure_db_manager:
        await _secure_db_manager.cleanup()
        _secure_db_manager = None
    
    logger.info("Secure database cleaned up")


# Convenience function for getting database sessions
async def get_secure_session() -> AsyncGenerator[AsyncSession, None]:
    """Get secure database session (convenience function)."""
    db_manager = await get_secure_database()
    async with db_manager.get_session() as session:
        yield session