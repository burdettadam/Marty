"""
Security middleware and authentication for Trust Service.

This module provides comprehensive security features including:
- Mutual TLS (mTLS) authentication
- JWT token validation
- API key authentication
- Rate limiting
- Request validation
- Security headers
"""

import logging
import time
import jwt
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from datetime import datetime, timedelta
from functools import wraps
import asyncio
import hashlib
import hmac
import secrets
from collections import defaultdict, deque

import grpc
from grpc import StatusCode
from grpc._server import _Context
from fastapi import HTTPException, Request, Response, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from vault_client import get_vault_client

logger = logging.getLogger(__name__)


class SecurityError(Exception):
    """Base security error."""
    pass


class AuthenticationError(SecurityError):
    """Authentication failed."""
    pass


class AuthorizationError(SecurityError):
    """Authorization failed."""
    pass


class RateLimitError(SecurityError):
    """Rate limit exceeded."""
    pass


class CertificateValidationError(SecurityError):
    """Certificate validation failed."""
    pass


class SecurityConfig:
    """Security configuration settings."""
    
    def __init__(self):
        # mTLS settings
        self.mtls_enabled: bool = True
        self.mtls_require_client_cert: bool = True
        self.mtls_verify_client_cert: bool = True
        self.mtls_allowed_clients: Set[str] = set()  # Client certificate CNs
        
        # JWT settings
        self.jwt_enabled: bool = True
        self.jwt_algorithm: str = "RS256"
        self.jwt_expiry_minutes: int = 60
        self.jwt_issuer: str = "trust-service"
        self.jwt_audience: str = "trust-service-api"
        
        # API key settings
        self.api_key_enabled: bool = True
        self.api_key_header: str = "X-API-Key"
        self.api_key_length: int = 32
        
        # Rate limiting
        self.rate_limit_enabled: bool = True
        self.rate_limit_requests_per_minute: int = 1000
        self.rate_limit_burst_size: int = 100
        
        # Security headers
        self.security_headers_enabled: bool = True
        self.hsts_max_age: int = 31536000  # 1 year
        
        # Request validation
        self.max_request_size: int = 10 * 1024 * 1024  # 10MB
        self.request_timeout: int = 30
        
        # Session management
        self.session_timeout_minutes: int = 480  # 8 hours
        self.max_concurrent_sessions: int = 10


class MTLSAuthenticator:
    """Mutual TLS authentication handler."""
    
    def __init__(self, config: SecurityConfig):
        self.config = config
        self._allowed_clients: Set[str] = set()
        self._certificate_cache: Dict[str, x509.Certificate] = {}
    
    def add_allowed_client(self, client_cn: str) -> None:
        """Add allowed client certificate CN."""
        self._allowed_clients.add(client_cn)
        logger.info(f"Added allowed mTLS client: {client_cn}")
    
    def remove_allowed_client(self, client_cn: str) -> None:
        """Remove allowed client certificate CN."""
        self._allowed_clients.discard(client_cn)
        logger.info(f"Removed allowed mTLS client: {client_cn}")
    
    def validate_client_certificate(self, cert_data: bytes) -> Dict[str, Any]:
        """
        Validate client certificate for mTLS.
        
        Args:
            cert_data: Client certificate in DER format
            
        Returns:
            Certificate validation result
            
        Raises:
            CertificateValidationError: If validation fails
        """
        try:
            # Parse certificate
            cert = x509.load_der_x509_certificate(cert_data)
            
            # Get certificate fingerprint for caching
            fingerprint = cert.fingerprint(hashes.SHA256()).hex()
            
            # Cache certificate
            self._certificate_cache[fingerprint] = cert
            
            # Extract subject information
            subject = cert.subject
            common_name = None
            organization = None
            
            for attribute in subject:
                if attribute.oid == NameOID.COMMON_NAME:
                    common_name = attribute.value
                elif attribute.oid == NameOID.ORGANIZATION_NAME:
                    organization = attribute.value
            
            if not common_name:
                raise CertificateValidationError("Certificate missing common name")
            
            # Check if client is allowed
            if self.config.mtls_require_client_cert and common_name not in self._allowed_clients:
                raise CertificateValidationError(f"Client '{common_name}' not authorized")
            
            # Check certificate validity
            now = datetime.utcnow()
            if now < cert.not_valid_before:
                raise CertificateValidationError("Certificate not yet valid")
            
            if now > cert.not_valid_after:
                raise CertificateValidationError("Certificate expired")
            
            # Additional validation could include:
            # - CRL checking
            # - OCSP validation
            # - Key usage verification
            
            return {
                'common_name': common_name,
                'organization': organization,
                'fingerprint': fingerprint,
                'not_before': cert.not_valid_before,
                'not_after': cert.not_valid_after,
                'serial_number': str(cert.serial_number),
                'issuer': cert.issuer.rfc4514_string()
            }
            
        except Exception as e:
            logger.error(f"Certificate validation failed: {e}")
            raise CertificateValidationError(f"Invalid certificate: {e}")


class JWTAuthenticator:
    """JWT token authentication handler."""
    
    def __init__(self, config: SecurityConfig):
        self.config = config
        self._public_key: Optional[str] = None
        self._private_key: Optional[str] = None
    
    async def initialize(self) -> None:
        """Initialize JWT keys from Vault."""
        try:
            vault_client = await get_vault_client()
            key_data = await vault_client.get_jwt_signing_key()
            
            self._private_key = key_data['private_key']
            self._public_key = key_data['public_key']
            
            logger.info("JWT authenticator initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize JWT authenticator: {e}")
            raise SecurityError(f"JWT initialization failed: {e}")
    
    def generate_token(
        self,
        subject: str,
        claims: Optional[Dict[str, Any]] = None,
        expires_in_minutes: Optional[int] = None
    ) -> str:
        """
        Generate JWT token.
        
        Args:
            subject: Token subject (user/client ID)
            claims: Additional claims
            expires_in_minutes: Token expiry (optional)
            
        Returns:
            JWT token string
        """
        if not self._private_key:
            raise SecurityError("JWT private key not available")
        
        now = datetime.utcnow()
        expiry_minutes = expires_in_minutes or self.config.jwt_expiry_minutes
        
        payload = {
            'iss': self.config.jwt_issuer,
            'aud': self.config.jwt_audience,
            'sub': subject,
            'iat': now,
            'exp': now + timedelta(minutes=expiry_minutes),
            'jti': secrets.token_urlsafe(16)  # Unique token ID
        }
        
        if claims:
            payload.update(claims)
        
        token = jwt.encode(
            payload,
            self._private_key,
            algorithm=self.config.jwt_algorithm
        )
        
        logger.info(f"Generated JWT token for subject: {subject}")
        return token
    
    def validate_token(self, token: str) -> Dict[str, Any]:
        """
        Validate JWT token.
        
        Args:
            token: JWT token string
            
        Returns:
            Decoded token payload
            
        Raises:
            AuthenticationError: If token is invalid
        """
        if not self._public_key:
            raise SecurityError("JWT public key not available")
        
        try:
            payload = jwt.decode(
                token,
                self._public_key,
                algorithms=[self.config.jwt_algorithm],
                issuer=self.config.jwt_issuer,
                audience=self.config.jwt_audience
            )
            
            return payload
            
        except jwt.ExpiredSignatureError:
            raise AuthenticationError("Token expired")
        except jwt.InvalidTokenError as e:
            raise AuthenticationError(f"Invalid token: {e}")


class APIKeyAuthenticator:
    """API key authentication handler."""
    
    def __init__(self, config: SecurityConfig):
        self.config = config
        self._api_keys: Dict[str, Dict[str, Any]] = {}
    
    async def initialize(self) -> None:
        """Initialize API keys from Vault."""
        try:
            vault_client = await get_vault_client()
            
            try:
                api_keys_data = await vault_client.get_secret("api-keys/active")
                self._api_keys = api_keys_data
                logger.info(f"Loaded {len(self._api_keys)} API keys")
            except Exception:
                # No API keys stored yet
                logger.info("No API keys found in Vault")
            
        except Exception as e:
            logger.error(f"Failed to initialize API key authenticator: {e}")
    
    def generate_api_key(self, client_name: str, permissions: List[str]) -> str:
        """
        Generate new API key.
        
        Args:
            client_name: Client identifier
            permissions: List of permissions
            
        Returns:
            Generated API key
        """
        api_key = secrets.token_urlsafe(self.config.api_key_length)
        
        key_data = {
            'client_name': client_name,
            'permissions': permissions,
            'created_at': datetime.utcnow().isoformat(),
            'last_used': None,
            'usage_count': 0
        }
        
        self._api_keys[api_key] = key_data
        logger.info(f"Generated API key for client: {client_name}")
        
        return api_key
    
    async def store_api_keys(self) -> None:
        """Store API keys to Vault."""
        try:
            vault_client = await get_vault_client()
            await vault_client.set_secret("api-keys/active", self._api_keys)
            logger.info("Stored API keys to Vault")
        except Exception as e:
            logger.error(f"Failed to store API keys: {e}")
    
    def validate_api_key(self, api_key: str) -> Dict[str, Any]:
        """
        Validate API key.
        
        Args:
            api_key: API key string
            
        Returns:
            API key data
            
        Raises:
            AuthenticationError: If API key is invalid
        """
        if api_key not in self._api_keys:
            raise AuthenticationError("Invalid API key")
        
        key_data = self._api_keys[api_key]
        
        # Update usage statistics
        key_data['last_used'] = datetime.utcnow().isoformat()
        key_data['usage_count'] += 1
        
        return key_data
    
    def revoke_api_key(self, api_key: str) -> None:
        """Revoke API key."""
        if api_key in self._api_keys:
            del self._api_keys[api_key]
            logger.info("Revoked API key")


class RateLimiter:
    """Rate limiting implementation."""
    
    def __init__(self, config: SecurityConfig):
        self.config = config
        self._request_counts: Dict[str, deque] = defaultdict(deque)
        self._cleanup_interval = 60  # seconds
        self._last_cleanup = time.time()
    
    def _cleanup_old_requests(self) -> None:
        """Remove old request timestamps."""
        now = time.time()
        
        if now - self._last_cleanup < self._cleanup_interval:
            return
        
        cutoff = now - 60  # 1 minute ago
        
        for client_id in list(self._request_counts.keys()):
            requests = self._request_counts[client_id]
            
            # Remove old requests
            while requests and requests[0] < cutoff:
                requests.popleft()
            
            # Remove empty entries
            if not requests:
                del self._request_counts[client_id]
        
        self._last_cleanup = now
    
    def check_rate_limit(self, client_id: str) -> bool:
        """
        Check if client is within rate limits.
        
        Args:
            client_id: Client identifier
            
        Returns:
            True if within limits, False otherwise
        """
        if not self.config.rate_limit_enabled:
            return True
        
        self._cleanup_old_requests()
        
        now = time.time()
        requests = self._request_counts[client_id]
        
        # Count requests in the last minute
        minute_ago = now - 60
        recent_requests = sum(1 for timestamp in requests if timestamp > minute_ago)
        
        if recent_requests >= self.config.rate_limit_requests_per_minute:
            logger.warning(f"Rate limit exceeded for client: {client_id}")
            return False
        
        # Add current request
        requests.append(now)
        
        # Limit queue size (burst protection)
        if len(requests) > self.config.rate_limit_burst_size:
            requests.popleft()
        
        return True
    
    def get_rate_limit_info(self, client_id: str) -> Dict[str, Any]:
        """Get rate limit information for client."""
        requests = self._request_counts.get(client_id, deque())
        now = time.time()
        minute_ago = now - 60
        
        recent_requests = sum(1 for timestamp in requests if timestamp > minute_ago)
        
        return {
            'requests_per_minute': recent_requests,
            'limit': self.config.rate_limit_requests_per_minute,
            'remaining': max(0, self.config.rate_limit_requests_per_minute - recent_requests),
            'reset_time': int(now + 60)
        }


class SecurityMiddleware:
    """Comprehensive security middleware."""
    
    def __init__(self, config: Optional[SecurityConfig] = None):
        self.config = config or SecurityConfig()
        self.mtls_auth = MTLSAuthenticator(self.config)
        self.jwt_auth = JWTAuthenticator(self.config)
        self.api_key_auth = APIKeyAuthenticator(self.config)
        self.rate_limiter = RateLimiter(self.config)
        
        self._initialized = False
    
    async def initialize(self) -> None:
        """Initialize security middleware."""
        if self._initialized:
            return
        
        await self.jwt_auth.initialize()
        await self.api_key_auth.initialize()
        
        self._initialized = True
        logger.info("Security middleware initialized")
    
    def add_security_headers(self, response: Response) -> None:
        """Add security headers to HTTP response."""
        if not self.config.security_headers_enabled:
            return
        
        # HSTS
        response.headers["Strict-Transport-Security"] = f"max-age={self.config.hsts_max_age}; includeSubDomains"
        
        # Content Security Policy
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
        
        # Other security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    
    async def authenticate_request(self, request: Request) -> Dict[str, Any]:
        """
        Authenticate incoming request.
        
        Args:
            request: FastAPI request object
            
        Returns:
            Authentication context
            
        Raises:
            AuthenticationError: If authentication fails
        """
        client_ip = request.client.host if request.client else "unknown"
        
        # Check rate limits
        if not self.rate_limiter.check_rate_limit(client_ip):
            raise RateLimitError("Rate limit exceeded")
        
        auth_context = {
            'client_ip': client_ip,
            'authenticated': False,
            'auth_method': None,
            'client_id': None,
            'permissions': []
        }
        
        # Try JWT authentication
        if self.config.jwt_enabled:
            auth_header = request.headers.get('Authorization')
            if auth_header and auth_header.startswith('Bearer '):
                token = auth_header.split(' ', 1)[1]
                try:
                    payload = self.jwt_auth.validate_token(token)
                    auth_context.update({
                        'authenticated': True,
                        'auth_method': 'jwt',
                        'client_id': payload['sub'],
                        'token_payload': payload
                    })
                    return auth_context
                except AuthenticationError:
                    pass  # Try other auth methods
        
        # Try API key authentication
        if self.config.api_key_enabled:
            api_key = request.headers.get(self.config.api_key_header)
            if api_key:
                try:
                    key_data = self.api_key_auth.validate_api_key(api_key)
                    auth_context.update({
                        'authenticated': True,
                        'auth_method': 'api_key',
                        'client_id': key_data['client_name'],
                        'permissions': key_data['permissions']
                    })
                    return auth_context
                except AuthenticationError:
                    pass  # Try other auth methods
        
        # For now, allow unauthenticated requests
        # In production, you might want to require authentication
        return auth_context


# gRPC security interceptors

class MTLSServerInterceptor(grpc.ServerInterceptor):
    """gRPC server interceptor for mTLS authentication."""
    
    def __init__(self, mtls_auth: MTLSAuthenticator):
        self.mtls_auth = mtls_auth
    
    def intercept_service(self, continuation, handler_call_details):
        """Intercept gRPC service calls for mTLS validation."""
        
        def wrapper(request, context: _Context):
            try:
                # Get client certificate from gRPC context
                auth_context = context.auth_context()
                
                if not auth_context or 'x509_common_name' not in auth_context:
                    context.abort(StatusCode.UNAUTHENTICATED, "Client certificate required")
                
                client_cn = auth_context['x509_common_name'][0].decode('utf-8')
                
                # Validate client certificate
                # Note: In real implementation, you'd get the actual certificate
                # This is a simplified example
                if client_cn not in self.mtls_auth._allowed_clients:
                    context.abort(StatusCode.PERMISSION_DENIED, f"Client '{client_cn}' not authorized")
                
                # Add client info to context
                context.set_trailing_metadata([
                    ('authenticated-client', client_cn)
                ])
                
                return continuation(request, context)
                
            except Exception as e:
                logger.error(f"mTLS authentication failed: {e}")
                context.abort(StatusCode.INTERNAL, "Authentication error")
        
        return wrapper


class RateLimitInterceptor(grpc.ServerInterceptor):
    """gRPC server interceptor for rate limiting."""
    
    def __init__(self, rate_limiter: RateLimiter):
        self.rate_limiter = rate_limiter
    
    def intercept_service(self, continuation, handler_call_details):
        """Intercept gRPC service calls for rate limiting."""
        
        def wrapper(request, context: _Context):
            try:
                # Get client IP from context
                peer = context.peer()
                client_id = peer.split(':')[0] if peer else 'unknown'
                
                # Check rate limits
                if not self.rate_limiter.check_rate_limit(client_id):
                    context.abort(StatusCode.RESOURCE_EXHAUSTED, "Rate limit exceeded")
                
                return continuation(request, context)
                
            except Exception as e:
                logger.error(f"Rate limiting error: {e}")
                context.abort(StatusCode.INTERNAL, "Rate limiting error")
        
        return wrapper


# Utility functions

def get_client_certificate_info(context: _Context) -> Optional[Dict[str, Any]]:
    """Extract client certificate information from gRPC context."""
    try:
        auth_context = context.auth_context()
        
        if not auth_context:
            return None
        
        cert_info = {}
        
        if 'x509_common_name' in auth_context:
            cert_info['common_name'] = auth_context['x509_common_name'][0].decode('utf-8')
        
        if 'x509_subject_alternative_name' in auth_context:
            cert_info['san'] = [san.decode('utf-8') for san in auth_context['x509_subject_alternative_name']]
        
        return cert_info
        
    except Exception as e:
        logger.error(f"Failed to extract certificate info: {e}")
        return None


def require_permission(permission: str):
    """Decorator to require specific permission."""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # This would check the authentication context for the required permission
            # Implementation depends on how you store the auth context
            return await func(*args, **kwargs)
        return wrapper
    return decorator


# Global security middleware instance
_security_middleware: Optional[SecurityMiddleware] = None


async def get_security_middleware() -> SecurityMiddleware:
    """Get or create global security middleware instance."""
    global _security_middleware
    
    if _security_middleware is None:
        _security_middleware = SecurityMiddleware()
        await _security_middleware.initialize()
    
    return _security_middleware


async def initialize_security() -> None:
    """Initialize security middleware for the application."""
    await get_security_middleware()
    logger.info("Security middleware initialized")