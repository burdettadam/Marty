"""
Security audit logging for Trust Service.

This module provides comprehensive audit logging for security events,
compliance tracking, and forensic analysis.
"""

import asyncio
import hashlib
import os
import json
import logging
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import structlog
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from sqlalchemy import and_, text
from sqlalchemy.ext.asyncio import AsyncSession

logger = structlog.get_logger(__name__)


class AuditEventType(Enum):
    """Types of audit events."""

    # Authentication events
    AUTH_SUCCESS = "auth_success"
    AUTH_FAILURE = "auth_failure"
    AUTH_LOGOUT = "auth_logout"
    AUTH_TOKEN_CREATED = "auth_token_created"
    AUTH_TOKEN_REVOKED = "auth_token_revoked"

    # Authorization events
    AUTHZ_GRANTED = "authz_granted"
    AUTHZ_DENIED = "authz_denied"
    AUTHZ_PRIVILEGE_ESCALATION = "authz_privilege_escalation"

    # Certificate operations
    CERT_VALIDATION = "cert_validation"
    CERT_REVOCATION = "cert_revocation"
    CERT_IMPORT = "cert_import"
    CERT_EXPORT = "cert_export"
    CERT_TRUST_CHANGE = "cert_trust_change"

    # Database operations
    DB_CONNECTION = "db_connection"
    DB_QUERY = "db_query"
    DB_MODIFICATION = "db_modification"
    DB_BACKUP = "db_backup"
    DB_RESTORE = "db_restore"

    # System events
    SYS_STARTUP = "sys_startup"
    SYS_SHUTDOWN = "sys_shutdown"
    SYS_CONFIG_CHANGE = "sys_config_change"
    SYS_ERROR = "sys_error"

    # Security events
    SEC_INTRUSION_ATTEMPT = "sec_intrusion_attempt"
    SEC_RATE_LIMIT = "sec_rate_limit"
    SEC_MALFORMED_REQUEST = "sec_malformed_request"
    SEC_SUSPICIOUS_ACTIVITY = "sec_suspicious_activity"

    # Data events
    DATA_ACCESS = "data_access"
    DATA_MODIFICATION = "data_modification"
    DATA_EXPORT = "data_export"
    DATA_DELETION = "data_deletion"


class AuditSeverity(Enum):
    """Audit event severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class AuditEvent:
    """Audit event data structure."""

    event_id: str
    event_type: AuditEventType
    severity: AuditSeverity
    timestamp: datetime
    source_ip: str | None
    user_id: str | None
    session_id: str | None
    resource: str | None
    action: str
    outcome: str  # success, failure, error
    details: dict[str, Any]
    user_agent: str | None = None
    request_id: str | None = None
    correlation_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        data = asdict(self)
        data["event_type"] = self.event_type.value
        data["severity"] = self.severity.value
        data["timestamp"] = self.timestamp.isoformat()
        return data

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), default=str)


class AuditEventBuilder:
    """Builder for creating audit events."""

    def __init__(self):
        self.event_id = str(uuid.uuid4())
        self.timestamp = datetime.now(timezone.utc)
        self.details: dict[str, Any] = {}

    def event_type(self, event_type: AuditEventType) -> "AuditEventBuilder":
        self._event_type = event_type
        return self

    def severity(self, severity: AuditSeverity) -> "AuditEventBuilder":
        self._severity = severity
        return self

    def source_ip(self, ip: str) -> "AuditEventBuilder":
        self._source_ip = ip
        return self

    def user_id(self, user_id: str) -> "AuditEventBuilder":
        self._user_id = user_id
        return self

    def session_id(self, session_id: str) -> "AuditEventBuilder":
        self._session_id = session_id
        return self

    def resource(self, resource: str) -> "AuditEventBuilder":
        self._resource = resource
        return self

    def action(self, action: str) -> "AuditEventBuilder":
        self._action = action
        return self

    def outcome(self, outcome: str) -> "AuditEventBuilder":
        self._outcome = outcome
        return self

    def detail(self, key: str, value: Any) -> "AuditEventBuilder":
        self.details[key] = value
        return self

    def details_dict(self, details: dict[str, Any]) -> "AuditEventBuilder":
        self.details.update(details)
        return self

    def user_agent(self, user_agent: str) -> "AuditEventBuilder":
        self._user_agent = user_agent
        return self

    def request_id(self, request_id: str) -> "AuditEventBuilder":
        self._request_id = request_id
        return self

    def correlation_id(self, correlation_id: str) -> "AuditEventBuilder":
        self._correlation_id = correlation_id
        return self

    def build(self) -> AuditEvent:
        """Build the audit event."""
        return AuditEvent(
            event_id=self.event_id,
            event_type=self._event_type,
            severity=self._severity,
            timestamp=self.timestamp,
            source_ip=getattr(self, "_source_ip", None),
            user_id=getattr(self, "_user_id", None),
            session_id=getattr(self, "_session_id", None),
            resource=getattr(self, "_resource", None),
            action=getattr(self, "_action", ""),
            outcome=getattr(self, "_outcome", "unknown"),
            details=self.details,
            user_agent=getattr(self, "_user_agent", None),
            request_id=getattr(self, "_request_id", None),
            correlation_id=getattr(self, "_correlation_id", None),
        )


class AuditLogger:
    """Central audit logging service."""

    def __init__(
        self,
        log_to_file: bool = True,
        log_to_database: bool = True,
        log_to_siem: bool = False,
        encryption_enabled: bool = True,
        retention_days: int = 365,
    ):
        self.log_to_file = log_to_file
        self.log_to_database = log_to_database
        self.log_to_siem = log_to_siem
        self.encryption_enabled = encryption_enabled
        self.retention_days = retention_days

        # Setup structured logging
        self.struct_logger = structlog.get_logger("audit")

        # File logging setup
        if self.log_to_file:
            self.audit_log_path = Path("logs/audit.log")
            self.audit_log_path.parent.mkdir(exist_ok=True)

        # Encryption setup
        if self.encryption_enabled:
            self._setup_encryption()

        # Database session
        self.db_session: AsyncSession | None = None

    def _setup_encryption(self) -> None:
        """Setup encryption for sensitive audit data."""
        try:
            # In production, this key should come from Vault
            # For now, use a derived key
            password = b"audit-encryption-key-change-in-production"
            salt = b"audit-salt-12345"  # Should be random in production

            kdf = Scrypt(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )

            self.encryption_key = kdf.derive(password)
            logger.info("Audit encryption initialized")

        except Exception as e:
            logger.error(f"Failed to setup audit encryption: {e}")
            self.encryption_enabled = False

    def _encrypt_sensitive_data(self, data: str) -> str:
        """Encrypt sensitive audit data."""
        if not self.encryption_enabled:
            return data

        try:
            # Generate random IV
            iv = os.urandom(16)

            # Create cipher
            cipher = Cipher(algorithms.AES(self.encryption_key), modes.CBC(iv))
            encryptor = cipher.encryptor()

            # Pad data to block size
            padded_data = data.encode("utf-8")
            padding_length = 16 - (len(padded_data) % 16)
            padded_data += bytes([padding_length]) * padding_length

            # Encrypt
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

            # Return base64 encoded IV + encrypted data
            import base64

            return base64.b64encode(iv + encrypted_data).decode("utf-8")

        except Exception as e:
            logger.error(f"Failed to encrypt audit data: {e}")
            return data  # Fallback to unencrypted

    def _decrypt_sensitive_data(self, encrypted_data: str) -> str:
        """Decrypt sensitive audit data."""
        if not self.encryption_enabled:
            return encrypted_data

        try:
            import base64

            # Decode base64
            raw_data = base64.b64decode(encrypted_data.encode("utf-8"))

            # Extract IV and encrypted data
            iv = raw_data[:16]
            encrypted = raw_data[16:]

            # Create cipher
            cipher = Cipher(algorithms.AES(self.encryption_key), modes.CBC(iv))
            decryptor = cipher.decryptor()

            # Decrypt
            padded_data = decryptor.update(encrypted) + decryptor.finalize()

            # Remove padding
            padding_length = padded_data[-1]
            data = padded_data[:-padding_length]

            return data.decode("utf-8")

        except Exception as e:
            logger.error(f"Failed to decrypt audit data: {e}")
            return encrypted_data  # Fallback to encrypted

    def set_database_session(self, session: AsyncSession) -> None:
        """Set database session for audit logging."""
        self.db_session = session

    async def log_event(self, event: AuditEvent) -> None:
        """Log audit event to all configured destinations."""
        try:
            # Log to structured logger
            self.struct_logger.info(
                "audit_event",
                event_id=event.event_id,
                event_type=event.event_type.value,
                severity=event.severity.value,
                user_id=event.user_id,
                action=event.action,
                outcome=event.outcome,
                details=event.details,
            )

            # Log to file
            if self.log_to_file:
                await self._log_to_file(event)

            # Log to database
            if self.log_to_database and self.db_session:
                await self._log_to_database(event)

            # Log to SIEM (if configured)
            if self.log_to_siem:
                await self._log_to_siem(event)

        except Exception as e:
            logger.error(f"Failed to log audit event: {e}")

    async def _log_to_file(self, event: AuditEvent) -> None:
        """Log audit event to file."""
        try:
            log_entry = {
                "timestamp": event.timestamp.isoformat(),
                "event_id": event.event_id,
                "event_type": event.event_type.value,
                "severity": event.severity.value,
                "user_id": event.user_id,
                "source_ip": event.source_ip,
                "action": event.action,
                "outcome": event.outcome,
                "resource": event.resource,
                "details": event.details,
            }

            # Encrypt sensitive details if enabled
            if self.encryption_enabled and event.details:
                sensitive_fields = ["password", "token", "key", "secret"]
                for field in sensitive_fields:
                    if field in event.details:
                        log_entry["details"][field] = self._encrypt_sensitive_data(
                            str(event.details[field])
                        )

            # Write to file
            with open(self.audit_log_path, "a") as f:
                f.write(json.dumps(log_entry, default=str) + "\n")

        except Exception as e:
            logger.error(f"Failed to log to file: {e}")

    async def _log_to_database(self, event: AuditEvent) -> None:
        """Log audit event to database."""
        try:
            # Create audit table if it doesn't exist
            await self.db_session.execute(
                text(
                    """
                CREATE TABLE IF NOT EXISTS trust_svc.audit_log (
                    id SERIAL PRIMARY KEY,
                    event_id VARCHAR(255) UNIQUE NOT NULL,
                    event_type VARCHAR(100) NOT NULL,
                    severity VARCHAR(20) NOT NULL,
                    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
                    source_ip INET,
                    user_id VARCHAR(255),
                    session_id VARCHAR(255),
                    resource VARCHAR(500),
                    action VARCHAR(255) NOT NULL,
                    outcome VARCHAR(50) NOT NULL,
                    details JSONB,
                    user_agent TEXT,
                    request_id VARCHAR(255),
                    correlation_id VARCHAR(255),
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
                )
            """
                )
            )

            # Insert audit event
            await self.db_session.execute(
                text(
                    """
                INSERT INTO trust_svc.audit_log (
                    event_id, event_type, severity, timestamp, source_ip,
                    user_id, session_id, resource, action, outcome,
                    details, user_agent, request_id, correlation_id
                ) VALUES (
                    :event_id, :event_type, :severity, :timestamp, :source_ip,
                    :user_id, :session_id, :resource, :action, :outcome,
                    :details, :user_agent, :request_id, :correlation_id
                )
            """
                ),
                {
                    "event_id": event.event_id,
                    "event_type": event.event_type.value,
                    "severity": event.severity.value,
                    "timestamp": event.timestamp,
                    "source_ip": event.source_ip,
                    "user_id": event.user_id,
                    "session_id": event.session_id,
                    "resource": event.resource,
                    "action": event.action,
                    "outcome": event.outcome,
                    "details": json.dumps(event.details) if event.details else None,
                    "user_agent": event.user_agent,
                    "request_id": event.request_id,
                    "correlation_id": event.correlation_id,
                },
            )

            await self.db_session.commit()

        except Exception as e:
            logger.error(f"Failed to log to database: {e}")
            await self.db_session.rollback()

    async def _log_to_siem(self, event: AuditEvent) -> None:
        """Log audit event to SIEM system."""
        # This would integrate with your SIEM system
        # Example: send to Splunk, ELK, QRadar, etc.
        pass

    async def search_events(
        self,
        event_type: AuditEventType | None = None,
        user_id: str | None = None,
        source_ip: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Search audit events."""
        if not self.db_session:
            raise RuntimeError("Database session not available")

        try:
            # Build query
            conditions = []
            params = {}

            if event_type:
                conditions.append("event_type = :event_type")
                params["event_type"] = event_type.value

            if user_id:
                conditions.append("user_id = :user_id")
                params["user_id"] = user_id

            if source_ip:
                conditions.append("source_ip = :source_ip")
                params["source_ip"] = source_ip

            if start_time:
                conditions.append("timestamp >= :start_time")
                params["start_time"] = start_time

            if end_time:
                conditions.append("timestamp <= :end_time")
                params["end_time"] = end_time

            where_clause = "WHERE " + " AND ".join(conditions) if conditions else ""

            query = f"""
                SELECT * FROM trust_svc.audit_log
                {where_clause}
                ORDER BY timestamp DESC
                LIMIT :limit
            """

            params["limit"] = limit

            result = await self.db_session.execute(text(query), params)
            rows = result.fetchall()

            # Convert to dictionaries
            events = []
            for row in rows:
                event_dict = dict(row._mapping)
                events.append(event_dict)

            return events

        except Exception as e:
            logger.error(f"Failed to search audit events: {e}")
            return []

    async def cleanup_old_events(self) -> int:
        """Cleanup old audit events based on retention policy."""
        if not self.db_session:
            return 0

        try:
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=self.retention_days)

            result = await self.db_session.execute(
                text(
                    """
                DELETE FROM trust_svc.audit_log
                WHERE timestamp < :cutoff_date
            """
                ),
                {"cutoff_date": cutoff_date},
            )

            deleted_count = result.rowcount
            await self.db_session.commit()

            logger.info(f"Cleaned up {deleted_count} old audit events")
            return deleted_count

        except Exception as e:
            logger.error(f"Failed to cleanup old audit events: {e}")
            await self.db_session.rollback()
            return 0


class SecurityAuditMixin:
    """Mixin class for adding audit logging to services."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.audit_logger = AuditLogger()

    async def audit_authentication(
        self, user_id: str, source_ip: str, success: bool, details: dict[str, Any] | None = None
    ) -> None:
        """Audit authentication event."""
        event = (
            AuditEventBuilder()
            .event_type(AuditEventType.AUTH_SUCCESS if success else AuditEventType.AUTH_FAILURE)
            .severity(AuditSeverity.MEDIUM if success else AuditSeverity.HIGH)
            .user_id(user_id)
            .source_ip(source_ip)
            .action("authenticate")
            .outcome("success" if success else "failure")
            .details_dict(details or {})
            .build()
        )

        await self.audit_logger.log_event(event)

    async def audit_authorization(
        self,
        user_id: str,
        resource: str,
        action: str,
        granted: bool,
        source_ip: str | None = None,
    ) -> None:
        """Audit authorization event."""
        event = (
            AuditEventBuilder()
            .event_type(AuditEventType.AUTHZ_GRANTED if granted else AuditEventType.AUTHZ_DENIED)
            .severity(AuditSeverity.LOW if granted else AuditSeverity.MEDIUM)
            .user_id(user_id)
            .source_ip(source_ip)
            .resource(resource)
            .action(action)
            .outcome("granted" if granted else "denied")
            .build()
        )

        await self.audit_logger.log_event(event)

    async def audit_certificate_operation(
        self,
        operation: str,
        certificate_id: str,
        user_id: str | None = None,
        success: bool = True,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Audit certificate operation."""
        event = (
            AuditEventBuilder()
            .event_type(AuditEventType.CERT_VALIDATION)
            .severity(AuditSeverity.MEDIUM)
            .user_id(user_id)
            .resource(f"certificate:{certificate_id}")
            .action(operation)
            .outcome("success" if success else "failure")
            .details_dict(details or {})
            .build()
        )

        await self.audit_logger.log_event(event)

    async def audit_data_access(
        self,
        user_id: str,
        resource: str,
        action: str,
        source_ip: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Audit data access event."""
        event = (
            AuditEventBuilder()
            .event_type(AuditEventType.DATA_ACCESS)
            .severity(AuditSeverity.LOW)
            .user_id(user_id)
            .source_ip(source_ip)
            .resource(resource)
            .action(action)
            .outcome("success")
            .details_dict(details or {})
            .build()
        )

        await self.audit_logger.log_event(event)

    async def audit_security_event(
        self,
        event_type: AuditEventType,
        severity: AuditSeverity,
        description: str,
        source_ip: str | None = None,
        user_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Audit security event."""
        event = (
            AuditEventBuilder()
            .event_type(event_type)
            .severity(severity)
            .user_id(user_id)
            .source_ip(source_ip)
            .action(description)
            .outcome("detected")
            .details_dict(details or {})
            .build()
        )

        await self.audit_logger.log_event(event)


# Global audit logger instance
_audit_logger: AuditLogger | None = None


async def get_audit_logger() -> AuditLogger:
    """Get or create global audit logger instance."""
    global _audit_logger

    if _audit_logger is None:
        _audit_logger = AuditLogger()

    return _audit_logger


async def initialize_audit_logging() -> None:
    """Initialize audit logging for the application."""
    await get_audit_logger()
    logger.info("Audit logging initialized")


# Convenience functions for common audit events


async def audit_auth_success(user_id: str, source_ip: str, details: dict[str, Any] | None = None):
    """Log successful authentication."""
    audit_logger = await get_audit_logger()
    event = (
        AuditEventBuilder()
        .event_type(AuditEventType.AUTH_SUCCESS)
        .severity(AuditSeverity.MEDIUM)
        .user_id(user_id)
        .source_ip(source_ip)
        .action("authenticate")
        .outcome("success")
        .details_dict(details or {})
        .build()
    )

    await audit_logger.log_event(event)


async def audit_auth_failure(user_id: str, source_ip: str, reason: str):
    """Log failed authentication."""
    audit_logger = await get_audit_logger()
    event = (
        AuditEventBuilder()
        .event_type(AuditEventType.AUTH_FAILURE)
        .severity(AuditSeverity.HIGH)
        .user_id(user_id)
        .source_ip(source_ip)
        .action("authenticate")
        .outcome("failure")
        .detail("reason", reason)
        .build()
    )

    await audit_logger.log_event(event)


async def audit_suspicious_activity(description: str, source_ip: str, details: dict[str, Any]):
    """Log suspicious activity."""
    audit_logger = await get_audit_logger()
    event = (
        AuditEventBuilder()
        .event_type(AuditEventType.SEC_SUSPICIOUS_ACTIVITY)
        .severity(AuditSeverity.HIGH)
        .source_ip(source_ip)
        .action(description)
        .outcome("detected")
        .details_dict(details)
        .build()
    )

    await audit_logger.log_event(event)
