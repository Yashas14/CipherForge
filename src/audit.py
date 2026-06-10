"""Structured audit logging for cryptographic operations.

Security notes:
- Never logs key material, plaintext, or sensitive data
- Logs: operation type, algorithm, key_id, data_size, timestamp, success/failure
- Uses structlog for structured JSON output
- Supports shipping to CloudWatch, Splunk, Elasticsearch via standard log handlers
- Thread-safe via structlog's built-in thread safety
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Literal

import structlog

# Configure structlog for JSON output
structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.make_filtering_bound_logger(0),
    context_class=dict,
    logger_factory=structlog.PrintLoggerFactory(),
    cache_logger_on_first_use=True,
)

log = structlog.get_logger("crypto_audit")

OperationType = Literal[
    "encrypt",
    "decrypt",
    "sign",
    "verify",
    "key_generate",
    "key_rotate",
    "key_import",
    "key_export",
    "key_delete",
    "stream_encrypt",
    "stream_decrypt",
]


class AuditLogger:
    """Structured audit logger for cryptographic operations.

    Records all crypto operations with metadata for compliance and forensics.
    Never logs sensitive data (keys, plaintext).
    """

    def __init__(self, service_name: str = "encryption-suite-v2") -> None:
        """Initialize audit logger.

        Args:
            service_name: Name of the service for log correlation.
        """
        self._service = service_name
        self._log = log.bind(service=service_name)

    async def audit(
        self,
        operation: OperationType,
        algorithm: str,
        key_id: str,
        data_size: int,
        user_id: str = "system",
        success: bool = True,
        error: str | None = None,
        duration_ms: float | None = None,
        ip_address: str | None = None,
        metadata: dict | None = None,
    ) -> None:
        """Emit a structured audit log entry.

        Args:
            operation: Type of cryptographic operation.
            algorithm: Algorithm used (e.g., "aes-256-gcm").
            key_id: Key identifier (NEVER the actual key).
            data_size: Size of data processed in bytes.
            user_id: User or service account identifier.
            success: Whether the operation succeeded.
            error: Error message if operation failed.
            duration_ms: Operation duration in milliseconds.
            ip_address: Client IP address if applicable.
            metadata: Additional metadata (nonce size, tag size, etc.).
        """
        entry = {
            "operation": operation,
            "algorithm": algorithm,
            "key_id": key_id,
            "data_size_bytes": data_size,
            "user_id": user_id,
            "success": success,
            "timestamp": datetime.now(UTC).isoformat(),
        }

        if error:
            entry["error"] = error
        if duration_ms is not None:
            entry["duration_ms"] = round(duration_ms, 2)
        if ip_address:
            entry["ip_address"] = ip_address
        if metadata:
            entry["metadata"] = metadata

        if success:
            self._log.info("crypto_operation", **entry)
        else:
            self._log.warning("crypto_operation_failed", **entry)

    def audit_sync(
        self,
        operation: OperationType,
        algorithm: str,
        key_id: str,
        data_size: int,
        user_id: str = "system",
        success: bool = True,
        error: str | None = None,
        duration_ms: float | None = None,
    ) -> None:
        """Synchronous audit log entry (for non-async contexts).

        Args:
            operation: Type of cryptographic operation.
            algorithm: Algorithm used.
            key_id: Key identifier.
            data_size: Size of data in bytes.
            user_id: User identifier.
            success: Whether operation succeeded.
            error: Error message if failed.
            duration_ms: Duration in milliseconds.
        """
        entry = {
            "operation": operation,
            "algorithm": algorithm,
            "key_id": key_id,
            "data_size_bytes": data_size,
            "user_id": user_id,
            "success": success,
            "timestamp": datetime.now(UTC).isoformat(),
        }

        if error:
            entry["error"] = error
        if duration_ms is not None:
            entry["duration_ms"] = round(duration_ms, 2)

        if success:
            self._log.info("crypto_operation", **entry)
        else:
            self._log.warning("crypto_operation_failed", **entry)


class AuditTimer:
    """Context manager to time operations for audit logging.

    Usage:
        with AuditTimer() as timer:
            result = encrypt(data)
        duration = timer.duration_ms
    """

    def __init__(self) -> None:
        self._start: float = 0
        self._end: float = 0

    @property
    def duration_ms(self) -> float:
        """Return duration in milliseconds."""
        return (self._end - self._start) * 1000

    def __enter__(self) -> AuditTimer:
        self._start = time.perf_counter()
        return self

    def __exit__(self, *args: object) -> None:
        self._end = time.perf_counter()


# Global audit logger instance
audit_logger = AuditLogger()
