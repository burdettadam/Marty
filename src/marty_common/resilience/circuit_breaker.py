"""
Circuit Breaker implementation for resilient service communication.

Provides fault tolerance for service-to-service communication by preventing
cascading failures and providing fallback mechanisms.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from enum import Enum
from functools import wraps
from typing import Any, Callable

logger = logging.getLogger(__name__)


class CircuitState(Enum):
    """Circuit breaker states."""

    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Circuit is open, rejecting calls
    HALF_OPEN = "half_open"  # Testing if service recovered


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker."""

    failure_threshold: int = 5  # Number of failures to open circuit
    success_threshold: int = 2  # Number of successes to close from half-open
    timeout: float = 60.0  # Seconds to wait before trying half-open
    monitor_period: float = 300.0  # Seconds between health checks


class CircuitBreakerOpenException(Exception):
    """Exception raised when circuit breaker is open."""

    def __init__(self, service_name: str) -> None:
        self.service_name = service_name
        super().__init__(f"Circuit breaker is open for service: {service_name}")


class CircuitBreaker:
    """
    Circuit breaker implementation for service resilience.

    Monitors service call failures and automatically opens the circuit
    when failure threshold is exceeded, preventing further calls until
    the service recovers.
    """

    def __init__(self, name: str, config: CircuitBreakerConfig | None = None) -> None:
        """
        Initialize circuit breaker.

        Args:
            name: Name of the service/resource being protected
            config: Circuit breaker configuration
        """
        self.name = name
        self.config = config or CircuitBreakerConfig()
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time = 0.0
        self.lock = threading.RLock()

        logger.info("Circuit breaker initialized for %s", name)

    def call(self, func: Callable, *args, **kwargs) -> Any:
        """
        Execute function with circuit breaker protection.

        Args:
            func: Function to execute
            *args: Function arguments
            **kwargs: Function keyword arguments

        Returns:
            Function result

        Raises:
            CircuitBreakerOpenException: When circuit is open
        """
        with self.lock:
            current_state = self._get_state()

            if current_state == CircuitState.OPEN:
                raise CircuitBreakerOpenException(self.name)

            try:
                result = func(*args, **kwargs)
                self._on_success()
                return result
            except Exception as e:
                self._on_failure(e)
                raise

    def _get_state(self) -> CircuitState:
        """Get current circuit state, potentially transitioning to half-open."""
        if self.state == CircuitState.OPEN:
            if time.time() - self.last_failure_time >= self.config.timeout:
                logger.info("Circuit breaker %s transitioning to half-open", self.name)
                self.state = CircuitState.HALF_OPEN
                self.success_count = 0

        return self.state

    def _on_success(self) -> None:
        """Handle successful function execution."""
        if self.state == CircuitState.HALF_OPEN:
            self.success_count += 1
            if self.success_count >= self.config.success_threshold:
                logger.info("Circuit breaker %s closing after recovery", self.name)
                self.state = CircuitState.CLOSED
                self.failure_count = 0
        elif self.state == CircuitState.CLOSED:
            # Reset failure count on successful call
            self.failure_count = 0

    def _on_failure(self, exception: Exception) -> None:
        """Handle failed function execution."""
        logger.warning("Circuit breaker %s recorded failure: %s", self.name, exception)

        self.failure_count += 1
        self.last_failure_time = time.time()

        if (
            self.state == CircuitState.CLOSED
            and self.failure_count >= self.config.failure_threshold
        ):
            logger.error("Circuit breaker %s opening due to failure threshold", self.name)
            self.state = CircuitState.OPEN
        elif self.state == CircuitState.HALF_OPEN:
            logger.warning("Circuit breaker %s reopening after half-open failure", self.name)
            self.state = CircuitState.OPEN

    def get_stats(self) -> dict[str, Any]:
        """Get circuit breaker statistics."""
        return {
            "name": self.name,
            "state": self.state.value,
            "failure_count": self.failure_count,
            "success_count": self.success_count,
            "last_failure_time": self.last_failure_time,
            "config": {
                "failure_threshold": self.config.failure_threshold,
                "success_threshold": self.config.success_threshold,
                "timeout": self.config.timeout,
            },
        }

    def reset(self) -> None:
        """Reset circuit breaker to closed state."""
        with self.lock:
            logger.info("Manually resetting circuit breaker %s", self.name)
            self.state = CircuitState.CLOSED
            self.failure_count = 0
            self.success_count = 0
            self.last_failure_time = 0.0


class CircuitBreakerManager:
    """Manages multiple circuit breakers for different services."""

    def __init__(self) -> None:
        self.circuit_breakers: dict[str, CircuitBreaker] = {}
        self.lock = threading.Lock()

    def get_circuit_breaker(
        self, name: str, config: CircuitBreakerConfig | None = None
    ) -> CircuitBreaker:
        """Get or create circuit breaker for service."""
        with self.lock:
            if name not in self.circuit_breakers:
                self.circuit_breakers[name] = CircuitBreaker(name, config)
            return self.circuit_breakers[name]

    def get_all_stats(self) -> dict[str, dict[str, Any]]:
        """Get statistics for all circuit breakers."""
        return {name: cb.get_stats() for name, cb in self.circuit_breakers.items()}

    def reset_all(self) -> None:
        """Reset all circuit breakers."""
        for cb in self.circuit_breakers.values():
            cb.reset()


# Global circuit breaker manager
_circuit_breaker_manager = CircuitBreakerManager()


def circuit_breaker(
    name: str | None = None, config: CircuitBreakerConfig | None = None
) -> Callable:
    """
    Decorator to add circuit breaker protection to functions.

    Args:
        name: Circuit breaker name (defaults to function name)
        config: Circuit breaker configuration

    Returns:
        Decorated function with circuit breaker protection
    """

    def decorator(func: Callable) -> Callable:
        breaker_name = name or f"{func.__module__}.{func.__name__}"
        cb = _circuit_breaker_manager.get_circuit_breaker(breaker_name, config)

        @wraps(func)
        def wrapper(*args, **kwargs):
            return cb.call(func, *args, **kwargs)

        wrapper.circuit_breaker = cb  # type: ignore
        return wrapper

    return decorator


def get_circuit_breaker_stats() -> dict[str, dict[str, Any]]:
    """Get statistics for all circuit breakers."""
    return _circuit_breaker_manager.get_all_stats()


def reset_circuit_breakers() -> None:
    """Reset all circuit breakers."""
    _circuit_breaker_manager.reset_all()
