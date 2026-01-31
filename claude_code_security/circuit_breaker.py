"""
Circuit Breaker: Fail-closed pattern for scanners. [Tier 2]

Prevents cascading failures and allows graceful degradation.
Standalone implementation with no external dependencies.

States:
    CLOSED: Normal operation, requests pass through
    OPEN: Failures exceeded threshold, requests fail fast
    HALF_OPEN: Testing if service recovered, limited requests
"""

import logging
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, Optional

logger = logging.getLogger("claude_code_security.circuit_breaker")


class CircuitState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreakerError(Exception):
    """Raised when circuit breaker is open."""
    pass


@dataclass
class CircuitBreakerConfig:
    failure_threshold: int = 5
    timeout_seconds: float = 60
    success_threshold: int = 3
    half_open_max_calls: int = 3
    window_seconds: float = 300
    expected_exceptions: tuple = (Exception,)


@dataclass
class CircuitBreakerStats:
    state: CircuitState = CircuitState.CLOSED
    failure_count: int = 0
    success_count: int = 0
    last_failure_time: Optional[float] = None
    last_state_change: float = field(default_factory=time.time)
    opened_at: Optional[float] = None
    half_opened_at: Optional[float] = None
    half_open_calls: int = 0
    total_calls: int = 0
    total_failures: int = 0
    total_successes: int = 0


class CircuitBreaker:
    """
    Circuit breaker for protecting operations from cascading failures.

    Tracks failures and opens circuit when threshold exceeded,
    preventing further calls until timeout expires.
    """

    def __init__(
        self,
        name: str,
        config: Optional[CircuitBreakerConfig] = None,
        **kwargs,
    ):
        self.name = name
        self.config = config or CircuitBreakerConfig(**kwargs)
        self.stats = CircuitBreakerStats()
        self._lock = threading.RLock()
        self._failure_times: list[float] = []

    def __call__(self, func: Callable) -> Callable:
        """Decorator to protect a function with circuit breaker."""
        def wrapper(*args, **kwargs):
            return self.call(func, *args, **kwargs)
        return wrapper

    @contextmanager
    def protected(self):
        """Context manager for circuit-breaker-protected code blocks."""
        self._before_call()
        try:
            yield self
            self._on_success()
        except CircuitBreakerError:
            raise
        except self.config.expected_exceptions:
            self._on_failure()
            raise

    def call(self, func: Callable, *args, **kwargs) -> Any:
        """Call function protected by circuit breaker."""
        self._before_call()
        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
        except CircuitBreakerError:
            raise
        except self.config.expected_exceptions:
            self._on_failure()
            raise

    def _before_call(self):
        with self._lock:
            self.stats.total_calls += 1
            if self.stats.state == CircuitState.CLOSED:
                return
            elif self.stats.state == CircuitState.OPEN:
                if self._should_attempt_reset():
                    self._transition_to_half_open()
                    return
                raise CircuitBreakerError(
                    f"Circuit breaker '{self.name}' is OPEN "
                    f"(timeout in {self._time_until_reset():.1f}s)"
                )
            elif self.stats.state == CircuitState.HALF_OPEN:
                if self.stats.half_open_calls >= self.config.half_open_max_calls:
                    raise CircuitBreakerError(
                        f"Circuit breaker '{self.name}' is HALF_OPEN "
                        f"(max concurrent calls reached)"
                    )
                self.stats.half_open_calls += 1

    def _on_success(self):
        with self._lock:
            self.stats.total_successes += 1
            if self.stats.state == CircuitState.HALF_OPEN:
                self.stats.success_count += 1
                self.stats.half_open_calls = max(0, self.stats.half_open_calls - 1)
                if self.stats.success_count >= self.config.success_threshold:
                    self._transition_to_closed()

    def _on_failure(self):
        with self._lock:
            current_time = time.time()
            self.stats.total_failures += 1
            self.stats.failure_count += 1
            self.stats.last_failure_time = current_time
            self._failure_times.append(current_time)
            self._clean_old_failures()

            if self.stats.state == CircuitState.CLOSED:
                if self._should_open():
                    self._transition_to_open()
            elif self.stats.state == CircuitState.HALF_OPEN:
                self.stats.half_open_calls = max(0, self.stats.half_open_calls - 1)
                self._transition_to_open()

    def _should_open(self) -> bool:
        return len(self._failure_times) >= self.config.failure_threshold

    def _should_attempt_reset(self) -> bool:
        if self.stats.opened_at is None:
            return False
        return (time.time() - self.stats.opened_at) >= self.config.timeout_seconds

    def _time_until_reset(self) -> float:
        if self.stats.opened_at is None:
            return 0.0
        return max(0.0, self.config.timeout_seconds - (time.time() - self.stats.opened_at))

    def _clean_old_failures(self):
        cutoff = time.time() - self.config.window_seconds
        self._failure_times = [t for t in self._failure_times if t > cutoff]

    def _transition_to_open(self):
        self.stats.state = CircuitState.OPEN
        self.stats.opened_at = time.time()
        self.stats.last_state_change = time.time()
        self.stats.success_count = 0

    def _transition_to_half_open(self):
        self.stats.state = CircuitState.HALF_OPEN
        self.stats.half_opened_at = time.time()
        self.stats.last_state_change = time.time()
        self.stats.success_count = 0
        self.stats.half_open_calls = 0

    def _transition_to_closed(self):
        self.stats.state = CircuitState.CLOSED
        self.stats.last_state_change = time.time()
        self.stats.failure_count = 0
        self.stats.success_count = 0
        self.stats.opened_at = None
        self.stats.half_opened_at = None
        self._failure_times.clear()

    def force_open(self):
        with self._lock:
            self._transition_to_open()

    def force_close(self):
        with self._lock:
            self._transition_to_closed()

    def reset(self):
        with self._lock:
            self.stats = CircuitBreakerStats()
            self._failure_times.clear()

    def get_state(self) -> CircuitState:
        return self.stats.state

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            from datetime import datetime
            return {
                "name": self.name,
                "state": self.stats.state.value,
                "failure_count": len(self._failure_times),
                "success_count": self.stats.success_count,
                "total_calls": self.stats.total_calls,
                "total_successes": self.stats.total_successes,
                "total_failures": self.stats.total_failures,
                "last_state_change": datetime.fromtimestamp(
                    self.stats.last_state_change
                ).isoformat(),
                "time_until_reset": (
                    self._time_until_reset()
                    if self.stats.state == CircuitState.OPEN
                    else None
                ),
            }
